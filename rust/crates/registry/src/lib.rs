//! Immutable tool/capability manifests, strict schemas, revocation, and snapshots.

use agent_trust_action_ir::RegistryPolicySnapshot;
use agent_trust_contracts::{
    EffectClass, RiskLevel, StrictJsonObject, TenantId, ToolId, ToolRef, ToolVersion,
};
use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;

pub const REGISTRY_SCHEMA_VERSION: &str = "agenttrust.registry.v1";
pub const AUTHORITATIVE_TOOLS_SCHEMA_VERSION: &str = "agenttrust.authoritative-tools.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolVersionStatus {
    Draft,
    Validated,
    Signed,
    Active,
    Deprecated,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationKind {
    WasmComponent,
    OciContainer,
    InternalService,
    HttpProxy,
    McpServer,
    IndustrialGateway,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    pub publisher_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompensationBinding {
    pub tool: ToolRef,
    pub precondition_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolLimits {
    pub timeout_ms: u64,
    pub max_result_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolImplementation {
    pub kind: ImplementationKind,
    pub digest: String,
    pub executor_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    pub schema_version: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub status: ToolVersionStatus,
    pub domain: String,
    pub display_name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub effect_class: EffectClass,
    pub risk_level: RiskLevel,
    pub executor_profile: String,
    pub credential_profile: String,
    pub approval_profile: String,
    pub compensation: Option<CompensationBinding>,
    pub limits: ToolLimits,
    pub network_profile_ref: String,
    pub filesystem_profile_ref: String,
    pub implementation: ToolImplementation,
    pub allowed_tenants: BTreeSet<TenantId>,
    pub signature: Option<ManifestSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    pub schema_version: String,
    pub capability_id: String,
    pub capability_version: String,
    pub description: String,
    pub required_tools: Vec<ToolRef>,
    pub optional_tools: Vec<ToolRef>,
    pub risk_summary: RiskLevel,
    pub supported_protocols: BTreeSet<String>,
    pub allowed_tenants: BTreeSet<TenantId>,
    pub signature: ManifestSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityDescriptor {
    pub manifest: CapabilityManifest,
    pub discovery_only: bool,
    pub authorization_required: bool,
}

#[derive(Debug, Clone)]
pub struct CapabilityQuery {
    pub tenant_id: TenantId,
    pub protocol: Option<String>,
    pub maximum_risk: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedToolSnapshot {
    pub schema_version: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub schema_hash: String,
    pub manifest_hash: String,
    pub effect_class: EffectClass,
    pub risk_level: RiskLevel,
    pub executor_profile: String,
    pub credential_profile: String,
    pub approval_profile: String,
    pub compensation: Option<CompensationBinding>,
    pub limits: ToolLimits,
    pub network_profile_ref: String,
    pub filesystem_profile_ref: String,
    pub implementation: ToolImplementation,
    pub registry_revision: u64,
    pub resolved_at: DateTime<Utc>,
    pub snapshot_hash: String,
    pub input_schema: Value,
    pub output_schema: Value,
}

impl ResolvedToolSnapshot {
    pub fn policy_snapshot(&self) -> RegistryPolicySnapshot {
        RegistryPolicySnapshot {
            snapshot_hash: self.snapshot_hash.clone(),
            tool_id: self.tool_id.0.clone(),
            tool_version: self.tool_version.0.clone(),
            risk: self.risk_level,
            effect: self.effect_class,
            implementation_digest: self.implementation.digest.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshot {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub revision: u64,
    pub tools: Vec<ResolvedToolSnapshot>,
    pub snapshot_hash: String,
    pub signed_at: DateTime<Utc>,
    /// Development registries do not publish an authoritative signature. The
    /// Postgres production store always returns `Some` and rejects unsigned
    /// persisted snapshots.
    pub signature: Option<ManifestSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeToolSummary {
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub effect_class: EffectClass,
    pub risk_level: RiskLevel,
    pub manifest_hash: String,
    pub implementation_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeToolsResponse {
    pub schema_version: String,
    pub authoritative: bool,
    pub tenant_id: TenantId,
    pub complete: bool,
    pub registry_revision: u64,
    pub digest: String,
    pub signed_at: DateTime<Utc>,
    pub signature: ManifestSignature,
    pub tools: Vec<AuthoritativeToolSummary>,
}

#[async_trait]
pub trait ToolRegistry: Send + Sync {
    async fn resolve_exact(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
    ) -> Result<ResolvedToolSnapshot, RegistryError>;
    async fn validate_arguments(
        &self,
        snapshot: &ResolvedToolSnapshot,
        args: &StrictJsonObject,
    ) -> Result<(), RegistryError>;
    async fn validate_output(
        &self,
        snapshot: &ResolvedToolSnapshot,
        output: &Value,
    ) -> Result<(), RegistryError>;
    async fn discover_capabilities(
        &self,
        query: CapabilityQuery,
    ) -> Result<Vec<CapabilityDescriptor>, RegistryError>;
    async fn snapshot(
        &self,
        tenant: &TenantId,
        refs: &[ToolRef],
    ) -> Result<RegistrySnapshot, RegistryError>;
    async fn is_revoked(&self, tool: &ToolRef, digest: &str) -> Result<bool, RegistryError>;
}

struct ToolRecord {
    manifest: ToolManifest,
    manifest_hash: String,
    schema_hash: String,
    revision: u64,
}

#[derive(Default)]
pub struct InMemoryToolRegistry {
    tools: RwLock<BTreeMap<ToolRef, ToolRecord>>,
    capabilities: RwLock<BTreeMap<(String, String), CapabilityManifest>>,
    publisher_keys: RwLock<BTreeMap<String, VerifyingKey>>,
    revision: AtomicU64,
    available: RwLock<bool>,
}

impl InMemoryToolRegistry {
    pub fn new() -> Self {
        Self {
            available: RwLock::new(true),
            ..Self::default()
        }
    }
    pub fn add_publisher_key(&self, key_id: impl Into<String>, key: VerifyingKey) {
        self.publisher_keys.write().insert(key_id.into(), key);
    }
    pub fn set_available(&self, available: bool) {
        *self.available.write() = available;
    }

    pub fn create_draft(&self, mut manifest: ToolManifest) -> Result<(), RegistryError> {
        manifest.status = ToolVersionStatus::Draft;
        manifest.signature = None;
        manifest
            .tool_ref()
            .validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let mut tools = self.tools.write();
        if tools.contains_key(&manifest.tool_ref()) {
            return Err(RegistryError::VersionConflict);
        }
        let revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        let manifest_hash = canonical_manifest_hash(&manifest)?;
        let schema_hash = canonical_schema_pair_hash(&manifest)?;
        tools.insert(
            manifest.tool_ref(),
            ToolRecord {
                manifest,
                manifest_hash,
                schema_hash,
                revision,
            },
        );
        Ok(())
    }

    pub fn validate_version(&self, tool: &ToolRef) -> Result<(), RegistryError> {
        let mut tools = self.tools.write();
        {
            let record = tools.get(tool).ok_or(RegistryError::ToolNotFound)?;
            if record.manifest.status != ToolVersionStatus::Draft {
                return Err(RegistryError::LifecycleInvalid);
            }
            validate_tool_manifest(&record.manifest, &tools)?;
        }
        let record = tools.get_mut(tool).ok_or(RegistryError::ToolNotFound)?;
        record.manifest.status = ToolVersionStatus::Validated;
        record.revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(())
    }

    pub fn sign_version(
        &self,
        tool: &ToolRef,
        publisher_id: String,
        key_id: String,
        key: &SigningKey,
    ) -> Result<(), RegistryError> {
        let mut tools = self.tools.write();
        let record = tools.get_mut(tool).ok_or(RegistryError::ToolNotFound)?;
        if record.manifest.status != ToolVersionStatus::Validated {
            return Err(RegistryError::LifecycleInvalid);
        }
        let signature =
            URL_SAFE_NO_PAD.encode(key.sign(record.manifest_hash.as_bytes()).to_bytes());
        record.manifest.signature = Some(ManifestSignature {
            publisher_id,
            key_id,
            algorithm: "Ed25519".into(),
            signature,
        });
        record.manifest.status = ToolVersionStatus::Signed;
        record.revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(())
    }

    pub fn activate(&self, tool: &ToolRef) -> Result<(), RegistryError> {
        let mut tools = self.tools.write();
        let record = tools.get_mut(tool).ok_or(RegistryError::ToolNotFound)?;
        if record.manifest.status != ToolVersionStatus::Signed {
            return Err(RegistryError::LifecycleInvalid);
        }
        verify_signature(record, &self.publisher_keys.read())?;
        record.manifest.status = ToolVersionStatus::Active;
        record.revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(())
    }

    pub fn deprecate(&self, tool: &ToolRef) -> Result<(), RegistryError> {
        self.transition(
            tool,
            ToolVersionStatus::Active,
            ToolVersionStatus::Deprecated,
        )
    }
    pub fn revoke(&self, tool: &ToolRef) -> Result<(), RegistryError> {
        let mut tools = self.tools.write();
        let record = tools.get_mut(tool).ok_or(RegistryError::ToolNotFound)?;
        if !matches!(
            record.manifest.status,
            ToolVersionStatus::Active | ToolVersionStatus::Deprecated
        ) {
            return Err(RegistryError::LifecycleInvalid);
        }
        record.manifest.status = ToolVersionStatus::Revoked;
        record.revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(())
    }
    fn transition(
        &self,
        tool: &ToolRef,
        from: ToolVersionStatus,
        to: ToolVersionStatus,
    ) -> Result<(), RegistryError> {
        let mut tools = self.tools.write();
        let record = tools.get_mut(tool).ok_or(RegistryError::ToolNotFound)?;
        if record.manifest.status != from {
            return Err(RegistryError::LifecycleInvalid);
        }
        record.manifest.status = to;
        record.revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(())
    }
    pub fn register_capability(&self, manifest: CapabilityManifest) -> Result<(), RegistryError> {
        if manifest.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(RegistryError::SchemaInvalid);
        }
        self.capabilities.write().insert(
            (
                manifest.capability_id.clone(),
                manifest.capability_version.clone(),
            ),
            manifest,
        );
        Ok(())
    }
}

impl ToolManifest {
    pub fn tool_ref(&self) -> ToolRef {
        ToolRef {
            tool_id: self.tool_id.clone(),
            tool_version: self.tool_version.clone(),
        }
    }
}

pub fn canonical_manifest_hash(manifest: &ToolManifest) -> Result<String, RegistryError> {
    let mut material = manifest.clone();
    material.signature = None;
    material.status = ToolVersionStatus::Draft;
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(&material).map_err(|_| RegistryError::ManifestHashMismatch)?,
    )))
}
pub fn canonical_schema_pair_hash(manifest: &ToolManifest) -> Result<String, RegistryError> {
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(&(&manifest.input_schema, &manifest.output_schema))
            .map_err(|_| RegistryError::SchemaInvalid)?,
    )))
}

fn verify_signature(
    record: &ToolRecord,
    keys: &BTreeMap<String, VerifyingKey>,
) -> Result<(), RegistryError> {
    let signature = record
        .manifest
        .signature
        .as_ref()
        .ok_or(RegistryError::SignatureInvalid)?;
    if signature.algorithm != "Ed25519" {
        return Err(RegistryError::SignatureInvalid);
    }
    let key = keys
        .get(&signature.key_id)
        .ok_or(RegistryError::SignatureInvalid)?;
    let raw = URL_SAFE_NO_PAD
        .decode(&signature.signature)
        .map_err(|_| RegistryError::SignatureInvalid)?;
    let signature = Signature::from_slice(&raw).map_err(|_| RegistryError::SignatureInvalid)?;
    key.verify(record.manifest_hash.as_bytes(), &signature)
        .map_err(|_| RegistryError::SignatureInvalid)
}

fn validate_tool_manifest(
    manifest: &ToolManifest,
    tools: &BTreeMap<ToolRef, ToolRecord>,
) -> Result<(), RegistryError> {
    validate_manifest_shape(manifest)?;
    if manifest.effect_class == EffectClass::Compensatable {
        let binding = manifest
            .compensation
            .as_ref()
            .ok_or(RegistryError::CompensationInvalid)?;
        if !tools.contains_key(&binding.tool) && binding.tool != manifest.tool_ref() {
            return Err(RegistryError::CompensationInvalid);
        }
    }
    Ok(())
}

fn validate_manifest_shape(manifest: &ToolManifest) -> Result<(), RegistryError> {
    if manifest.schema_version != REGISTRY_SCHEMA_VERSION
        || !valid_tool_id(&manifest.tool_id.0)
        || !valid_semver(&manifest.tool_version.0)
        || !valid_domain(&manifest.domain)
        || !valid_text(&manifest.display_name, 256)
        || !valid_text(&manifest.description, 8192)
        || !valid_profile_ref(&manifest.executor_profile)
        || !valid_profile_ref(&manifest.credential_profile)
        || !valid_profile_ref(&manifest.approval_profile)
        || !valid_profile_ref(&manifest.network_profile_ref)
        || !valid_profile_ref(&manifest.filesystem_profile_ref)
        || !valid_profile_ref(&manifest.implementation.executor_id)
    {
        return Err(RegistryError::SchemaInvalid);
    }
    if manifest.allowed_tenants.is_empty()
        || manifest
            .allowed_tenants
            .iter()
            .any(|tenant| match uuid::Uuid::parse_str(&tenant.0) {
                Ok(parsed) => parsed.to_string() != tenant.0,
                Err(_) => true,
            })
    {
        return Err(RegistryError::SchemaInvalid);
    }
    if let Some(compensation) = &manifest.compensation {
        if !valid_tool_id(&compensation.tool.tool_id.0)
            || !valid_semver(&compensation.tool.tool_version.0)
            || !valid_profile_ref(&compensation.precondition_kind)
        {
            return Err(RegistryError::CompensationInvalid);
        }
    }
    if let Some(signature) = &manifest.signature {
        let decoded = URL_SAFE_NO_PAD
            .decode(&signature.signature)
            .map_err(|_| RegistryError::SignatureInvalid)?;
        if signature.algorithm != "Ed25519"
            || !valid_identifier(&signature.publisher_id, 128)
            || !valid_identifier(&signature.key_id, 128)
            || decoded.len() != 64
        {
            return Err(RegistryError::SignatureInvalid);
        }
    }
    validate_schema_security(&manifest.input_schema)?;
    validate_schema_security(&manifest.output_schema)?;
    compile_schema(&manifest.input_schema)?;
    compile_schema(&manifest.output_schema)?;
    if !is_sha256_digest(&manifest.implementation.digest) {
        return Err(RegistryError::ImplementationDigestMismatch);
    }
    if manifest.limits.timeout_ms == 0
        || manifest.limits.timeout_ms > 86_400_000
        || manifest.limits.max_result_bytes == 0
        || manifest.limits.max_result_bytes > 1_073_741_824
    {
        return Err(RegistryError::SchemaInvalid);
    }
    if manifest.effect_class == EffectClass::Pure && manifest.credential_profile != "none" {
        return Err(RegistryError::CompensationInvalid);
    }
    if manifest.effect_class == EffectClass::Compensatable && manifest.compensation.is_none() {
        return Err(RegistryError::CompensationInvalid);
    }
    if manifest.effect_class == EffectClass::Irreversible
        && (manifest.risk_level < RiskLevel::High || manifest.approval_profile == "none")
    {
        return Err(RegistryError::CompensationInvalid);
    }
    Ok(())
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= maximum
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    valid_text(value, maximum)
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_profile_ref(value: &str) -> bool {
    valid_text(value, 256)
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_tool_id(value: &str) -> bool {
    value.len() <= 128
        && value.split('.').count() >= 2
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment.len() <= 63
                && segment
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !segment.ends_with('-')
        })
}

fn valid_semver(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let (version, build) = value
        .split_once('+')
        .map_or((value, None), |(version, build)| (version, Some(build)));
    if build.is_some_and(|identifiers| {
        identifiers.contains('+') || !valid_semver_identifiers(identifiers, false)
    }) {
        return false;
    }
    let (core, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    if prerelease.is_some_and(|identifiers| !valid_semver_identifiers(identifiers, true)) {
        return false;
    }
    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3 && parts.into_iter().all(valid_semver_number)
}

fn valid_semver_number(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_semver_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!reject_numeric_leading_zero
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || identifier == "0"
                    || !identifier.starts_with('0'))
        })
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_sha256_hex)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Reconstructs the immutable execution snapshot from an ACTIVE persisted manifest.
/// Production composition uses this instead of reimplementing Registry validation or hashes.
pub fn resolved_snapshot_from_active_manifest(
    tenant: &TenantId,
    manifest: &ToolManifest,
    compensation_target_active: bool,
) -> Result<ResolvedToolSnapshot, RegistryError> {
    if manifest.status != ToolVersionStatus::Active
        || (!manifest.allowed_tenants.is_empty() && !manifest.allowed_tenants.contains(tenant))
    {
        return Err(RegistryError::VersionNotActive);
    }
    validate_manifest_shape(manifest)?;
    if manifest.effect_class == EffectClass::Compensatable
        && manifest
            .compensation
            .as_ref()
            .is_some_and(|binding| binding.tool != manifest.tool_ref())
        && !compensation_target_active
    {
        return Err(RegistryError::CompensationInvalid);
    }
    let mut snapshot = ResolvedToolSnapshot {
        schema_version: REGISTRY_SCHEMA_VERSION.into(),
        tool_id: manifest.tool_id.clone(),
        tool_version: manifest.tool_version.clone(),
        schema_hash: canonical_schema_pair_hash(manifest)?,
        manifest_hash: canonical_manifest_hash(manifest)?,
        effect_class: manifest.effect_class,
        risk_level: manifest.risk_level,
        executor_profile: manifest.executor_profile.clone(),
        credential_profile: manifest.credential_profile.clone(),
        approval_profile: manifest.approval_profile.clone(),
        compensation: manifest.compensation.clone(),
        limits: manifest.limits.clone(),
        network_profile_ref: manifest.network_profile_ref.clone(),
        filesystem_profile_ref: manifest.filesystem_profile_ref.clone(),
        implementation: manifest.implementation.clone(),
        // The persisted ACTIVE row is authoritative and immutable, but is not itself a
        // signed registry snapshot. Revision 0 explicitly means row-bound resolution.
        registry_revision: 0,
        resolved_at: Utc::now(),
        snapshot_hash: String::new(),
        input_schema: manifest.input_schema.clone(),
        output_schema: manifest.output_schema.clone(),
    };
    snapshot.snapshot_hash = snapshot_hash(&snapshot)?;
    Ok(snapshot)
}

fn validate_schema_security(schema: &Value) -> Result<(), RegistryError> {
    fn declares_object(map: &serde_json::Map<String, Value>) -> bool {
        match map.get("type") {
            Some(Value::String(value)) => value == "object",
            Some(Value::Array(values)) => {
                values.iter().any(|value| value.as_str() == Some("object"))
            }
            _ => false,
        }
    }
    let root = schema.as_object().ok_or(RegistryError::SchemaInvalid)?;
    if root.is_empty()
        || root.get("$schema").is_some_and(|value| {
            value.as_str() != Some("https://json-schema.org/draft/2020-12/schema")
        })
        || (declares_object(root) && root.get("additionalProperties") != Some(&Value::Bool(false)))
    {
        return Err(RegistryError::SchemaInvalid);
    }
    fn walk(value: &Value, depth: usize) -> Result<(), RegistryError> {
        if depth > 32 {
            return Err(RegistryError::SchemaInvalid);
        }
        match value {
            Value::Object(map) => {
                if declares_object(map)
                    && map.get("additionalProperties") != Some(&Value::Bool(false))
                {
                    return Err(RegistryError::SchemaInvalid);
                }
                for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
                    if let Some(reference) = map.get(keyword) {
                        if !reference
                            .as_str()
                            .is_some_and(|reference| reference.starts_with('#'))
                        {
                            return Err(RegistryError::SchemaInvalid);
                        }
                    }
                }
                for child in map.values() {
                    walk(child, depth + 1)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    walk(child, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(schema, 0)
}

fn compile_schema(schema: &Value) -> Result<jsonschema::Validator, RegistryError> {
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(schema)
        .map_err(|_| RegistryError::SchemaInvalid)
}

pub fn validate_schema_instance(
    schema: &Value,
    instance: &Value,
    output: bool,
) -> Result<(), RegistryError> {
    let validator = compile_schema(schema)?;
    if validator.validate(instance).is_err() {
        return Err(if output {
            RegistryError::OutputInvalid
        } else {
            RegistryError::ArgumentInvalid
        });
    }
    Ok(())
}

#[async_trait]
impl ToolRegistry for InMemoryToolRegistry {
    async fn resolve_exact(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
    ) -> Result<ResolvedToolSnapshot, RegistryError> {
        if !*self.available.read() {
            return Err(RegistryError::UnavailableFailClosed);
        }
        tool.validate_exact()
            .map_err(|_| RegistryError::VersionRequired)?;
        let tools = self.tools.read();
        let record = tools.get(tool).ok_or(RegistryError::ToolNotFound)?;
        match record.manifest.status {
            ToolVersionStatus::Revoked => return Err(RegistryError::ToolRevoked),
            ToolVersionStatus::Active => {}
            _ => return Err(RegistryError::VersionNotActive),
        }
        if !record.manifest.allowed_tenants.is_empty()
            && !record.manifest.allowed_tenants.contains(tenant)
        {
            return Err(RegistryError::ToolNotFound);
        }
        let mut snapshot = ResolvedToolSnapshot {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            tool_id: record.manifest.tool_id.clone(),
            tool_version: record.manifest.tool_version.clone(),
            schema_hash: record.schema_hash.clone(),
            manifest_hash: record.manifest_hash.clone(),
            effect_class: record.manifest.effect_class,
            risk_level: record.manifest.risk_level,
            executor_profile: record.manifest.executor_profile.clone(),
            credential_profile: record.manifest.credential_profile.clone(),
            approval_profile: record.manifest.approval_profile.clone(),
            compensation: record.manifest.compensation.clone(),
            limits: record.manifest.limits.clone(),
            network_profile_ref: record.manifest.network_profile_ref.clone(),
            filesystem_profile_ref: record.manifest.filesystem_profile_ref.clone(),
            implementation: record.manifest.implementation.clone(),
            registry_revision: record.revision,
            resolved_at: Utc::now(),
            snapshot_hash: String::new(),
            input_schema: record.manifest.input_schema.clone(),
            output_schema: record.manifest.output_schema.clone(),
        };
        snapshot.snapshot_hash = snapshot_hash(&snapshot)?;
        Ok(snapshot)
    }
    async fn validate_arguments(
        &self,
        snapshot: &ResolvedToolSnapshot,
        args: &StrictJsonObject,
    ) -> Result<(), RegistryError> {
        validate_schema_instance(&snapshot.input_schema, &Value::Object(args.clone()), false)
    }
    async fn validate_output(
        &self,
        snapshot: &ResolvedToolSnapshot,
        output: &Value,
    ) -> Result<(), RegistryError> {
        validate_schema_instance(&snapshot.output_schema, output, true)
    }
    async fn discover_capabilities(
        &self,
        query: CapabilityQuery,
    ) -> Result<Vec<CapabilityDescriptor>, RegistryError> {
        if !*self.available.read() {
            return Err(RegistryError::UnavailableFailClosed);
        }
        Ok(self
            .capabilities
            .read()
            .values()
            .filter(|manifest| {
                (manifest.allowed_tenants.is_empty()
                    || manifest.allowed_tenants.contains(&query.tenant_id))
                    && manifest.risk_summary <= query.maximum_risk
                    && query
                        .protocol
                        .as_ref()
                        .is_none_or(|protocol| manifest.supported_protocols.contains(protocol))
            })
            .cloned()
            .map(|manifest| CapabilityDescriptor {
                manifest,
                discovery_only: true,
                authorization_required: true,
            })
            .collect())
    }
    async fn snapshot(
        &self,
        tenant: &TenantId,
        refs: &[ToolRef],
    ) -> Result<RegistrySnapshot, RegistryError> {
        let mut tools = Vec::with_capacity(refs.len());
        for tool in refs {
            tools.push(self.resolve_exact(tenant, tool).await?);
        }
        tools.sort_by(|a, b| (&a.tool_id, &a.tool_version).cmp(&(&b.tool_id, &b.tool_version)));
        let revision = self.revision.load(Ordering::SeqCst);
        let signed_at = Utc::now();
        let mut snapshot = RegistrySnapshot {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            revision,
            tools,
            snapshot_hash: String::new(),
            signed_at,
            signature: None,
        };
        snapshot.snapshot_hash = canonical_registry_snapshot_hash(&snapshot)?;
        Ok(snapshot)
    }
    async fn is_revoked(&self, tool: &ToolRef, digest: &str) -> Result<bool, RegistryError> {
        if !*self.available.read() {
            return Err(RegistryError::UnavailableFailClosed);
        }
        let tools = self.tools.read();
        let record = tools.get(tool).ok_or(RegistryError::ToolNotFound)?;
        Ok(record.manifest.status == ToolVersionStatus::Revoked
            || record.manifest.implementation.digest != digest)
    }
}

fn snapshot_hash(snapshot: &ResolvedToolSnapshot) -> Result<String, RegistryError> {
    let mut material = snapshot.clone();
    material.snapshot_hash.clear();
    material.resolved_at = DateTime::UNIX_EPOCH;
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(&material).map_err(|_| RegistryError::ManifestHashMismatch)?,
    )))
}

pub fn canonical_registry_snapshot_hash(
    snapshot: &RegistrySnapshot,
) -> Result<String, RegistryError> {
    let mut material = snapshot.clone();
    material.snapshot_hash.clear();
    material.signature = None;
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(&material).map_err(|_| RegistryError::ManifestHashMismatch)?,
    )))
}

mod postgres;
pub mod server;
pub use postgres::{
    PostgresRegistryStore, RegistryActivationReceipt, RegistryActivationRequest,
    RegistryPublisherSigner,
};

#[derive(Debug, Clone)]
pub struct RegistryAdminContext {
    pub tenant_id: TenantId,
    pub subject: String,
    pub can_write: bool,
}

#[derive(Debug, Clone)]
pub struct RegistryPeerIdentity(pub String);

#[async_trait]
pub trait RegistryAdminAuthorizer: Send + Sync {
    async fn authorize(
        &self,
        peer_identity: &str,
        headers: &HeaderMap,
        write: bool,
    ) -> Result<RegistryAdminContext, RegistryError>;
    fn production_ready(&self) -> bool;
}

#[derive(Clone)]
pub struct RegistryApiState {
    registry: RegistryApiBackend,
    authorizer: Arc<dyn RegistryAdminAuthorizer>,
    development_signer: Option<(String, String, Arc<SigningKey>)>,
}

#[derive(Clone)]
enum RegistryApiBackend {
    Development(Arc<InMemoryToolRegistry>),
    Production(Arc<PostgresRegistryStore>),
}

impl RegistryApiState {
    /// Compatibility constructor for development/test only. Passing
    /// `production=true` is deliberately rejected so production can never
    /// silently compose the in-memory registry.
    pub fn new(
        production: bool,
        registry: Arc<InMemoryToolRegistry>,
        authorizer: Arc<dyn RegistryAdminAuthorizer>,
        publisher_id: String,
        key_id: String,
        signing_key: SigningKey,
    ) -> Result<Self, RegistryError> {
        if production {
            return Err(RegistryError::InMemoryProductionForbidden);
        }
        registry.add_publisher_key(key_id.clone(), signing_key.verifying_key());
        Ok(Self {
            registry: RegistryApiBackend::Development(registry),
            authorizer,
            development_signer: Some((publisher_id, key_id, Arc::new(signing_key))),
        })
    }

    pub fn production(
        registry: Arc<PostgresRegistryStore>,
        authorizer: Arc<dyn RegistryAdminAuthorizer>,
    ) -> Result<Self, RegistryError> {
        if !authorizer.production_ready() {
            return Err(RegistryError::ManagementIdentityNotConfigured);
        }
        if !registry.production_signer_configured() {
            return Err(RegistryError::PublisherNotConfigured);
        }
        Ok(Self {
            registry: RegistryApiBackend::Production(registry),
            authorizer,
            development_signer: None,
        })
    }
}

pub fn registry_management_router(state: RegistryApiState) -> Router {
    Router::new()
        .route("/v1/tools:draft", post(api_create_draft))
        .route(
            "/v1/tools/{id}/versions/{version}/validate",
            post(api_validate),
        )
        .route("/v1/tools/{id}/versions/{version}/sign", post(api_sign))
        .route(
            "/v1/tools/{id}/versions/{version}/activate",
            post(api_activate),
        )
        .route(
            "/v1/tools/{id}/versions/{version}/deprecate",
            post(api_deprecate),
        )
        .route("/v1/tools/{id}/versions/{version}/revoke", post(api_revoke))
        .route("/v1/tools/{id}/versions/{version}", get(api_get_tool))
        .route("/v1/authoritative/tools", get(api_authoritative_tools))
        .route("/v1/capabilities", get(api_capabilities))
        .with_state(state)
}

async fn api_create_draft(
    State(state): State<RegistryApiState>,
    Extension(peer): Extension<RegistryPeerIdentity>,
    headers: HeaderMap,
    Json(mut manifest): Json<ToolManifest>,
) -> Result<StatusCode, RegistryApiError> {
    let context = state.authorizer.authorize(&peer.0, &headers, true).await?;
    if !context.can_write {
        return Err(RegistryError::ManagementForbidden.into());
    }
    manifest.allowed_tenants = BTreeSet::from([context.tenant_id.clone()]);
    match &state.registry {
        RegistryApiBackend::Development(registry) => registry.create_draft(manifest)?,
        RegistryApiBackend::Production(registry) => {
            registry
                .insert_draft_as(&context.tenant_id, &manifest, &context.subject)
                .await?
        }
    }
    Ok(StatusCode::CREATED)
}
fn api_tool(id: String, version: String) -> ToolRef {
    ToolRef {
        tool_id: ToolId(id),
        tool_version: ToolVersion(version),
    }
}
async fn api_validate(
    State(state): State<RegistryApiState>,
    Path((id, version)): Path<(String, String)>,
    Extension(peer): Extension<RegistryPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<RegistryActivationRequest>,
) -> Result<Json<RegistryActivationReceipt>, RegistryApiError> {
    let context = require_registry_write(&state, &peer.0, &headers).await?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let tool = api_tool(id, version);
    let receipt = match &state.registry {
        RegistryApiBackend::Development(registry) => {
            require_development_tenant(registry, &context.tenant_id, &tool)?;
            let manifest_hash = require_development_request(registry, &tool, &request)?;
            registry.validate_version(&tool)?;
            development_receipt(
                &context.tenant_id,
                &tool,
                "VALIDATE",
                ToolVersionStatus::Validated,
                manifest_hash,
                None,
                idempotency_key,
            )
        }
        RegistryApiBackend::Production(registry) => {
            registry
                .validate_version(
                    &context.tenant_id,
                    &tool,
                    &request,
                    idempotency_key,
                    &context.subject,
                )
                .await?
        }
    };
    Ok(Json(receipt))
}
async fn api_sign(
    State(state): State<RegistryApiState>,
    Path((id, version)): Path<(String, String)>,
    Extension(peer): Extension<RegistryPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<RegistryActivationRequest>,
) -> Result<Json<RegistryActivationReceipt>, RegistryApiError> {
    let context = require_registry_write(&state, &peer.0, &headers).await?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let tool = api_tool(id, version);
    let receipt = match &state.registry {
        RegistryApiBackend::Development(registry) => {
            require_development_tenant(registry, &context.tenant_id, &tool)?;
            let manifest_hash = require_development_request(registry, &tool, &request)?;
            let (publisher_id, key_id, signing_key) = state
                .development_signer
                .as_ref()
                .ok_or(RegistryError::PublisherNotConfigured)?;
            registry.sign_version(&tool, publisher_id.clone(), key_id.clone(), signing_key)?;
            development_receipt(
                &context.tenant_id,
                &tool,
                "SIGN",
                ToolVersionStatus::Signed,
                manifest_hash,
                None,
                idempotency_key,
            )
        }
        RegistryApiBackend::Production(registry) => {
            registry
                .sign_version(
                    &context.tenant_id,
                    &tool,
                    &request,
                    idempotency_key,
                    &context.subject,
                )
                .await?
        }
    };
    Ok(Json(receipt))
}
async fn api_activate(
    State(state): State<RegistryApiState>,
    Path((id, version)): Path<(String, String)>,
    Extension(peer): Extension<RegistryPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<RegistryActivationRequest>,
) -> Result<Json<RegistryActivationReceipt>, RegistryApiError> {
    let context = require_registry_write(&state, &peer.0, &headers).await?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let tool = api_tool(id, version);
    let receipt = match &state.registry {
        RegistryApiBackend::Development(registry) => {
            require_development_tenant(registry, &context.tenant_id, &tool)?;
            let manifest = registry
                .tools
                .read()
                .get(&tool)
                .map(|record| record.manifest_hash.clone())
                .ok_or(RegistryError::ToolNotFound)?;
            if request.schema_version != REGISTRY_SCHEMA_VERSION
                || request.expected_manifest_hash != manifest
            {
                return Err(RegistryError::ManifestHashMismatch.into());
            }
            registry.activate(&tool)?;
            let snapshot = registry.resolve_exact(&context.tenant_id, &tool).await?;
            RegistryActivationReceipt {
                schema_version: REGISTRY_SCHEMA_VERSION.into(),
                tenant_id: context.tenant_id,
                tool_id: tool.tool_id,
                tool_version: tool.tool_version,
                operation: "ACTIVATE".into(),
                status: ToolVersionStatus::Active,
                registry_revision: Some(snapshot.registry_revision),
                manifest_hash: snapshot.manifest_hash,
                snapshot_hash: Some(snapshot.snapshot_hash),
                event_ref: format!("development-registry://{idempotency_key}"),
                idempotent: false,
            }
        }
        RegistryApiBackend::Production(registry) => {
            registry
                .activate(
                    &context.tenant_id,
                    &tool,
                    &request,
                    idempotency_key,
                    &context.subject,
                )
                .await?
        }
    };
    Ok(Json(receipt))
}
async fn api_deprecate(
    State(state): State<RegistryApiState>,
    Path((id, version)): Path<(String, String)>,
    Extension(peer): Extension<RegistryPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<RegistryActivationRequest>,
) -> Result<Json<RegistryActivationReceipt>, RegistryApiError> {
    let context = require_registry_write(&state, &peer.0, &headers).await?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let tool = api_tool(id, version);
    let receipt = match &state.registry {
        RegistryApiBackend::Development(registry) => {
            require_development_tenant(registry, &context.tenant_id, &tool)?;
            let manifest_hash = require_development_request(registry, &tool, &request)?;
            registry.deprecate(&tool)?;
            development_receipt(
                &context.tenant_id,
                &tool,
                "DEPRECATE",
                ToolVersionStatus::Deprecated,
                manifest_hash,
                None,
                idempotency_key,
            )
        }
        RegistryApiBackend::Production(registry) => {
            registry
                .deprecate(
                    &context.tenant_id,
                    &tool,
                    &request,
                    idempotency_key,
                    &context.subject,
                )
                .await?
        }
    };
    Ok(Json(receipt))
}
async fn api_revoke(
    State(state): State<RegistryApiState>,
    Path((id, version)): Path<(String, String)>,
    Extension(peer): Extension<RegistryPeerIdentity>,
    headers: HeaderMap,
    Json(request): Json<RegistryActivationRequest>,
) -> Result<Json<RegistryActivationReceipt>, RegistryApiError> {
    let context = require_registry_write(&state, &peer.0, &headers).await?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let tool = api_tool(id, version);
    let receipt = match &state.registry {
        RegistryApiBackend::Development(registry) => {
            require_development_tenant(registry, &context.tenant_id, &tool)?;
            let manifest_hash = require_development_request(registry, &tool, &request)?;
            registry.revoke(&tool)?;
            development_receipt(
                &context.tenant_id,
                &tool,
                "REVOKE",
                ToolVersionStatus::Revoked,
                manifest_hash,
                None,
                idempotency_key,
            )
        }
        RegistryApiBackend::Production(registry) => {
            registry
                .revoke(
                    &context.tenant_id,
                    &tool,
                    &request,
                    idempotency_key,
                    &context.subject,
                )
                .await?
        }
    };
    Ok(Json(receipt))
}
async fn api_get_tool(
    State(state): State<RegistryApiState>,
    Path((id, version)): Path<(String, String)>,
    Extension(peer): Extension<RegistryPeerIdentity>,
    headers: HeaderMap,
) -> Result<Json<ResolvedToolSnapshot>, RegistryApiError> {
    let context = state.authorizer.authorize(&peer.0, &headers, false).await?;
    let tool = api_tool(id, version);
    let snapshot = match &state.registry {
        RegistryApiBackend::Development(registry) => {
            registry.resolve_exact(&context.tenant_id, &tool).await?
        }
        RegistryApiBackend::Production(registry) => {
            registry.resolve_exact(&context.tenant_id, &tool).await?
        }
    };
    Ok(Json(snapshot))
}
async fn api_capabilities(
    State(state): State<RegistryApiState>,
    Extension(peer): Extension<RegistryPeerIdentity>,
    headers: HeaderMap,
) -> Result<Json<Vec<CapabilityDescriptor>>, RegistryApiError> {
    let context = state.authorizer.authorize(&peer.0, &headers, false).await?;
    let query = CapabilityQuery {
        tenant_id: context.tenant_id,
        protocol: None,
        maximum_risk: RiskLevel::Critical,
    };
    let capabilities = match &state.registry {
        RegistryApiBackend::Development(registry) => registry.discover_capabilities(query).await?,
        RegistryApiBackend::Production(registry) => registry.discover_capabilities(query).await?,
    };
    Ok(Json(capabilities))
}

async fn api_authoritative_tools(
    State(state): State<RegistryApiState>,
    Extension(peer): Extension<RegistryPeerIdentity>,
    headers: HeaderMap,
) -> Result<Json<AuthoritativeToolsResponse>, RegistryApiError> {
    let context = state.authorizer.authorize(&peer.0, &headers, false).await?;
    let snapshot = match &state.registry {
        RegistryApiBackend::Development(registry) => {
            let refs = registry
                .tools
                .read()
                .iter()
                .filter(|(_, record)| {
                    record.manifest.status == ToolVersionStatus::Active
                        && (record.manifest.allowed_tenants.is_empty()
                            || record.manifest.allowed_tenants.contains(&context.tenant_id))
                })
                .map(|(tool, _)| tool.clone())
                .collect::<Vec<_>>();
            registry.snapshot(&context.tenant_id, &refs).await?
        }
        RegistryApiBackend::Production(registry) => {
            registry.snapshot(&context.tenant_id, &[]).await?
        }
    };
    if snapshot.tools.len() > 1_000 {
        return Err(RegistryError::UnavailableFailClosed.into());
    }
    let signature = snapshot
        .signature
        .clone()
        .ok_or(RegistryError::SignatureInvalid)?;
    let tools = snapshot
        .tools
        .into_iter()
        .map(|tool| AuthoritativeToolSummary {
            tool_id: tool.tool_id,
            tool_version: tool.tool_version,
            effect_class: tool.effect_class,
            risk_level: tool.risk_level,
            manifest_hash: tool.manifest_hash,
            implementation_digest: tool.implementation.digest,
        })
        .collect();
    Ok(Json(AuthoritativeToolsResponse {
        schema_version: AUTHORITATIVE_TOOLS_SCHEMA_VERSION.into(),
        authoritative: true,
        tenant_id: context.tenant_id,
        complete: true,
        registry_revision: snapshot.revision,
        digest: snapshot.snapshot_hash,
        signed_at: snapshot.signed_at,
        signature,
        tools,
    }))
}

async fn require_registry_write(
    state: &RegistryApiState,
    peer_identity: &str,
    headers: &HeaderMap,
) -> Result<RegistryAdminContext, RegistryError> {
    let context = state
        .authorizer
        .authorize(peer_identity, headers, true)
        .await?;
    if !context.can_write {
        return Err(RegistryError::ManagementForbidden);
    }
    Ok(context)
}

fn require_development_tenant(
    registry: &InMemoryToolRegistry,
    tenant: &TenantId,
    tool: &ToolRef,
) -> Result<(), RegistryError> {
    let tools = registry.tools.read();
    let record = tools.get(tool).ok_or(RegistryError::ToolNotFound)?;
    if !record.manifest.allowed_tenants.contains(tenant) {
        return Err(RegistryError::ToolNotFound);
    }
    Ok(())
}

fn require_development_request(
    registry: &InMemoryToolRegistry,
    tool: &ToolRef,
    request: &RegistryActivationRequest,
) -> Result<String, RegistryError> {
    let tools = registry.tools.read();
    let manifest_hash = tools
        .get(tool)
        .map(|record| record.manifest_hash.clone())
        .ok_or(RegistryError::ToolNotFound)?;
    if request.schema_version != REGISTRY_SCHEMA_VERSION
        || !is_sha256_hex(&request.expected_manifest_hash)
        || request.expected_manifest_hash != manifest_hash
    {
        return Err(RegistryError::ManifestHashMismatch);
    }
    Ok(manifest_hash)
}

fn development_receipt(
    tenant: &TenantId,
    tool: &ToolRef,
    operation: &str,
    status: ToolVersionStatus,
    manifest_hash: String,
    snapshot_hash: Option<String>,
    idempotency_key: &str,
) -> RegistryActivationReceipt {
    RegistryActivationReceipt {
        schema_version: REGISTRY_SCHEMA_VERSION.into(),
        tenant_id: tenant.clone(),
        tool_id: tool.tool_id.clone(),
        tool_version: tool.tool_version.clone(),
        operation: operation.into(),
        status,
        registry_revision: None,
        manifest_hash,
        snapshot_hash,
        event_ref: format!("development-registry://{idempotency_key}"),
        idempotent: false,
    }
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, RegistryError> {
    let mut values = headers.get_all("Idempotency-Key").iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
                })
        })
        .ok_or(RegistryError::IdempotencyInvalid)?;
    if values.next().is_some() {
        return Err(RegistryError::IdempotencyInvalid);
    }
    Ok(value)
}

pub struct RegistryApiError(RegistryError);
impl From<RegistryError> for RegistryApiError {
    fn from(value: RegistryError) -> Self {
        Self(value)
    }
}
impl IntoResponse for RegistryApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            RegistryError::ToolNotFound => StatusCode::NOT_FOUND,
            RegistryError::VersionConflict
            | RegistryError::LifecycleInvalid
            | RegistryError::ManifestHashMismatch
            | RegistryError::IdempotencyConflict
            | RegistryError::PublisherInUse => StatusCode::CONFLICT,
            RegistryError::ManagementForbidden => StatusCode::FORBIDDEN,
            RegistryError::SchemaInvalid
            | RegistryError::VersionRequired
            | RegistryError::CompensationInvalid
            | RegistryError::ProfileNotFound
            | RegistryError::IdempotencyInvalid => StatusCode::BAD_REQUEST,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(serde_json::json!({"error":{"code":self.0.to_string(),"summary":"registry request rejected"}}))).into_response()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RegistryError {
    #[error("REGISTRY_TOOL_NOT_FOUND")]
    ToolNotFound,
    #[error("REGISTRY_VERSION_REQUIRED")]
    VersionRequired,
    #[error("REGISTRY_VERSION_NOT_ACTIVE")]
    VersionNotActive,
    #[error("REGISTRY_TOOL_REVOKED")]
    ToolRevoked,
    #[error("REGISTRY_SCHEMA_INVALID")]
    SchemaInvalid,
    #[error("REGISTRY_ARGUMENT_INVALID")]
    ArgumentInvalid,
    #[error("REGISTRY_OUTPUT_INVALID")]
    OutputInvalid,
    #[error("REGISTRY_MANIFEST_HASH_MISMATCH")]
    ManifestHashMismatch,
    #[error("REGISTRY_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("REGISTRY_IMPLEMENTATION_DIGEST_MISMATCH")]
    ImplementationDigestMismatch,
    #[error("REGISTRY_COMPENSATION_INVALID")]
    CompensationInvalid,
    #[error("REGISTRY_PROFILE_NOT_FOUND")]
    ProfileNotFound,
    #[error("REGISTRY_UNAVAILABLE_FAIL_CLOSED")]
    UnavailableFailClosed,
    #[error("REGISTRY_VERSION_CONFLICT")]
    VersionConflict,
    #[error("REGISTRY_LIFECYCLE_INVALID")]
    LifecycleInvalid,
    #[error("REGISTRY_STORE_FAILURE")]
    StoreFailure,
    #[error("REGISTRY_MANAGEMENT_IDENTITY_NOT_CONFIGURED")]
    ManagementIdentityNotConfigured,
    #[error("REGISTRY_MANAGEMENT_FORBIDDEN")]
    ManagementForbidden,
    #[error("REGISTRY_IN_MEMORY_PRODUCTION_FORBIDDEN")]
    InMemoryProductionForbidden,
    #[error("REGISTRY_PUBLISHER_NOT_CONFIGURED")]
    PublisherNotConfigured,
    #[error("REGISTRY_PUBLISHER_INVALID")]
    PublisherInvalid,
    #[error("REGISTRY_PUBLISHER_CONFLICT")]
    PublisherConflict,
    #[error("REGISTRY_PUBLISHER_IN_USE")]
    PublisherInUse,
    #[error("REGISTRY_IDEMPOTENCY_INVALID")]
    IdempotencyInvalid,
    #[error("REGISTRY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("REGISTRY_TENANT_REQUIRED")]
    TenantRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(tenant: TenantId) -> ToolManifest {
        ToolManifest {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            tool_id: ToolId("coding.repo-read".into()),
            tool_version: ToolVersion("1.0.0".into()),
            status: ToolVersionStatus::Draft,
            domain: "coding".into(),
            display_name: "Repo read".into(),
            description: "Read a repository path".into(),
            input_schema: serde_json::json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["path"],"properties":{"path":{"type":"string","maxLength":256}}}),
            output_schema: serde_json::json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["content"],"properties":{"content":{"type":"string"}}}),
            effect_class: EffectClass::Pure,
            risk_level: RiskLevel::Low,
            executor_profile: "coding-read".into(),
            credential_profile: "none".into(),
            approval_profile: "none".into(),
            compensation: None,
            limits: ToolLimits {
                timeout_ms: 5000,
                max_result_bytes: 4096,
            },
            network_profile_ref: "none".into(),
            filesystem_profile_ref: "repo-ro".into(),
            implementation: ToolImplementation {
                kind: ImplementationKind::InternalService,
                digest: format!("sha256:{}", "a".repeat(64)),
                executor_id: "repo-reader".into(),
            },
            allowed_tenants: BTreeSet::from([tenant]),
            signature: None,
        }
    }

    fn active_registry(tenant: &TenantId) -> (InMemoryToolRegistry, ToolRef) {
        let registry = InMemoryToolRegistry::new();
        let key = SigningKey::from_bytes(&[4u8; 32]);
        registry.add_publisher_key("publisher", key.verifying_key());
        let manifest = manifest(tenant.clone());
        let tool = manifest.tool_ref();
        registry
            .create_draft(manifest)
            .unwrap_or_else(|_| panic!("draft"));
        registry
            .validate_version(&tool)
            .unwrap_or_else(|_| panic!("validate"));
        registry
            .sign_version(&tool, "pub".into(), "publisher".into(), &key)
            .unwrap_or_else(|_| panic!("sign"));
        registry
            .activate(&tool)
            .unwrap_or_else(|_| panic!("activate"));
        (registry, tool)
    }

    #[tokio::test]
    async fn exact_active_version_and_schema_are_enforced() {
        let tenant = TenantId::new();
        let (registry, tool) = active_registry(&tenant);
        let snapshot = registry
            .resolve_exact(&tenant, &tool)
            .await
            .unwrap_or_else(|_| panic!("resolve"));
        assert!(
            registry
                .validate_arguments(
                    &snapshot,
                    &serde_json::from_value(serde_json::json!({"path":"src"})).unwrap_or_default()
                )
                .await
                .is_ok()
        );
        assert_eq!(
            registry
                .validate_arguments(
                    &snapshot,
                    &serde_json::from_value(serde_json::json!({"path":"src","token":"x"}))
                        .unwrap_or_default()
                )
                .await,
            Err(RegistryError::ArgumentInvalid)
        );
        let latest = ToolRef {
            tool_id: tool.tool_id.clone(),
            tool_version: ToolVersion("latest".into()),
        };
        assert_eq!(
            registry.resolve_exact(&tenant, &latest).await,
            Err(RegistryError::VersionRequired)
        );
    }

    #[tokio::test]
    async fn revocation_wins_over_snapshot_cache() {
        let tenant = TenantId::new();
        let (registry, tool) = active_registry(&tenant);
        let snapshot = registry
            .resolve_exact(&tenant, &tool)
            .await
            .unwrap_or_else(|_| panic!("resolve"));
        registry.revoke(&tool).unwrap_or_else(|_| panic!("revoke"));
        assert_eq!(
            registry.resolve_exact(&tenant, &tool).await,
            Err(RegistryError::ToolRevoked)
        );
        assert_eq!(
            registry
                .is_revoked(&tool, &snapshot.implementation.digest)
                .await,
            Ok(true)
        );
    }

    #[tokio::test]
    async fn tenant_isolation_hides_tool_existence() {
        let tenant = TenantId::new();
        let other = TenantId::new();
        let (registry, tool) = active_registry(&tenant);
        assert_eq!(
            registry.resolve_exact(&other, &tool).await,
            Err(RegistryError::ToolNotFound)
        );
    }

    #[test]
    fn remote_schema_refs_are_rejected() {
        let tenant = TenantId::new();
        let registry = InMemoryToolRegistry::new();
        let mut bad = manifest(tenant);
        bad.input_schema = serde_json::json!({"type":"object","additionalProperties":false,"properties":{"x":{"$ref":"https://evil/schema"}}});
        let tool = bad.tool_ref();
        registry
            .create_draft(bad)
            .unwrap_or_else(|_| panic!("draft"));
        assert_eq!(
            registry.validate_version(&tool),
            Err(RegistryError::SchemaInvalid)
        );
    }

    #[test]
    fn manifest_identifiers_semver_and_digest_are_strict() {
        assert!(valid_tool_id("coding.repo-read"));
        assert!(!valid_tool_id("repo-read"));
        assert!(valid_semver("1.2.3-alpha-beta.1+build-7.sha"));
        assert!(valid_semver("184467440737095516160.0.0"));
        for invalid in ["latest", "01.2.3", "1.2.3-01", "1.2.3+", "1.2.3++x"] {
            assert!(!valid_semver(invalid), "{invalid}");
        }
        assert!(is_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_sha256_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(valid_identifier("publisher:key-1", 128));
        assert!(!valid_identifier("-publisher", 128));
    }

    #[test]
    fn manifest_business_invariants_are_fail_closed() {
        let tenant = TenantId::new();
        let mut invalid = manifest(tenant.clone());
        invalid.credential_profile = "unexpected".into();
        assert_eq!(
            validate_manifest_shape(&invalid),
            Err(RegistryError::CompensationInvalid)
        );
        invalid = manifest(tenant);
        invalid.display_name = " padded ".into();
        assert_eq!(
            validate_manifest_shape(&invalid),
            Err(RegistryError::SchemaInvalid)
        );
    }

    struct UnreadyAuthorizer;

    #[async_trait]
    impl RegistryAdminAuthorizer for UnreadyAuthorizer {
        async fn authorize(
            &self,
            _peer_identity: &str,
            _headers: &HeaderMap,
            _write: bool,
        ) -> Result<RegistryAdminContext, RegistryError> {
            Err(RegistryError::ManagementForbidden)
        }

        fn production_ready(&self) -> bool {
            false
        }
    }

    #[test]
    fn production_management_api_requires_real_authorizer() {
        let result = RegistryApiState::new(
            true,
            Arc::new(InMemoryToolRegistry::new()),
            Arc::new(UnreadyAuthorizer),
            "publisher".into(),
            "publisher-key".into(),
            SigningKey::from_bytes(&[23u8; 32]),
        );
        assert!(matches!(
            result,
            Err(RegistryError::InMemoryProductionForbidden)
        ));
    }

    #[test]
    fn repository_json_schemas_are_valid_and_example_is_conformant() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap_or_else(|_| panic!("workspace root"));
        let schema_dir = root.join("schemas/json");
        let entries = std::fs::read_dir(&schema_dir).unwrap_or_else(|_| panic!("schema directory"));
        for entry in entries {
            let path = entry.unwrap_or_else(|_| panic!("schema entry")).path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let schema: Value = serde_json::from_slice(
                &std::fs::read(&path).unwrap_or_else(|_| panic!("schema file")),
            )
            .unwrap_or_else(|_| panic!("schema json"));
            assert!(jsonschema::meta::is_valid(&schema), "{}", path.display());
        }

        let common: Value = serde_json::from_slice(
            &std::fs::read(schema_dir.join("common.schema.json"))
                .unwrap_or_else(|_| panic!("common schema")),
        )
        .unwrap_or_else(|_| panic!("common schema json"));
        let registry = jsonschema::Registry::new()
            .add(
                "https://agenttrust.local/schemas/common.schema.json",
                common,
            )
            .unwrap_or_else(|_| panic!("schema registry"))
            .prepare()
            .unwrap_or_else(|_| panic!("prepared schema registry"));
        let goal_schema: Value = serde_json::from_slice(
            &std::fs::read(schema_dir.join("signed-goal.schema.json"))
                .unwrap_or_else(|_| panic!("goal schema")),
        )
        .unwrap_or_else(|_| panic!("goal schema json"));
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&goal_schema)
            .unwrap_or_else(|_| panic!("goal validator"));
        let example: Value = serde_json::from_slice(
            &std::fs::read(root.join("schemas/examples/valid/signed-goal.json"))
                .unwrap_or_else(|_| panic!("goal example")),
        )
        .unwrap_or_else(|_| panic!("goal example json"));
        assert!(validator.is_valid(&example));
    }
}
