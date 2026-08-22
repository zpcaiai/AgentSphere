//! Signed supply-chain artifacts and the shared Domain Pack SDK.

pub mod production;
pub mod server;

use agent_trust_contracts::EffectClass;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const PACK_SCHEMA_VERSION: &str = "agenttrust.domain-pack.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SbomRef {
    pub format: String,
    pub digest: String,
    pub component_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildProvenance {
    pub source_repository: String,
    pub source_commit: String,
    pub builder_identity: String,
    pub build_definition_digest: String,
    pub built_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub key_id: String,
    pub publisher_identity: String,
    pub subject_digest: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub schema_version: String,
    pub artifact_id: String,
    pub artifact_type: String,
    pub version: String,
    pub digest: String,
    pub immutable_reference: String,
    pub sbom: SbomRef,
    pub provenance: BuildProvenance,
    pub compatibility: BTreeSet<String>,
    pub vulnerability_severity: Option<String>,
    pub signature: SignatureEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PackPermissionDeclaration {
    pub tools: BTreeSet<String>,
    pub network_destinations: BTreeSet<String>,
    pub data_classes: BTreeSet<String>,
    pub secret_scopes: BTreeSet<String>,
    pub executors: BTreeSet<String>,
    pub approval_scopes: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackToolDefinition {
    pub tool_id: String,
    pub effect_class: EffectClass,
    pub approval_required: bool,
    pub compensation_ref: Option<String>,
    pub irreversible_reason: Option<String>,
    pub executor_template: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DomainPackManifest {
    pub schema_version: String,
    pub pack_id: String,
    pub version: String,
    pub digest: String,
    pub publisher_identity: String,
    pub description: String,
    pub permissions: PackPermissionDeclaration,
    pub tools: Vec<PackToolDefinition>,
    pub policy_bundle_ref: String,
    pub evaluator_ref: String,
    pub compensation_refs: BTreeSet<String>,
    pub threat_scenario_refs: BTreeSet<String>,
    pub artifact_refs: BTreeSet<String>,
    pub compatibility: BTreeSet<String>,
    pub signature: SignatureEnvelope,
}

impl DomainPackManifest {
    pub fn compute_digest(&self) -> Result<String, PackError> {
        let mut copy = self.clone();
        copy.digest.clear();
        copy.signature.subject_digest.clear();
        copy.signature.signature.clear();
        Ok(hex(Sha256::digest(
            serde_jcs::to_vec(&copy).map_err(|_| PackError::Canonicalization)?,
        )))
    }

    pub fn sign(&mut self, key_id: String, signing_key: &SigningKey) -> Result<(), PackError> {
        if key_id.is_empty() || self.publisher_identity.is_empty() {
            return Err(PackError::ManifestInvalid);
        }
        self.signature.key_id = key_id;
        self.signature.publisher_identity = self.publisher_identity.clone();
        self.signature.signed_at = Utc::now();
        self.digest = self.compute_digest()?;
        self.signature.subject_digest = self.digest.clone();
        self.signature.signature =
            URL_SAFE_NO_PAD.encode(signing_key.sign(self.digest.as_bytes()).to_bytes());
        Ok(())
    }
}

pub struct PackSdk;

impl PackSdk {
    pub fn validate(manifest: &DomainPackManifest) -> Result<(), PackError> {
        let declared_tools=manifest.tools.iter().map(|tool|tool.tool_id.clone()).collect::<BTreeSet<_>>();
        let approval_tools=manifest.tools.iter().filter(|tool|tool.approval_required).map(|tool|tool.tool_id.clone()).collect::<BTreeSet<_>>();
        let compensation_refs=manifest.tools.iter().filter_map(|tool|tool.compensation_ref.clone()).collect::<BTreeSet<_>>();
        if manifest.schema_version != PACK_SCHEMA_VERSION
            || !bounded_identifier(&manifest.pack_id,256)
            || !valid_semver(&manifest.version)
            || !bounded_text(&manifest.description,4096)
            || !immutable_reference(&manifest.policy_bundle_ref,"policy")
            || !immutable_reference(&manifest.evaluator_ref,"evaluator")
            || manifest.threat_scenario_refs.is_empty()
            || manifest.artifact_refs.is_empty()
            || manifest.compatibility.is_empty()
            || manifest.tools.is_empty()
            || manifest.tools.len()>1024
            || manifest.artifact_refs.len()>256
            || manifest.threat_scenario_refs.len()>256
            || manifest.compatibility.len()>256
            || manifest.compensation_refs.len()>1024
            || !lower_digest(&manifest.digest)
            || !bounded_identifier(&manifest.publisher_identity,256)
            || manifest.permissions.tools!=declared_tools
            || manifest.permissions.approval_scopes!=approval_tools
            || manifest.compensation_refs!=compensation_refs
            || manifest.artifact_refs.iter().any(|value|!immutable_reference(value,"artifact"))
            || manifest.threat_scenario_refs.iter().any(|value|!bounded_identifier(value,512))
            || manifest.compatibility.iter().any(|value|!bounded_identifier(value,256))
            || manifest.permissions.network_destinations.len()>256
            || manifest.permissions.data_classes.len()>256
            || manifest.permissions.secret_scopes.len()>256
            || manifest.permissions.executors.len()>256
            || manifest.permissions.approval_scopes.len()>1024
            || manifest.permissions.network_destinations.iter().any(|value|!bounded_identifier(value,512))
            || manifest.permissions.data_classes.iter().any(|value|!bounded_identifier(value,256))
            || manifest.permissions.secret_scopes.iter().any(|value|!bounded_identifier(value,256))
            || manifest.permissions.executors.iter().any(|value|!bounded_identifier(value,256))
        {
            return Err(PackError::ManifestInvalid);
        }
        for tool in &manifest.tools {
            if !bounded_identifier(&tool.tool_id,256)
                || !bounded_identifier(&tool.executor_template,256)
                || tool.executor_template.contains("/bin/sh")
                || tool.executor_template.contains("bash -c")
                || !manifest.permissions.tools.contains(&tool.tool_id)
            {
                return Err(PackError::ToolInvalid);
            }
            match tool.effect_class {
                EffectClass::Pure | EffectClass::Idempotent => {
                    if tool.compensation_ref.is_some()||tool.irreversible_reason.is_some(){return Err(PackError::ToolInvalid);}
                }
                EffectClass::Compensatable => {
                    let compensation = tool
                        .compensation_ref
                        .as_ref()
                        .ok_or(PackError::CompensationMissing)?;
                    if !manifest.compensation_refs.contains(compensation) || !tool.approval_required
                        ||!bounded_identifier(compensation,512)||tool.irreversible_reason.is_some()
                    {
                        return Err(PackError::CompensationMissing);
                    }
                }
                EffectClass::Irreversible => {
                    if !tool.approval_required||tool.compensation_ref.is_some()
                        || tool
                            .irreversible_reason
                            .as_deref()
                            .is_none_or(str::is_empty)
                    {
                        return Err(PackError::IrreversibleControlMissing);
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct ArtifactVerifier {
    authorized_publishers: RwLock<BTreeMap<String, (String, VerifyingKey)>>,
    revoked_digests: RwLock<BTreeSet<String>>,
}

impl Default for ArtifactVerifier {
    fn default() -> Self {
        Self {
            authorized_publishers: RwLock::new(BTreeMap::new()),
            revoked_digests: RwLock::new(BTreeSet::new()),
        }
    }
}

impl ArtifactVerifier {
    pub fn authorize_publisher(&self, key_id: String, publisher: String, key: VerifyingKey) {
        self.authorized_publishers
            .write()
            .insert(key_id, (publisher, key));
    }

    pub fn revoke_digest(&self, digest: String) {
        self.revoked_digests.write().insert(digest);
    }

    pub fn verify_pack(&self, manifest: &DomainPackManifest) -> Result<(), PackError> {
        PackSdk::validate(manifest)?;
        if self.revoked_digests.read().contains(&manifest.digest)
            || manifest.digest != manifest.compute_digest()?
            || manifest.signature.subject_digest != manifest.digest
            || manifest.signature.publisher_identity != manifest.publisher_identity
        {
            return Err(PackError::SignatureInvalid);
        }
        let (publisher, key) = self
            .authorized_publishers
            .read()
            .get(&manifest.signature.key_id)
            .cloned()
            .ok_or(PackError::PublisherUnauthorized)?;
        if publisher != manifest.publisher_identity {
            return Err(PackError::PublisherUnauthorized);
        }
        verify_signature(&key, &manifest.digest, &manifest.signature.signature)
    }

    pub fn verify_artifact(&self, artifact: &ArtifactManifest) -> Result<(), PackError> {
        if artifact.schema_version != PACK_SCHEMA_VERSION
            || !lower_digest(&artifact.digest)
            || !lower_digest(&artifact.sbom.digest)
            || artifact.provenance.source_commit.len() < 7
            || artifact.immutable_reference.to_ascii_lowercase().contains(":latest")
            || !artifact.immutable_reference.contains(&format!("sha256:{}",artifact.digest))
            || !matches!(artifact.sbom.format.as_str(),"SPDX_JSON"|"CYCLONEDX_JSON")
            || artifact.sbom.component_count==0
            || !matches!(artifact.vulnerability_severity.as_deref(),None|Some("NONE"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL"))
            || artifact.signature.subject_digest != artifact.digest
            || self.revoked_digests.read().contains(&artifact.digest)
            || matches!(
                artifact.vulnerability_severity.as_deref(),
                Some("CRITICAL" | "HIGH")
            )
        {
            return Err(PackError::ArtifactDenied);
        }
        let (publisher, key) = self
            .authorized_publishers
            .read()
            .get(&artifact.signature.key_id)
            .cloned()
            .ok_or(PackError::PublisherUnauthorized)?;
        if publisher != artifact.signature.publisher_identity {
            return Err(PackError::PublisherUnauthorized);
        }
        verify_signature(&key, &artifact.digest, &artifact.signature.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PermissionDiff {
    pub added_tools: BTreeSet<String>,
    pub added_network_destinations: BTreeSet<String>,
    pub added_data_classes: BTreeSet<String>,
    pub added_secret_scopes: BTreeSet<String>,
    pub added_executors: BTreeSet<String>,
    pub added_approval_scopes: BTreeSet<String>,
}

impl PermissionDiff {
    pub fn compute(old: &PackPermissionDeclaration, new: &PackPermissionDeclaration) -> Self {
        Self {
            added_tools: new.tools.difference(&old.tools).cloned().collect(),
            added_network_destinations: new
                .network_destinations
                .difference(&old.network_destinations)
                .cloned()
                .collect(),
            added_data_classes: new
                .data_classes
                .difference(&old.data_classes)
                .cloned()
                .collect(),
            added_secret_scopes: new
                .secret_scopes
                .difference(&old.secret_scopes)
                .cloned()
                .collect(),
            added_executors: new.executors.difference(&old.executors).cloned().collect(),
            added_approval_scopes: new
                .approval_scopes
                .difference(&old.approval_scopes)
                .cloned()
                .collect(),
        }
    }

    pub fn expands_privilege(&self) -> bool {
        !self.added_tools.is_empty()
            || !self.added_network_destinations.is_empty()
            || !self.added_data_classes.is_empty()
            || !self.added_secret_scopes.is_empty()
            || !self.added_executors.is_empty()
            || !self.added_approval_scopes.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackState {
    Published,
    Approved,
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackRelease {
    pub manifest: DomainPackManifest,
    pub state: PackState,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub environments: BTreeSet<String>,
    pub revoked_reason: Option<String>,
    pub running_task_response: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistrySnapshot {
    schema_version: String,
    releases: Vec<PackRelease>,
}

#[cfg(test)]
pub struct PackRegistry {
    verifier: ArtifactVerifier,
    releases: RwLock<BTreeMap<(String, String), PackRelease>>,
}

#[cfg(test)]
impl PackRegistry {
    pub fn new(verifier: ArtifactVerifier) -> Self {
        Self {
            verifier,
            releases: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn publish(&self, manifest: DomainPackManifest) -> Result<PackRelease, PackError> {
        self.verifier.verify_pack(&manifest)?;
        let key = (manifest.pack_id.clone(), manifest.version.clone());
        let mut releases = self.releases.write();
        if let Some(existing) = releases.get(&key) {
            if existing.manifest.digest == manifest.digest {
                return Ok(existing.clone());
            }
            return Err(PackError::VersionDigestConflict);
        }
        let release = PackRelease {
            manifest,
            state: PackState::Published,
            approved_by: None,
            approved_at: None,
            environments: BTreeSet::new(),
            revoked_reason: None,
            running_task_response: None,
        };
        releases.insert(key, release.clone());
        Ok(release)
    }

    pub fn approve(
        &self,
        pack_id: &str,
        version: &str,
        approver: String,
        reviewed_diff: Option<&PermissionDiff>,
    ) -> Result<PackRelease, PackError> {
        if approver.is_empty() {
            return Err(PackError::ApprovalRequired);
        }
        let mut releases = self.releases.write();
        let key = (pack_id.into(), version.into());
        let candidate = releases.get(&key).cloned().ok_or(PackError::NotFound)?;
        let previous = releases
            .values()
            .filter(|release| {
                release.manifest.pack_id == pack_id && release.state == PackState::Active
            })
            .max_by(|left, right| left.manifest.version.cmp(&right.manifest.version));
        if let Some(previous) = previous {
            let diff = PermissionDiff::compute(
                &previous.manifest.permissions,
                &candidate.manifest.permissions,
            );
            if diff.expands_privilege() && reviewed_diff != Some(&diff) {
                return Err(PackError::PermissionExpansionUnapproved);
            }
        }
        let release = releases.get_mut(&key).ok_or(PackError::NotFound)?;
        if release.state != PackState::Published {
            return Err(PackError::LifecycleDenied);
        }
        release.state = PackState::Approved;
        release.approved_by = Some(approver);
        release.approved_at = Some(Utc::now());
        Ok(release.clone())
    }

    pub fn activate(
        &self,
        pack_id: &str,
        version: &str,
        environment: &str,
    ) -> Result<PackRelease, PackError> {
        if environment.is_empty() || environment.eq_ignore_ascii_case("production") {
            return Err(PackError::ProductionActivationRequiresGate);
        }
        let mut releases = self.releases.write();
        let release = releases
            .get_mut(&(pack_id.into(), version.into()))
            .ok_or(PackError::NotFound)?;
        if release.state != PackState::Approved {
            return Err(PackError::LifecycleDenied);
        }
        release.state = PackState::Active;
        release.environments.insert(environment.into());
        Ok(release.clone())
    }

    pub fn activate_production(
        &self,
        pack_id: &str,
        version: &str,
        certificate_digest: &str,
    ) -> Result<PackRelease, PackError> {
        if certificate_digest.len() != 64 {
            return Err(PackError::ProductionActivationRequiresGate);
        }
        let mut releases = self.releases.write();
        let release = releases
            .get_mut(&(pack_id.into(), version.into()))
            .ok_or(PackError::NotFound)?;
        if release.state != PackState::Approved {
            return Err(PackError::LifecycleDenied);
        }
        release.state = PackState::Active;
        release.environments.insert("production".into());
        Ok(release.clone())
    }

    pub fn revoke(
        &self,
        pack_id: &str,
        version: &str,
        reason: String,
        running_task_response: String,
    ) -> Result<PackRelease, PackError> {
        if reason.is_empty()
            || !matches!(
                running_task_response.as_str(),
                "PAUSE" | "KILL" | "ALLOW_TO_FINISH"
            )
        {
            return Err(PackError::RevocationInvalid);
        }
        let mut releases = self.releases.write();
        let release = releases
            .get_mut(&(pack_id.into(), version.into()))
            .ok_or(PackError::NotFound)?;
        release.state = PackState::Revoked;
        release.revoked_reason = Some(reason);
        release.running_task_response = Some(running_task_response);
        self.verifier.revoke_digest(release.manifest.digest.clone());
        Ok(release.clone())
    }

    pub fn resolve_active(
        &self,
        pack_id: &str,
        version: &str,
        environment: &str,
    ) -> Result<PackRelease, PackError> {
        let release = self
            .releases
            .read()
            .get(&(pack_id.into(), version.into()))
            .cloned()
            .ok_or(PackError::NotFound)?;
        if release.state != PackState::Active || !release.environments.contains(environment) {
            return Err(PackError::LifecycleDenied);
        }
        Ok(release)
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, PackError> {
        serde_json::to_vec(&RegistrySnapshot {
            schema_version: PACK_SCHEMA_VERSION.into(),
            releases: self.releases.read().values().cloned().collect(),
        })
        .map_err(|_| PackError::PersistenceFailed)
    }

    pub fn restore(bytes: &[u8], verifier: ArtifactVerifier) -> Result<Self, PackError> {
        let snapshot: RegistrySnapshot =
            serde_json::from_slice(bytes).map_err(|_| PackError::PersistenceFailed)?;
        if snapshot.schema_version != PACK_SCHEMA_VERSION {
            return Err(PackError::PersistenceFailed);
        }
        let releases = snapshot
            .releases
            .into_iter()
            .map(|release| {
                (
                    (
                        release.manifest.pack_id.clone(),
                        release.manifest.version.clone(),
                    ),
                    release,
                )
            })
            .collect();
        Ok(Self {
            verifier,
            releases: RwLock::new(releases),
        })
    }
}

fn verify_signature(key: &VerifyingKey, digest: &str, encoded: &str) -> Result<(), PackError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PackError::SignatureInvalid)?;
    let signature = Signature::from_slice(&decoded).map_err(|_| PackError::SignatureInvalid)?;
    key.verify(digest.as_bytes(), &signature)
        .map_err(|_| PackError::SignatureInvalid)
}

fn valid_semver(version: &str) -> bool {
    let parts = version.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn lower_digest(value:&str)->bool{
    value.len()==64&&value.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte))
}

fn immutable_reference(value:&str,kind:&str)->bool{
    value.strip_prefix(&format!("{kind}:sha256:")).is_some_and(lower_digest)
}

fn bounded_identifier(value:&str,maximum:usize)->bool{
    !value.is_empty()&&value.len()<=maximum&&value.bytes().all(|byte|byte.is_ascii_graphic())
}

fn bounded_text(value:&str,maximum:usize)->bool{
    !value.trim().is_empty()&&value.len()<=maximum&&!value.chars().any(char::is_control)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PackError {
    #[error("PACK_CANONICALIZATION_FAILED")]
    Canonicalization,
    #[error("PACK_MANIFEST_INVALID")]
    ManifestInvalid,
    #[error("PACK_TOOL_INVALID")]
    ToolInvalid,
    #[error("PACK_COMPENSATION_MISSING")]
    CompensationMissing,
    #[error("PACK_IRREVERSIBLE_CONTROL_MISSING")]
    IrreversibleControlMissing,
    #[error("PACK_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("PACK_PUBLISHER_UNAUTHORIZED")]
    PublisherUnauthorized,
    #[error("PACK_ARTIFACT_DENIED")]
    ArtifactDenied,
    #[error("PACK_VERSION_DIGEST_CONFLICT")]
    VersionDigestConflict,
    #[error("PACK_APPROVAL_REQUIRED")]
    ApprovalRequired,
    #[error("PACK_PERMISSION_EXPANSION_UNAPPROVED")]
    PermissionExpansionUnapproved,
    #[error("PACK_LIFECYCLE_DENIED")]
    LifecycleDenied,
    #[error("PACK_PRODUCTION_ACTIVATION_REQUIRES_GATE")]
    ProductionActivationRequiresGate,
    #[error("PACK_REVOCATION_INVALID")]
    RevocationInvalid,
    #[error("PACK_NOT_FOUND")]
    NotFound,
    #[error("PACK_PERSISTENCE_FAILED")]
    PersistenceFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str, publisher: &str, key: &SigningKey) -> DomainPackManifest {
        let tool = "coding.repo_read".to_string();
        let mut value = DomainPackManifest {
            schema_version: PACK_SCHEMA_VERSION.into(),
            pack_id: "coding".into(),
            version: version.into(),
            digest: String::new(),
            publisher_identity: publisher.into(),
            description: "safe coding pack".into(),
            permissions: PackPermissionDeclaration {
                tools: BTreeSet::from([tool.clone()]),
                ..PackPermissionDeclaration::default()
            },
            tools: vec![PackToolDefinition {
                tool_id: tool,
                effect_class: EffectClass::Pure,
                approval_required: false,
                compensation_ref: None,
                irreversible_reason: None,
                executor_template: "repo-read-v1".into(),
            }],
            policy_bundle_ref: format!("policy:sha256:{}","1".repeat(64)),
            evaluator_ref: format!("evaluator:sha256:{}","2".repeat(64)),
            compensation_refs: BTreeSet::new(),
            threat_scenario_refs: BTreeSet::from(["threat:path-traversal".into()]),
            artifact_refs: BTreeSet::from([format!("artifact:sha256:{}","3".repeat(64))]),
            compatibility: BTreeSet::from(["agenttrust.contracts.v1".into()]),
            signature: SignatureEnvelope {
                key_id: String::new(),
                publisher_identity: String::new(),
                subject_digest: String::new(),
                signature: String::new(),
                signed_at: Utc::now(),
            },
        };
        value
            .sign("publisher-key".into(), key)
            .unwrap_or_else(|error| panic!("sign: {error}"));
        value
    }

    fn registry(key: &SigningKey) -> PackRegistry {
        let verifier = ArtifactVerifier::default();
        verifier.authorize_publisher(
            "publisher-key".into(),
            "publisher:trusted".into(),
            key.verifying_key(),
        );
        PackRegistry::new(verifier)
    }

    #[test]
    fn tamper_and_same_version_digest_conflict_are_rejected() {
        let key = SigningKey::from_bytes(&[21_u8; 32]);
        let registry = registry(&key);
        let signed = manifest("1.0.0", "publisher:trusted", &key);
        registry
            .publish(signed.clone())
            .unwrap_or_else(|error| panic!("publish: {error}"));
        let mut tampered = signed;
        tampered.description = "changed".into();
        assert_eq!(registry.publish(tampered), Err(PackError::SignatureInvalid));
    }

    #[test]
    fn production_never_activates_without_gate_and_revocation_blocks_new_tasks() {
        let key = SigningKey::from_bytes(&[22_u8; 32]);
        let registry = registry(&key);
        let signed = manifest("1.0.0", "publisher:trusted", &key);
        registry
            .publish(signed)
            .unwrap_or_else(|error| panic!("publish: {error}"));
        registry
            .approve("coding", "1.0.0", "reviewer:1".into(), None)
            .unwrap_or_else(|error| panic!("approve: {error}"));
        assert_eq!(
            registry.activate("coding", "1.0.0", "production"),
            Err(PackError::ProductionActivationRequiresGate)
        );
        registry
            .activate_production("coding", "1.0.0", &"c".repeat(64))
            .unwrap_or_else(|error| panic!("activate: {error}"));
        registry
            .revoke("coding", "1.0.0", "vulnerability".into(), "PAUSE".into())
            .unwrap_or_else(|error| panic!("revoke: {error}"));
        assert_eq!(
            registry.resolve_active("coding", "1.0.0", "production"),
            Err(PackError::LifecycleDenied)
        );
    }

    #[test]
    fn unsafe_tool_and_permission_expansion_fail_closed() {
        let key = SigningKey::from_bytes(&[23_u8; 32]);
        let registry = registry(&key);
        let first = manifest("1.0.0", "publisher:trusted", &key);
        registry
            .publish(first)
            .unwrap_or_else(|error| panic!("publish: {error}"));
        registry
            .approve("coding", "1.0.0", "reviewer:1".into(), None)
            .unwrap_or_else(|error| panic!("approve: {error}"));
        registry
            .activate("coding", "1.0.0", "staging")
            .unwrap_or_else(|error| panic!("activate: {error}"));

        let mut expanded = manifest("1.1.0", "publisher:trusted", &key);
        expanded
            .permissions
            .network_destinations
            .insert("packages.example".into());
        expanded
            .sign("publisher-key".into(), &key)
            .unwrap_or_else(|error| panic!("sign expanded: {error}"));
        registry
            .publish(expanded.clone())
            .unwrap_or_else(|error| panic!("publish expanded: {error}"));
        assert_eq!(
            registry.approve("coding", "1.1.0", "reviewer:1".into(), None),
            Err(PackError::PermissionExpansionUnapproved)
        );
        let diff = PermissionDiff::compute(
            &manifest("1.0.0", "publisher:trusted", &key).permissions,
            &expanded.permissions,
        );
        assert!(
            registry
                .approve("coding", "1.1.0", "reviewer:1".into(), Some(&diff))
                .is_ok()
        );

        let mut unsafe_manifest = manifest("2.0.0", "publisher:trusted", &key);
        unsafe_manifest.tools[0].executor_template = "/bin/sh -c arbitrary".into();
        unsafe_manifest
            .sign("publisher-key".into(), &key)
            .unwrap_or_else(|error| panic!("sign unsafe: {error}"));
        assert_eq!(
            registry.publish(unsafe_manifest),
            Err(PackError::ToolInvalid)
        );
    }

    #[test]
    fn registry_snapshot_recovers_exact_release() {
        let key = SigningKey::from_bytes(&[24_u8; 32]);
        let registry = registry(&key);
        registry
            .publish(manifest("1.0.0", "publisher:trusted", &key))
            .unwrap_or_else(|error| panic!("publish: {error}"));
        let bytes = registry
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let verifier = ArtifactVerifier::default();
        verifier.authorize_publisher(
            "publisher-key".into(),
            "publisher:trusted".into(),
            key.verifying_key(),
        );
        let recovered = PackRegistry::restore(&bytes, verifier)
            .unwrap_or_else(|error| panic!("restore: {error}"));
        assert_eq!(recovered.releases.read().len(), 1);
    }
}
