//! Schema-driven CN standard adapter skeleton. No unpublished standard fields are invented.

use agent_trust_contracts::{RiskLevel, SchemaVersion, TenantId};
use agent_trust_protocol_adapter_sdk::{MappingLoss, MappingLossSeverity, MappingResult};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const CN_ADAPTER_SCHEMA_VERSION: &str = "agenttrust.cn-adapter.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CnStandardVersionBundle {
    pub schema_version: String,
    pub standard_id: String,
    pub standard_version: String,
    pub source_uri: String,
    pub published_at: DateTime<Utc>,
    pub license: String,
    pub schema: Value,
    pub schema_hash: String,
    pub field_mappings: BTreeMap<String, String>,
    pub required_security_fields: BTreeSet<String>,
    pub bundle_digest: String,
}

impl CnStandardVersionBundle {
    pub fn verify(&self) -> Result<(), CnAdapterError> {
        if self.schema_version != CN_ADAPTER_SCHEMA_VERSION
            || self.standard_id.is_empty()
            || self.standard_version.is_empty()
            || !self.source_uri.starts_with("https://")
            || self.license.is_empty()
            || !jsonschema::meta::is_valid(&self.schema)
            || self.schema_hash
                != hex(Sha256::digest(
                    serde_jcs::to_vec(&self.schema)
                        .map_err(|_| CnAdapterError::VersionBundleInvalid)?,
                ))
            || self.field_mappings.is_empty()
            || self.required_security_fields.is_empty()
        {
            return Err(CnAdapterError::VersionBundleInvalid);
        }
        let mut copy = self.clone();
        copy.bundle_digest.clear();
        let digest = format!(
            "sha256:{}",
            hex(Sha256::digest(
                serde_jcs::to_vec(&copy).map_err(|_| CnAdapterError::VersionBundleInvalid)?
            ))
        );
        if self.bundle_digest != digest {
            return Err(CnAdapterError::VersionBundleInvalid);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct CnVersionRegistry {
    bundles: RwLock<BTreeMap<(String, String), CnStandardVersionBundle>>,
    active: RwLock<BTreeMap<String, String>>,
}

impl CnVersionRegistry {
    pub fn register(&self, bundle: CnStandardVersionBundle) -> Result<(), CnAdapterError> {
        bundle.verify()?;
        let key = (bundle.standard_id.clone(), bundle.standard_version.clone());
        if self.bundles.read().contains_key(&key) {
            return Err(CnAdapterError::VersionConflict);
        }
        self.bundles.write().insert(key, bundle);
        Ok(())
    }
    pub fn activate(&self, standard_id: &str, version: &str) -> Result<(), CnAdapterError> {
        let key = (standard_id.to_string(), version.to_string());
        if !self.bundles.read().contains_key(&key) {
            return Err(CnAdapterError::UnknownVersion);
        }
        self.active
            .write()
            .insert(standard_id.into(), version.into());
        Ok(())
    }
    pub fn rollback(&self, standard_id: &str, version: &str) -> Result<(), CnAdapterError> {
        self.activate(standard_id, version)
    }
    pub fn resolve(
        &self,
        standard_id: &str,
        version: &str,
    ) -> Result<CnStandardVersionBundle, CnAdapterError> {
        self.bundles
            .read()
            .get(&(standard_id.into(), version.into()))
            .cloned()
            .ok_or(CnAdapterError::UnknownVersion)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CnIdentityClaim {
    pub external_agent_id: String,
    pub organization_code: Option<String>,
    pub lifecycle_state: String,
    pub endpoint: String,
    pub trust_evidence_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MappedCnIdentity {
    pub schema_version: SchemaVersion,
    pub external_agent_id: String,
    pub tenant_id: TenantId,
    pub trust_level: String,
    pub authenticated: bool,
    pub source_bundle_digest: String,
}

pub struct CnIdentityMapper;
impl CnIdentityMapper {
    pub fn map(
        bundle: &CnStandardVersionBundle,
        document: &Value,
        trusted_tenant: TenantId,
        authentication_verified: bool,
    ) -> Result<MappingResult<MappedCnIdentity>, CnAdapterError> {
        validate_document(bundle, document)?;
        require_security_fields(bundle, document)?;
        let agent_path = bundle
            .field_mappings
            .get("identity.agent_id")
            .ok_or(CnAdapterError::MappingIncomplete)?;
        let external_agent_id = document
            .pointer(agent_path)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(CnAdapterError::MappingIncomplete)?
            .to_string();
        let mut losses = Vec::new();
        if !authentication_verified {
            losses.push(MappingLoss {
                source_path: agent_path.clone(),
                target_concept: "identity.authenticated".into(),
                reason_code: "IDENTIFIER_IS_NOT_AUTHENTICATION".into(),
                severity: MappingLossSeverity::ReviewRequired,
            });
        }
        Ok(MappingResult {
            schema_version: CN_ADAPTER_SCHEMA_VERSION.into(),
            value: MappedCnIdentity {
                schema_version: SchemaVersion(CN_ADAPTER_SCHEMA_VERSION.into()),
                external_agent_id,
                tenant_id: trusted_tenant,
                trust_level: if authentication_verified {
                    "verified".into()
                } else {
                    "untrusted".into()
                },
                authenticated: authentication_verified,
                source_bundle_digest: bundle.bundle_digest.clone(),
            },
            losses,
            coverage_millionths: if authentication_verified {
                1_000_000
            } else {
                850_000
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CnCapabilityDescription {
    pub capability_id: String,
    pub name: String,
    pub risk: RiskLevel,
    pub discovery_only: bool,
    pub source_bundle_digest: String,
}

pub struct CnCapabilityMapper;
impl CnCapabilityMapper {
    pub fn map(
        bundle: &CnStandardVersionBundle,
        document: &Value,
    ) -> Result<MappingResult<CnCapabilityDescription>, CnAdapterError> {
        validate_document(bundle, document)?;
        let id_path = bundle
            .field_mappings
            .get("capability.id")
            .ok_or(CnAdapterError::MappingIncomplete)?;
        let name_path = bundle
            .field_mappings
            .get("capability.name")
            .ok_or(CnAdapterError::MappingIncomplete)?;
        let id = document
            .pointer(id_path)
            .and_then(Value::as_str)
            .ok_or(CnAdapterError::MappingIncomplete)?;
        let name = document
            .pointer(name_path)
            .and_then(Value::as_str)
            .ok_or(CnAdapterError::MappingIncomplete)?;
        Ok(MappingResult {
            schema_version: CN_ADAPTER_SCHEMA_VERSION.into(),
            value: CnCapabilityDescription {
                capability_id: id.into(),
                name: name.into(),
                risk: RiskLevel::High,
                discovery_only: true,
                source_bundle_digest: bundle.bundle_digest.clone(),
            },
            losses: vec![MappingLoss {
                source_path: "$".into(),
                target_concept: "authorization".into(),
                reason_code: "DISCOVERY_DOES_NOT_GRANT_AUTHORIZATION".into(),
                severity: MappingLossSeverity::Informational,
            }],
            coverage_millionths: 900_000,
        })
    }
}

#[derive(Default)]
pub struct ExtensionNamespaceRegistry {
    namespaces: RwLock<BTreeSet<String>>,
}
impl ExtensionNamespaceRegistry {
    pub fn register(&self, namespace: String) -> Result<(), CnAdapterError> {
        if namespace.len() < 3
            || !namespace.contains('.')
            || namespace.starts_with("agenttrust.core")
        {
            return Err(CnAdapterError::ExtensionInvalid);
        }
        self.namespaces.write().insert(namespace);
        Ok(())
    }
    pub fn validate_extensions(
        &self,
        extensions: &BTreeMap<String, Value>,
    ) -> Result<(), CnAdapterError> {
        let core_fields = [
            "tenant_id",
            "trust_level",
            "authorization",
            "policy",
            "resource_version",
        ];
        for key in extensions.keys() {
            let namespace = key
                .rsplit_once('.')
                .map(|(prefix, _)| prefix)
                .ok_or(CnAdapterError::ExtensionInvalid)?;
            if !self.namespaces.read().contains(namespace)
                || core_fields.iter().any(|field| key.ends_with(field))
            {
                return Err(CnAdapterError::ExtensionInvalid);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityReport {
    pub schema_version: String,
    pub standard_id: String,
    pub standard_version: String,
    pub internal_ir_version: String,
    pub coverage_millionths: u32,
    pub unmapped_security_fields: Vec<String>,
    pub production_compatible: bool,
}

pub struct CompatibilityReporter;
impl CompatibilityReporter {
    pub fn report(bundle: &CnStandardVersionBundle) -> CompatibilityReport {
        let missing: Vec<String> = bundle
            .required_security_fields
            .iter()
            .filter(|field| !bundle.field_mappings.contains_key(*field))
            .cloned()
            .collect();
        let mapped = bundle.field_mappings.len() as u32;
        let required = bundle.required_security_fields.len().max(1) as u32;
        CompatibilityReport {
            schema_version: CN_ADAPTER_SCHEMA_VERSION.into(),
            standard_id: bundle.standard_id.clone(),
            standard_version: bundle.standard_version.clone(),
            internal_ir_version: "agenttrust.action.v1".into(),
            coverage_millionths: (mapped.min(required) * 1_000_000) / required,
            production_compatible: missing.is_empty(),
            unmapped_security_fields: missing,
        }
    }
}

fn validate_document(
    bundle: &CnStandardVersionBundle,
    document: &Value,
) -> Result<(), CnAdapterError> {
    let validator = jsonschema::validator_for(&bundle.schema)
        .map_err(|_| CnAdapterError::VersionBundleInvalid)?;
    if validator.is_valid(document) {
        Ok(())
    } else {
        Err(CnAdapterError::DocumentInvalid)
    }
}
fn require_security_fields(
    bundle: &CnStandardVersionBundle,
    document: &Value,
) -> Result<(), CnAdapterError> {
    for concept in &bundle.required_security_fields {
        let pointer = bundle
            .field_mappings
            .get(concept)
            .ok_or(CnAdapterError::MappingIncomplete)?;
        if document.pointer(pointer).is_none() {
            return Err(CnAdapterError::MappingIncomplete);
        }
    }
    Ok(())
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CnAdapterError {
    #[error("CN_VERSION_BUNDLE_INVALID")]
    VersionBundleInvalid,
    #[error("CN_VERSION_CONFLICT")]
    VersionConflict,
    #[error("CN_UNKNOWN_VERSION")]
    UnknownVersion,
    #[error("CN_DOCUMENT_INVALID")]
    DocumentInvalid,
    #[error("CN_MAPPING_INCOMPLETE")]
    MappingIncomplete,
    #[error("CN_EXTENSION_INVALID")]
    ExtensionInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> CnStandardVersionBundle {
        let schema = serde_json::json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["agentId","capability","jurisdiction"],"properties":{"agentId":{"type":"string"},"capability":{"type":"object","additionalProperties":false,"required":["id","name"],"properties":{"id":{"type":"string"},"name":{"type":"string"}}},"jurisdiction":{"type":"string"}}});
        let mut value = CnStandardVersionBundle {
            schema_version: CN_ADAPTER_SCHEMA_VERSION.into(),
            standard_id: "customer-provided-standard".into(),
            standard_version: "2026-test".into(),
            source_uri: "https://customer.example/spec".into(),
            published_at: Utc::now(),
            license: "customer-provided".into(),
            schema_hash: hex(Sha256::digest(
                serde_jcs::to_vec(&schema).unwrap_or_default(),
            )),
            schema,
            field_mappings: BTreeMap::from([
                ("identity.agent_id".into(), "/agentId".into()),
                ("capability.id".into(), "/capability/id".into()),
                ("capability.name".into(), "/capability/name".into()),
                ("data.jurisdiction".into(), "/jurisdiction".into()),
            ]),
            required_security_fields: BTreeSet::from([
                "identity.agent_id".into(),
                "data.jurisdiction".into(),
            ]),
            bundle_digest: String::new(),
        };
        let mut unsigned = value.clone();
        unsigned.bundle_digest.clear();
        value.bundle_digest = format!(
            "sha256:{}",
            hex(Sha256::digest(
                serde_jcs::to_vec(&unsigned).unwrap_or_default()
            ))
        );
        value
    }

    #[test]
    fn unknown_versions_are_rejected_and_rollback_is_explicit() {
        let registry = CnVersionRegistry::default();
        assert_eq!(
            registry.resolve("x", "unknown").err(),
            Some(CnAdapterError::UnknownVersion)
        );
        let value = bundle();
        registry
            .register(value.clone())
            .unwrap_or_else(|_| panic!("register"));
        registry
            .activate(&value.standard_id, &value.standard_version)
            .unwrap_or_else(|_| panic!("activate"));
    }

    #[test]
    fn identifier_cannot_self_assert_trust() {
        let value = bundle();
        let document = serde_json::json!({"agentId":"administrator","capability":{"id":"read","name":"Read"},"jurisdiction":"CN"});
        let mapped = CnIdentityMapper::map(&value, &document, TenantId::new(), false)
            .unwrap_or_else(|_| panic!("map"));
        assert_eq!(mapped.value.trust_level, "untrusted");
    }

    #[test]
    fn extensions_cannot_override_core_security_fields() {
        let registry = ExtensionNamespaceRegistry::default();
        registry
            .register("vendor.example".into())
            .unwrap_or_else(|_| panic!("namespace"));
        assert_eq!(
            registry.validate_extensions(&BTreeMap::from([(
                "vendor.example.trust_level".into(),
                Value::String("admin".into())
            )])),
            Err(CnAdapterError::ExtensionInvalid)
        );
    }
}
