//! Production gVisor job contracts and fail-closed runtime verification.
//!
//! The worker never accepts a bare command. A PEP-signed ExecutionAuthorization,
//! an immutable registry snapshot, a dispatcher-signed job, a separately signed
//! dedicated-host/runtime attestation, and a durable single-use replay record are
//! all required before `runsc` is invoked.

use crate::{
    FilesystemProfile, NetworkProfile, ResourceBudget, SandboxError, SandboxProfile,
    is_sha256_digest,
};
use agent_trust_action_ir::{ParseLimits, parse_strict_json};
use agent_trust_contracts::{ExecutionAuthorization, PEP_EXECUTION_AUTHORIZATION_KEY_USAGE};
use agent_trust_registry::{ImplementationKind, ResolvedToolSnapshot};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

pub const GVISOR_JOB_SCHEMA_VERSION: &str = "agenttrust.gvisor-execution-job.v1";
pub const GVISOR_KEYRING_SCHEMA_VERSION: &str = "agenttrust.gvisor-worker-keyring.v1";
pub const GVISOR_RUNTIME_ATTESTATION_SCHEMA_VERSION: &str =
    "agenttrust.gvisor-runtime-attestation.v1";
pub const GVISOR_EXECUTION_RECEIPT_SCHEMA_VERSION: &str = "agenttrust.gvisor-execution-receipt.v1";
pub const GVISOR_RECEIPT_SIGNING_KEY_SCHEMA_VERSION: &str =
    "agenttrust.gvisor-receipt-signing-key.v1";
pub const GVISOR_DISPATCH_KEY_USAGE: &str = "AGENTTRUST_GVISOR_JOB_DISPATCH_V1";
pub const GVISOR_RUNTIME_ATTESTATION_KEY_USAGE: &str = "AGENTTRUST_GVISOR_RUNTIME_ATTESTATION_V1";
pub const GVISOR_REGISTRY_ATTESTATION_KEY_USAGE: &str = "AGENTTRUST_GVISOR_REGISTRY_ATTESTATION_V1";
pub const GVISOR_EXECUTION_RECEIPT_KEY_USAGE: &str = "AGENTTRUST_GVISOR_EXECUTION_RECEIPT_V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GvisorWorkerKeyring {
    pub schema_version: String,
    pub environment: String,
    pub keys: Vec<GvisorWorkerKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GvisorWorkerKey {
    pub key_id: String,
    pub issuer: String,
    pub key_usage: String,
    pub public_key: String,
    pub valid_from: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

/// Host-local signing material loaded through the systemd encrypted credential
/// store. It is never accepted from the dispatcher-controlled spool.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GvisorReceiptSigningKey {
    pub schema_version: String,
    pub environment: String,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GvisorExecutorSpec {
    pub executor_id: String,
    pub image_digest: String,
    pub entrypoint: PathBuf,
    pub fixed_args: Vec<String>,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub shell: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OciBundleBinding {
    pub bundle_path: PathBuf,
    pub config_digest: String,
    pub container_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionGvisorJob {
    pub schema_version: String,
    pub job_id: String,
    pub authorization: ExecutionAuthorization,
    pub tool: ResolvedToolSnapshot,
    pub executor: GvisorExecutorSpec,
    pub profile: SandboxProfile,
    pub network_profile: NetworkProfile,
    pub filesystem_profile: FilesystemProfile,
    pub budget: ResourceBudget,
    pub oci_bundle: OciBundleBinding,
    pub registry_attestation: GvisorRegistryAttestation,
    pub runtime_attestation_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub dispatcher_key_id: String,
    pub dispatcher_key_usage: String,
    pub job_digest: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GvisorRegistryAttestation {
    pub schema_version: String,
    pub tenant_id: String,
    pub tool_id: String,
    pub tool_version: String,
    pub tool_snapshot_hash: String,
    pub implementation_digest: String,
    pub canonical_arguments_hash: String,
    pub executor_spec_digest: String,
    pub registry_revision: u64,
    pub status: String,
    pub checked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub attestation_digest: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GvisorRuntimeAttestation {
    pub schema_version: String,
    pub environment: String,
    pub hostname: String,
    pub node_pool: String,
    pub dedicated: bool,
    pub runtime: String,
    pub execution_mode: String,
    pub runtime_profile_id: String,
    pub runtime_handler: String,
    pub runsc_binary_digest: String,
    pub runsc_version_digest: String,
    pub handler_config_digest: String,
    pub cgroup_version: String,
    pub seccomp_enabled: bool,
    pub user_namespaces_enabled: bool,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub measured_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub attestation_digest: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GvisorExecutionStatus {
    Succeeded,
    Failed,
    TimedOut,
    Killed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GvisorExecutionReceipt {
    pub schema_version: String,
    pub job_id: String,
    pub job_digest: String,
    pub authorization_id: String,
    pub action_hash: String,
    pub container_id: String,
    pub image_digest: String,
    pub oci_config_digest: String,
    pub runsc_binary_digest: String,
    pub runtime_attestation_digest: String,
    pub worker_hostname: String,
    pub status: GvisorExecutionStatus,
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub replay_consumed: bool,
    pub runsc_deleted: bool,
    pub bundle_removed: bool,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub receipt_digest: String,
    pub signature: String,
}

impl GvisorWorkerKeyring {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), SandboxError> {
        if self.schema_version != GVISOR_KEYRING_SCHEMA_VERSION
            || self.environment != "production"
            || self.keys.is_empty()
            || self.keys.len() > 64
        {
            return Err(SandboxError::RuntimeAttestationInvalid);
        }
        let mut identities = BTreeSet::new();
        for key in &self.keys {
            if !valid_identifier(&key.key_id, 256)
                || key.issuer.is_empty()
                || key.issuer.len() > 256
                || !matches!(
                    key.key_usage.as_str(),
                    PEP_EXECUTION_AUTHORIZATION_KEY_USAGE
                        | GVISOR_DISPATCH_KEY_USAGE
                        | GVISOR_RUNTIME_ATTESTATION_KEY_USAGE
                        | GVISOR_REGISTRY_ATTESTATION_KEY_USAGE
                        | GVISOR_EXECUTION_RECEIPT_KEY_USAGE
                )
                || key.valid_from >= key.expires_at
                || key.expires_at - key.valid_from > chrono::Duration::days(397)
                || decode_public_key(&key.public_key).is_err()
                || !identities.insert((key.key_id.clone(), key.key_usage.clone()))
            {
                return Err(SandboxError::RuntimeAttestationInvalid);
            }
        }
        if !self.keys.iter().any(|key| {
            !key.revoked
                && key.key_usage == PEP_EXECUTION_AUTHORIZATION_KEY_USAGE
                && key.valid_from <= now
                && key.expires_at > now
        }) || !self.keys.iter().any(|key| {
            !key.revoked
                && key.key_usage == GVISOR_DISPATCH_KEY_USAGE
                && key.valid_from <= now
                && key.expires_at > now
        }) || !self.keys.iter().any(|key| {
            !key.revoked
                && key.key_usage == GVISOR_RUNTIME_ATTESTATION_KEY_USAGE
                && key.valid_from <= now
                && key.expires_at > now
        }) || !self.keys.iter().any(|key| {
            !key.revoked
                && key.key_usage == GVISOR_REGISTRY_ATTESTATION_KEY_USAGE
                && key.valid_from <= now
                && key.expires_at > now
        }) || !self.keys.iter().any(|key| {
            !key.revoked
                && key.key_usage == GVISOR_EXECUTION_RECEIPT_KEY_USAGE
                && key.valid_from <= now
                && key.expires_at > now
        }) {
            return Err(SandboxError::RuntimeAttestationInvalid);
        }
        Ok(())
    }

    fn active_key(
        &self,
        key_id: &str,
        key_usage: &str,
        issuer: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(&GvisorWorkerKey, VerifyingKey), SandboxError> {
        let key = self
            .keys
            .iter()
            .find(|candidate| candidate.key_id == key_id && candidate.key_usage == key_usage)
            .ok_or(SandboxError::RuntimeAttestationInvalid)?;
        if key.revoked
            || key.valid_from > now
            || key.expires_at <= now
            || issuer.is_some_and(|issuer| issuer != key.issuer)
        {
            return Err(SandboxError::RuntimeAttestationInvalid);
        }
        Ok((key, decode_public_key(&key.public_key)?))
    }
}

impl GvisorReceiptSigningKey {
    fn resolve(
        &self,
        keyring: &GvisorWorkerKeyring,
        now: DateTime<Utc>,
    ) -> Result<SigningKey, SandboxError> {
        if self.schema_version != GVISOR_RECEIPT_SIGNING_KEY_SCHEMA_VERSION
            || self.environment != "production"
            || self.key_usage != GVISOR_EXECUTION_RECEIPT_KEY_USAGE
            || !valid_identifier(&self.key_id, 256)
            || self.issuer.is_empty()
            || self.issuer.len() > 256
        {
            return Err(SandboxError::RuntimeAttestationInvalid);
        }
        let seed = URL_SAFE_NO_PAD
            .decode(&self.private_key)
            .map_err(|_| SandboxError::RuntimeAttestationInvalid)?;
        if URL_SAFE_NO_PAD.encode(&seed) != self.private_key {
            return Err(SandboxError::RuntimeAttestationInvalid);
        }
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| SandboxError::RuntimeAttestationInvalid)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let (_, expected_public_key) = keyring.active_key(
            &self.key_id,
            GVISOR_EXECUTION_RECEIPT_KEY_USAGE,
            Some(&self.issuer),
            now,
        )?;
        if signing_key.verifying_key() != expected_public_key {
            return Err(SandboxError::RuntimeAttestationInvalid);
        }
        Ok(signing_key)
    }
}

impl GvisorRegistryAttestation {
    pub fn canonical_payload(&self) -> Result<Vec<u8>, SandboxError> {
        let mut material = self.clone();
        material.attestation_digest.clear();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| SandboxError::AuthorizationInvalid)
    }

    pub fn verify(
        &self,
        keyring: &GvisorWorkerKeyring,
        job: &ProductionGvisorJob,
        now: DateTime<Utc>,
    ) -> Result<(), SandboxError> {
        if self.schema_version != "agenttrust.gvisor-registry-attestation.v1"
            || self.tenant_id.as_str() != job.authorization.tenant_id.0.as_str()
            || self.tool_id.as_str() != job.tool.tool_id.0.as_str()
            || self.tool_version.as_str() != job.tool.tool_version.0.as_str()
            || self.tool_snapshot_hash.as_str() != job.tool.snapshot_hash.as_str()
            || self.implementation_digest.as_str() != job.tool.implementation.digest.as_str()
            || self.canonical_arguments_hash.as_str()
                != job.authorization.canonical_arguments_hash.as_str()
            || !is_bare_sha256_digest(&self.canonical_arguments_hash)
            || self.executor_spec_digest != canonical_executor_spec_digest(&job.executor)?
            || self.registry_revision != job.tool.registry_revision
            || self.registry_revision == 0
            || self.status != "ACTIVE"
            || self.key_usage != GVISOR_REGISTRY_ATTESTATION_KEY_USAGE
            || self.checked_at > now
            || self.expires_at <= now
            || self.expires_at <= self.checked_at
            || self.expires_at - self.checked_at > chrono::Duration::minutes(2)
        {
            return Err(SandboxError::AuthorizationInvalid);
        }
        let payload = self.canonical_payload()?;
        if format!("sha256:{}", hex_digest(&payload)) != self.attestation_digest {
            return Err(SandboxError::AuthorizationInvalid);
        }
        let (_, key) = keyring.active_key(
            &self.key_id,
            GVISOR_REGISTRY_ATTESTATION_KEY_USAGE,
            Some(&self.issuer),
            now,
        )?;
        verify_signature(&key, &payload, &self.signature)
            .map_err(|_| SandboxError::AuthorizationInvalid)
    }
}

impl GvisorRuntimeAttestation {
    pub fn canonical_payload(&self) -> Result<Vec<u8>, SandboxError> {
        let mut material = self.clone();
        material.attestation_digest.clear();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| SandboxError::RuntimeAttestationInvalid)
    }

    pub fn verify(
        &self,
        keyring: &GvisorWorkerKeyring,
        expected_hostname: &str,
        expected_runsc_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), SandboxError> {
        keyring.validate(now)?;
        if self.schema_version != GVISOR_RUNTIME_ATTESTATION_SCHEMA_VERSION
            || self.environment != "production"
            || self.hostname != expected_hostname
            || self.hostname.is_empty()
            || self.node_pool.is_empty()
            || !self.dedicated
            || self.runtime != "runsc"
            || self.execution_mode != "NATIVE_SYSTEMD_RUNSC"
            || self.runtime_profile_id != "agenttrust-gvisor"
            || self.runtime_handler != "runsc"
            || self.runsc_binary_digest != expected_runsc_digest
            || !is_sha256_digest(&self.runsc_binary_digest)
            || !is_sha256_digest(&self.runsc_version_digest)
            || !is_sha256_digest(&self.handler_config_digest)
            || self.cgroup_version != "v2"
            || !self.seccomp_enabled
            || !self.user_namespaces_enabled
            || self.key_usage != GVISOR_RUNTIME_ATTESTATION_KEY_USAGE
            || self.measured_at > now
            || self.expires_at <= now
            || self.expires_at <= self.measured_at
            || self.expires_at - self.measured_at > chrono::Duration::days(30)
        {
            return Err(SandboxError::RuntimeAttestationInvalid);
        }
        let payload = self.canonical_payload()?;
        let digest = format!("sha256:{}", hex_digest(&payload));
        if digest != self.attestation_digest {
            return Err(SandboxError::RuntimeAttestationInvalid);
        }
        let (_, key) = keyring.active_key(
            &self.key_id,
            GVISOR_RUNTIME_ATTESTATION_KEY_USAGE,
            Some(&self.issuer),
            now,
        )?;
        verify_signature(&key, &payload, &self.signature)
    }
}

impl GvisorExecutionReceipt {
    pub fn canonical_payload(&self) -> Result<Vec<u8>, SandboxError> {
        let mut material = self.clone();
        material.receipt_digest.clear();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| SandboxError::CollectFailed)
    }

    pub fn sign(
        &mut self,
        signing_material: &GvisorReceiptSigningKey,
        keyring: &GvisorWorkerKeyring,
        now: DateTime<Utc>,
    ) -> Result<(), SandboxError> {
        let signing_key = signing_material.resolve(keyring, now)?;
        self.issuer.clone_from(&signing_material.issuer);
        self.key_id.clone_from(&signing_material.key_id);
        self.key_usage.clone_from(&signing_material.key_usage);
        self.receipt_digest.clear();
        self.signature.clear();
        let payload = self.canonical_payload()?;
        self.receipt_digest = format!("sha256:{}", hex_digest(&payload));
        self.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&payload).to_bytes());
        Ok(())
    }

    pub fn verify(
        &self,
        keyring: &GvisorWorkerKeyring,
        now: DateTime<Utc>,
    ) -> Result<(), SandboxError> {
        keyring.validate(now)?;
        if self.schema_version != GVISOR_EXECUTION_RECEIPT_SCHEMA_VERSION
            || Uuid::parse_str(&self.job_id).is_err()
            || Uuid::parse_str(&self.authorization_id).is_err()
            || !is_sha256_digest(&self.job_digest)
            || !is_bare_sha256_digest(&self.action_hash)
            || !valid_container_id(&self.container_id)
            || !is_sha256_digest(&self.image_digest)
            || !is_sha256_digest(&self.oci_config_digest)
            || !is_sha256_digest(&self.runsc_binary_digest)
            || !is_sha256_digest(&self.runtime_attestation_digest)
            || self.worker_hostname.is_empty()
            || self.worker_hostname.len() > 253
            || self.worker_hostname.contains(char::is_whitespace)
            || !is_bare_sha256_digest(&self.stdout_sha256)
            || !is_bare_sha256_digest(&self.stderr_sha256)
            || !self.replay_consumed
            || !self.runsc_deleted
            || !self.bundle_removed
            || self.started_at > self.finished_at
            || self.finished_at > now + chrono::Duration::minutes(1)
            || self.key_usage != GVISOR_EXECUTION_RECEIPT_KEY_USAGE
        {
            return Err(SandboxError::CollectFailed);
        }
        let payload = self.canonical_payload()?;
        if format!("sha256:{}", hex_digest(&payload)) != self.receipt_digest {
            return Err(SandboxError::CollectFailed);
        }
        let (_, key) = keyring.active_key(
            &self.key_id,
            GVISOR_EXECUTION_RECEIPT_KEY_USAGE,
            Some(&self.issuer),
            now,
        )?;
        verify_signature(&key, &payload, &self.signature).map_err(|_| SandboxError::CollectFailed)
    }
}

impl ProductionGvisorJob {
    pub fn canonical_payload(&self) -> Result<Vec<u8>, SandboxError> {
        let mut material = self.clone();
        material.job_digest.clear();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| SandboxError::JobInvalid)
    }

    pub fn verify(
        &self,
        keyring: &GvisorWorkerKeyring,
        runtime: &GvisorRuntimeAttestation,
        expected_hostname: &str,
        expected_runsc_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), SandboxError> {
        keyring.validate(now)?;
        runtime.verify(keyring, expected_hostname, expected_runsc_digest, now)?;
        self.registry_attestation.verify(keyring, self, now)?;
        if self.schema_version != GVISOR_JOB_SCHEMA_VERSION
            || Uuid::parse_str(&self.job_id).is_err()
            || self.dispatcher_key_usage != GVISOR_DISPATCH_KEY_USAGE
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > chrono::Duration::minutes(10)
            || self.expires_at > self.authorization.expires_at
            || self.runtime_attestation_digest != runtime.attestation_digest
            || !self.authorization.single_use
            || Uuid::parse_str(&self.authorization.authorization_id).is_err()
            || self.authorization.tool_id != self.tool.tool_id
            || self.authorization.tool_version != self.tool.tool_version
            || self.authorization.tool_snapshot_hash != self.tool.snapshot_hash
            || self.authorization.implementation_digest != self.tool.implementation.digest
            || self.authorization.executor_profile != self.tool.executor_profile
            || self.authorization.network_profile != self.network_profile.profile_id
            || self.authorization.network_profile != self.tool.network_profile_ref
            || self.filesystem_profile.profile_id != self.tool.filesystem_profile_ref
            || self.authorization.sandbox_profile != self.profile.profile_id
            || self.executor.executor_id != self.tool.implementation.executor_id
            || self.executor.image_digest != self.tool.implementation.digest
            || self.tool.implementation.kind != ImplementationKind::OciContainer
            || !is_sha256_digest(&self.executor.image_digest)
            || !is_sha256_digest(&self.oci_bundle.config_digest)
            || !valid_container_id(&self.oci_bundle.container_id)
            || !valid_executor(&self.executor)
            || !strict_production_profile(&self.profile, &self.network_profile)
        {
            return Err(SandboxError::JobInvalid);
        }
        self.budget.validate(&self.authorization)?;
        super::validate_filesystem_profile(&self.filesystem_profile)?;
        if canonical_tool_snapshot_hash(&self.tool)? != self.tool.snapshot_hash {
            return Err(SandboxError::AuthorizationInvalid);
        }
        let (_, pep_key) = keyring.active_key(
            &self.authorization.key_id,
            PEP_EXECUTION_AUTHORIZATION_KEY_USAGE,
            Some(&self.authorization.issuer),
            now,
        )?;
        self.authorization
            .verify(&pep_key, now)
            .map_err(|_| SandboxError::AuthorizationInvalid)?;
        let payload = self.canonical_payload()?;
        if format!("sha256:{}", hex_digest(&payload)) != self.job_digest {
            return Err(SandboxError::JobInvalid);
        }
        let (_, dispatcher_key) = keyring.active_key(
            &self.dispatcher_key_id,
            GVISOR_DISPATCH_KEY_USAGE,
            None,
            now,
        )?;
        verify_signature(&dispatcher_key, &payload, &self.signature)
            .map_err(|_| SandboxError::JobInvalid)
    }

    pub fn verify_bundle(&self, workspace_root: &Path) -> Result<PathBuf, SandboxError> {
        if !workspace_root.is_absolute()
            || !self.oci_bundle.bundle_path.is_absolute()
            || self
                .oci_bundle
                .bundle_path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(SandboxError::FilesystemDenied);
        }
        let root = workspace_root
            .canonicalize()
            .map_err(|_| SandboxError::FilesystemDenied)?;
        let bundle = self
            .oci_bundle
            .bundle_path
            .canonicalize()
            .map_err(|_| SandboxError::FilesystemDenied)?;
        if !bundle.starts_with(&root)
            || bundle == root
            || bundle.file_name().and_then(|value| value.to_str())
                != Some(self.oci_bundle.container_id.as_str())
        {
            return Err(SandboxError::FilesystemDenied);
        }
        let config_path = bundle.join("config.json");
        let metadata =
            fs::symlink_metadata(&config_path).map_err(|_| SandboxError::FilesystemDenied)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024
        {
            return Err(SandboxError::FilesystemDenied);
        }
        let bytes = fs::read(&config_path).map_err(|_| SandboxError::FilesystemDenied)?;
        if format!("sha256:{}", hex_digest(&bytes)) != self.oci_bundle.config_digest {
            return Err(SandboxError::ImageDigestMismatch);
        }
        let spec = parse_oci_runtime_spec(&bytes)?;
        verify_oci_job_binding(&spec, self)?;
        Ok(bundle)
    }
}

pub struct FileReplayLedger {
    root: PathBuf,
}

impl FileReplayLedger {
    pub fn new(root: PathBuf) -> Result<Self, SandboxError> {
        if !root.is_absolute() {
            return Err(SandboxError::ReplayLedgerFailed);
        }
        let metadata = fs::symlink_metadata(&root).map_err(|_| SandboxError::ReplayLedgerFailed)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || insecure_permissions(&metadata)
        {
            return Err(SandboxError::ReplayLedgerFailed);
        }
        Ok(Self {
            root: root
                .canonicalize()
                .map_err(|_| SandboxError::ReplayLedgerFailed)?,
        })
    }

    pub fn consume(
        &self,
        job: &ProductionGvisorJob,
        now: DateTime<Utc>,
    ) -> Result<(), SandboxError> {
        let authorization_id = &job.authorization.authorization_id;
        if Uuid::parse_str(authorization_id).is_err() {
            return Err(SandboxError::AuthorizationInvalid);
        }
        let path = self.root.join(format!("{authorization_id}.json"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                SandboxError::AuthorizationReplayed
            } else {
                SandboxError::ReplayLedgerFailed
            }
        })?;
        let record = serde_jcs::to_vec(&serde_json::json!({
            "schema_version": "agenttrust.gvisor-replay-record.v1",
            "authorization_id": authorization_id,
            "job_id": job.job_id,
            "job_digest": job.job_digest,
            "consumed_at": now,
        }))
        .map_err(|_| SandboxError::ReplayLedgerFailed)?;
        file.write_all(&record)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|_| SandboxError::ReplayLedgerFailed)?;
        fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| SandboxError::ReplayLedgerFailed)
    }
}

/// Enforces the portable subset of the OCI runtime spec required by the
/// production gVisor worker. The caller separately verifies the config digest.
pub fn parse_oci_runtime_spec(bytes: &[u8]) -> Result<Value, SandboxError> {
    let value = parse_strict_json(
        bytes,
        &ParseLimits {
            max_body_bytes: 1024 * 1024,
            max_depth: 32,
            max_array_items: 4096,
            max_string_bytes: 65_536,
            max_object_keys: 4096,
            max_number_chars: 128,
        },
    )
    .map_err(|_| SandboxError::ProfileDenied)?;
    validate_oci_runtime_spec(&value)?;
    Ok(value)
}

pub fn validate_oci_runtime_spec(spec: &Value) -> Result<(), SandboxError> {
    let root = spec
        .get("root")
        .and_then(Value::as_object)
        .ok_or(SandboxError::ProfileDenied)?;
    let root_path = root
        .get("path")
        .and_then(Value::as_str)
        .ok_or(SandboxError::ProfileDenied)?;
    let process = spec
        .get("process")
        .and_then(Value::as_object)
        .ok_or(SandboxError::ProfileDenied)?;
    let linux = spec
        .get("linux")
        .and_then(Value::as_object)
        .ok_or(SandboxError::ProfileDenied)?;
    let user = process
        .get("user")
        .and_then(Value::as_object)
        .ok_or(SandboxError::ProfileDenied)?;
    let uid = user
        .get("uid")
        .and_then(Value::as_u64)
        .ok_or(SandboxError::ProfileDenied)?;
    let gid = user
        .get("gid")
        .and_then(Value::as_u64)
        .ok_or(SandboxError::ProfileDenied)?;
    let capabilities = process
        .get("capabilities")
        .and_then(Value::as_object)
        .ok_or(SandboxError::ProfileDenied)?;
    let capability_sets = [
        "bounding",
        "effective",
        "inheritable",
        "permitted",
        "ambient",
    ];
    let namespaces = linux
        .get("namespaces")
        .and_then(Value::as_array)
        .ok_or(SandboxError::ProfileDenied)?;
    let namespace_types = namespaces
        .iter()
        .filter_map(|entry| entry.get("type").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let resources = linux
        .get("resources")
        .and_then(Value::as_object)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let memory_limit = resources
        .get("memory")
        .and_then(|value| value.get("limit"))
        .and_then(Value::as_i64)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let pids_limit = resources
        .get("pids")
        .and_then(|value| value.get("limit"))
        .and_then(Value::as_i64)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let cpu = resources
        .get("cpu")
        .and_then(Value::as_object)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let quota = cpu
        .get("quota")
        .and_then(Value::as_i64)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let period = cpu
        .get("period")
        .and_then(Value::as_u64)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let seccomp = linux
        .get("seccomp")
        .and_then(Value::as_object)
        .ok_or(SandboxError::ProfileDenied)?;
    let default_action = seccomp
        .get("defaultAction")
        .and_then(Value::as_str)
        .ok_or(SandboxError::ProfileDenied)?;
    let args = process
        .get("args")
        .and_then(Value::as_array)
        .ok_or(SandboxError::ProfileDenied)?;
    let cwd = process
        .get("cwd")
        .and_then(Value::as_str)
        .ok_or(SandboxError::ProfileDenied)?;
    let env = process
        .get("env")
        .and_then(Value::as_array)
        .ok_or(SandboxError::ProfileDenied)?;
    if spec.get("ociVersion").and_then(Value::as_str).is_none()
        || root.get("readonly").and_then(Value::as_bool) != Some(true)
        || root_path.is_empty()
        || Path::new(root_path).is_absolute()
        || Path::new(root_path)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || process.get("noNewPrivileges").and_then(Value::as_bool) != Some(true)
        || uid == 0
        || gid == 0
        || !capability_sets.iter().all(|name| {
            capabilities
                .get(*name)
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        })
        || !["pid", "mount", "ipc", "uts", "network", "user"]
            .iter()
            .all(|required| namespace_types.contains(required))
        || memory_limit <= 0
        || pids_limit <= 0
        || quota <= 0
        || period == 0
        || !matches!(
            default_action,
            "SCMP_ACT_ERRNO" | "SCMP_ACT_KILL" | "SCMP_ACT_KILL_PROCESS"
        )
        || args.is_empty()
        || args
            .iter()
            .any(|argument| argument.as_str().is_none_or(|value| value.contains('\0')))
        || !Path::new(cwd).is_absolute()
        || env.iter().any(|entry| {
            entry.as_str().is_none_or(|value| {
                value.contains('\0')
                    || value.starts_with("LD_PRELOAD=")
                    || value.starts_with("LD_LIBRARY_PATH=")
                    || value.starts_with("DYLD_INSERT_LIBRARIES=")
            })
        })
        || unsafe_mounts(spec)
    {
        return Err(SandboxError::ProfileDenied);
    }
    Ok(())
}

fn verify_oci_job_binding(spec: &Value, job: &ProductionGvisorJob) -> Result<(), SandboxError> {
    let process = spec.get("process").ok_or(SandboxError::JobInvalid)?;
    let expected_args = std::iter::once(job.executor.entrypoint.display().to_string())
        .chain(job.executor.fixed_args.iter().cloned())
        .collect::<Vec<_>>();
    let expected_environment = job
        .executor
        .environment
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<BTreeSet<_>>();
    let actual_environment = process
        .get("env")
        .and_then(Value::as_array)
        .ok_or(SandboxError::JobInvalid)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or(SandboxError::JobInvalid)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let annotations = spec
        .get("annotations")
        .and_then(Value::as_object)
        .ok_or(SandboxError::JobInvalid)?;
    let resources = spec
        .pointer("/linux/resources")
        .and_then(Value::as_object)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let memory = resources
        .get("memory")
        .and_then(|value| value.get("limit"))
        .and_then(Value::as_i64)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let pids = resources
        .get("pids")
        .and_then(|value| value.get("limit"))
        .and_then(Value::as_i64)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let quota = resources
        .get("cpu")
        .and_then(|value| value.get("quota"))
        .and_then(Value::as_i64)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let period = resources
        .get("cpu")
        .and_then(|value| value.get("period"))
        .and_then(Value::as_u64)
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let cpu_millis = (quota as u128)
        .saturating_mul(1000)
        .checked_div(period as u128)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(SandboxError::ResourceLimitInvalid)?;
    let expected_working_directory = job.executor.working_directory.to_string_lossy();
    let expected_disk_bytes = job.budget.disk_bytes.to_string();
    if process.get("args")
        != Some(&serde_json::to_value(expected_args).map_err(|_| SandboxError::JobInvalid)?)
        || process.get("cwd").and_then(Value::as_str) != Some(expected_working_directory.as_ref())
        || actual_environment != expected_environment
        || annotations
            .get("com.agenttrust.image-digest")
            .and_then(Value::as_str)
            != Some(job.executor.image_digest.as_str())
        || annotations
            .get("com.agenttrust.authorization-id")
            .and_then(Value::as_str)
            != Some(job.authorization.authorization_id.as_str())
        || annotations
            .get("com.agenttrust.tool-snapshot-hash")
            .and_then(Value::as_str)
            != Some(job.tool.snapshot_hash.as_str())
        || annotations
            .get("com.agenttrust.ephemeral-storage-bytes")
            .and_then(Value::as_str)
            != Some(expected_disk_bytes.as_str())
        || u64::try_from(memory)
            .ok()
            .is_none_or(|value| value > job.budget.memory_bytes)
        || u32::try_from(pids)
            .ok()
            .is_none_or(|value| value > job.budget.pids)
        || cpu_millis == 0
        || cpu_millis > job.budget.cpu_millis
    {
        return Err(SandboxError::JobInvalid);
    }
    Ok(())
}

fn unsafe_mounts(spec: &Value) -> bool {
    spec.get("mounts")
        .and_then(Value::as_array)
        .is_none_or(|mounts| {
            mounts.iter().any(|mount| {
                let destination = mount
                    .get("destination")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let source = mount.get("source").and_then(Value::as_str).unwrap_or("");
                !Path::new(destination).is_absolute()
                    || destination == "/"
                    || destination.starts_with("/home/")
                    || destination == "/var/run/docker.sock"
                    || destination == "/run/docker.sock"
                    || source == "/var/run/docker.sock"
                    || source == "/run/docker.sock"
                    || source.starts_with("/Users/")
                    || source == "/"
                    || source.starts_with("/root")
            })
        })
}

fn strict_production_profile(profile: &SandboxProfile, network: &NetworkProfile) -> bool {
    profile.production_isolation_required
        && profile.non_root
        && profile.read_only_rootfs
        && profile.network_none
        && profile.no_new_privileges
        && profile.drop_all_capabilities
        && network.default_deny
        && network.allowed_endpoints.is_empty()
        && network.max_connections == 0
        && network.max_upload_bytes == 0
}

fn valid_executor(executor: &GvisorExecutorSpec) -> bool {
    !executor.executor_id.is_empty()
        && executor.executor_id.len() <= 256
        && executor.entrypoint.is_absolute()
        && executor
            .entrypoint
            .components()
            .all(|component| !matches!(component, Component::ParentDir))
        && executor.working_directory.is_absolute()
        && executor
            .working_directory
            .components()
            .all(|component| !matches!(component, Component::ParentDir))
        && !executor.shell
        && executor.fixed_args.len() <= 256
        && executor
            .fixed_args
            .iter()
            .all(|value| value.len() <= 16_384 && !value.contains('\0'))
        && executor.environment.len() <= 64
        && executor.environment.iter().all(|(key, value)| {
            valid_environment_key(key)
                && value.len() <= 16_384
                && !value.contains('\0')
                && !matches!(
                    key.as_str(),
                    "LD_PRELOAD" | "LD_LIBRARY_PATH" | "DYLD_INSERT_LIBRARIES"
                )
        })
}

fn valid_environment_key(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_container_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn canonical_tool_snapshot_hash(snapshot: &ResolvedToolSnapshot) -> Result<String, SandboxError> {
    let mut material = snapshot.clone();
    material.snapshot_hash.clear();
    material.resolved_at = DateTime::UNIX_EPOCH;
    let bytes = serde_jcs::to_vec(&material).map_err(|_| SandboxError::AuthorizationInvalid)?;
    Ok(hex_digest(bytes))
}

fn canonical_executor_spec_digest(executor: &GvisorExecutorSpec) -> Result<String, SandboxError> {
    let bytes = serde_jcs::to_vec(executor).map_err(|_| SandboxError::AuthorizationInvalid)?;
    Ok(format!("sha256:{}", hex_digest(bytes)))
}

fn is_bare_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_public_key(value: &str) -> Result<VerifyingKey, SandboxError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SandboxError::RuntimeAttestationInvalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(SandboxError::RuntimeAttestationInvalid);
    }
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SandboxError::RuntimeAttestationInvalid)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| SandboxError::RuntimeAttestationInvalid)
}

fn verify_signature(key: &VerifyingKey, payload: &[u8], encoded: &str) -> Result<(), SandboxError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SandboxError::RuntimeAttestationInvalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(SandboxError::RuntimeAttestationInvalid);
    }
    let signature =
        Signature::from_slice(&bytes).map_err(|_| SandboxError::RuntimeAttestationInvalid)?;
    key.verify(payload, &signature)
        .map_err(|_| SandboxError::RuntimeAttestationInvalid)
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn insecure_permissions(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o022 != 0
}

#[cfg(not(unix))]
fn insecure_permissions(_: &fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};

    fn safe_oci_spec() -> Value {
        serde_json::json!({
            "ociVersion": "1.1.0",
            "root": {"path": "rootfs", "readonly": true},
            "process": {
                "terminal": false,
                "user": {"uid": 65532, "gid": 65532},
                "args": ["/usr/bin/true"],
                "env": [],
                "cwd": "/workspace",
                "capabilities": {
                    "bounding": [], "effective": [], "inheritable": [],
                    "permitted": [], "ambient": []
                },
                "noNewPrivileges": true
            },
            "linux": {
                "namespaces": [
                    {"type": "pid"}, {"type": "mount"}, {"type": "ipc"},
                    {"type": "uts"}, {"type": "network"}, {"type": "user"}
                ],
                "resources": {
                    "memory": {"limit": 67108864},
                    "pids": {"limit": 16},
                    "cpu": {"quota": 10000, "period": 100000}
                },
                "seccomp": {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
            },
            "mounts": [],
            "annotations": {}
        })
    }

    fn key_entry(
        signing: &SigningKey,
        key_id: &str,
        usage: &str,
        now: DateTime<Utc>,
    ) -> GvisorWorkerKey {
        GvisorWorkerKey {
            key_id: key_id.into(),
            issuer: "production-security".into(),
            key_usage: usage.into(),
            public_key: URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),
            valid_from: now - chrono::Duration::minutes(1),
            expires_at: now + chrono::Duration::days(30),
            revoked: false,
        }
    }

    #[test]
    fn oci_spec_requires_read_only_non_root_seccomp_and_namespaces() {
        let mut spec = safe_oci_spec();
        validate_oci_runtime_spec(&spec).unwrap_or_else(|_| panic!("safe spec"));
        spec["root"]["readonly"] = Value::Bool(false);
        assert_eq!(
            validate_oci_runtime_spec(&spec),
            Err(SandboxError::ProfileDenied)
        );
    }

    #[test]
    fn runtime_attestation_is_signature_digest_and_expiry_bound() {
        let now = Utc::now();
        let pep = SigningKey::from_bytes(&[1; 32]);
        let dispatch = SigningKey::from_bytes(&[2; 32]);
        let runtime = SigningKey::from_bytes(&[3; 32]);
        let registry = SigningKey::from_bytes(&[4; 32]);
        let receipt = SigningKey::from_bytes(&[5; 32]);
        let keyring = GvisorWorkerKeyring {
            schema_version: GVISOR_KEYRING_SCHEMA_VERSION.into(),
            environment: "production".into(),
            keys: vec![
                key_entry(&pep, "pep-1", PEP_EXECUTION_AUTHORIZATION_KEY_USAGE, now),
                key_entry(&dispatch, "dispatch-1", GVISOR_DISPATCH_KEY_USAGE, now),
                key_entry(
                    &runtime,
                    "runtime-1",
                    GVISOR_RUNTIME_ATTESTATION_KEY_USAGE,
                    now,
                ),
                key_entry(
                    &registry,
                    "registry-1",
                    GVISOR_REGISTRY_ATTESTATION_KEY_USAGE,
                    now,
                ),
                key_entry(
                    &receipt,
                    "receipt-1",
                    GVISOR_EXECUTION_RECEIPT_KEY_USAGE,
                    now,
                ),
            ],
        };
        let runsc_digest = format!("sha256:{}", "1".repeat(64));
        let mut attestation = GvisorRuntimeAttestation {
            schema_version: GVISOR_RUNTIME_ATTESTATION_SCHEMA_VERSION.into(),
            environment: "production".into(),
            hostname: "sandbox-01.example".into(),
            node_pool: "dedicated-gvisor-a".into(),
            dedicated: true,
            runtime: "runsc".into(),
            execution_mode: "NATIVE_SYSTEMD_RUNSC".into(),
            runtime_profile_id: "agenttrust-gvisor".into(),
            runtime_handler: "runsc".into(),
            runsc_binary_digest: runsc_digest.clone(),
            runsc_version_digest: format!("sha256:{}", "2".repeat(64)),
            handler_config_digest: format!("sha256:{}", "3".repeat(64)),
            cgroup_version: "v2".into(),
            seccomp_enabled: true,
            user_namespaces_enabled: true,
            issuer: "production-security".into(),
            key_id: "runtime-1".into(),
            key_usage: GVISOR_RUNTIME_ATTESTATION_KEY_USAGE.into(),
            measured_at: now - chrono::Duration::minutes(1),
            expires_at: now + chrono::Duration::days(7),
            attestation_digest: String::new(),
            signature: String::new(),
        };
        let payload = attestation
            .canonical_payload()
            .unwrap_or_else(|_| panic!("payload"));
        attestation.attestation_digest = format!("sha256:{}", hex_digest(&payload));
        attestation.signature = URL_SAFE_NO_PAD.encode(runtime.sign(&payload).to_bytes());
        attestation
            .verify(&keyring, "sandbox-01.example", &runsc_digest, now)
            .unwrap_or_else(|_| panic!("verify"));
        attestation.runsc_binary_digest = format!("sha256:{}", "4".repeat(64));
        assert_eq!(
            attestation.verify(&keyring, "sandbox-01.example", &runsc_digest, now),
            Err(SandboxError::RuntimeAttestationInvalid)
        );
    }

    #[test]
    fn execution_receipt_requires_independent_host_signature_and_cleanup() {
        let now = Utc::now();
        let pep = SigningKey::from_bytes(&[1; 32]);
        let dispatch = SigningKey::from_bytes(&[2; 32]);
        let runtime = SigningKey::from_bytes(&[3; 32]);
        let registry = SigningKey::from_bytes(&[4; 32]);
        let receipt_key = SigningKey::from_bytes(&[5; 32]);
        let keyring = GvisorWorkerKeyring {
            schema_version: GVISOR_KEYRING_SCHEMA_VERSION.into(),
            environment: "production".into(),
            keys: vec![
                key_entry(&pep, "pep-1", PEP_EXECUTION_AUTHORIZATION_KEY_USAGE, now),
                key_entry(&dispatch, "dispatch-1", GVISOR_DISPATCH_KEY_USAGE, now),
                key_entry(
                    &runtime,
                    "runtime-1",
                    GVISOR_RUNTIME_ATTESTATION_KEY_USAGE,
                    now,
                ),
                key_entry(
                    &registry,
                    "registry-1",
                    GVISOR_REGISTRY_ATTESTATION_KEY_USAGE,
                    now,
                ),
                key_entry(
                    &receipt_key,
                    "receipt-1",
                    GVISOR_EXECUTION_RECEIPT_KEY_USAGE,
                    now,
                ),
            ],
        };
        let secret = GvisorReceiptSigningKey {
            schema_version: GVISOR_RECEIPT_SIGNING_KEY_SCHEMA_VERSION.into(),
            environment: "production".into(),
            issuer: "production-security".into(),
            key_id: "receipt-1".into(),
            key_usage: GVISOR_EXECUTION_RECEIPT_KEY_USAGE.into(),
            private_key: URL_SAFE_NO_PAD.encode(receipt_key.to_bytes()),
        };
        let mut receipt = GvisorExecutionReceipt {
            schema_version: GVISOR_EXECUTION_RECEIPT_SCHEMA_VERSION.into(),
            job_id: Uuid::new_v4().to_string(),
            job_digest: format!("sha256:{}", "1".repeat(64)),
            authorization_id: Uuid::new_v4().to_string(),
            action_hash: "2".repeat(64),
            container_id: "sandbox-01".into(),
            image_digest: format!("sha256:{}", "3".repeat(64)),
            oci_config_digest: format!("sha256:{}", "4".repeat(64)),
            runsc_binary_digest: format!("sha256:{}", "5".repeat(64)),
            runtime_attestation_digest: format!("sha256:{}", "6".repeat(64)),
            worker_hostname: "sandbox-01.example".into(),
            status: GvisorExecutionStatus::Succeeded,
            exit_code: Some(0),
            stdout_sha256: "7".repeat(64),
            stderr_sha256: "8".repeat(64),
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            replay_consumed: true,
            runsc_deleted: true,
            bundle_removed: true,
            started_at: now - chrono::Duration::seconds(1),
            finished_at: now,
            issuer: String::new(),
            key_id: String::new(),
            key_usage: String::new(),
            receipt_digest: String::new(),
            signature: String::new(),
        };
        receipt
            .sign(&secret, &keyring, now)
            .unwrap_or_else(|_| panic!("sign"));
        receipt
            .verify(&keyring, now)
            .unwrap_or_else(|_| panic!("verify"));
        receipt.runsc_deleted = false;
        assert_eq!(
            receipt.verify(&keyring, now),
            Err(SandboxError::CollectFailed)
        );
    }
}
