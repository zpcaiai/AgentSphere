use crate::activation::ActivationGuardianConfig;
use agent_trust_action_ir::{ParseLimits, parse_strict_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("PRODUCTION_RUNTIME_CONFIG_IO")]
    Io,
    #[error("PRODUCTION_RUNTIME_CONFIG_INVALID")]
    Invalid,
    #[error("PRODUCTION_RUNTIME_SECRET_FILE_INVALID")]
    SecretFileInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsClientConfig {
    pub ca_bundle: PathBuf,
    pub client_identity_pem: Option<PathBuf>,
    pub bearer_token_file: Option<PathBuf>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    20_000
}

impl TlsClientConfig {
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if self.timeout_ms == 0 || self.timeout_ms > 120_000 || !self.ca_bundle.is_file() {
            return Err(ConfigurationError::Invalid);
        }
        for path in [&self.client_identity_pem, &self.bearer_token_file]
            .into_iter()
            .flatten()
        {
            validate_private_file(path)?;
        }
        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

#[cfg(unix)]
fn validate_private_file(path: &Path) -> Result<(), ConfigurationError> {
    validate_private_file_for_identity(
        path,
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    )
}

#[cfg(unix)]
fn validate_private_file_for_identity(
    path: &Path,
    effective_uid: u32,
    effective_gid: u32,
) -> Result<(), ConfigurationError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path).map_err(|_| ConfigurationError::SecretFileInvalid)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let owner_can_read = metadata.uid() == effective_uid && mode & 0o400 != 0;
    let group_readable = mode & 0o040 != 0;
    let group_can_read = metadata.gid() == effective_gid && group_readable;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || (!owner_can_read && !group_can_read)
        || (group_readable && metadata.gid() != effective_gid)
        || mode & !0o440 != 0
    {
        return Err(ConfigurationError::SecretFileInvalid);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file(path: &Path) -> Result<(), ConfigurationError> {
    if !path.is_file() {
        return Err(ConfigurationError::SecretFileInvalid);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    pub base_url: String,
    pub tls: TlsClientConfig,
    #[serde(default)]
    pub health_path: Option<String>,
}

impl EndpointConfig {
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        self.tls.validate()?;
        let url = Url::parse(&self.base_url).map_err(|_| ConfigurationError::Invalid)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ConfigurationError::Invalid);
        }
        if let Some(path) = &self.health_path {
            validate_relative_path(path)?;
        } else {
            return Err(ConfigurationError::Invalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectMappingConfig {
    pub subject: String,
    pub organization_id: String,
    pub tenant_id: String,
    pub owner_subject: String,
    pub agent_instance_id: String,
    pub roles: Vec<String>,
    pub auth_strength: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub issuer: String,
    pub audience: String,
    pub authorized_party: Option<String>,
    pub jwks_endpoint: String,
    pub jwks_tls: TlsClientConfig,
    #[serde(default = "default_jwks_ttl_seconds")]
    pub jwks_ttl_seconds: u64,
    #[serde(default)]
    pub require_mtls_peer: bool,
    pub subject_mappings: Vec<SubjectMappingConfig>,
}

fn default_jwks_ttl_seconds() -> u64 {
    300
}

impl IdentityConfig {
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        self.jwks_tls.validate()?;
        for raw in [&self.issuer, &self.jwks_endpoint] {
            let url = Url::parse(raw).map_err(|_| ConfigurationError::Invalid)?;
            if url.scheme() != "https" || url.host_str().is_none() {
                return Err(ConfigurationError::Invalid);
            }
        }
        if self.audience.is_empty()
            || self.jwks_ttl_seconds < 30
            || self.jwks_ttl_seconds > 86_400
            || self.subject_mappings.is_empty()
            || self.subject_mappings.len() > 100_000
        {
            return Err(ConfigurationError::Invalid);
        }
        let mut subjects = BTreeSet::new();
        for mapping in &self.subject_mappings {
            if mapping.subject.is_empty()
                || mapping.organization_id.is_empty()
                || mapping.owner_subject.is_empty()
                || mapping.auth_strength.is_empty()
                || mapping.roles.is_empty()
                || mapping.roles.iter().any(String::is_empty)
                || !subjects.insert(mapping.subject.clone())
            {
                return Err(ConfigurationError::Invalid);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub data: String,
    pub management: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFilesConfig {
    pub batch_statuses: PathBuf,
    pub gate_evidence: PathBuf,
    pub residual_risks: PathBuf,
    pub exceptions: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionRuntimeConfig {
    pub schema_version: String,
    pub fail_closed: bool,
    pub activation_guardian: ActivationGuardianConfig,
    pub listeners: ListenerConfig,
    pub identity: IdentityConfig,
    pub endpoints: BTreeMap<String, EndpointConfig>,
    pub model_versions: BTreeMap<String, String>,
    pub evidence_files: EvidenceFilesConfig,
}

impl ProductionRuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigurationError> {
        let bytes = fs::read(path).map_err(|_| ConfigurationError::Io)?;
        let value = parse_strict_json(
            &bytes,
            &ParseLimits {
                max_body_bytes: 4 * 1_048_576,
                max_depth: 32,
                max_array_items: 100_000,
                max_string_bytes: 65_536,
                max_object_keys: 100_000,
                max_number_chars: 128,
            },
        )
        .map_err(|_| ConfigurationError::Invalid)?;
        let config: Self =
            serde_json::from_value(value).map_err(|_| ConfigurationError::Invalid)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigurationError> {
        const REQUIRED_ENDPOINTS: [&str; 11] = [
            "orchestrator",
            "secret_broker",
            "backup",
            "containment",
            "recertification",
            "enterprise_integration",
            "authority",
            "notification",
            "industrial",
            "runtime_control",
            "lifecycle",
        ];
        let data_listener = self
            .listeners
            .data
            .parse::<std::net::SocketAddr>()
            .map_err(|_| ConfigurationError::Invalid)?;
        if self.schema_version != "agenttrust.production-runtime-config.v1"
            || !self.fail_closed
            || self
                .listeners
                .management
                .parse::<std::net::SocketAddr>()
                .is_err()
            || self.endpoints.is_empty()
            || self.model_versions.is_empty()
        {
            return Err(ConfigurationError::Invalid);
        }
        self.activation_guardian
            .validate()
            .map_err(|_| ConfigurationError::Invalid)?;
        self.identity.validate()?;
        // When a local mTLS ingress proxy supplies the verified certificate digest,
        // the application listener must not be reachable off-host.
        if self.identity.require_mtls_peer && !data_listener.ip().is_loopback() {
            return Err(ConfigurationError::Invalid);
        }
        for (name, endpoint) in &self.endpoints {
            if name.is_empty()
                || !name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
            {
                return Err(ConfigurationError::Invalid);
            }
            endpoint.validate()?;
        }
        if REQUIRED_ENDPOINTS
            .iter()
            .any(|name| !self.endpoints.contains_key(*name))
            || !self.endpoints.keys().any(|name| name.starts_with("model:"))
            || !self.endpoints.keys().any(|name| name.starts_with("mcp:"))
            || !self.endpoints.keys().any(|name| name.starts_with("a2a:"))
        {
            return Err(ConfigurationError::Invalid);
        }
        if self.model_versions.iter().any(|(profile, model)| {
            profile.is_empty()
                || !profile
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                || model.is_empty()
                || model.len() > 256
                || !self.endpoints.contains_key(&format!("model:{profile}"))
        }) {
            return Err(ConfigurationError::Invalid);
        }
        let evidence_paths = [
            &self.evidence_files.batch_statuses,
            &self.evidence_files.gate_evidence,
            &self.evidence_files.residual_risks,
            &self.evidence_files.exceptions,
        ];
        if evidence_paths.iter().any(|path| !path.is_absolute())
            || evidence_paths.iter().collect::<BTreeSet<_>>().len() != evidence_paths.len()
        {
            return Err(ConfigurationError::Invalid);
        }
        Ok(())
    }
}

pub fn validate_relative_path(path: &str) -> Result<(), ConfigurationError> {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("..")
        || path.contains('?')
        || path.contains('#')
    {
        return Err(ConfigurationError::Invalid);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod unix_secret_file_tests {
    use super::{ConfigurationError, validate_private_file_for_identity};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn test_directory() -> std::io::Result<PathBuf> {
        let directory = std::env::temp_dir().join(format!(
            "agenttrust-private-file-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory)?;
        Ok(directory)
    }

    #[test]
    fn accepts_csi_group_read_only_for_effective_group() -> std::io::Result<()> {
        let directory = test_directory()?;
        let secret = directory.join("secret");
        fs::write(&secret, b"secret")?;
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o440))?;
        let metadata = fs::symlink_metadata(&secret)?;

        assert!(
            validate_private_file_for_identity(
                &secret,
                metadata.uid().wrapping_add(1),
                metadata.gid(),
            )
            .is_ok()
        );
        assert!(matches!(
            validate_private_file_for_identity(
                &secret,
                metadata.uid().wrapping_add(1),
                metadata.gid().wrapping_add(1),
            ),
            Err(ConfigurationError::SecretFileInvalid),
        ));
        assert!(matches!(
            validate_private_file_for_identity(
                &secret,
                metadata.uid(),
                metadata.gid().wrapping_add(1),
            ),
            Err(ConfigurationError::SecretFileInvalid),
        ));

        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn rejects_group_write_world_access_and_symbolic_links() -> std::io::Result<()> {
        let directory = test_directory()?;
        let secret = directory.join("secret");
        let link = directory.join("secret-link");
        fs::write(&secret, b"secret")?;
        let metadata = fs::symlink_metadata(&secret)?;

        for mode in [0o460, 0o441, 0o600, 0o500, 0o1440] {
            fs::set_permissions(&secret, fs::Permissions::from_mode(mode))?;
            assert!(matches!(
                validate_private_file_for_identity(&secret, metadata.uid(), metadata.gid()),
                Err(ConfigurationError::SecretFileInvalid),
            ));
        }

        fs::set_permissions(&secret, fs::Permissions::from_mode(0o400))?;
        symlink(&secret, &link)?;
        assert!(matches!(
            validate_private_file_for_identity(&link, metadata.uid(), metadata.gid()),
            Err(ConfigurationError::SecretFileInvalid),
        ));

        fs::remove_dir_all(directory)?;
        Ok(())
    }
}
