#[cfg(feature = "development-local-signing")]
use agent_trust_production_closure::ClosureAuthority;
use agent_trust_production_closure::{
    ClosureInput, ClosureReport, ClosureRunner, ClosureScope, DomainAssuranceAttestation,
    ExternalCertificateSignature, ExternalCertificateSigningRequest,
    ExternalGateAssuranceAttestation, ExternalRevocationRegistrySignature,
    ExternalRevocationRegistrySigningRequest, ProductionActivationExpectation,
    ProductionActivationVerifier, ProductionClosureCertificate, RevocationRegistryUpdate,
    SignedCertificateRevocationRegistry, TrustedReviewerKeyring,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
#[cfg(any(test, feature = "development-local-signing"))]
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAXIMUM_INPUT_BYTES: u64 = 128 * 1024 * 1024;
const ACTIVATION_WATCH_INTERVAL: Duration = Duration::from_secs(25);
const ACTIVATION_WATCH_FRESHNESS_SECONDS: i64 = 60;

#[cfg(feature = "development-local-signing")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningKeySpec {
    schema_version: String,
    key_id: String,
    private_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeySpec {
    schema_version: String,
    key_id: String,
    public_key: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivationWatchStatus {
    schema_version: String,
    ready: bool,
    last_success_at: Option<DateTime<Utc>>,
    receipt_digest: Option<String>,
    revocation_registry_id: Option<String>,
    revocation_registry_sequence: Option<u64>,
    revocation_registry_digest: Option<String>,
    projection_id: Option<String>,
    projection_head_digest: Option<String>,
    maximum_age_seconds: i64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevocationProjectionHead {
    schema_version: String,
    projection_id: String,
    environment_reference: String,
    base_checkpoint_digest: String,
    registry_id: String,
    registry_key_id: String,
    registry_sequence: u64,
    registry_digest: String,
    projected_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    projection_key_id: String,
    signature: String,
}

impl RevocationProjectionHead {
    fn digest(&self) -> Result<String, &'static str> {
        let bytes = serde_jcs::to_vec(self).map_err(|_| "CLOSURE_PROJECTION_HEAD_INVALID")?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn verify(
        &self,
        registry: &SignedCertificateRevocationRegistry,
        registry_digest: &str,
        projection_key_spec: &PublicKeySpec,
        now: DateTime<Utc>,
    ) -> Result<(), &'static str> {
        if self.schema_version != "agenttrust.production-revocation-projection-head.v1"
            || !valid_key_id(&self.projection_id)
            || !valid_production_environment_reference(&self.environment_reference)
            || !valid_sha256(&self.base_checkpoint_digest)
            || !valid_key_id(&self.registry_id)
            || !valid_key_id(&self.registry_key_id)
            || !valid_sha256(&self.registry_digest)
            || self.registry_id != registry.registry_id
            || self.registry_key_id != registry.key_id
            || self.registry_sequence != registry.sequence
            || self.registry_digest != registry_digest
            || projection_key_spec.schema_version != "agenttrust.ed25519-public-key.v1"
            || projection_key_spec.key_id != self.projection_key_id
            || self.projection_key_id == registry.key_id
            || self.projected_at > now + ChronoDuration::minutes(1)
            || self.expires_at <= now
            || self.expires_at <= self.projected_at
            || self.expires_at - self.projected_at > ChronoDuration::minutes(5)
        {
            return Err("CLOSURE_PROJECTION_HEAD_INVALID");
        }
        let key = VerifyingKey::from_bytes(&decode_32(&projection_key_spec.public_key)?)
            .map_err(|_| "CLOSURE_PROJECTION_KEY_INVALID")?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| "CLOSURE_PROJECTION_HEAD_INVALID")?;
        if URL_SAFE_NO_PAD.encode(&signature_bytes) != self.signature {
            return Err("CLOSURE_PROJECTION_HEAD_INVALID");
        }
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| "CLOSURE_PROJECTION_HEAD_INVALID")?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let bytes = serde_jcs::to_vec(&unsigned)
            .map_err(|_| "CLOSURE_PROJECTION_HEAD_INVALID")?;
        key.verify(&bytes, &signature)
            .map_err(|_| "CLOSURE_PROJECTION_HEAD_INVALID")
    }
}

fn read_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T, &'static str> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| "CLOSURE_INPUT_UNREADABLE")?;
    let metadata = file.metadata().map_err(|_| "CLOSURE_INPUT_UNREADABLE")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err("CLOSURE_INPUT_SIZE_INVALID");
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| "CLOSURE_INPUT_SIZE_INVALID")?;
    let maximum = usize::try_from(limit).map_err(|_| "CLOSURE_INPUT_SIZE_INVALID")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "CLOSURE_INPUT_UNREADABLE")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("CLOSURE_INPUT_SIZE_INVALID");
    }
    serde_json::from_slice(&bytes).map_err(|_| "CLOSURE_INPUT_INVALID")
}

fn write_new<T: Serialize>(path: &Path, value: &T) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| "CLOSURE_OUTPUT_INVALID")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if path.file_name().is_none() || !parent.is_dir() {
        return Err("CLOSURE_OUTPUT_ALREADY_EXISTS_OR_UNWRITABLE");
    }
    let temporary = parent.join(format!(".production-closure-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| "CLOSURE_OUTPUT_ALREADY_EXISTS_OR_UNWRITABLE")?;
    let write_result = file
        .write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all());
    drop(file);
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("CLOSURE_OUTPUT_WRITE_FAILED");
    }
    if fs::hard_link(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("CLOSURE_OUTPUT_ALREADY_EXISTS_OR_UNWRITABLE");
    }
    fs::remove_file(&temporary).map_err(|_| "CLOSURE_OUTPUT_WRITE_FAILED")?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "CLOSURE_OUTPUT_WRITE_FAILED")
}

#[cfg(target_os = "linux")]
fn current_filesystem_ids() -> Result<(u32, u32), &'static str> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|_| "CLOSURE_ACTIVATION_DIRECTORY_IDENTITY_UNAVAILABLE")?;
    let parse = |prefix: &str| -> Result<u32, &'static str> {
        let fields = status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .ok_or("CLOSURE_ACTIVATION_DIRECTORY_IDENTITY_UNAVAILABLE")?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "CLOSURE_ACTIVATION_DIRECTORY_IDENTITY_UNAVAILABLE")?;
        if fields.len() != 4 {
            return Err("CLOSURE_ACTIVATION_DIRECTORY_IDENTITY_UNAVAILABLE");
        }
        Ok(fields[3])
    };
    Ok((parse("Uid:")?, parse("Gid:")?))
}

#[cfg(not(target_os = "linux"))]
fn current_filesystem_ids() -> Result<(u32, u32), &'static str> {
    Err("CLOSURE_ACTIVATION_DIRECTORY_REQUIRES_LINUX")
}

#[cfg(unix)]
fn prepare_activation_directory(target: &Path) -> Result<(), &'static str> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    if !target.is_absolute()
        || target.file_name().is_none()
        || target.components().any(|component| {
            !matches!(component, Component::RootDir | Component::Normal(_))
        })
    {
        return Err("CLOSURE_ACTIVATION_DIRECTORY_PATH_INVALID");
    }
    let parent = target
        .parent()
        .filter(|path| path.is_absolute())
        .ok_or("CLOSURE_ACTIVATION_DIRECTORY_PATH_INVALID")?;
    let parent_before = fs::symlink_metadata(parent)
        .map_err(|_| "CLOSURE_ACTIVATION_DIRECTORY_PARENT_INVALID")?;
    if parent_before.file_type().is_symlink() || !parent_before.is_dir() {
        return Err("CLOSURE_ACTIVATION_DIRECTORY_PARENT_INVALID");
    }
    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        _ => return Err("CLOSURE_ACTIVATION_DIRECTORY_ALREADY_EXISTS"),
    }
    let mut builder = DirBuilder::new();
    builder.mode(0o750);
    builder
        .create(target)
        .map_err(|error| match error.kind() {
            ErrorKind::AlreadyExists => "CLOSURE_ACTIVATION_DIRECTORY_ALREADY_EXISTS",
            _ => "CLOSURE_ACTIVATION_DIRECTORY_CREATE_FAILED",
        })?;
    let validate = || -> Result<(), &'static str> {
        let parent_after = fs::symlink_metadata(parent)
            .map_err(|_| "CLOSURE_ACTIVATION_DIRECTORY_PARENT_CHANGED")?;
        if parent_after.file_type().is_symlink()
            || !parent_after.is_dir()
            || parent_after.dev() != parent_before.dev()
            || parent_after.ino() != parent_before.ino()
        {
            return Err("CLOSURE_ACTIVATION_DIRECTORY_PARENT_CHANGED");
        }
        fs::set_permissions(target, fs::Permissions::from_mode(0o750))
            .map_err(|_| "CLOSURE_ACTIVATION_DIRECTORY_MODE_INVALID")?;
        let metadata = fs::symlink_metadata(target)
            .map_err(|_| "CLOSURE_ACTIVATION_DIRECTORY_VALIDATION_FAILED")?;
        let (current_uid, current_gid) = current_filesystem_ids()?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != current_uid
            || metadata.gid() != current_gid
            || metadata.permissions().mode() & 0o777 != 0o750
            || fs::read_dir(target)
                .map_err(|_| "CLOSURE_ACTIVATION_DIRECTORY_VALIDATION_FAILED")?
                .next()
                .is_some()
        {
            return Err("CLOSURE_ACTIVATION_DIRECTORY_VALIDATION_FAILED");
        }
        fs::File::open(target)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "CLOSURE_ACTIVATION_DIRECTORY_SYNC_FAILED")?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "CLOSURE_ACTIVATION_DIRECTORY_SYNC_FAILED")
    };
    if let Err(error) = validate() {
        let _ = fs::remove_dir(target);
        return Err(error);
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_activation_directory(_: &Path) -> Result<(), &'static str> {
    Err("CLOSURE_ACTIVATION_DIRECTORY_REQUIRES_UNIX")
}

#[cfg(unix)]
fn read_watch_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T, &'static str> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !path.is_absolute() {
        return Err("CLOSURE_WATCH_INPUT_PATH_INVALID");
    }
    let before = fs::symlink_metadata(path).map_err(|_| "CLOSURE_WATCH_INPUT_UNREADABLE")?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.nlink() != 1
        || before.permissions().mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > limit
    {
        return Err("CLOSURE_WATCH_INPUT_UNSAFE");
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| "CLOSURE_WATCH_INPUT_UNREADABLE")?;
    let opened = file
        .metadata()
        .map_err(|_| "CLOSURE_WATCH_INPUT_UNREADABLE")?;
    let after = fs::symlink_metadata(path).map_err(|_| "CLOSURE_WATCH_INPUT_UNREADABLE")?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.file_type().is_symlink()
        || after.nlink() != 1
        || after.permissions().mode() & 0o022 != 0
        || after.len() != opened.len()
    {
        return Err("CLOSURE_WATCH_INPUT_CHANGED");
    }
    let maximum = usize::try_from(limit).map_err(|_| "CLOSURE_WATCH_INPUT_SIZE_INVALID")?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).map_err(|_| "CLOSURE_WATCH_INPUT_SIZE_INVALID")?,
    );
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "CLOSURE_WATCH_INPUT_UNREADABLE")?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || u64::try_from(bytes.len()).map_err(|_| "CLOSURE_WATCH_INPUT_SIZE_INVALID")?
            != opened.len()
    {
        return Err("CLOSURE_WATCH_INPUT_SIZE_INVALID");
    }
    let final_metadata =
        fs::symlink_metadata(path).map_err(|_| "CLOSURE_WATCH_INPUT_UNREADABLE")?;
    if final_metadata.dev() != opened.dev()
        || final_metadata.ino() != opened.ino()
        || final_metadata.len() != opened.len()
    {
        return Err("CLOSURE_WATCH_INPUT_CHANGED");
    }
    serde_json::from_slice(&bytes).map_err(|_| "CLOSURE_WATCH_INPUT_INVALID")
}

#[cfg(not(unix))]
fn read_watch_json<T: DeserializeOwned>(_: &Path, _: u64) -> Result<T, &'static str> {
    Err("CLOSURE_WATCH_REQUIRES_UNIX")
}

#[cfg(unix)]
fn write_watch_receipt<T: Serialize>(path: &Path, value: &T) -> Result<(), &'static str> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    if !path.is_absolute() || path.file_name().is_none() {
        return Err("CLOSURE_WATCH_OUTPUT_PATH_INVALID");
    }
    let parent = path.parent().ok_or("CLOSURE_WATCH_OUTPUT_PATH_INVALID")?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| "CLOSURE_WATCH_OUTPUT_PATH_INVALID")?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err("CLOSURE_WATCH_OUTPUT_UNSAFE");
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o022 != 0 =>
        {
            return Err("CLOSURE_WATCH_OUTPUT_UNSAFE");
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err("CLOSURE_WATCH_OUTPUT_UNREADABLE"),
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| "CLOSURE_WATCH_OUTPUT_INVALID")?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err("CLOSURE_WATCH_OUTPUT_INVALID");
    }
    let temporary = parent.join(format!(".production-activation-{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| "CLOSURE_WATCH_OUTPUT_WRITE_FAILED")?;
    let result = file
        .write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .and_then(|_| file.set_permissions(fs::Permissions::from_mode(0o440)))
        .and_then(|_| file.sync_all());
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("CLOSURE_WATCH_OUTPUT_WRITE_FAILED");
    }
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("CLOSURE_WATCH_OUTPUT_WRITE_FAILED");
    }
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "CLOSURE_WATCH_OUTPUT_WRITE_FAILED")
}

#[cfg(not(unix))]
fn write_watch_receipt<T: Serialize>(_: &Path, _: &T) -> Result<(), &'static str> {
    Err("CLOSURE_WATCH_REQUIRES_UNIX")
}

struct ActivationWatchPaths {
    certificate: PathBuf,
    report: PathBuf,
    input: PathBuf,
    certificate_key: PathBuf,
    baseline_registry: PathBuf,
    registry: PathBuf,
    projection_head: PathBuf,
    projection_key: PathBuf,
    registry_key: PathBuf,
    expectation: PathBuf,
    output: PathBuf,
}

#[derive(Default)]
struct ActivationWatchState {
    last_registry: Option<SignedCertificateRevocationRegistry>,
    last_registry_digest: Option<String>,
    last_projection_id: Option<String>,
    last_projection_head_digest: Option<String>,
    last_success: Option<DateTime<Utc>>,
    last_valid_until: Option<DateTime<Utc>>,
    last_receipt_digest: Option<String>,
    last_attempt_succeeded: bool,
}

impl ActivationWatchState {
    fn ready(&self, now: DateTime<Utc>) -> bool {
        self.last_attempt_succeeded
            && self
                .last_valid_until
                .as_ref()
                .is_some_and(|valid_until| valid_until > &now)
            && self.last_success.as_ref().is_some_and(|verified_at| {
                verified_at.to_owned()
                    + ChronoDuration::seconds(ACTIVATION_WATCH_FRESHNESS_SECONDS)
                    >= now
            })
    }
}

fn initialize_activation_watch(
    paths: &ActivationWatchPaths,
) -> Result<ActivationWatchState, &'static str> {
    let baseline: SignedCertificateRevocationRegistry =
        read_watch_json(&paths.baseline_registry, 32 * 1024 * 1024)?;
    let registry_key_spec: PublicKeySpec = read_watch_json(&paths.registry_key, 64 * 1024)?;
    if registry_key_spec.schema_version != "agenttrust.ed25519-public-key.v1"
        || registry_key_spec.key_id != baseline.key_id
    {
        return Err("CLOSURE_WATCH_BASELINE_KEY_INVALID");
    }
    let registry_key = VerifyingKey::from_bytes(&decode_32(&registry_key_spec.public_key)?)
        .map_err(|_| "CLOSURE_WATCH_BASELINE_KEY_INVALID")?;
    baseline
        .verify(&registry_key, baseline.published_at)
        .map_err(|_| "CLOSURE_WATCH_BASELINE_INVALID")?;
    let baseline_digest = baseline
        .digest()
        .map_err(|_| "CLOSURE_WATCH_BASELINE_INVALID")?;
    Ok(ActivationWatchState {
        last_registry: Some(baseline),
        last_registry_digest: Some(baseline_digest),
        ..ActivationWatchState::default()
    })
}

fn registry_preserves(
    previous: &SignedCertificateRevocationRegistry,
    current: &SignedCertificateRevocationRegistry,
) -> bool {
    previous.entries.iter().all(|previous_entry| {
        current
            .entries
            .binary_search_by(|entry| {
                entry
                    .certificate_id
                    .as_str()
                    .cmp(previous_entry.certificate_id.as_str())
            })
            .ok()
            .and_then(|index| current.entries.get(index))
            == Some(previous_entry)
    })
}

fn verify_projected_registry_lineage(
    previous: &SignedCertificateRevocationRegistry,
    previous_digest: &str,
    registry: &SignedCertificateRevocationRegistry,
    registry_digest: &str,
    projection_head: &RevocationProjectionHead,
    projection_key_spec: &PublicKeySpec,
    now: DateTime<Utc>,
) -> Result<String, &'static str> {
    if registry.registry_id != previous.registry_id
        || registry.key_id != previous.key_id
        || registry.sequence < previous.sequence
        || (registry.sequence == previous.sequence && registry_digest != previous_digest)
        || !registry_preserves(previous, registry)
    {
        return Err("CLOSURE_WATCH_REVOCATION_ROLLBACK");
    }
    projection_head.verify(registry, registry_digest, projection_key_spec, now)?;
    projection_head.digest()
}

fn refresh_activation(
    paths: &ActivationWatchPaths,
    state: &mut ActivationWatchState,
) -> Result<(), &'static str> {
    let now = Utc::now();
    let certificate: ProductionClosureCertificate =
        read_watch_json(&paths.certificate, MAXIMUM_INPUT_BYTES)?;
    let report: ClosureReport = read_watch_json(&paths.report, MAXIMUM_INPUT_BYTES)?;
    let input: ClosureInput = read_watch_json(&paths.input, MAXIMUM_INPUT_BYTES)?;
    let certificate_key_spec: PublicKeySpec =
        read_watch_json(&paths.certificate_key, 64 * 1024)?;
    let registry: SignedCertificateRevocationRegistry =
        read_watch_json(&paths.registry, 32 * 1024 * 1024)?;
    let projection_head: RevocationProjectionHead =
        read_watch_json(&paths.projection_head, 64 * 1024)?;
    let projection_key_spec: PublicKeySpec =
        read_watch_json(&paths.projection_key, 64 * 1024)?;
    let registry_key_spec: PublicKeySpec = read_watch_json(&paths.registry_key, 64 * 1024)?;
    let expectation: ProductionActivationExpectation =
        read_watch_json(&paths.expectation, 64 * 1024)?;
    if certificate_key_spec.schema_version != "agenttrust.ed25519-public-key.v1"
        || certificate_key_spec.key_id != certificate.key_id
        || registry_key_spec.schema_version != "agenttrust.ed25519-public-key.v1"
        || registry_key_spec.key_id != registry.key_id
    {
        return Err("CLOSURE_WATCH_KEY_INVALID");
    }
    let certificate_key = VerifyingKey::from_bytes(&decode_32(&certificate_key_spec.public_key)?)
        .map_err(|_| "CLOSURE_WATCH_KEY_INVALID")?;
    let registry_key = VerifyingKey::from_bytes(&decode_32(&registry_key_spec.public_key)?)
        .map_err(|_| "CLOSURE_WATCH_KEY_INVALID")?;
    let registry_digest = registry
        .digest()
        .map_err(|_| "CLOSURE_WATCH_REVOCATION_INVALID")?;
    registry
        .verify(&registry_key, now)
        .map_err(|_| "CLOSURE_WATCH_REVOCATION_INVALID")?;
    let previous = state
        .last_registry
        .as_ref()
        .ok_or("CLOSURE_WATCH_BASELINE_INVALID")?;
    let previous_digest = state
        .last_registry_digest
        .as_deref()
        .ok_or("CLOSURE_WATCH_BASELINE_INVALID")?;
    let projection_head_digest = verify_projected_registry_lineage(
        previous,
        previous_digest,
        &registry,
        &registry_digest,
        &projection_head,
        &projection_key_spec,
        now,
    )?;
    let receipt = ProductionActivationVerifier::verify(
        &certificate,
        &report,
        &input,
        &certificate_key,
        &registry,
        &registry_key,
        &expectation,
        now,
    )
    .map_err(|_| "CLOSURE_WATCH_ACTIVATION_INVALID")?;
    write_watch_receipt(&paths.output, &receipt)?;
    state.last_registry = Some(registry);
    state.last_registry_digest = Some(registry_digest);
    state.last_projection_id = Some(projection_head.projection_id);
    state.last_projection_head_digest = Some(projection_head_digest);
    state.last_success = Some(now);
    state.last_valid_until = Some(receipt.valid_until);
    state.last_receipt_digest = Some(receipt.receipt_digest);
    state.last_attempt_succeeded = true;
    Ok(())
}

fn serve_readiness(stream: &mut TcpStream, state: &ActivationWatchState) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
    let mut request = [0_u8; 4096];
    let request_ok = stream
        .read(&mut request)
        .ok()
        .filter(|length| *length > 0)
        .is_some_and(|length| request[..length].starts_with(b"GET /ready HTTP/1.1\r\n"));
    let now = Utc::now();
    let ready = request_ok && state.ready(now);
    let status = if !request_ok {
        "404 Not Found"
    } else if ready {
        "200 OK"
    } else {
        "503 Service Unavailable"
    };
    let body = serde_json::to_vec(&json!({
        "schema_version":"agenttrust.production-activation-watch-status.v1",
        "ready":ready,
        "last_success_at":state.last_success.as_ref().map(DateTime::to_rfc3339),
        "receipt_digest":state.last_receipt_digest.as_deref(),
        "revocation_registry_id":state.last_registry.as_ref().map(|registry| registry.registry_id.as_str()),
        "revocation_registry_sequence":state.last_registry.as_ref().map(|registry| registry.sequence),
        "revocation_registry_digest":state.last_registry_digest.as_deref(),
        "projection_id":state.last_projection_id.as_deref(),
        "projection_head_digest":state.last_projection_head_digest.as_deref(),
        "maximum_age_seconds":ACTIVATION_WATCH_FRESHNESS_SECONDS,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

fn check_activation_watch(address: SocketAddr) -> Result<ActivationWatchStatus, &'static str> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("CLOSURE_WATCH_READINESS_ADDRESS_INVALID");
    }
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|_| "CLOSURE_WATCH_READINESS_UNAVAILABLE")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(2))))
        .map_err(|_| "CLOSURE_WATCH_READINESS_UNAVAILABLE")?;
    let request = format!(
        "GET /ready HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|_| "CLOSURE_WATCH_READINESS_UNAVAILABLE")?;
    let mut response = Vec::with_capacity(16 * 1024);
    stream
        .take(16 * 1024 + 1)
        .read_to_end(&mut response)
        .map_err(|_| "CLOSURE_WATCH_READINESS_UNAVAILABLE")?;
    if response.is_empty() || response.len() > 16 * 1024 {
        return Err("CLOSURE_WATCH_READINESS_RESPONSE_INVALID");
    }
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("CLOSURE_WATCH_READINESS_RESPONSE_INVALID")?;
    let headers = std::str::from_utf8(&response[..separator])
        .map_err(|_| "CLOSURE_WATCH_READINESS_RESPONSE_INVALID")?;
    let mut header_lines = headers.split("\r\n");
    if header_lines.next() != Some("HTTP/1.1 200 OK") {
        return Err("CLOSURE_WATCH_NOT_READY");
    }
    let body = &response[separator + 4..];
    let declared_length = header_lines
        .find_map(|line| {
            line.strip_prefix("Content-Length: ")
                .and_then(|value| value.parse::<usize>().ok())
        })
        .ok_or("CLOSURE_WATCH_READINESS_RESPONSE_INVALID")?;
    if body.len() != declared_length || body.is_empty() {
        return Err("CLOSURE_WATCH_READINESS_RESPONSE_INVALID");
    }
    let status: ActivationWatchStatus =
        serde_json::from_slice(body).map_err(|_| "CLOSURE_WATCH_READINESS_RESPONSE_INVALID")?;
    let last_success = status
        .last_success_at
        .as_ref()
        .ok_or("CLOSURE_WATCH_NOT_READY")?
        .to_owned();
    let age = Utc::now().signed_duration_since(last_success);
    let receipt_digest = status
        .receipt_digest
        .as_deref()
        .ok_or("CLOSURE_WATCH_NOT_READY")?;
    let registry_id = status
        .revocation_registry_id
        .as_deref()
        .ok_or("CLOSURE_WATCH_NOT_READY")?;
    let registry_sequence = status
        .revocation_registry_sequence
        .ok_or("CLOSURE_WATCH_NOT_READY")?;
    let registry_digest = status
        .revocation_registry_digest
        .as_deref()
        .ok_or("CLOSURE_WATCH_NOT_READY")?;
    let projection_id = status
        .projection_id
        .as_deref()
        .ok_or("CLOSURE_WATCH_NOT_READY")?;
    let projection_head_digest = status
        .projection_head_digest
        .as_deref()
        .ok_or("CLOSURE_WATCH_NOT_READY")?;
    if status.schema_version != "agenttrust.production-activation-watch-status.v1"
        || !status.ready
        || status.maximum_age_seconds != ACTIVATION_WATCH_FRESHNESS_SECONDS
        || age < ChronoDuration::zero()
        || age > ChronoDuration::seconds(ACTIVATION_WATCH_FRESHNESS_SECONDS)
        || !valid_sha256(receipt_digest)
        || !valid_key_id(registry_id)
        || registry_sequence == 0
        || !valid_sha256(registry_digest)
        || !valid_key_id(projection_id)
        || !valid_sha256(projection_head_digest)
    {
        return Err("CLOSURE_WATCH_NOT_READY");
    }
    Ok(status)
}

fn watch_activation(paths: ActivationWatchPaths, address: SocketAddr) -> Result<(), &'static str> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("CLOSURE_WATCH_READINESS_ADDRESS_INVALID");
    }
    let listener = TcpListener::bind(address).map_err(|_| "CLOSURE_WATCH_READINESS_BIND_FAILED")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "CLOSURE_WATCH_READINESS_BIND_FAILED")?;
    let mut state = initialize_activation_watch(&paths)?;
    let mut next_refresh = Instant::now();
    loop {
        if Instant::now() >= next_refresh {
            state.last_attempt_succeeded = false;
            if let Err(error) = refresh_activation(&paths, &mut state) {
                eprintln!("{error}");
            }
            next_refresh = Instant::now() + ACTIVATION_WATCH_INTERVAL;
        }
        for _ in 0..8 {
            match listener.accept() {
                Ok((mut stream, _)) => serve_readiness(&mut stream, &state),
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => return Err("CLOSURE_WATCH_READINESS_ACCEPT_FAILED"),
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn decode_32(value: &str) -> Result<[u8; 32], &'static str> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "CLOSURE_KEY_INVALID")?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err("CLOSURE_KEY_INVALID");
    }
    decoded.try_into().map_err(|_| "CLOSURE_KEY_INVALID")
}

#[cfg(all(unix, feature = "development-local-signing"))]
fn require_private_permissions(path: &Path) -> Result<(), &'static str> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|_| "CLOSURE_KEY_UNREADABLE")?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err("CLOSURE_PRIVATE_KEY_PERMISSIONS_TOO_OPEN");
    }
    Ok(())
}

#[cfg(all(not(unix), feature = "development-local-signing"))]
fn require_private_permissions(_: &Path) -> Result<(), &'static str> {
    Err("CLOSURE_PRIVATE_KEY_PERMISSION_CHECK_UNSUPPORTED")
}

#[cfg(feature = "development-local-signing")]
fn require_development_local_signing() -> Result<(), &'static str> {
    if env::var("AGENT_TRUST_PROFILE").as_deref() != Ok("development")
        || env::var("AGENT_TRUST_ALLOW_LOCAL_CLOSURE_SIGNING").as_deref()
            != Ok("I_UNDERSTAND_LOCAL_KEYS_ARE_NOT_PRODUCTION")
    {
        return Err("CLOSURE_LOCAL_SIGNING_DISABLED");
    }
    Ok(())
}

fn valid_key_id(value: &str) -> bool {
    value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_production_environment_reference(value: &str) -> bool {
    value
        .strip_prefix("environment://production/")
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 480
                && suffix.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
                })
        })
}

fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("prepare-activation-directory") => {
            let target = PathBuf::from(
                args.next()
                    .ok_or("CLOSURE_ACTIVATION_DIRECTORY_PATH_REQUIRED")?,
            );
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            prepare_activation_directory(&target)?;
            let (uid, gid) = current_filesystem_ids()?;
            println!(
                "{}",
                json!({"path":target.display().to_string(),"created":true,"mode":"0750","uid":uid,"gid":gid})
            );
        }
        Some("check-activation-watch") => {
            let address: SocketAddr = args
                .next()
                .ok_or("CLOSURE_WATCH_READINESS_ADDRESS_REQUIRED")?
                .parse()
                .map_err(|_| "CLOSURE_WATCH_READINESS_ADDRESS_INVALID")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let status = check_activation_watch(address)?;
            println!(
                "{}",
                serde_json::to_string(&status)
                    .map_err(|_| "CLOSURE_WATCH_READINESS_RESPONSE_INVALID")?
            );
        }
        Some("evaluate") => {
            let input: ClosureInput = read_json(
                Path::new(&args.next().ok_or("CLOSURE_INPUT_REQUIRED")?),
                MAXIMUM_INPUT_BYTES,
            )?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let report = ClosureRunner::evaluate(&input, Utc::now())
                .map_err(|_| "CLOSURE_EVALUATION_FAILED")?;
            write_new(Path::new(&output), &report)?;
            println!(
                "{}",
                json!({"eligible":report.eligible,"report_digest":report.report_digest,"blocker_count":report.blockers.len()})
            );
        }
        Some("issue") => return Err("CLOSURE_EXTERNAL_SIGNING_REQUIRED"),
        #[cfg(feature = "development-local-signing")]
        Some("issue-local") => {
            require_development_local_signing()?;
            let report_path = args.next().ok_or("CLOSURE_REPORT_REQUIRED")?;
            let input_path = args.next().ok_or("CLOSURE_INPUT_REQUIRED")?;
            let key_path = args.next().ok_or("CLOSURE_KEY_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let report: ClosureReport = read_json(Path::new(&report_path), MAXIMUM_INPUT_BYTES)?;
            let input: ClosureInput = read_json(Path::new(&input_path), MAXIMUM_INPUT_BYTES)?;
            require_private_permissions(Path::new(&key_path))?;
            let spec: SigningKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-signing-key.v1" || spec.key_id.is_empty()
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let authority = ClosureAuthority::new(
                spec.key_id,
                SigningKey::from_bytes(&decode_32(&spec.private_key)?),
            )
            .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let certificate = authority
                .issue(&report, &input, Utc::now())
                .map_err(|_| "CLOSURE_CERTIFICATE_NOT_ELIGIBLE")?;
            write_new(Path::new(&output), &certificate)?;
            println!(
                "{}",
                json!({"certificate_id":certificate.certificate_id,"issued":true,"production_signing":false})
            );
        }
        Some("prepare-external-signing") => {
            let report_path = args.next().ok_or("CLOSURE_REPORT_REQUIRED")?;
            let input_path = args.next().ok_or("CLOSURE_INPUT_REQUIRED")?;
            let key_id = args.next().ok_or("CLOSURE_KEY_ID_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() || !valid_key_id(&key_id) {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let report: ClosureReport = read_json(Path::new(&report_path), MAXIMUM_INPUT_BYTES)?;
            let input: ClosureInput = read_json(Path::new(&input_path), MAXIMUM_INPUT_BYTES)?;
            let request =
                ExternalCertificateSigningRequest::prepare(&report, &input, key_id, Utc::now())
                    .map_err(|_| "CLOSURE_CERTIFICATE_NOT_ELIGIBLE")?;
            let request_digest = request
                .digest()
                .map_err(|_| "CLOSURE_SIGNING_REQUEST_INVALID")?;
            write_new(Path::new(&output), &request)?;
            println!(
                "{}",
                json!({"request_digest":request_digest,"prepared":true,"private_key_loaded":false})
            );
        }
        Some("finalize-external-signing") => {
            let request_path = args.next().ok_or("CLOSURE_SIGNING_REQUEST_REQUIRED")?;
            let signature_path = args.next().ok_or("CLOSURE_EXTERNAL_SIGNATURE_REQUIRED")?;
            let key_path = args.next().ok_or("CLOSURE_KEY_REQUIRED")?;
            let report_path = args.next().ok_or("CLOSURE_REPORT_REQUIRED")?;
            let input_path = args.next().ok_or("CLOSURE_INPUT_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let request: ExternalCertificateSigningRequest =
                read_json(Path::new(&request_path), MAXIMUM_INPUT_BYTES)?;
            let signature: ExternalCertificateSignature =
                read_json(Path::new(&signature_path), 64 * 1024)?;
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            let report: ClosureReport = read_json(Path::new(&report_path), MAXIMUM_INPUT_BYTES)?;
            let input: ClosureInput = read_json(Path::new(&input_path), MAXIMUM_INPUT_BYTES)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != request.key_id
                || spec.key_id != signature.key_id
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let certificate = signature
                .finalize(&request, &report, &input, &key, Utc::now())
                .map_err(|_| "CLOSURE_EXTERNAL_SIGNING_INVALID")?;
            write_new(Path::new(&output), &certificate)?;
            println!(
                "{}",
                json!({"certificate_id":certificate.certificate_id,"issued":true,"production_signing":true,"verified":true})
            );
        }
        Some("verify") => {
            let certificate_path = args.next().ok_or("CLOSURE_CERTIFICATE_REQUIRED")?;
            let report_path = args.next().ok_or("CLOSURE_REPORT_REQUIRED")?;
            let input_path = args.next().ok_or("CLOSURE_INPUT_REQUIRED")?;
            let key_path = args.next().ok_or("CLOSURE_KEY_REQUIRED")?;
            let registry_path = args.next().ok_or("CLOSURE_REVOCATION_REGISTRY_REQUIRED")?;
            let registry_key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let certificate: ProductionClosureCertificate =
                read_json(Path::new(&certificate_path), MAXIMUM_INPUT_BYTES)?;
            let report: ClosureReport = read_json(Path::new(&report_path), MAXIMUM_INPUT_BYTES)?;
            let input: ClosureInput = read_json(Path::new(&input_path), MAXIMUM_INPUT_BYTES)?;
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            let registry: SignedCertificateRevocationRegistry =
                read_json(Path::new(&registry_path), 32 * 1024 * 1024)?;
            let registry_key_spec: PublicKeySpec =
                read_json(Path::new(&registry_key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != certificate.key_id
                || registry_key_spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || registry_key_spec.key_id != registry.key_id
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let registry_key = VerifyingKey::from_bytes(&decode_32(&registry_key_spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            registry
                .verify_active(
                    &certificate,
                    &report,
                    &input,
                    &key,
                    &registry_key,
                    Utc::now(),
                )
                .map_err(|_| "CLOSURE_CERTIFICATE_INVALID")?;
            println!(
                "{}",
                json!({"certificate_id":certificate.certificate_id,"verified":true,"revocation_registry_id":registry.registry_id,"revocation_sequence":registry.sequence,"revocation_registry_digest":registry.digest().map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?})
            );
        }
        Some("verify-activation") => {
            let certificate_path = args.next().ok_or("CLOSURE_CERTIFICATE_REQUIRED")?;
            let report_path = args.next().ok_or("CLOSURE_REPORT_REQUIRED")?;
            let input_path = args.next().ok_or("CLOSURE_INPUT_REQUIRED")?;
            let key_path = args.next().ok_or("CLOSURE_KEY_REQUIRED")?;
            let registry_path = args.next().ok_or("CLOSURE_REVOCATION_REGISTRY_REQUIRED")?;
            let registry_key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            let expectation_path = args
                .next()
                .ok_or("CLOSURE_ACTIVATION_EXPECTATION_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let certificate: ProductionClosureCertificate =
                read_json(Path::new(&certificate_path), MAXIMUM_INPUT_BYTES)?;
            let report: ClosureReport = read_json(Path::new(&report_path), MAXIMUM_INPUT_BYTES)?;
            let input: ClosureInput = read_json(Path::new(&input_path), MAXIMUM_INPUT_BYTES)?;
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            let registry: SignedCertificateRevocationRegistry =
                read_json(Path::new(&registry_path), 32 * 1024 * 1024)?;
            let registry_key_spec: PublicKeySpec =
                read_json(Path::new(&registry_key_path), 64 * 1024)?;
            let expectation: ProductionActivationExpectation =
                read_json(Path::new(&expectation_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != certificate.key_id
                || registry_key_spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || registry_key_spec.key_id != registry.key_id
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let registry_key = VerifyingKey::from_bytes(&decode_32(&registry_key_spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let receipt = ProductionActivationVerifier::verify(
                &certificate,
                &report,
                &input,
                &key,
                &registry,
                &registry_key,
                &expectation,
                Utc::now(),
            )
            .map_err(|_| "CLOSURE_ACTIVATION_INVALID")?;
            write_new(Path::new(&output), &receipt)?;
            println!(
                "{}",
                json!({"certificate_id":receipt.certificate_id,"release_id":receipt.release_id,"production_write_enabled":true,"valid_until":receipt.valid_until,"receipt_digest":receipt.receipt_digest})
            );
        }
        Some("watch-activation") => {
            let paths = ActivationWatchPaths {
                certificate: PathBuf::from(
                    args.next().ok_or("CLOSURE_CERTIFICATE_REQUIRED")?,
                ),
                report: PathBuf::from(args.next().ok_or("CLOSURE_REPORT_REQUIRED")?),
                input: PathBuf::from(args.next().ok_or("CLOSURE_INPUT_REQUIRED")?),
                certificate_key: PathBuf::from(
                    args.next().ok_or("CLOSURE_KEY_REQUIRED")?,
                ),
                baseline_registry: PathBuf::from(
                    args.next()
                        .ok_or("CLOSURE_BASELINE_REVOCATION_REGISTRY_REQUIRED")?,
                ),
                registry: PathBuf::from(
                    args.next()
                        .ok_or("CLOSURE_REVOCATION_REGISTRY_REQUIRED")?,
                ),
                projection_head: PathBuf::from(
                    args.next()
                        .ok_or("CLOSURE_REVOCATION_PROJECTION_HEAD_REQUIRED")?,
                ),
                projection_key: PathBuf::from(
                    args.next()
                        .ok_or("CLOSURE_REVOCATION_PROJECTION_KEY_REQUIRED")?,
                ),
                registry_key: PathBuf::from(
                    args.next()
                        .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?,
                ),
                expectation: PathBuf::from(
                    args.next()
                        .ok_or("CLOSURE_ACTIVATION_EXPECTATION_REQUIRED")?,
                ),
                output: PathBuf::from(args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?),
            };
            let address: SocketAddr = args
                .next()
                .ok_or("CLOSURE_WATCH_READINESS_ADDRESS_REQUIRED")?
                .parse()
                .map_err(|_| "CLOSURE_WATCH_READINESS_ADDRESS_INVALID")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            watch_activation(paths, address)?;
        }
        Some("verify-revocation-projection") => {
            let registry_path = args.next().ok_or("CLOSURE_REVOCATION_REGISTRY_REQUIRED")?;
            let projection_head_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_PROJECTION_HEAD_REQUIRED")?;
            let projection_key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_PROJECTION_KEY_REQUIRED")?;
            let registry_key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            let expected_sequence = args
                .next()
                .ok_or("CLOSURE_REVOCATION_SEQUENCE_REQUIRED")?
                .parse::<u64>()
                .map_err(|_| "CLOSURE_REVOCATION_SEQUENCE_INVALID")?;
            let expected_digest = args
                .next()
                .ok_or("CLOSURE_REVOCATION_DIGEST_REQUIRED")?;
            if args.next().is_some() || expected_sequence == 0 || !valid_sha256(&expected_digest) {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let registry: SignedCertificateRevocationRegistry =
                read_json(Path::new(&registry_path), 32 * 1024 * 1024)?;
            let projection_head: RevocationProjectionHead =
                read_json(Path::new(&projection_head_path), 64 * 1024)?;
            let projection_key_spec: PublicKeySpec =
                read_json(Path::new(&projection_key_path), 64 * 1024)?;
            let registry_key_spec: PublicKeySpec =
                read_json(Path::new(&registry_key_path), 64 * 1024)?;
            if registry_key_spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || registry_key_spec.key_id != registry.key_id
            {
                return Err("CLOSURE_REVOCATION_REGISTRY_KEY_INVALID");
            }
            let registry_key =
                VerifyingKey::from_bytes(&decode_32(&registry_key_spec.public_key)?)
                    .map_err(|_| "CLOSURE_REVOCATION_REGISTRY_KEY_INVALID")?;
            let now = Utc::now();
            registry
                .verify(&registry_key, now)
                .map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?;
            let registry_digest = registry
                .digest()
                .map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?;
            if registry.sequence != expected_sequence
                || registry_digest != expected_digest
            {
                return Err("CLOSURE_REVOCATION_PROJECTION_ROLLBACK");
            }
            projection_head.verify(
                &registry,
                &registry_digest,
                &projection_key_spec,
                now,
            )?;
            let projection_head_digest = projection_head.digest()?;
            println!(
                "{}",
                json!({
                    "verified":true,
                    "registry_id":registry.registry_id,
                    "registry_sequence":registry.sequence,
                    "registry_digest":registry_digest,
                    "projection_id":projection_head.projection_id,
                    "projection_head_digest":projection_head_digest,
                })
            );
        }
        Some("verify-revocation-registry") => {
            let registry_path = args.next().ok_or("CLOSURE_REVOCATION_REGISTRY_REQUIRED")?;
            let key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let registry: SignedCertificateRevocationRegistry =
                read_json(Path::new(&registry_path), 32 * 1024 * 1024)?;
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != registry.key_id
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            registry
                .verify(&key, Utc::now())
                .map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?;
            println!(
                "{}",
                json!({"registry_id":registry.registry_id,"sequence":registry.sequence,"verified":true,"registry_digest":registry.digest().map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?})
            );
        }
        Some("verify-revocation-successor") => {
            let previous_path = args
                .next()
                .ok_or("CLOSURE_PREVIOUS_REVOCATION_REGISTRY_REQUIRED")?;
            let current_path = args.next().ok_or("CLOSURE_REVOCATION_REGISTRY_REQUIRED")?;
            let key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let previous: SignedCertificateRevocationRegistry =
                read_json(Path::new(&previous_path), 32 * 1024 * 1024)?;
            let current: SignedCertificateRevocationRegistry =
                read_json(Path::new(&current_path), 32 * 1024 * 1024)?;
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != previous.key_id
                || spec.key_id != current.key_id
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            current
                .verify_successor(&previous, &key, Utc::now())
                .map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?;
            println!(
                "{}",
                json!({"registry_id":current.registry_id,"previous_sequence":previous.sequence,"sequence":current.sequence,"verified_successor":true,"registry_digest":current.digest().map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?})
            );
        }
        Some("prepare-revocation-signing") => {
            let update_path = args.next().ok_or("CLOSURE_REVOCATION_UPDATE_REQUIRED")?;
            let previous_path = args
                .next()
                .ok_or("CLOSURE_PREVIOUS_REVOCATION_REGISTRY_REQUIRED")?;
            let key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let update: RevocationRegistryUpdate =
                read_json(Path::new(&update_path), 32 * 1024 * 1024)?;
            let previous = if previous_path == "-" {
                None
            } else {
                Some(read_json::<SignedCertificateRevocationRegistry>(
                    Path::new(&previous_path),
                    32 * 1024 * 1024,
                )?)
            };
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != update.key_id
                || previous
                    .as_ref()
                    .is_some_and(|registry| registry.key_id != spec.key_id)
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let request = ExternalRevocationRegistrySigningRequest::prepare(
                &update,
                previous.as_ref(),
                &key,
                Utc::now(),
            )
            .map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?;
            let request_digest = request
                .digest()
                .map_err(|_| "CLOSURE_SIGNING_REQUEST_INVALID")?;
            write_new(Path::new(&output), &request)?;
            println!(
                "{}",
                json!({"request_digest":request_digest,"registry_id":request.registry.registry_id,"sequence":request.registry.sequence,"prepared":true,"private_key_loaded":false})
            );
        }
        Some("finalize-revocation-signing") => {
            let request_path = args.next().ok_or("CLOSURE_SIGNING_REQUEST_REQUIRED")?;
            let signature_path = args.next().ok_or("CLOSURE_EXTERNAL_SIGNATURE_REQUIRED")?;
            let previous_path = args
                .next()
                .ok_or("CLOSURE_PREVIOUS_REVOCATION_REGISTRY_REQUIRED")?;
            let key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let request: ExternalRevocationRegistrySigningRequest =
                read_json(Path::new(&request_path), 32 * 1024 * 1024)?;
            let signature: ExternalRevocationRegistrySignature =
                read_json(Path::new(&signature_path), 64 * 1024)?;
            let previous = if previous_path == "-" {
                None
            } else {
                Some(read_json::<SignedCertificateRevocationRegistry>(
                    Path::new(&previous_path),
                    32 * 1024 * 1024,
                )?)
            };
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != request.key_id
                || spec.key_id != signature.key_id
                || previous
                    .as_ref()
                    .is_some_and(|registry| registry.key_id != spec.key_id)
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let registry = signature
                .finalize(&request, previous.as_ref(), &key, Utc::now())
                .map_err(|_| "CLOSURE_EXTERNAL_SIGNING_INVALID")?;
            let registry_digest = registry
                .digest()
                .map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?;
            write_new(Path::new(&output), &registry)?;
            println!(
                "{}",
                json!({"registry_id":registry.registry_id,"sequence":registry.sequence,"registry_digest":registry_digest,"issued":true,"production_signing":true,"verified":true})
            );
        }
        Some("verify-domain-assurance") => {
            let attestation_path = args.next().ok_or("CLOSURE_ATTESTATION_REQUIRED")?;
            let keyring_path = args.next().ok_or("CLOSURE_KEYRING_REQUIRED")?;
            let scope_path = args.next().ok_or("CLOSURE_SCOPE_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let attestation: DomainAssuranceAttestation =
                read_json(Path::new(&attestation_path), MAXIMUM_INPUT_BYTES)?;
            let keyring: TrustedReviewerKeyring =
                read_json(Path::new(&keyring_path), 4 * 1024 * 1024)?;
            let scope: ClosureScope = read_json(Path::new(&scope_path), MAXIMUM_INPUT_BYTES)?;
            let evidence = attestation
                .verified_gate_evidence(&scope, &keyring, Utc::now())
                .map_err(|_| "CLOSURE_DOMAIN_ASSURANCE_INVALID")?;
            write_new(Path::new(&output), &evidence)?;
            println!(
                "{}",
                json!({"attestation_id":attestation.attestation_id,"gate_id":evidence.gate_id,"verified":true,"attestation_digest":attestation.digest().map_err(|_| "CLOSURE_DOMAIN_ASSURANCE_INVALID")?,"reviewer_keyring_digest":keyring.digest().map_err(|_| "CLOSURE_DOMAIN_ASSURANCE_INVALID")?})
            );
        }
        Some("verify-external-assurance") => {
            let attestation_path = args.next().ok_or("CLOSURE_ATTESTATION_REQUIRED")?;
            let keyring_path = args.next().ok_or("CLOSURE_KEYRING_REQUIRED")?;
            let scope_path = args.next().ok_or("CLOSURE_SCOPE_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let attestation: ExternalGateAssuranceAttestation =
                read_json(Path::new(&attestation_path), MAXIMUM_INPUT_BYTES)?;
            let keyring: TrustedReviewerKeyring =
                read_json(Path::new(&keyring_path), 4 * 1024 * 1024)?;
            let scope: ClosureScope = read_json(Path::new(&scope_path), MAXIMUM_INPUT_BYTES)?;
            let evidence = attestation
                .verified_gate_evidence(&scope, &keyring, Utc::now())
                .map_err(|_| "CLOSURE_EXTERNAL_ASSURANCE_INVALID")?;
            write_new(Path::new(&output), &evidence)?;
            println!(
                "{}",
                json!({"attestation_id":attestation.attestation_id,"gate_id":attestation.gate_id,"verified":true,"attestation_digest":attestation.digest().map_err(|_| "CLOSURE_EXTERNAL_ASSURANCE_INVALID")?,"reviewer_keyring_digest":keyring.digest().map_err(|_| "CLOSURE_EXTERNAL_ASSURANCE_INVALID")?})
            );
        }
        _ => {
            return Err(
                "USAGE: production-closure prepare-activation-directory|check-activation-watch|evaluate|prepare-external-signing|finalize-external-signing|issue-local|verify|verify-activation|watch-activation|verify-revocation-projection|prepare-revocation-signing|finalize-revocation-signing|verify-revocation-registry|verify-revocation-successor|verify-domain-assurance|verify-external-assurance ...",
            );
        }
    }
    Ok(())
}

fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_production_closure::CertificateRevocationEntry;
    use ed25519_dalek::Signer;

    fn sign_registry(
        registry: &mut SignedCertificateRevocationRegistry,
        key: &SigningKey,
    ) {
        registry.signature = URL_SAFE_NO_PAD.encode(
            key.sign(
                &registry
                    .signing_bytes()
                    .unwrap_or_else(|error| panic!("registry payload: {error}")),
            )
            .to_bytes(),
        );
    }

    fn sign_head(head: &mut RevocationProjectionHead, key: &SigningKey) {
        head.signature.clear();
        let payload = serde_jcs::to_vec(head)
            .unwrap_or_else(|error| panic!("projection payload: {error}"));
        head.signature = URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes());
    }

    #[test]
    fn signed_projection_allows_restart_after_multiple_successors_but_not_omission() {
        let now = Utc::now();
        let registry_key = SigningKey::from_bytes(&[31_u8; 32]);
        let projection_key = SigningKey::from_bytes(&[32_u8; 32]);
        let first_entry = CertificateRevocationEntry {
            certificate_id: format!("pc-{}", "1".repeat(24)),
            release_id: format!("git:sha1:{}", "2".repeat(40)),
            reason_code: "KEY_COMPROMISE".into(),
            evidence_digest: "3".repeat(64),
            revoked_at: now - ChronoDuration::minutes(2),
        };
        let mut baseline = SignedCertificateRevocationRegistry {
            schema_version: "agenttrust.production-closure-revocation-registry.v1".into(),
            registry_id: "production-registry".into(),
            sequence: 1,
            previous_registry_digest: None,
            published_at: now - ChronoDuration::minutes(1),
            expires_at: now + ChronoDuration::days(1),
            key_id: "revocation-key-1".into(),
            entries: vec![first_entry.clone()],
            signature: String::new(),
        };
        sign_registry(&mut baseline, &registry_key);
        baseline
            .verify(&registry_key.verifying_key(), now)
            .unwrap_or_else(|error| panic!("baseline verification: {error}"));
        let baseline_digest = baseline
            .digest()
            .unwrap_or_else(|error| panic!("baseline digest: {error}"));

        let mut current = SignedCertificateRevocationRegistry {
            schema_version: baseline.schema_version.clone(),
            registry_id: baseline.registry_id.clone(),
            sequence: 3,
            previous_registry_digest: Some("4".repeat(64)),
            published_at: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::days(1),
            key_id: baseline.key_id.clone(),
            entries: vec![
                first_entry,
                CertificateRevocationEntry {
                    certificate_id: format!("pc-{}", "5".repeat(24)),
                    release_id: format!("git:sha1:{}", "6".repeat(40)),
                    reason_code: "POLICY_VIOLATION".into(),
                    evidence_digest: "7".repeat(64),
                    revoked_at: now - ChronoDuration::seconds(2),
                },
            ],
            signature: String::new(),
        };
        sign_registry(&mut current, &registry_key);
        current
            .verify(&registry_key.verifying_key(), now)
            .unwrap_or_else(|error| panic!("current verification: {error}"));
        let current_digest = current
            .digest()
            .unwrap_or_else(|error| panic!("current digest: {error}"));
        let projection_key_spec = PublicKeySpec {
            schema_version: "agenttrust.ed25519-public-key.v1".into(),
            key_id: "projection-key-1".into(),
            public_key: URL_SAFE_NO_PAD.encode(projection_key.verifying_key().to_bytes()),
        };
        let mut head = RevocationProjectionHead {
            schema_version: "agenttrust.production-revocation-projection-head.v1".into(),
            projection_id: "projection-restart-sequence-3".into(),
            environment_reference: "environment://production/test-region".into(),
            base_checkpoint_digest: "8".repeat(64),
            registry_id: current.registry_id.clone(),
            registry_key_id: current.key_id.clone(),
            registry_sequence: current.sequence,
            registry_digest: current_digest.clone(),
            projected_at: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::minutes(2),
            projection_key_id: projection_key_spec.key_id.clone(),
            signature: String::new(),
        };
        sign_head(&mut head, &projection_key);

        assert!(verify_projected_registry_lineage(
            &baseline,
            &baseline_digest,
            &current,
            &current_digest,
            &head,
            &projection_key_spec,
            now,
        )
        .is_ok());

        let mut omission = current;
        omission.entries.remove(0);
        assert_eq!(
            verify_projected_registry_lineage(
                &baseline,
                &baseline_digest,
                &omission,
                &current_digest,
                &head,
                &projection_key_spec,
                now,
            ),
            Err("CLOSURE_WATCH_REVOCATION_ROLLBACK")
        );
    }
}
