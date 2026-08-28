use agent_trust_action_ir::{ParseLimits, parse_strict_json};
use agent_trust_sandbox_runtime::gvisor::{
    FileReplayLedger, GVISOR_EXECUTION_RECEIPT_SCHEMA_VERSION, GvisorExecutionReceipt,
    GvisorExecutionStatus, GvisorReceiptSigningKey, GvisorRuntimeAttestation, GvisorWorkerKeyring,
    ProductionGvisorJob,
};
use agent_trust_sandbox_runtime::{OciGvisorCommandBuilder, SandboxError};
use chrono::Utc;
use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

const MAXIMUM_JOB_BYTES: u64 = 32 * 1024 * 1024;
const MAXIMUM_TRUST_BYTES: u64 = 1024 * 1024;

struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), SandboxError> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() != Some("execute") {
        return Err(SandboxError::JobInvalid);
    }
    let job_path = absolute_argument(arguments.next())?;
    let keyring_path = absolute_argument(arguments.next())?;
    let attestation_path = absolute_argument(arguments.next())?;
    let receipt_signing_key_path = absolute_argument(arguments.next())?;
    let runsc_path = absolute_argument(arguments.next())?;
    let workspace_root = absolute_argument(arguments.next())?;
    let replay_root = absolute_argument(arguments.next())?;
    let output_directory = absolute_argument(arguments.next())?;
    if arguments.next().is_some() {
        return Err(SandboxError::JobInvalid);
    }
    let job: ProductionGvisorJob = read_json(&job_path, MAXIMUM_JOB_BYTES)?;
    let keyring: GvisorWorkerKeyring = read_json(&keyring_path, MAXIMUM_TRUST_BYTES)?;
    let attestation: GvisorRuntimeAttestation = read_json(&attestation_path, MAXIMUM_TRUST_BYTES)?;
    let receipt_signing_key: GvisorReceiptSigningKey =
        read_secret_json(&receipt_signing_key_path, MAXIMUM_TRUST_BYTES)?;
    verify_dispatch_paths(&job, &job_path, &workspace_root, &output_directory)?;
    let hostname = read_hostname()?;
    let measured_runsc_digest = verify_runsc_binary(&runsc_path)?;
    job.verify(
        &keyring,
        &attestation,
        &hostname,
        &measured_runsc_digest,
        Utc::now(),
    )?;
    let bundle = job.verify_bundle(&workspace_root)?;
    let data_root = workspace_root
        .canonicalize()
        .map_err(|_| SandboxError::FilesystemDenied)?
        .parent()
        .ok_or(SandboxError::FilesystemDenied)?
        .to_path_buf();
    let state_parent = secure_private_directory(&data_root.join("state"))?;
    let state_root = state_parent.join(&job.authorization.authorization_id);
    let builder = OciGvisorCommandBuilder {
        runsc_path: runsc_path.clone(),
        expected_runsc_digest: attestation.runsc_binary_digest.clone(),
    };
    let template = builder.build(
        &job.oci_bundle.container_id,
        &bundle,
        &state_root,
        &job.executor.image_digest,
        &job.oci_bundle.config_digest,
    )?;
    let replay = FileReplayLedger::new(replay_root)?;
    replay.consume(&job, Utc::now())?;
    if fs::create_dir(&state_root).is_err() {
        let _ = remove_bundle(&workspace_root, &bundle);
        return Err(SandboxError::PrepareFailed);
    }
    if create_private_directory(&output_directory).is_err() {
        let _ = fs::remove_dir(&state_root);
        let _ = remove_bundle(&workspace_root, &bundle);
        return Err(SandboxError::PrepareFailed);
    }

    let started_at = Utc::now();
    let mut command = Command::new(&template.program);
    command
        .args(&template.fixed_args)
        .env_clear()
        .current_dir(&bundle)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let _ =
                ensure_runsc_deleted(&runsc_path, &state_root, &job.oci_bundle.container_id).await;
            let _ = remove_bundle(&workspace_root, &bundle);
            return Err(SandboxError::StartFailed);
        }
    };
    let process_group = match child.id() {
        Some(process_group) => process_group,
        None => {
            let _ = child.wait().await;
            let _ =
                ensure_runsc_deleted(&runsc_path, &state_root, &job.oci_bundle.container_id).await;
            let _ = remove_bundle(&workspace_root, &bundle);
            return Err(SandboxError::StartFailed);
        }
    };
    let stdout_reader = match child.stdout.take() {
        Some(reader) => reader,
        None => {
            let _ = killpg(Pid::from_raw(process_group as i32), Signal::SIGKILL);
            let _ = child.wait().await;
            let _ =
                ensure_runsc_deleted(&runsc_path, &state_root, &job.oci_bundle.container_id).await;
            let _ = remove_bundle(&workspace_root, &bundle);
            return Err(SandboxError::StartFailed);
        }
    };
    let stderr_reader = match child.stderr.take() {
        Some(reader) => reader,
        None => {
            let _ = killpg(Pid::from_raw(process_group as i32), Signal::SIGKILL);
            let _ = child.wait().await;
            let _ =
                ensure_runsc_deleted(&runsc_path, &state_root, &job.oci_bundle.container_id).await;
            let _ = remove_bundle(&workspace_root, &bundle);
            return Err(SandboxError::StartFailed);
        }
    };
    let stdout_limit = job.budget.max_stdout_bytes;
    let stderr_limit = job.budget.max_stderr_bytes;
    let stdout = tokio::spawn(async move { read_bounded(stdout_reader, stdout_limit).await });
    let stderr = tokio::spawn(async move { read_bounded(stderr_reader, stderr_limit).await });
    let waited =
        tokio::time::timeout(Duration::from_millis(job.budget.timeout_ms), child.wait()).await;
    let (status, exit_code) = match waited {
        Ok(Ok(result)) if result.success() => (GvisorExecutionStatus::Succeeded, result.code()),
        Ok(Ok(result)) => (GvisorExecutionStatus::Failed, result.code()),
        Ok(Err(_)) => {
            let _ = killpg(Pid::from_raw(process_group as i32), Signal::SIGKILL);
            let _ = child.wait().await;
            (GvisorExecutionStatus::Killed, None)
        }
        Err(_) => {
            let _ = killpg(Pid::from_raw(process_group as i32), Signal::SIGKILL);
            let _ = child.wait().await;
            (GvisorExecutionStatus::TimedOut, None)
        }
    };
    let stdout = stdout.await;
    let stderr = stderr.await;
    let runsc_deleted =
        ensure_runsc_deleted(&runsc_path, &state_root, &job.oci_bundle.container_id).await;
    let bundle_removed = remove_bundle(&workspace_root, &bundle);
    let stdout = stdout
        .map_err(|_| SandboxError::CollectFailed)?
        .map_err(|_| SandboxError::CollectFailed)?;
    let stderr = stderr
        .map_err(|_| SandboxError::CollectFailed)?
        .map_err(|_| SandboxError::CollectFailed)?;
    write_new_bytes(&output_directory.join("stdout.bin"), &stdout.bytes)?;
    write_new_bytes(&output_directory.join("stderr.bin"), &stderr.bytes)?;
    if !runsc_deleted || !bundle_removed {
        return Err(SandboxError::CleanupIncomplete);
    }
    let finished_at = Utc::now();
    let mut receipt = GvisorExecutionReceipt {
        schema_version: GVISOR_EXECUTION_RECEIPT_SCHEMA_VERSION.into(),
        job_id: job.job_id,
        job_digest: job.job_digest,
        authorization_id: job.authorization.authorization_id,
        action_hash: job.authorization.action_hash.0,
        container_id: job.oci_bundle.container_id,
        image_digest: job.executor.image_digest,
        oci_config_digest: job.oci_bundle.config_digest,
        runsc_binary_digest: attestation.runsc_binary_digest,
        runtime_attestation_digest: attestation.attestation_digest,
        worker_hostname: hostname,
        status,
        exit_code,
        stdout_sha256: hex_digest(&stdout.bytes),
        stderr_sha256: hex_digest(&stderr.bytes),
        stdout_bytes: stdout.bytes.len() as u64,
        stderr_bytes: stderr.bytes.len() as u64,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        replay_consumed: true,
        runsc_deleted,
        bundle_removed,
        started_at,
        finished_at,
        issuer: String::new(),
        key_id: String::new(),
        key_usage: String::new(),
        receipt_digest: String::new(),
        signature: String::new(),
    };
    receipt.sign(&receipt_signing_key, &keyring, Utc::now())?;
    receipt.verify(&keyring, Utc::now())?;
    write_new_json(&output_directory.join("receipt.json"), &receipt)?;
    println!("{}", receipt.receipt_digest);
    Ok(())
}

async fn ensure_runsc_deleted(runsc: &Path, root: &Path, container_id: &str) -> bool {
    let root_flag = format!("--root={}", root.display());
    let _ = runsc_command(runsc, [&root_flag, "delete", "--force", container_id]).await;
    let state_absent = runsc_command(runsc, [&root_flag, "state", container_id])
        .await
        .is_err();
    let state_root_empty = fs::read_dir(root)
        .ok()
        .is_some_and(|mut entries| entries.next().is_none());
    state_absent && state_root_empty && fs::remove_dir(root).is_ok() && !root.exists()
}

async fn runsc_command<const N: usize>(runsc: &Path, args: [&str; N]) -> Result<(), ()> {
    Command::new(runsc)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|_| ())?
        .success()
        .then_some(())
        .ok_or(())
}

async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: u64,
) -> std::io::Result<BoundedOutput> {
    let mut stored = Vec::with_capacity(limit.min(65_536) as usize);
    let mut truncated = false;
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(stored.len() as u64) as usize;
        let take = remaining.min(read);
        stored.extend_from_slice(&buffer[..take]);
        if take < read {
            truncated = true;
        }
    }
    Ok(BoundedOutput {
        bytes: stored,
        truncated,
    })
}

fn read_json<T: DeserializeOwned>(path: &Path, maximum: u64) -> Result<T, SandboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SandboxError::JobInvalid)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(SandboxError::JobInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(SandboxError::JobInvalid);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| SandboxError::JobInvalid)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| SandboxError::JobInvalid)?;
    if bytes.len() as u64 > maximum {
        return Err(SandboxError::JobInvalid);
    }
    let value = parse_strict_json(
        &bytes,
        &ParseLimits {
            max_body_bytes: maximum as usize,
            max_depth: 64,
            max_array_items: 16_384,
            max_string_bytes: maximum.min(32 * 1024 * 1024) as usize,
            max_object_keys: 16_384,
            max_number_chars: 128,
        },
    )
    .map_err(|_| SandboxError::JobInvalid)?;
    serde_json::from_value(value).map_err(|_| SandboxError::JobInvalid)
}

fn read_secret_json<T: DeserializeOwned>(path: &Path, maximum: u64) -> Result<T, SandboxError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SandboxError::RuntimeAttestationInvalid)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SandboxError::RuntimeAttestationInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SandboxError::RuntimeAttestationInvalid);
        }
    }
    read_json(path, maximum).map_err(|_| SandboxError::RuntimeAttestationInvalid)
}

fn verify_runsc_binary(path: &Path) -> Result<String, SandboxError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SandboxError::ProductionIsolationUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        return Err(SandboxError::ProductionIsolationUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(SandboxError::ProductionIsolationUnavailable);
        }
    }
    let bytes = fs::read(path).map_err(|_| SandboxError::ProductionIsolationUnavailable)?;
    Ok(format!("sha256:{}", hex_digest(bytes)))
}

fn verify_dispatch_paths(
    job: &ProductionGvisorJob,
    job_path: &Path,
    workspace_root: &Path,
    output_directory: &Path,
) -> Result<(), SandboxError> {
    let expected_name = format!("{}.json", job.authorization.authorization_id);
    if job_path.file_name().and_then(|value| value.to_str()) != Some(&expected_name) {
        return Err(SandboxError::JobInvalid);
    }
    let workspace_root = workspace_root
        .canonicalize()
        .map_err(|_| SandboxError::FilesystemDenied)?;
    let data_root = workspace_root
        .parent()
        .ok_or(SandboxError::FilesystemDenied)?;
    let results_root = secure_private_directory(&data_root.join("results"))?;
    if output_directory.parent() != Some(results_root.as_path())
        || output_directory
            .file_name()
            .and_then(|value| value.to_str())
            != Some(job.authorization.authorization_id.as_str())
    {
        return Err(SandboxError::FilesystemDenied);
    }
    Ok(())
}

fn secure_private_directory(path: &Path) -> Result<PathBuf, SandboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SandboxError::FilesystemDenied)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SandboxError::FilesystemDenied);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SandboxError::FilesystemDenied);
        }
    }
    path.canonicalize()
        .map_err(|_| SandboxError::FilesystemDenied)
}

fn absolute_argument(value: Option<String>) -> Result<PathBuf, SandboxError> {
    let path = PathBuf::from(value.ok_or(SandboxError::JobInvalid)?);
    if !path.is_absolute() {
        return Err(SandboxError::JobInvalid);
    }
    Ok(path)
}

fn read_hostname() -> Result<String, SandboxError> {
    let hostname =
        fs::read_to_string("/etc/hostname").map_err(|_| SandboxError::RuntimeAttestationInvalid)?;
    let hostname = hostname.trim();
    if hostname.is_empty() || hostname.len() > 253 || hostname.contains(char::is_whitespace) {
        return Err(SandboxError::RuntimeAttestationInvalid);
    }
    Ok(hostname.to_owned())
}

fn create_private_directory(path: &Path) -> Result<(), SandboxError> {
    fs::create_dir(path).map_err(|_| SandboxError::PrepareFailed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| SandboxError::PrepareFailed)?;
    }
    Ok(())
}

fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), SandboxError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| SandboxError::CollectFailed)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| SandboxError::CollectFailed)
}

fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<(), SandboxError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| SandboxError::CollectFailed)?;
    write_new_bytes(path, &[bytes.as_slice(), b"\n"].concat())
}

fn remove_bundle(root: &Path, bundle: &Path) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    let Ok(bundle) = bundle.canonicalize() else {
        return !bundle.exists();
    };
    if bundle == root || !bundle.starts_with(root) {
        return false;
    }
    fs::remove_dir_all(&bundle).is_ok() && !bundle.exists()
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
