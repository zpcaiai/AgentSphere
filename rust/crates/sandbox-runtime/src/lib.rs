//! Authorization-bound sandbox runtime, bounded process execution, and supervisor controls.

pub mod gvisor;

use agent_trust_contracts::{ActionHash, ExecutionAuthorization, ExecutionId, ToolRef};
use agent_trust_policy_pep::{PolicyError, RuntimeControlPort};
use agent_trust_registry::{ResolvedToolSnapshot, ToolRegistry};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::Mutex,
    task::JoinHandle,
};
use uuid::Uuid;

pub const SANDBOX_SCHEMA_VERSION: &str = "agenttrust.sandbox.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SandboxState {
    Created,
    Preparing,
    Ready,
    Running,
    PauseRequested,
    Paused,
    ResumeRequested,
    CancelRequested,
    Cancelling,
    KillRequested,
    Killed,
    Succeeded,
    Failed,
    TimedOut,
    Collecting,
    Destroying,
    Destroyed,
    Orphaned,
    ManualRecoveryRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub pids: u32,
    pub disk_bytes: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub timeout_ms: u64,
}

impl ResourceBudget {
    fn validate(&self, authorization: &ExecutionAuthorization) -> Result<(), SandboxError> {
        if self.cpu_millis == 0
            || self.memory_bytes == 0
            || self.pids == 0
            || self.disk_bytes == 0
            || self.timeout_ms == 0
            || self.timeout_ms > authorization.max_execution_ms
            || self.max_stdout_bytes + self.max_stderr_bytes > authorization.max_result_bytes
        {
            return Err(SandboxError::ResourceLimitInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutorTemplate {
    pub executor_id: String,
    /// Digest of the immutable workload implementation (OCI image or WASM component).
    pub implementation_digest: String,
    /// Digest of the isolation runtime binary. Production OCI execution requires this
    /// to be the independently pinned `runsc` digest; it must never be substituted for
    /// the workload implementation digest carried by ExecutionAuthorization.
    pub runtime_digest: Option<String>,
    /// Digest of the exact OCI `config.json`. Required for production gVisor and
    /// absent for non-OCI development and WASM templates.
    pub oci_config_digest: Option<String>,
    pub program: PathBuf,
    pub fixed_args: Vec<String>,
    pub allowed_environment: BTreeMap<String, String>,
    pub shell: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SandboxProfile {
    pub profile_id: String,
    pub production_isolation_required: bool,
    pub non_root: bool,
    pub read_only_rootfs: bool,
    pub network_none: bool,
    pub no_new_privileges: bool,
    pub drop_all_capabilities: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkProfile {
    pub profile_id: String,
    pub default_deny: bool,
    pub allowed_endpoints: BTreeSet<String>,
    pub max_connections: u32,
    pub max_upload_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilesystemProfile {
    pub profile_id: String,
    pub read_only_inputs: bool,
    pub writable_paths: BTreeSet<PathBuf>,
    pub max_files: u64,
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotRef {
    pub snapshot_id: String,
    pub digest: String,
    pub read_only: bool,
}

#[derive(Debug, Clone)]
pub struct PrepareRequest {
    pub authorization: ExecutionAuthorization,
    pub tool: ResolvedToolSnapshot,
    pub template: ExecutorTemplate,
    pub profile: SandboxProfile,
    pub network_profile: NetworkProfile,
    pub filesystem_profile: FilesystemProfile,
    pub budget: ResourceBudget,
    pub credential_refs: Vec<String>,
    pub workspace_snapshot: Option<WorkspaceSnapshotRef>,
    pub trace_id: String,
}

#[derive(Debug, Clone)]
pub struct PreparedSandbox {
    sandbox_id: String,
    execution_id: ExecutionId,
    action_hash: ActionHash,
    template: ExecutorTemplate,
    profile: SandboxProfile,
    budget: ResourceBudget,
    credential_refs: Vec<String>,
    workspace: PathBuf,
    prepared_at: DateTime<Utc>,
}

impl PreparedSandbox {
    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }
    pub fn action_hash(&self) -> &ActionHash {
        &self.action_hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionHandle {
    pub sandbox_id: String,
    pub execution_id: ExecutionId,
    pub action_hash: ActionHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSnapshot {
    pub handle: ExecutionHandle,
    pub state: SandboxState,
    pub process_id: Option<u32>,
    pub heartbeat_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlReceipt {
    pub handle: ExecutionHandle,
    pub requested: SandboxState,
    pub applied_at: DateTime<Utc>,
    pub process_group: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupReceipt {
    pub sandbox_id: String,
    pub workspace_removed: bool,
    pub credentials_revoked: bool,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub execution_id: ExecutionId,
    pub status: SandboxState,
    pub exit_code: Option<i32>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub runtime_profile_hash: String,
    pub implementation_digest: String,
    pub network_summary: String,
    pub credential_refs_used: Vec<String>,
    pub cleanup: CleanupReceipt,
}

#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    async fn prepare(&self, request: PrepareRequest) -> Result<PreparedSandbox, SandboxError>;
    async fn start(&self, prepared: PreparedSandbox) -> Result<ExecutionHandle, SandboxError>;
    async fn inspect(&self, handle: &ExecutionHandle) -> Result<ExecutionSnapshot, SandboxError>;
    async fn pause(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError>;
    async fn resume(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError>;
    async fn cancel(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError>;
    async fn kill(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError>;
    async fn collect(&self, handle: ExecutionHandle) -> Result<ExecutionResult, SandboxError>;
    async fn destroy(&self, sandbox_id: &str) -> Result<CleanupReceipt, SandboxError>;
}

#[async_trait]
pub trait CredentialLifecyclePort: Send + Sync {
    async fn revoke_all(&self, credential_refs: &[String]) -> Result<(), SandboxError>;
}

#[derive(Default)]
pub struct InMemoryCredentialLifecycle {
    revoked: RwLock<BTreeSet<String>>,
}

impl InMemoryCredentialLifecycle {
    pub fn was_revoked(&self, credential_ref: &str) -> bool {
        self.revoked.read().contains(credential_ref)
    }
}

#[async_trait]
impl CredentialLifecyclePort for InMemoryCredentialLifecycle {
    async fn revoke_all(&self, credential_refs: &[String]) -> Result<(), SandboxError> {
        self.revoked.write().extend(credential_refs.iter().cloned());
        Ok(())
    }
}

pub struct ExecutionAuthorizationVerifier<R: ToolRegistry> {
    registry: Arc<R>,
    keys: RwLock<BTreeMap<String, (String, VerifyingKey)>>,
    used: RwLock<BTreeSet<String>>,
}

impl<R: ToolRegistry> ExecutionAuthorizationVerifier<R> {
    pub fn new(registry: Arc<R>) -> Self {
        Self {
            registry,
            keys: RwLock::new(BTreeMap::new()),
            used: RwLock::new(BTreeSet::new()),
        }
    }
    pub fn add_issuer_key(&self, key_id: String, issuer: String, key: VerifyingKey) {
        self.keys.write().insert(key_id, (issuer, key));
    }
    pub async fn verify_and_consume(
        &self,
        request: &PrepareRequest,
        now: DateTime<Utc>,
    ) -> Result<(), SandboxError> {
        let authorization = &request.authorization;
        let (issuer, key) = self
            .keys
            .read()
            .get(&authorization.key_id)
            .cloned()
            .ok_or(SandboxError::AuthorizationInvalid)?;
        if issuer != authorization.issuer {
            return Err(SandboxError::AuthorizationInvalid);
        }
        authorization
            .verify(&key, now)
            .map_err(|_| SandboxError::AuthorizationInvalid)?;
        if authorization.action_hash != request.authorization.action_hash
            || authorization.tool_snapshot_hash != request.tool.snapshot_hash
            || authorization.sandbox_profile != request.profile.profile_id
            || authorization.network_profile != request.tool.network_profile_ref
            || authorization.network_profile != request.network_profile.profile_id
            || request.tool.filesystem_profile_ref != request.filesystem_profile.profile_id
            || request.template.executor_id != request.tool.implementation.executor_id
            || request.template.implementation_digest != request.tool.implementation.digest
        {
            return Err(SandboxError::AuthorizationInvalid);
        }
        request.budget.validate(authorization)?;
        if self
            .registry
            .is_revoked(
                &ToolRef {
                    tool_id: request.tool.tool_id.clone(),
                    tool_version: request.tool.tool_version.clone(),
                },
                &request.tool.implementation.digest,
            )
            .await
            .map_err(|_| SandboxError::AuthorizationInvalid)?
        {
            return Err(SandboxError::ImageDigestMismatch);
        }
        if authorization.single_use
            && !self
                .used
                .write()
                .insert(authorization.authorization_id.clone())
        {
            return Err(SandboxError::AuthorizationReplayed);
        }
        Ok(())
    }
}

struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
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

struct RunningEntry {
    child: Child,
    handle: ExecutionHandle,
    state: SandboxState,
    started_at: DateTime<Utc>,
    budget: ResourceBudget,
    profile: SandboxProfile,
    implementation_digest: String,
    credential_refs: Vec<String>,
    workspace: PathBuf,
    stdout: JoinHandle<std::io::Result<BoundedOutput>>,
    stderr: JoinHandle<std::io::Result<BoundedOutput>>,
}

pub struct LocalProcessSandbox<R: ToolRegistry> {
    verifier: Arc<ExecutionAuthorizationVerifier<R>>,
    workspace_root: PathBuf,
    credential_lifecycle: Option<Arc<dyn CredentialLifecyclePort>>,
    running: Mutex<BTreeMap<String, RunningEntry>>,
}

impl<R: ToolRegistry> LocalProcessSandbox<R> {
    pub fn new(
        verifier: Arc<ExecutionAuthorizationVerifier<R>>,
        workspace_root: PathBuf,
    ) -> Result<Self, SandboxError> {
        Self::new_with_credential_lifecycle(verifier, workspace_root, None)
    }

    pub fn new_with_credential_lifecycle(
        verifier: Arc<ExecutionAuthorizationVerifier<R>>,
        workspace_root: PathBuf,
        credential_lifecycle: Option<Arc<dyn CredentialLifecyclePort>>,
    ) -> Result<Self, SandboxError> {
        if !workspace_root.is_absolute() {
            return Err(SandboxError::ProfileDenied);
        }
        std::fs::create_dir_all(&workspace_root).map_err(|_| SandboxError::PrepareFailed)?;
        Ok(Self {
            verifier,
            workspace_root,
            credential_lifecycle,
            running: Mutex::new(BTreeMap::new()),
        })
    }
    fn workspace_for(&self, sandbox_id: &str) -> PathBuf {
        self.workspace_root.join(sandbox_id)
    }

    async fn revoke_credentials(&self, credential_refs: &[String]) -> Result<bool, SandboxError> {
        if credential_refs.is_empty() {
            return Ok(true);
        }
        let lifecycle = self
            .credential_lifecycle
            .as_ref()
            .ok_or(SandboxError::CredentialInjectionFailed)?;
        lifecycle.revoke_all(credential_refs).await?;
        Ok(true)
    }
}

#[async_trait]
impl<R: ToolRegistry + 'static> SandboxRuntime for LocalProcessSandbox<R> {
    async fn prepare(&self, request: PrepareRequest) -> Result<PreparedSandbox, SandboxError> {
        self.verifier
            .verify_and_consume(&request, Utc::now())
            .await?;
        if request.template.shell || request.template.program.as_os_str().is_empty() {
            return Err(SandboxError::ProfileDenied);
        }
        validate_network_profile(&request.profile, &request.network_profile)?;
        validate_filesystem_profile(&request.filesystem_profile)?;
        if let Some(snapshot) = &request.workspace_snapshot
            && (!snapshot.read_only || !is_sha256_digest(&snapshot.digest))
        {
            return Err(SandboxError::FilesystemDenied);
        }
        if !request.credential_refs.is_empty() && self.credential_lifecycle.is_none() {
            return Err(SandboxError::CredentialInjectionFailed);
        }
        if request.profile.production_isolation_required {
            verify_production_executor(&request.template)?;
        }
        if !request.profile.non_root
            || !request.profile.read_only_rootfs
            || !request.profile.network_none
            || !request.profile.no_new_privileges
            || !request.profile.drop_all_capabilities
        {
            return Err(SandboxError::ProfileDenied);
        }
        for key in request.template.allowed_environment.keys() {
            if matches!(
                key.as_str(),
                "LD_PRELOAD" | "LD_LIBRARY_PATH" | "DYLD_INSERT_LIBRARIES"
            ) {
                return Err(SandboxError::ProfileDenied);
            }
        }
        let sandbox_id = Uuid::new_v4().to_string();
        let workspace = self.workspace_for(&sandbox_id);
        std::fs::create_dir(&workspace).map_err(|_| SandboxError::PrepareFailed)?;
        Ok(PreparedSandbox {
            sandbox_id,
            execution_id: ExecutionId::new(),
            action_hash: request.authorization.action_hash,
            template: request.template,
            profile: request.profile,
            budget: request.budget,
            credential_refs: request.credential_refs,
            workspace,
            prepared_at: Utc::now(),
        })
    }

    async fn start(&self, prepared: PreparedSandbox) -> Result<ExecutionHandle, SandboxError> {
        if prepared.prepared_at + chrono::Duration::minutes(1) < Utc::now() {
            return Err(SandboxError::StartFailed);
        }
        let mut command = Command::new(&prepared.template.program);
        command
            .args(&prepared.template.fixed_args)
            .env_clear()
            .envs(&prepared.template.allowed_environment)
            .current_dir(&prepared.workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            command.process_group(0);
        }
        let mut child = command.spawn().map_err(|_| SandboxError::StartFailed)?;
        let stdout_reader = child.stdout.take().ok_or(SandboxError::StartFailed)?;
        let stderr_reader = child.stderr.take().ok_or(SandboxError::StartFailed)?;
        let stdout_limit = prepared.budget.max_stdout_bytes;
        let stderr_limit = prepared.budget.max_stderr_bytes;
        let stdout = tokio::spawn(async move { read_bounded(stdout_reader, stdout_limit).await });
        let stderr = tokio::spawn(async move { read_bounded(stderr_reader, stderr_limit).await });
        let handle = ExecutionHandle {
            sandbox_id: prepared.sandbox_id.clone(),
            execution_id: prepared.execution_id,
            action_hash: prepared.action_hash,
        };
        self.running.lock().await.insert(
            prepared.sandbox_id,
            RunningEntry {
                child,
                handle: handle.clone(),
                state: SandboxState::Running,
                started_at: Utc::now(),
                budget: prepared.budget,
                profile: prepared.profile,
                implementation_digest: prepared.template.implementation_digest,
                credential_refs: prepared.credential_refs,
                workspace: prepared.workspace,
                stdout,
                stderr,
            },
        );
        Ok(handle)
    }

    async fn inspect(&self, handle: &ExecutionHandle) -> Result<ExecutionSnapshot, SandboxError> {
        let mut running = self.running.lock().await;
        let entry = running
            .get_mut(&handle.sandbox_id)
            .ok_or(SandboxError::Orphaned)?;
        if let Some(status) = entry.child.try_wait().map_err(|_| SandboxError::Orphaned)? {
            entry.state = if status.success() {
                SandboxState::Succeeded
            } else {
                SandboxState::Failed
            };
        }
        Ok(ExecutionSnapshot {
            handle: entry.handle.clone(),
            state: entry.state,
            process_id: entry.child.id(),
            heartbeat_at: Utc::now(),
        })
    }

    async fn pause(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError> {
        let refs = self
            .running
            .lock()
            .await
            .get(&handle.sandbox_id)
            .map(|entry| entry.credential_refs.clone())
            .ok_or(SandboxError::Orphaned)?;
        self.revoke_credentials(&refs).await?;
        signal_entry(&self.running, handle, Signal::SIGSTOP, SandboxState::Paused).await
    }
    async fn resume(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError> {
        signal_entry(
            &self.running,
            handle,
            Signal::SIGCONT,
            SandboxState::Running,
        )
        .await
    }
    async fn cancel(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError> {
        let refs = self
            .running
            .lock()
            .await
            .get(&handle.sandbox_id)
            .map(|entry| entry.credential_refs.clone())
            .ok_or(SandboxError::Orphaned)?;
        self.revoke_credentials(&refs).await?;
        signal_entry(
            &self.running,
            handle,
            Signal::SIGTERM,
            SandboxState::Cancelling,
        )
        .await
    }
    async fn kill(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError> {
        let refs = self
            .running
            .lock()
            .await
            .get(&handle.sandbox_id)
            .map(|entry| entry.credential_refs.clone())
            .ok_or(SandboxError::Orphaned)?;
        self.revoke_credentials(&refs).await?;
        signal_entry(&self.running, handle, Signal::SIGKILL, SandboxState::Killed).await
    }

    async fn collect(&self, handle: ExecutionHandle) -> Result<ExecutionResult, SandboxError> {
        let mut entry = self
            .running
            .lock()
            .await
            .remove(&handle.sandbox_id)
            .ok_or(SandboxError::Orphaned)?;
        let requested_state = entry.state;
        entry.state = SandboxState::Collecting;
        let timeout = Duration::from_millis(entry.budget.timeout_ms);
        let wait_result = tokio::time::timeout(timeout, entry.child.wait()).await;
        let (status, exit_code) = match wait_result {
            Ok(Ok(status)) => (
                if status.success() {
                    SandboxState::Succeeded
                } else if requested_state == SandboxState::Killed {
                    SandboxState::Killed
                } else {
                    SandboxState::Failed
                },
                status.code(),
            ),
            Ok(Err(_)) => return Err(SandboxError::CollectFailed),
            Err(_) => {
                if let Some(pid) = entry.child.id() {
                    let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
                }
                let _ = entry.child.wait().await;
                (SandboxState::TimedOut, None)
            }
        };
        let stdout = entry
            .stdout
            .await
            .map_err(|_| SandboxError::CollectFailed)?
            .map_err(|_| SandboxError::CollectFailed)?;
        let stderr = entry
            .stderr
            .await
            .map_err(|_| SandboxError::CollectFailed)?
            .map_err(|_| SandboxError::CollectFailed)?;
        let credentials_revoked = self.revoke_credentials(&entry.credential_refs).await?;
        let cleanup = cleanup_workspace(
            &self.workspace_root,
            &entry.workspace,
            &handle.sandbox_id,
            credentials_revoked,
        )?;
        let profile_hash = hex_string(Sha256::digest(
            serde_json::to_vec(&entry.profile).map_err(|_| SandboxError::CollectFailed)?,
        ));
        Ok(ExecutionResult {
            execution_id: handle.execution_id,
            status,
            exit_code,
            started_at: entry.started_at,
            finished_at: Utc::now(),
            stdout: stdout.bytes,
            stderr: stderr.bytes,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
            runtime_profile_hash: profile_hash,
            implementation_digest: entry.implementation_digest,
            network_summary: "network:none".into(),
            credential_refs_used: entry.credential_refs,
            cleanup,
        })
    }

    async fn destroy(&self, sandbox_id: &str) -> Result<CleanupReceipt, SandboxError> {
        if let Some(entry) = self.running.lock().await.remove(sandbox_id) {
            if let Some(pid) = entry.child.id() {
                let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
            }
            let credentials_revoked = self.revoke_credentials(&entry.credential_refs).await?;
            cleanup_workspace(
                &self.workspace_root,
                &entry.workspace,
                sandbox_id,
                credentials_revoked,
            )
        } else {
            cleanup_workspace(
                &self.workspace_root,
                &self.workspace_for(sandbox_id),
                sandbox_id,
                true,
            )
        }
    }
}

async fn signal_entry(
    entries: &Mutex<BTreeMap<String, RunningEntry>>,
    handle: &ExecutionHandle,
    signal: Signal,
    state: SandboxState,
) -> Result<ControlReceipt, SandboxError> {
    let mut entries = entries.lock().await;
    let entry = entries
        .get_mut(&handle.sandbox_id)
        .ok_or(SandboxError::Orphaned)?;
    let pid = entry.child.id().ok_or(SandboxError::KillFailed)?;
    killpg(Pid::from_raw(pid as i32), signal).map_err(|_| SandboxError::KillFailed)?;
    entry.state = state;
    Ok(ControlReceipt {
        handle: handle.clone(),
        requested: state,
        applied_at: Utc::now(),
        process_group: Some(pid),
    })
}

fn cleanup_workspace(
    root: &Path,
    workspace: &Path,
    sandbox_id: &str,
    credentials_revoked: bool,
) -> Result<CleanupReceipt, SandboxError> {
    if !workspace.starts_with(root)
        || workspace.file_name().and_then(|name| name.to_str()) != Some(sandbox_id)
    {
        return Err(SandboxError::CleanupIncomplete);
    }
    let removed = if workspace.exists() {
        std::fs::remove_dir_all(workspace).is_ok()
    } else {
        true
    };
    if !removed {
        return Err(SandboxError::CleanupIncomplete);
    }
    Ok(CleanupReceipt {
        sandbox_id: sandbox_id.into(),
        workspace_removed: true,
        credentials_revoked,
        completed_at: Utc::now(),
    })
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_network_profile(
    sandbox: &SandboxProfile,
    profile: &NetworkProfile,
) -> Result<(), SandboxError> {
    if !profile.default_deny {
        return Err(SandboxError::NetworkDenied);
    }
    if sandbox.network_none {
        if !profile.allowed_endpoints.is_empty()
            || profile.max_connections != 0
            || profile.max_upload_bytes != 0
        {
            return Err(SandboxError::NetworkDenied);
        }
        return Ok(());
    }
    if profile.max_connections == 0 || profile.max_upload_bytes == 0 {
        return Err(SandboxError::NetworkDenied);
    }
    for endpoint in &profile.allowed_endpoints {
        let url = url::Url::parse(endpoint).map_err(|_| SandboxError::NetworkDenied)?;
        let host = url.host_str().ok_or(SandboxError::NetworkDenied)?;
        if url.scheme() != "https"
            || host.eq_ignore_ascii_case("localhost")
            || host == "169.254.169.254"
            || host == "metadata.google.internal"
            || host.parse::<std::net::IpAddr>().is_ok_and(|address| {
                address.is_loopback() || address.is_unspecified() || is_private_ip(address)
            })
        {
            return Err(SandboxError::NetworkDenied);
        }
    }
    Ok(())
}

fn is_private_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        std::net::IpAddr::V6(address) => address.is_unique_local(),
    }
}

fn validate_filesystem_profile(profile: &FilesystemProfile) -> Result<(), SandboxError> {
    if !profile.read_only_inputs || profile.max_files == 0 || profile.max_file_bytes == 0 {
        return Err(SandboxError::FilesystemDenied);
    }
    for path in &profile.writable_paths {
        if path.is_absolute()
            || path.as_os_str().is_empty()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(SandboxError::FilesystemDenied);
        }
    }
    Ok(())
}

fn hex_string(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub struct RuntimeSupervisor<R: SandboxRuntime> {
    runtime: Arc<R>,
    actions: RwLock<BTreeMap<ActionHash, ExecutionHandle>>,
}

impl<R: SandboxRuntime> RuntimeSupervisor<R> {
    pub fn new(runtime: Arc<R>) -> Self {
        Self {
            runtime,
            actions: RwLock::new(BTreeMap::new()),
        }
    }
    pub fn register(&self, handle: ExecutionHandle) {
        self.actions
            .write()
            .insert(handle.action_hash.clone(), handle);
    }
}

#[async_trait]
impl<R: SandboxRuntime + 'static> RuntimeControlPort for RuntimeSupervisor<R> {
    async fn pause(&self, action_hash: &ActionHash) -> Result<(), PolicyError> {
        let handle = self
            .actions
            .read()
            .get(action_hash)
            .cloned()
            .ok_or(PolicyError::ObligationFailed)?;
        self.runtime
            .pause(&handle)
            .await
            .map(|_| ())
            .map_err(|_| PolicyError::ObligationFailed)
    }
    async fn kill(&self, action_hash: &ActionHash) -> Result<(), PolicyError> {
        let handle = self
            .actions
            .read()
            .get(action_hash)
            .cloned()
            .ok_or(PolicyError::ObligationFailed)?;
        self.runtime
            .kill(&handle)
            .await
            .map(|_| ())
            .map_err(|_| PolicyError::ObligationFailed)
    }
    async fn security_alert(&self, _: &str, _: &ActionHash) -> Result<(), PolicyError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLease {
    pub sandbox_id: String,
    pub owner_id: String,
    pub epoch: u64,
    pub expires_at: DateTime<Utc>,
}

pub trait ExecutionLeaseStore: Send + Sync {
    fn acquire(
        &self,
        sandbox_id: &str,
        owner_id: &str,
        now: DateTime<Utc>,
        ttl: chrono::Duration,
    ) -> Result<ExecutionLease, SandboxError>;
    fn renew(
        &self,
        lease: &ExecutionLease,
        now: DateTime<Utc>,
        ttl: chrono::Duration,
    ) -> Result<ExecutionLease, SandboxError>;
    fn release(&self, lease: &ExecutionLease) -> Result<(), SandboxError>;
    fn expired(&self, now: DateTime<Utc>) -> Vec<ExecutionLease>;
}

#[derive(Default)]
pub struct InMemoryExecutionLeaseStore {
    leases: RwLock<BTreeMap<String, ExecutionLease>>,
}

impl ExecutionLeaseStore for InMemoryExecutionLeaseStore {
    fn acquire(
        &self,
        sandbox_id: &str,
        owner_id: &str,
        now: DateTime<Utc>,
        ttl: chrono::Duration,
    ) -> Result<ExecutionLease, SandboxError> {
        if sandbox_id.is_empty() || owner_id.is_empty() || ttl <= chrono::Duration::zero() {
            return Err(SandboxError::LeaseConflict);
        }
        let mut leases = self.leases.write();
        if leases
            .get(sandbox_id)
            .is_some_and(|lease| lease.expires_at > now && lease.owner_id != owner_id)
        {
            return Err(SandboxError::LeaseConflict);
        }
        let epoch = leases.get(sandbox_id).map_or(1, |lease| lease.epoch + 1);
        let lease = ExecutionLease {
            sandbox_id: sandbox_id.into(),
            owner_id: owner_id.into(),
            epoch,
            expires_at: now + ttl,
        };
        leases.insert(sandbox_id.into(), lease.clone());
        Ok(lease)
    }

    fn renew(
        &self,
        lease: &ExecutionLease,
        now: DateTime<Utc>,
        ttl: chrono::Duration,
    ) -> Result<ExecutionLease, SandboxError> {
        if ttl <= chrono::Duration::zero() || lease.expires_at <= now {
            return Err(SandboxError::LeaseConflict);
        }
        let mut leases = self.leases.write();
        let current = leases
            .get(&lease.sandbox_id)
            .ok_or(SandboxError::LeaseConflict)?;
        if current.owner_id != lease.owner_id || current.epoch != lease.epoch {
            return Err(SandboxError::LeaseConflict);
        }
        let renewed = ExecutionLease {
            expires_at: now + ttl,
            ..lease.clone()
        };
        leases.insert(lease.sandbox_id.clone(), renewed.clone());
        Ok(renewed)
    }

    fn release(&self, lease: &ExecutionLease) -> Result<(), SandboxError> {
        let mut leases = self.leases.write();
        let current = leases
            .get(&lease.sandbox_id)
            .ok_or(SandboxError::LeaseConflict)?;
        if current.owner_id != lease.owner_id || current.epoch != lease.epoch {
            return Err(SandboxError::LeaseConflict);
        }
        leases.remove(&lease.sandbox_id);
        Ok(())
    }

    fn expired(&self, now: DateTime<Utc>) -> Vec<ExecutionLease> {
        self.leases
            .read()
            .values()
            .filter(|lease| lease.expires_at <= now)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalSafetyJournalEntry {
    pub sequence: u64,
    pub action_hash: ActionHash,
    pub event_type: String,
    pub occurred_at: DateTime<Utc>,
    pub previous_hash: String,
    pub entry_hash: String,
}

#[derive(Default)]
pub struct LocalSafetyJournal {
    entries: RwLock<Vec<LocalSafetyJournalEntry>>,
}

impl LocalSafetyJournal {
    pub fn append(
        &self,
        action_hash: ActionHash,
        event_type: String,
        now: DateTime<Utc>,
    ) -> Result<LocalSafetyJournalEntry, SandboxError> {
        if event_type.is_empty() {
            return Err(SandboxError::JournalFailed);
        }
        let mut entries = self.entries.write();
        let previous_hash = entries
            .last()
            .map_or_else(|| "0".repeat(64), |entry| entry.entry_hash.clone());
        let sequence = entries.len() as u64 + 1;
        let canonical = serde_jcs::to_vec(&serde_json::json!({
            "sequence": sequence,
            "action_hash": action_hash,
            "event_type": event_type,
            "occurred_at": now,
            "previous_hash": previous_hash
        }))
        .map_err(|_| SandboxError::JournalFailed)?;
        let entry = LocalSafetyJournalEntry {
            sequence,
            action_hash,
            event_type,
            occurred_at: now,
            previous_hash,
            entry_hash: hex_string(Sha256::digest(canonical)),
        };
        entries.push(entry.clone());
        Ok(entry)
    }

    pub fn verify_chain(&self) -> bool {
        let entries = self.entries.read();
        let mut previous_hash = "0".repeat(64);
        for entry in entries.iter() {
            if entry.previous_hash != previous_hash {
                return false;
            }
            let Ok(canonical) = serde_jcs::to_vec(&serde_json::json!({
                "sequence": entry.sequence,
                "action_hash": entry.action_hash,
                "event_type": entry.event_type,
                "occurred_at": entry.occurred_at,
                "previous_hash": entry.previous_hash
            })) else {
                return false;
            };
            if hex_string(Sha256::digest(canonical)) != entry.entry_hash {
                return false;
            }
            previous_hash.clone_from(&entry.entry_hash);
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactExportRequest {
    pub sandbox_id: String,
    pub relative_path: PathBuf,
    pub media_type: String,
    pub maximum_bytes: u64,
    pub policy_approved: bool,
    pub output_schema_validated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactExportReceipt {
    pub artifact_ref: String,
    pub sha256: String,
    pub bytes: u64,
    pub dlp_passed: bool,
    pub exported_at: DateTime<Utc>,
}

#[async_trait]
pub trait ArtifactGateway: Send + Sync {
    async fn export(
        &self,
        request: ArtifactExportRequest,
    ) -> Result<ArtifactExportReceipt, SandboxError>;
}

pub struct LocalArtifactGateway {
    workspace_root: PathBuf,
    artifact_root: PathBuf,
    allowed_media_types: BTreeSet<String>,
}

impl LocalArtifactGateway {
    pub fn new(
        workspace_root: PathBuf,
        artifact_root: PathBuf,
        allowed_media_types: BTreeSet<String>,
    ) -> Result<Self, SandboxError> {
        if !workspace_root.is_absolute()
            || !artifact_root.is_absolute()
            || allowed_media_types.is_empty()
        {
            return Err(SandboxError::ArtifactDenied);
        }
        std::fs::create_dir_all(&artifact_root).map_err(|_| SandboxError::ArtifactDenied)?;
        Ok(Self {
            workspace_root,
            artifact_root,
            allowed_media_types,
        })
    }

    fn source_path(&self, request: &ArtifactExportRequest) -> Result<PathBuf, SandboxError> {
        if request.relative_path.is_absolute()
            || request.relative_path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(SandboxError::ArtifactDenied);
        }
        let sandbox_root = self.workspace_root.join(&request.sandbox_id);
        let canonical_root = sandbox_root
            .canonicalize()
            .map_err(|_| SandboxError::ArtifactDenied)?;
        let source = sandbox_root
            .join(&request.relative_path)
            .canonicalize()
            .map_err(|_| SandboxError::ArtifactDenied)?;
        if !source.starts_with(canonical_root) {
            return Err(SandboxError::ArtifactDenied);
        }
        Ok(source)
    }
}

#[async_trait]
impl ArtifactGateway for LocalArtifactGateway {
    async fn export(
        &self,
        request: ArtifactExportRequest,
    ) -> Result<ArtifactExportReceipt, SandboxError> {
        if !request.policy_approved
            || !request.output_schema_validated
            || request.maximum_bytes == 0
            || !self.allowed_media_types.contains(&request.media_type)
        {
            return Err(SandboxError::ArtifactDenied);
        }
        let source = self.source_path(&request)?;
        let metadata =
            std::fs::symlink_metadata(&source).map_err(|_| SandboxError::ArtifactDenied)?;
        if !metadata.is_file() || metadata.len() > request.maximum_bytes {
            return Err(SandboxError::ArtifactDenied);
        }
        let bytes = std::fs::read(&source).map_err(|_| SandboxError::ArtifactDenied)?;
        if contains_secret_material(&bytes) {
            return Err(SandboxError::ArtifactDlpDenied);
        }
        let digest = hex_string(Sha256::digest(&bytes));
        let artifact_name = format!("{digest}.artifact");
        let destination = self.artifact_root.join(&artifact_name);
        std::fs::write(&destination, &bytes).map_err(|_| SandboxError::ArtifactDenied)?;
        Ok(ArtifactExportReceipt {
            artifact_ref: format!("artifact:sha256:{digest}"),
            sha256: digest,
            bytes: metadata.len(),
            dlp_passed: true,
            exported_at: Utc::now(),
        })
    }
}

fn contains_secret_material(bytes: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    [
        "authorization: bearer ",
        "-----begin private key-----",
        "api_key=",
        "password=",
        "secret=",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

pub struct WasmComponentCommandBuilder {
    pub wasmtime_path: PathBuf,
    pub engine_digest: String,
}

impl WasmComponentCommandBuilder {
    pub fn production_available(&self) -> bool {
        self.wasmtime_path.is_absolute()
            && self.wasmtime_path.exists()
            && is_sha256_digest(&self.engine_digest)
    }

    pub fn build(
        &self,
        executor_id: String,
        component_path: &Path,
        expected_component_digest: &str,
        fuel: u64,
        max_memory_bytes: u64,
    ) -> Result<ExecutorTemplate, SandboxError> {
        if !self.production_available()
            || !component_path.is_absolute()
            || fuel == 0
            || max_memory_bytes == 0
            || !is_sha256_digest(expected_component_digest)
        {
            return Err(SandboxError::ProductionIsolationUnavailable);
        }
        let component = std::fs::read(component_path).map_err(|_| SandboxError::PrepareFailed)?;
        let actual_digest = format!("sha256:{}", hex_string(Sha256::digest(component)));
        if actual_digest != expected_component_digest {
            return Err(SandboxError::ImageDigestMismatch);
        }
        Ok(ExecutorTemplate {
            executor_id,
            implementation_digest: expected_component_digest.into(),
            runtime_digest: Some(self.engine_digest.clone()),
            oci_config_digest: None,
            program: self.wasmtime_path.clone(),
            fixed_args: vec![
                "run".into(),
                "--fuel".into(),
                fuel.to_string(),
                "-W".into(),
                format!("max-memory-size={max_memory_bytes}"),
                component_path.display().to_string(),
            ],
            allowed_environment: BTreeMap::new(),
            shell: false,
        })
    }
}

pub struct OciGvisorCommandBuilder {
    pub runsc_path: PathBuf,
    pub expected_runsc_digest: String,
}
impl OciGvisorCommandBuilder {
    pub fn production_available(&self) -> bool {
        cfg!(target_os = "linux")
            && self.runsc_path.is_absolute()
            && self.runsc_path.is_file()
            && is_sha256_digest(&self.expected_runsc_digest)
            && std::fs::read(&self.runsc_path).ok().is_some_and(|bytes| {
                format!("sha256:{}", hex_string(Sha256::digest(bytes)))
                    == self.expected_runsc_digest
            })
    }
    pub fn build(
        &self,
        sandbox_id: &str,
        bundle: &Path,
        state_root: &Path,
        workload_implementation_digest: &str,
        expected_config_digest: &str,
    ) -> Result<ExecutorTemplate, SandboxError> {
        if !self.production_available()
            || !valid_sandbox_identifier(sandbox_id)
            || !bundle.is_absolute()
            || !bundle.is_dir()
            || !bundle.join("config.json").is_file()
            || !state_root.is_absolute()
            || state_root.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::Prefix(_)
                )
            })
            || !is_sha256_digest(workload_implementation_digest)
            || !is_sha256_digest(expected_config_digest)
        {
            return Err(SandboxError::ProductionIsolationUnavailable);
        }
        validate_oci_bundle(bundle, expected_config_digest)?;
        Ok(ExecutorTemplate {
            executor_id: "gvisor-runsc".into(),
            implementation_digest: workload_implementation_digest.into(),
            runtime_digest: Some(self.expected_runsc_digest.clone()),
            oci_config_digest: Some(expected_config_digest.into()),
            program: self.runsc_path.clone(),
            fixed_args: vec![
                "--network=none".into(),
                "--rootless=true".into(),
                format!("--root={}", state_root.display()),
                "run".into(),
                "--bundle".into(),
                bundle.display().to_string(),
                sandbox_id.into(),
            ],
            allowed_environment: BTreeMap::new(),
            shell: false,
        })
    }
}

fn verify_production_executor(template: &ExecutorTemplate) -> Result<(), SandboxError> {
    let runtime_digest = template
        .runtime_digest
        .as_deref()
        .ok_or(SandboxError::ProductionIsolationUnavailable)?;
    let config_digest = template
        .oci_config_digest
        .as_deref()
        .ok_or(SandboxError::ProductionIsolationUnavailable)?;
    if !cfg!(target_os = "linux")
        || template.executor_id != "gvisor-runsc"
        || !template.program.is_absolute()
        || !template.program.is_file()
        || !is_sha256_digest(&template.implementation_digest)
        || !is_sha256_digest(runtime_digest)
        || !is_sha256_digest(config_digest)
        || template.shell
        || template.fixed_args.len() != 7
        || template.fixed_args[0] != "--network=none"
        || template.fixed_args[1] != "--rootless=true"
        || !template.fixed_args[2].starts_with("--root=/")
        || template.fixed_args[3] != "run"
        || template.fixed_args[4] != "--bundle"
        || !Path::new(&template.fixed_args[5]).is_absolute()
        || !valid_sandbox_identifier(&template.fixed_args[6])
    {
        return Err(SandboxError::ProductionIsolationUnavailable);
    }
    let bytes = std::fs::read(&template.program)
        .map_err(|_| SandboxError::ProductionIsolationUnavailable)?;
    let actual = format!("sha256:{}", hex_string(Sha256::digest(bytes)));
    if actual != runtime_digest {
        return Err(SandboxError::ImageDigestMismatch);
    }
    validate_oci_bundle(Path::new(&template.fixed_args[5]), config_digest)?;
    Ok(())
}

fn validate_oci_bundle(bundle: &Path, expected_config_digest: &str) -> Result<(), SandboxError> {
    let config_path = bundle.join("config.json");
    let metadata = std::fs::symlink_metadata(&config_path)
        .map_err(|_| SandboxError::ProductionIsolationUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err(SandboxError::ProductionIsolationUnavailable);
    }
    let bytes =
        std::fs::read(&config_path).map_err(|_| SandboxError::ProductionIsolationUnavailable)?;
    let actual = format!("sha256:{}", hex_string(Sha256::digest(&bytes)));
    if actual != expected_config_digest {
        return Err(SandboxError::ImageDigestMismatch);
    }
    gvisor::parse_oci_runtime_spec(&bytes).map(|_| ())
}

fn valid_sandbox_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SandboxError {
    #[error("SANDBOX_AUTHORIZATION_INVALID")]
    AuthorizationInvalid,
    #[error("SANDBOX_AUTHORIZATION_REPLAYED")]
    AuthorizationReplayed,
    #[error("SANDBOX_PROFILE_DENIED")]
    ProfileDenied,
    #[error("SANDBOX_NETWORK_DENIED")]
    NetworkDenied,
    #[error("SANDBOX_FILESYSTEM_DENIED")]
    FilesystemDenied,
    #[error("SANDBOX_CREDENTIAL_INJECTION_FAILED")]
    CredentialInjectionFailed,
    #[error("SANDBOX_LEASE_CONFLICT")]
    LeaseConflict,
    #[error("SANDBOX_JOURNAL_FAILED")]
    JournalFailed,
    #[error("SANDBOX_ARTIFACT_DENIED")]
    ArtifactDenied,
    #[error("SANDBOX_ARTIFACT_DLP_DENIED")]
    ArtifactDlpDenied,
    #[error("SANDBOX_IMAGE_DIGEST_MISMATCH")]
    ImageDigestMismatch,
    #[error("SANDBOX_RESOURCE_LIMIT_INVALID")]
    ResourceLimitInvalid,
    #[error("SANDBOX_PREPARE_FAILED")]
    PrepareFailed,
    #[error("SANDBOX_START_FAILED")]
    StartFailed,
    #[error("SANDBOX_COLLECT_FAILED")]
    CollectFailed,
    #[error("SANDBOX_KILL_FAILED")]
    KillFailed,
    #[error("SANDBOX_CLEANUP_INCOMPLETE")]
    CleanupIncomplete,
    #[error("SANDBOX_ORPHANED")]
    Orphaned,
    #[error("SANDBOX_PRODUCTION_ISOLATION_UNAVAILABLE")]
    ProductionIsolationUnavailable,
    #[error("SANDBOX_GVISOR_JOB_INVALID")]
    JobInvalid,
    #[error("SANDBOX_GVISOR_RUNTIME_ATTESTATION_INVALID")]
    RuntimeAttestationInvalid,
    #[error("SANDBOX_REPLAY_LEDGER_FAILED")]
    ReplayLedgerFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::*;
    use agent_trust_registry::{
        CapabilityDescriptor, CapabilityQuery, ImplementationKind, RegistryError, RegistrySnapshot,
        ToolImplementation, ToolLimits,
    };
    use serde_json::Value;

    struct Registry {
        snapshot: ResolvedToolSnapshot,
        revoked: RwLock<bool>,
    }
    #[async_trait]
    impl ToolRegistry for Registry {
        async fn resolve_exact(
            &self,
            _: &TenantId,
            _: &ToolRef,
        ) -> Result<ResolvedToolSnapshot, RegistryError> {
            Ok(self.snapshot.clone())
        }
        async fn validate_arguments(
            &self,
            _: &ResolvedToolSnapshot,
            _: &StrictJsonObject,
        ) -> Result<(), RegistryError> {
            Ok(())
        }
        async fn validate_output(
            &self,
            _: &ResolvedToolSnapshot,
            _: &Value,
        ) -> Result<(), RegistryError> {
            Ok(())
        }
        async fn discover_capabilities(
            &self,
            _: CapabilityQuery,
        ) -> Result<Vec<CapabilityDescriptor>, RegistryError> {
            Ok(vec![])
        }
        async fn snapshot(
            &self,
            _: &TenantId,
            _: &[ToolRef],
        ) -> Result<RegistrySnapshot, RegistryError> {
            Err(RegistryError::ToolNotFound)
        }
        async fn is_revoked(&self, _: &ToolRef, _: &str) -> Result<bool, RegistryError> {
            Ok(*self.revoked.read())
        }
    }

    fn setup(
        program: &str,
        args: Vec<String>,
        output_limit: u64,
    ) -> (Arc<LocalProcessSandbox<Registry>>, PrepareRequest, PathBuf) {
        let tool = ResolvedToolSnapshot {
            schema_version: "registry".into(),
            tool_id: ToolId("coding.test".into()),
            tool_version: ToolVersion("1.0.0".into()),
            schema_hash: "schema".into(),
            manifest_hash: "manifest".into(),
            effect_class: EffectClass::Pure,
            risk_level: RiskLevel::Low,
            executor_profile: "local-safe".into(),
            credential_profile: "none".into(),
            approval_profile: "none".into(),
            compensation: None,
            limits: ToolLimits {
                timeout_ms: 5000,
                max_result_bytes: output_limit * 2,
            },
            network_profile_ref: "none".into(),
            filesystem_profile_ref: "workspace".into(),
            implementation: ToolImplementation {
                kind: ImplementationKind::InternalService,
                digest: format!("sha256:{}", "c".repeat(64)),
                executor_id: "fixed".into(),
            },
            registry_revision: 1,
            resolved_at: Utc::now(),
            snapshot_hash: "b".repeat(64),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
        };
        let registry = Arc::new(Registry {
            snapshot: tool.clone(),
            revoked: RwLock::new(false),
        });
        let verifier = Arc::new(ExecutionAuthorizationVerifier::new(registry));
        let signing = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        verifier.add_issuer_key("key".into(), "pep".into(), signing.verifying_key());
        let now = Utc::now();
        let mut authorization = ExecutionAuthorization {
            schema_version: SchemaVersion(EXECUTION_AUTHORIZATION_SCHEMA_VERSION.into()),
            authorization_id: Uuid::new_v4().to_string(),
            tenant_id: TenantId::new(),
            task_id: TaskId::new(),
            step_id: StepId::new(),
            agent_instance_id: AgentInstanceId::new(),
            action_hash: ActionHash("a".repeat(64)),
            tool_id: tool.tool_id.clone(),
            tool_version: tool.tool_version.clone(),
            tool_snapshot_hash: tool.snapshot_hash.clone(),
            implementation_digest: tool.implementation.digest.clone(),
            executor_profile: tool.executor_profile.clone(),
            operation: "execute".into(),
            resource: "workspace:output".into(),
            canonical_arguments_hash: "c".repeat(64),
            target_profile: "local".into(),
            environment: "test".into(),
            idempotency_key: IdempotencyKey(Uuid::new_v4().to_string()),
            ledger_execution_id: ExecutionId::new(),
            ledger_event_id: Uuid::new_v4().to_string(),
            ledger_event_digest: "2".repeat(64),
            fence_digest: "d".repeat(64),
            policy_decision_id: "decision".into(),
            policy_decision_digest: "3".repeat(64),
            policy_version: PolicyVersion("policy-1".into()),
            policy_bundle_hash: "e".repeat(64),
            policy_input_hash: "f".repeat(64),
            authorization_evidence_ref: String::new(),
            authorization_evidence_digest: String::new(),
            preapproval_digest: "0".repeat(64),
            approval_ids: vec![],
            approval_consumption_ref: None,
            approval_receipt_digest: None,
            resource_version: ResourceVersion("v1".into()),
            sandbox_profile: "local-safe".into(),
            network_profile: "none".into(),
            credential_profile: "none".into(),
            workload_credential_id: Uuid::new_v4().to_string(),
            workload_credential_claims_digest: "1".repeat(64),
            workload_credential_audience: "tool-proxy".into(),
            workload_credential_revocation_epoch: 0,
            max_execution_ms: 5000,
            max_result_bytes: output_limit * 2,
            issued_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::minutes(1),
            single_use: true,
            issuer: "pep".into(),
            key_id: "key".into(),
            key_usage: PEP_EXECUTION_AUTHORIZATION_KEY_USAGE.into(),
            signature: String::new(),
        };
        authorization
            .bind_evidence()
            .unwrap_or_else(|_| panic!("bind evidence"));
        authorization
            .sign(&signing)
            .unwrap_or_else(|_| panic!("sign"));
        let root =
            std::env::temp_dir().join(format!("agent-trust-sandbox-tests-{}", Uuid::new_v4()));
        let runtime = Arc::new(
            LocalProcessSandbox::new(verifier, root.clone()).unwrap_or_else(|_| panic!("runtime")),
        );
        let request = PrepareRequest {
            authorization,
            tool: tool.clone(),
            template: ExecutorTemplate {
                executor_id: "fixed".into(),
                implementation_digest: tool.implementation.digest,
                runtime_digest: None,
                oci_config_digest: None,
                program: PathBuf::from(program),
                fixed_args: args,
                allowed_environment: BTreeMap::new(),
                shell: false,
            },
            profile: SandboxProfile {
                profile_id: "local-safe".into(),
                production_isolation_required: false,
                non_root: true,
                read_only_rootfs: true,
                network_none: true,
                no_new_privileges: true,
                drop_all_capabilities: true,
            },
            network_profile: NetworkProfile {
                profile_id: "none".into(),
                default_deny: true,
                allowed_endpoints: BTreeSet::new(),
                max_connections: 0,
                max_upload_bytes: 0,
            },
            filesystem_profile: FilesystemProfile {
                profile_id: "workspace".into(),
                read_only_inputs: true,
                writable_paths: BTreeSet::from([PathBuf::from("output")]),
                max_files: 100,
                max_file_bytes: 1024 * 1024,
            },
            budget: ResourceBudget {
                cpu_millis: 1000,
                memory_bytes: 64 * 1024 * 1024,
                pids: 16,
                disk_bytes: 1024 * 1024,
                max_stdout_bytes: output_limit,
                max_stderr_bytes: output_limit,
                timeout_ms: 5000,
            },
            credential_refs: vec![],
            workspace_snapshot: Some(WorkspaceSnapshotRef {
                snapshot_id: "snapshot-1".into(),
                digest: format!("sha256:{}", "d".repeat(64)),
                read_only: true,
            }),
            trace_id: "trace".into(),
        };
        (runtime, request, root)
    }

    #[tokio::test]
    async fn authorization_is_single_use_and_output_is_bounded() {
        let (runtime, request, root) = setup("/usr/bin/printf", vec!["1234567890".into()], 4);
        let replay = request.clone();
        let prepared = runtime
            .prepare(request)
            .await
            .unwrap_or_else(|_| panic!("prepare"));
        assert_eq!(
            runtime.prepare(replay).await.err(),
            Some(SandboxError::AuthorizationReplayed)
        );
        let handle = runtime
            .start(prepared)
            .await
            .unwrap_or_else(|_| panic!("start"));
        let result = runtime
            .collect(handle)
            .await
            .unwrap_or_else(|_| panic!("collect"));
        assert_eq!(result.stdout, b"1234");
        assert!(result.stdout_truncated);
        assert!(result.cleanup.workspace_removed);
        let _ = std::fs::remove_dir(&root);
    }

    #[tokio::test]
    async fn kill_targets_the_process_group() {
        let (runtime, request, root) = setup("/bin/sleep", vec!["10".into()], 64);
        let prepared = runtime
            .prepare(request)
            .await
            .unwrap_or_else(|_| panic!("prepare"));
        let handle = runtime
            .start(prepared)
            .await
            .unwrap_or_else(|_| panic!("start"));
        let receipt = runtime
            .kill(&handle)
            .await
            .unwrap_or_else(|_| panic!("kill"));
        assert!(receipt.process_group.is_some());
        let result = runtime
            .collect(handle)
            .await
            .unwrap_or_else(|_| panic!("collect"));
        assert!(matches!(
            result.status,
            SandboxState::Failed | SandboxState::Killed
        ));
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn macos_cannot_claim_gvisor_production_isolation() {
        let builder = OciGvisorCommandBuilder {
            runsc_path: PathBuf::from("/usr/local/bin/runsc"),
            expected_runsc_digest: format!("sha256:{}", "a".repeat(64)),
        };
        if cfg!(target_os = "macos") {
            assert!(!builder.production_available());
        }
    }

    #[tokio::test]
    async fn unsafe_network_and_unmanaged_credentials_fail_closed() {
        let (runtime, mut request, root) = setup("/usr/bin/true", vec![], 64);
        request
            .network_profile
            .allowed_endpoints
            .insert("https://169.254.169.254/latest/meta-data".into());
        assert_eq!(
            runtime.prepare(request).await.err(),
            Some(SandboxError::NetworkDenied)
        );

        let (_, mut credential_request, credential_root) = setup("/usr/bin/true", vec![], 64);
        credential_request.credential_refs = vec!["credential:short-lived".into()];
        let (credential_runtime, _, _) = setup("/usr/bin/true", vec![], 64);
        assert_eq!(
            credential_runtime.prepare(credential_request).await.err(),
            Some(SandboxError::CredentialInjectionFailed)
        );
        let _ = std::fs::remove_dir(&root);
        let _ = std::fs::remove_dir(&credential_root);
    }

    #[test]
    fn execution_lease_fences_competing_supervisors() {
        let store = InMemoryExecutionLeaseStore::default();
        let now = Utc::now();
        let first = store
            .acquire("sandbox-1", "owner-1", now, chrono::Duration::seconds(30))
            .unwrap_or_else(|_| panic!("lease"));
        assert_eq!(
            store.acquire(
                "sandbox-1",
                "owner-2",
                now + chrono::Duration::seconds(1),
                chrono::Duration::seconds(30)
            ),
            Err(SandboxError::LeaseConflict)
        );
        let takeover = store
            .acquire(
                "sandbox-1",
                "owner-2",
                now + chrono::Duration::seconds(31),
                chrono::Duration::seconds(30),
            )
            .unwrap_or_else(|_| panic!("takeover"));
        assert!(takeover.epoch > first.epoch);
        assert_eq!(
            store.renew(&first, now, chrono::Duration::seconds(30)),
            Err(SandboxError::LeaseConflict)
        );
    }

    #[test]
    fn safety_journal_is_hash_chained() {
        let journal = LocalSafetyJournal::default();
        journal
            .append(ActionHash("action-1".into()), "KILL".into(), Utc::now())
            .unwrap_or_else(|_| panic!("journal"));
        journal
            .append(
                ActionHash("action-2".into()),
                "EMERGENCY_STOP".into(),
                Utc::now(),
            )
            .unwrap_or_else(|_| panic!("journal"));
        assert!(journal.verify_chain());
    }

    #[tokio::test]
    async fn artifact_export_blocks_traversal_and_secret_material() {
        let root = std::env::temp_dir().join(format!("agent-trust-artifact-{}", Uuid::new_v4()));
        let workspace = root.join("workspaces");
        let sandbox = workspace.join("sandbox-1");
        let exports = root.join("exports");
        std::fs::create_dir_all(&sandbox).unwrap_or_else(|_| panic!("sandbox directory"));
        std::fs::write(sandbox.join("safe.txt"), b"safe result")
            .unwrap_or_else(|_| panic!("safe artifact"));
        std::fs::write(sandbox.join("secret.txt"), b"password=do-not-export")
            .unwrap_or_else(|_| panic!("secret artifact"));
        let gateway =
            LocalArtifactGateway::new(workspace, exports, BTreeSet::from(["text/plain".into()]))
                .unwrap_or_else(|_| panic!("artifact gateway"));
        let request = |path: &str| ArtifactExportRequest {
            sandbox_id: "sandbox-1".into(),
            relative_path: PathBuf::from(path),
            media_type: "text/plain".into(),
            maximum_bytes: 1024,
            policy_approved: true,
            output_schema_validated: true,
        };
        assert!(gateway.export(request("safe.txt")).await.is_ok());
        assert_eq!(
            gateway.export(request("secret.txt")).await.err(),
            Some(SandboxError::ArtifactDlpDenied)
        );
        assert_eq!(
            gateway.export(request("../outside.txt")).await.err(),
            Some(SandboxError::ArtifactDenied)
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
