//! Fail-closed bindings to the authoritative services required by Batch 29.

#[cfg(test)]
use crate::runtime::ActionMaterializationRef;
use crate::runtime::{
    ResolvedTransitionFacts, RuntimeCommandType, RuntimeExecutionRecord, RuntimeWorkflowCommand,
    RuntimeWorkflowState, passed_evaluation,
};
use agent_trust_contracts::ExecutionStatus;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Certificate, Client, Identity, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use url::Url;

const FACT_SCHEMA_VERSION: &str = "agenttrust.authoritative-fact.v1";
const FACT_QUERY_SCHEMA_VERSION: &str = "agenttrust.authoritative-fact-query.v1";
const FACT_READINESS_SCHEMA_VERSION: &str = "agenttrust.authoritative-fact-readiness.v1";
const MAX_FACT_RESPONSE_BYTES: usize = 1_048_576;
const MAX_READINESS_RESPONSE_BYTES: usize = 65_536;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactKind {
    PolicyCheckpoint,
    Approval,
    CredentialLease,
    ExecutionLedger,
    Evaluator,
    Evidence,
    RuntimeSupervisor,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactDecision {
    Verified,
    Granted,
    Active,
    Revoked,
    Pass,
    Contained,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeFactQuery<'a> {
    pub schema_version: &'static str,
    pub tenant_id: &'a str,
    pub task_id: &'a str,
    pub action_id: &'a str,
    pub command_id: &'a str,
    pub command_type: RuntimeCommandType,
    pub recovery_cursor: u64,
    pub ingress_digest: &'a str,
    pub payload_digest: &'a str,
    pub requested_by: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeFact {
    pub schema_version: String,
    pub fact_kind: FactKind,
    pub tenant_id: String,
    pub task_id: String,
    pub action_id: String,
    pub command_id: String,
    pub recovery_cursor: u64,
    pub payload_digest: String,
    pub decision: FactDecision,
    pub immutable_digest: String,
    pub evidence_refs: BTreeSet<String>,
    pub valid_until: DateTime<Utc>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

impl AuthoritativeFact {
    fn validate(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
        kind: FactKind,
        decisions: &[FactDecision],
    ) -> Result<(), FactResolutionError> {
        if self.schema_version != FACT_SCHEMA_VERSION
            || self.fact_kind != kind
            || self.tenant_id != state.tenant_id
            || self.task_id != state.task_id
            || self.action_id != state.action_id
            || self.command_id != command.command_id
            || self.recovery_cursor != state.recovery_cursor
            || self.payload_digest != command.payload_digest
            || !decisions.contains(&self.decision)
            || !is_digest(&self.immutable_digest)
            || self.evidence_refs.is_empty()
            || self.evidence_refs.iter().any(|value| value.is_empty())
            || self.valid_until <= Utc::now()
        {
            return Err(FactResolutionError::Denied);
        }
        Ok(())
    }

    fn append_evidence(&self, target: &mut BTreeSet<String>) {
        target.extend(self.evidence_refs.iter().cloned());
        target.insert(format!(
            "fact:{:?}:{}",
            self.fact_kind, self.immutable_digest
        ));
    }
}

#[async_trait]
pub trait PolicyCheckpointPort: Send + Sync {
    async fn verify(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait ApprovalWaitPort: Send + Sync {
    async fn verify(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait CredentialLeasePort: Send + Sync {
    async fn verify(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError>;
    async fn revoke(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait ExecutionLedgerPort: Send + Sync {
    async fn verify(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait EvaluatorPort: Send + Sync {
    async fn verify(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait EvidencePort: Send + Sync {
    async fn verify(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError>;
    async fn ready(&self) -> bool;
}

#[async_trait]
pub trait RuntimeSupervisorPort: Send + Sync {
    async fn contain(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError>;
    async fn ready(&self) -> bool;
}

#[derive(Clone)]
pub struct HttpsFactClient {
    client: Client,
    base_url: Url,
    bearer_token: Arc<str>,
}

impl HttpsFactClient {
    pub fn new(
        endpoint: &str,
        bearer_token: String,
        ca_file: &Path,
        certificate_file: &Path,
        private_key_file: &Path,
    ) -> Result<Self, FactResolutionError> {
        let base_url = Url::parse(endpoint).map_err(|_| FactResolutionError::Configuration)?;
        if base_url.scheme() != "https"
            || base_url.host_str().is_none()
            || base_url.cannot_be_a_base()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.path() != "/"
            || bearer_token.is_empty()
        {
            return Err(FactResolutionError::Configuration);
        }
        let ca = std::fs::read(ca_file).map_err(|_| FactResolutionError::Configuration)?;
        let certificate =
            std::fs::read(certificate_file).map_err(|_| FactResolutionError::Configuration)?;
        let private_key =
            std::fs::read(private_key_file).map_err(|_| FactResolutionError::Configuration)?;
        let mut identity = certificate;
        if !identity.ends_with(b"\n") {
            identity.push(b'\n');
        }
        identity.extend(private_key);
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .add_root_certificate(
                Certificate::from_pem(&ca).map_err(|_| FactResolutionError::Configuration)?,
            )
            .identity(
                Identity::from_pem(&identity).map_err(|_| FactResolutionError::Configuration)?,
            )
            .build()
            .map_err(|_| FactResolutionError::Configuration)?;
        Ok(Self {
            client,
            base_url,
            bearer_token: bearer_token.into(),
        })
    }

    async fn fetch(
        &self,
        path: &str,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError> {
        let url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| FactResolutionError::Configuration)?;
        let query = AuthoritativeFactQuery {
            schema_version: FACT_QUERY_SCHEMA_VERSION,
            tenant_id: &state.tenant_id,
            task_id: &state.task_id,
            action_id: &state.action_id,
            command_id: &command.command_id,
            command_type: command.command_type,
            recovery_cursor: state.recovery_cursor,
            ingress_digest: &state.ingress_digest,
            payload_digest: &command.payload_digest,
            requested_by: &command.requested_by,
        };
        let mut response = self
            .client
            .post(url)
            .bearer_auth(self.bearer_token.as_ref())
            .header("Accept", "application/json")
            .header("Idempotency-Key", &command.command_id)
            .json(&query)
            .send()
            .await
            .map_err(|_| FactResolutionError::Unavailable)?;
        if response.status() == StatusCode::FORBIDDEN
            || response.status() == StatusCode::UNAUTHORIZED
        {
            return Err(FactResolutionError::Denied);
        }
        if !response.status().is_success() {
            return Err(FactResolutionError::Unavailable);
        }
        if response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| value.split(';').next() != Some("application/json"))
        {
            return Err(FactResolutionError::ResponseInvalid);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_FACT_RESPONSE_BYTES as u64)
        {
            return Err(FactResolutionError::ResponseInvalid);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| FactResolutionError::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_FACT_RESPONSE_BYTES {
                return Err(FactResolutionError::ResponseInvalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| FactResolutionError::ResponseInvalid)
    }

    async fn ready(&self) -> bool {
        let Ok(url) = self.base_url.join("ready") else {
            return false;
        };
        let Ok(mut response) = self
            .client
            .get(url)
            .bearer_auth(self.bearer_token.as_ref())
            .send()
            .await
        else {
            return false;
        };
        if response.status() != StatusCode::OK
            || response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| value.split(';').next() != Some("application/json"))
            || response
                .content_length()
                .is_some_and(|length| length > MAX_READINESS_RESPONSE_BYTES as u64)
        {
            return false;
        }
        let mut bytes = Vec::new();
        loop {
            let chunk = match response.chunk().await {
                Ok(value) => value,
                Err(_) => return false,
            };
            let Some(chunk) = chunk else {
                break;
            };
            if bytes.len().saturating_add(chunk.len()) > MAX_READINESS_RESPONSE_BYTES {
                return false;
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return false;
        }
        serde_json::from_slice::<DependencyReadiness>(&bytes).is_ok_and(|value| {
            value.schema_version == FACT_READINESS_SCHEMA_VERSION && value.ready
        })
    }
}

macro_rules! fact_binding {
    ($name:ident, $trait_name:ident, $path:literal) => {
        #[derive(Clone)]
        pub struct $name(pub HttpsFactClient);

        #[async_trait]
        impl $trait_name for $name {
            async fn verify(
                &self,
                state: &RuntimeWorkflowState,
                command: &RuntimeWorkflowCommand,
            ) -> Result<AuthoritativeFact, FactResolutionError> {
                self.0.fetch($path, state, command).await
            }

            async fn ready(&self) -> bool {
                self.0.ready().await
            }
        }
    };
}

fact_binding!(
    HttpsPolicyCheckpoint,
    PolicyCheckpointPort,
    "/v1/checkpoints/verify"
);
fact_binding!(HttpsApprovalWait, ApprovalWaitPort, "/v1/approvals/verify");
fact_binding!(
    HttpsExecutionLedger,
    ExecutionLedgerPort,
    "/v1/executions/facts"
);
fact_binding!(HttpsEvaluator, EvaluatorPort, "/v1/evaluations/latest");
fact_binding!(HttpsEvidence, EvidencePort, "/v1/evidence/verify");

#[derive(Clone)]
pub struct HttpsCredentialLease(pub HttpsFactClient);

#[async_trait]
impl CredentialLeasePort for HttpsCredentialLease {
    async fn verify(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError> {
        self.0.fetch("/v1/leases/status", state, command).await
    }

    async fn revoke(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError> {
        self.0.fetch("/v1/leases/revoke", state, command).await
    }

    async fn ready(&self) -> bool {
        self.0.ready().await
    }
}

#[derive(Clone)]
pub struct HttpsRuntimeSupervisor(pub HttpsFactClient);

#[async_trait]
impl RuntimeSupervisorPort for HttpsRuntimeSupervisor {
    async fn contain(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<AuthoritativeFact, FactResolutionError> {
        self.0.fetch("/v1/runtime/kill", state, command).await
    }

    async fn ready(&self) -> bool {
        self.0.ready().await
    }
}

#[async_trait]
pub trait TransitionFactResolver: Clone + Send + Sync + 'static {
    async fn resolve(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<ResolvedTransitionFacts, FactResolutionError>;
    async fn ready(&self) -> bool;
}

#[derive(Clone)]
pub struct ProductionFactResolver {
    policy: Arc<dyn PolicyCheckpointPort>,
    approval: Arc<dyn ApprovalWaitPort>,
    credential: Arc<dyn CredentialLeasePort>,
    ledger: Arc<dyn ExecutionLedgerPort>,
    evaluator: Arc<dyn EvaluatorPort>,
    evidence: Arc<dyn EvidencePort>,
    supervisor: Arc<dyn RuntimeSupervisorPort>,
}

impl ProductionFactResolver {
    pub fn new(
        policy: Arc<dyn PolicyCheckpointPort>,
        approval: Arc<dyn ApprovalWaitPort>,
        credential: Arc<dyn CredentialLeasePort>,
        ledger: Arc<dyn ExecutionLedgerPort>,
        evaluator: Arc<dyn EvaluatorPort>,
        evidence: Arc<dyn EvidencePort>,
        supervisor: Arc<dyn RuntimeSupervisorPort>,
    ) -> Self {
        Self {
            policy,
            approval,
            credential,
            ledger,
            evaluator,
            evidence,
            supervisor,
        }
    }
}

#[async_trait]
impl TransitionFactResolver for ProductionFactResolver {
    async fn resolve(
        &self,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> Result<ResolvedTransitionFacts, FactResolutionError> {
        let mut resolved = ResolvedTransitionFacts {
            evidence_refs: BTreeSet::new(),
            ledger_status: None,
            evaluation: None,
            compensation_verified: false,
            credential_revoked: false,
            supervisor_acknowledged: false,
            execution: None,
        };

        // Emergency containment is ordered ahead of every observational dependency. If an
        // evidence or ledger service is unavailable, KILL still reaches the runtime supervisor
        // and lease authority first. Both endpoints receive the command id as their idempotency
        // key, so a workflow retry cannot duplicate the physical containment operation.
        if command.command_type == RuntimeCommandType::Kill {
            let supervisor = self.supervisor.contain(state, command).await?;
            supervisor.validate(
                state,
                command,
                FactKind::RuntimeSupervisor,
                &[FactDecision::Contained],
            )?;
            supervisor.append_evidence(&mut resolved.evidence_refs);
            resolved.supervisor_acknowledged = true;
            let credential = self.credential.revoke(state, command).await?;
            credential.validate(
                state,
                command,
                FactKind::CredentialLease,
                &[FactDecision::Revoked],
            )?;
            credential.append_evidence(&mut resolved.evidence_refs);
            resolved.credential_revoked = true;
            return Ok(resolved);
        }

        let evidence = self.evidence.verify(state, command).await?;
        evidence.validate(
            state,
            command,
            FactKind::Evidence,
            &[FactDecision::Verified],
        )?;
        evidence.append_evidence(&mut resolved.evidence_refs);
        resolved.compensation_verified = evidence
            .attributes
            .get("compensation_verified")
            .is_some_and(|value| value == "true");

        if matches!(
            command.command_type,
            RuntimeCommandType::Start
                | RuntimeCommandType::Resume
                | RuntimeCommandType::Checkpoint
                | RuntimeCommandType::Verify
        ) {
            let policy = self.policy.verify(state, command).await?;
            policy.validate(
                state,
                command,
                FactKind::PolicyCheckpoint,
                &[FactDecision::Verified],
            )?;
            policy.append_evidence(&mut resolved.evidence_refs);
            let credential = self.credential.verify(state, command).await?;
            credential.validate(
                state,
                command,
                FactKind::CredentialLease,
                &[FactDecision::Active],
            )?;
            credential.append_evidence(&mut resolved.evidence_refs);
        }
        if command.command_type == RuntimeCommandType::Start {
            let approval = self.approval.verify(state, command).await?;
            approval.validate(state, command, FactKind::Approval, &[FactDecision::Granted])?;
            approval.append_evidence(&mut resolved.evidence_refs);
        }
        if matches!(
            command.command_type,
            RuntimeCommandType::Cancel
                | RuntimeCommandType::Kill
                | RuntimeCommandType::Verify
                | RuntimeCommandType::Complete
                | RuntimeCommandType::NeedsHuman
        ) {
            let ledger = self.ledger.verify(state, command).await?;
            ledger.validate(
                state,
                command,
                FactKind::ExecutionLedger,
                &[FactDecision::Verified],
            )?;
            ledger.append_evidence(&mut resolved.evidence_refs);
            resolved.ledger_status = Some(parse_execution_status(
                ledger
                    .attributes
                    .get("execution_status")
                    .ok_or(FactResolutionError::ResponseInvalid)?,
            )?);
            let ledger_execution_id = ledger
                .attributes
                .get("ledger_execution_id")
                .filter(|value| !value.is_empty() && value.len() <= 256 && is_token(value))
                .cloned()
                .ok_or(FactResolutionError::ResponseInvalid)?;
            let fence_digest = ledger
                .attributes
                .get("fence_digest")
                .filter(|value| is_digest(value))
                .cloned()
                .ok_or(FactResolutionError::ResponseInvalid)?;
            let outcome_digest = ledger
                .attributes
                .get("outcome_digest")
                .filter(|value| is_digest(value))
                .cloned()
                .ok_or(FactResolutionError::ResponseInvalid)?;
            resolved.execution = Some(RuntimeExecutionRecord {
                ledger_execution_id,
                fence_digest,
                outcome_digest,
                status: resolved
                    .ledger_status
                    .ok_or(FactResolutionError::ResponseInvalid)?,
                evidence_refs: ledger.evidence_refs.clone(),
            });
        }
        if matches!(
            command.command_type,
            RuntimeCommandType::Verify | RuntimeCommandType::Complete
        ) {
            let evaluator = self.evaluator.verify(state, command).await?;
            evaluator.validate(state, command, FactKind::Evaluator, &[FactDecision::Pass])?;
            evaluator.append_evidence(&mut resolved.evidence_refs);
            let hard_gates_passed = evaluator
                .attributes
                .get("hard_gates_passed")
                .is_some_and(|value| value == "true");
            if !hard_gates_passed {
                return Err(FactResolutionError::Denied);
            }
            let score = evaluator
                .attributes
                .get("score_millionths")
                .ok_or(FactResolutionError::ResponseInvalid)?
                .parse::<u32>()
                .map_err(|_| FactResolutionError::ResponseInvalid)?;
            if score > 1_000_000 {
                return Err(FactResolutionError::ResponseInvalid);
            }
            resolved.evaluation = Some(passed_evaluation(
                &resolved.evidence_refs,
                evaluator
                    .attributes
                    .get("evaluator_id")
                    .filter(|value| !value.is_empty())
                    .cloned()
                    .ok_or(FactResolutionError::ResponseInvalid)?,
                evaluator
                    .attributes
                    .get("evaluator_version")
                    .filter(|value| !value.is_empty())
                    .cloned()
                    .ok_or(FactResolutionError::ResponseInvalid)?,
                score,
            ));
        }
        Ok(resolved)
    }

    async fn ready(&self) -> bool {
        tokio::time::timeout(Duration::from_millis(1_500), async {
            let (policy, approval, credential, ledger, evaluator, evidence, supervisor) =
                tokio::join!(
                    self.policy.ready(),
                    self.approval.ready(),
                    self.credential.ready(),
                    self.ledger.ready(),
                    self.evaluator.ready(),
                    self.evidence.ready(),
                    self.supervisor.ready(),
                );
            policy && approval && credential && ledger && evaluator && evidence && supervisor
        })
        .await
        .unwrap_or(false)
    }
}

fn parse_execution_status(value: &str) -> Result<ExecutionStatus, FactResolutionError> {
    match value {
        "PREPARED" => Ok(ExecutionStatus::Prepared),
        "RUNNING" => Ok(ExecutionStatus::Running),
        "SUCCEEDED" => Ok(ExecutionStatus::Succeeded),
        "FAILED" => Ok(ExecutionStatus::Failed),
        "TIMED_OUT" => Ok(ExecutionStatus::TimedOut),
        "CANCELLED" => Ok(ExecutionStatus::Cancelled),
        "KILLED" => Ok(ExecutionStatus::Killed),
        "COMPENSATING" => Ok(ExecutionStatus::Compensating),
        "COMPENSATED" => Ok(ExecutionStatus::Compensated),
        "COMPENSATION_FAILED" => Ok(ExecutionStatus::CompensationFailed),
        "UNKNOWN" => Ok(ExecutionStatus::Unknown),
        _ => Err(FactResolutionError::ResponseInvalid),
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FactResolutionError {
    #[error("ORCHESTRATOR_FACT_BINDING_CONFIGURATION_INVALID")]
    Configuration,
    #[error("ORCHESTRATOR_AUTHORITATIVE_FACT_UNAVAILABLE")]
    Unavailable,
    #[error("ORCHESTRATOR_AUTHORITATIVE_FACT_DENIED")]
    Denied,
    #[error("ORCHESTRATOR_AUTHORITATIVE_FACT_RESPONSE_INVALID")]
    ResponseInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        RUNTIME_COMMAND_SCHEMA_VERSION, RUNTIME_STATE_SCHEMA_VERSION, RuntimeWorkflowCommand,
        RuntimeWorkflowState, runtime_command_payload_digest,
    };
    use agent_trust_contracts::TaskStatus;
    use chrono::Duration as ChronoDuration;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct StaticPort(AuthoritativeFact);

    #[derive(Clone)]
    struct OrderedSupervisor {
        calls: Arc<AtomicUsize>,
        fact: AuthoritativeFact,
    }

    #[derive(Clone)]
    struct OrderedCredential {
        calls: Arc<AtomicUsize>,
        fact: AuthoritativeFact,
    }

    #[derive(Clone)]
    struct FailingEvidence {
        calls: Arc<AtomicUsize>,
    }

    macro_rules! static_port {
        ($port:ident) => {
            #[async_trait]
            impl $port for StaticPort {
                async fn verify(
                    &self,
                    state: &RuntimeWorkflowState,
                    command: &RuntimeWorkflowCommand,
                ) -> Result<AuthoritativeFact, FactResolutionError> {
                    Ok(bind_fact(self.0.clone(), state, command))
                }

                async fn ready(&self) -> bool {
                    true
                }
            }
        };
    }

    static_port!(PolicyCheckpointPort);
    static_port!(ApprovalWaitPort);
    static_port!(ExecutionLedgerPort);
    static_port!(EvaluatorPort);
    static_port!(EvidencePort);

    #[async_trait]
    impl CredentialLeasePort for StaticPort {
        async fn verify(
            &self,
            state: &RuntimeWorkflowState,
            command: &RuntimeWorkflowCommand,
        ) -> Result<AuthoritativeFact, FactResolutionError> {
            Ok(bind_fact(self.0.clone(), state, command))
        }

        async fn revoke(
            &self,
            state: &RuntimeWorkflowState,
            command: &RuntimeWorkflowCommand,
        ) -> Result<AuthoritativeFact, FactResolutionError> {
            let mut value = bind_fact(self.0.clone(), state, command);
            value.decision = FactDecision::Revoked;
            Ok(value)
        }

        async fn ready(&self) -> bool {
            true
        }
    }

    #[async_trait]
    impl RuntimeSupervisorPort for StaticPort {
        async fn contain(
            &self,
            state: &RuntimeWorkflowState,
            command: &RuntimeWorkflowCommand,
        ) -> Result<AuthoritativeFact, FactResolutionError> {
            Ok(bind_fact(self.0.clone(), state, command))
        }

        async fn ready(&self) -> bool {
            true
        }
    }

    #[async_trait]
    impl RuntimeSupervisorPort for OrderedSupervisor {
        async fn contain(
            &self,
            state: &RuntimeWorkflowState,
            command: &RuntimeWorkflowCommand,
        ) -> Result<AuthoritativeFact, FactResolutionError> {
            assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 0);
            Ok(bind_fact(self.fact.clone(), state, command))
        }

        async fn ready(&self) -> bool {
            true
        }
    }

    #[async_trait]
    impl CredentialLeasePort for OrderedCredential {
        async fn verify(
            &self,
            _state: &RuntimeWorkflowState,
            _command: &RuntimeWorkflowCommand,
        ) -> Result<AuthoritativeFact, FactResolutionError> {
            panic!("KILL must revoke rather than verify a credential lease")
        }

        async fn revoke(
            &self,
            state: &RuntimeWorkflowState,
            command: &RuntimeWorkflowCommand,
        ) -> Result<AuthoritativeFact, FactResolutionError> {
            assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 1);
            let mut fact = bind_fact(self.fact.clone(), state, command);
            fact.decision = FactDecision::Revoked;
            Ok(fact)
        }

        async fn ready(&self) -> bool {
            true
        }
    }

    #[async_trait]
    impl EvidencePort for FailingEvidence {
        async fn verify(
            &self,
            _state: &RuntimeWorkflowState,
            _command: &RuntimeWorkflowCommand,
        ) -> Result<AuthoritativeFact, FactResolutionError> {
            assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 2);
            Err(FactResolutionError::Unavailable)
        }

        async fn ready(&self) -> bool {
            false
        }
    }

    fn state() -> RuntimeWorkflowState {
        RuntimeWorkflowState {
            schema_version: RUNTIME_STATE_SCHEMA_VERSION.into(),
            tenant_id: "00000000-0000-4000-8000-000000000001".into(),
            task_id: "00000000-0000-4000-8000-000000000002".into(),
            action_id: "00000000-0000-4000-8000-000000000003".into(),
            status: TaskStatus::Created,
            recovery_cursor: 0,
            terminal: false,
            evidence_refs: BTreeSet::new(),
            ingress_digest: "a".repeat(64),
            action_materialization: ActionMaterializationRef {
                schema_version: "agenttrust.action-materialization-ref.v1".into(),
                tenant_id: "00000000-0000-4000-8000-000000000001".into(),
                action_id: "00000000-0000-4000-8000-000000000003".into(),
                payload_hash: "b".repeat(64),
                store: "ORCHESTRATOR_INGRESS_POSTGRESQL".into(),
                uri: "orchestrator-ingress://00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000003".into(),
            },
            has_side_effects: true,
            execution: None,
            processed_commands: BTreeSet::new(),
            processed_command_fingerprints: BTreeMap::new(),
            processed_idempotency_keys: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    fn fact(kind: FactKind, decision: FactDecision) -> AuthoritativeFact {
        let current = state();
        AuthoritativeFact {
            schema_version: FACT_SCHEMA_VERSION.into(),
            fact_kind: kind,
            tenant_id: current.tenant_id,
            task_id: current.task_id,
            action_id: current.action_id,
            command_id: String::new(),
            recovery_cursor: 0,
            payload_digest: String::new(),
            decision,
            immutable_digest: "c".repeat(64),
            evidence_refs: BTreeSet::from([format!("evidence:{kind:?}")]),
            valid_until: Utc::now() + ChronoDuration::hours(1),
            attributes: BTreeMap::from([
                ("execution_status".into(), "SUCCEEDED".into()),
                ("ledger_execution_id".into(), "execution:test".into()),
                ("fence_digest".into(), "d".repeat(64)),
                ("outcome_digest".into(), "e".repeat(64)),
                ("hard_gates_passed".into(), "true".into()),
                ("score_millionths".into(), "1000000".into()),
                ("evaluator_id".into(), "test".into()),
                ("evaluator_version".into(), "1".into()),
            ]),
        }
    }

    fn bind_fact(
        mut value: AuthoritativeFact,
        state: &RuntimeWorkflowState,
        command: &RuntimeWorkflowCommand,
    ) -> AuthoritativeFact {
        value.action_id.clone_from(&state.action_id);
        value.command_id.clone_from(&command.command_id);
        value.recovery_cursor = state.recovery_cursor;
        value.payload_digest.clone_from(&command.payload_digest);
        value
    }

    fn resolver(approval_decision: FactDecision) -> ProductionFactResolver {
        ProductionFactResolver::new(
            Arc::new(StaticPort(fact(
                FactKind::PolicyCheckpoint,
                FactDecision::Verified,
            ))),
            Arc::new(StaticPort(fact(FactKind::Approval, approval_decision))),
            Arc::new(StaticPort(fact(
                FactKind::CredentialLease,
                FactDecision::Active,
            ))),
            Arc::new(StaticPort(fact(
                FactKind::ExecutionLedger,
                FactDecision::Verified,
            ))),
            Arc::new(StaticPort(fact(FactKind::Evaluator, FactDecision::Pass))),
            Arc::new(StaticPort(fact(FactKind::Evidence, FactDecision::Verified))),
            Arc::new(StaticPort(fact(
                FactKind::RuntimeSupervisor,
                FactDecision::Contained,
            ))),
        )
    }

    #[test]
    fn production_fact_binding_requires_https_mtls_and_token() {
        let result = HttpsFactClient::new(
            "http://policy.example/",
            "token".into(),
            Path::new("missing-ca"),
            Path::new("missing-cert"),
            Path::new("missing-key"),
        );
        assert!(matches!(result, Err(FactResolutionError::Configuration)));
        assert_eq!(
            parse_execution_status("NOT_A_LEDGER_STATUS"),
            Err(FactResolutionError::ResponseInvalid)
        );
    }

    #[tokio::test]
    async fn start_facts_come_from_all_authoritative_ports_and_deny_wrong_approval() {
        let current = state();
        let command = RuntimeWorkflowCommand {
            schema_version: RUNTIME_COMMAND_SCHEMA_VERSION.into(),
            command_id: "start:1".into(),
            request_idempotency_key: "request:start:1".into(),
            tenant_id: current.tenant_id.clone(),
            task_id: current.task_id.clone(),
            command_type: RuntimeCommandType::Start,
            expected_state_version: 0,
            payload_digest: runtime_command_payload_digest(RuntimeCommandType::Start),
            requested_by: "user:1".into(),
            requested_at: Utc::now(),
        };
        let resolved = resolver(FactDecision::Granted)
            .resolve(&current, &command)
            .await
            .unwrap_or_else(|error| panic!("resolve: {error}"));
        assert!(resolved.evidence_refs.len() >= 8);
        assert!(!resolved.credential_revoked);
        assert!(matches!(
            resolver(FactDecision::Verified)
                .resolve(&current, &command)
                .await,
            Err(FactResolutionError::Denied)
        ));
    }

    #[tokio::test]
    async fn kill_invokes_supervisor_and_revokes_credentials_before_acknowledgement() {
        let mut current = state();
        current.status = TaskStatus::Running;
        let command = RuntimeWorkflowCommand {
            schema_version: RUNTIME_COMMAND_SCHEMA_VERSION.into(),
            command_id: "kill:1".into(),
            request_idempotency_key: "request:kill:1".into(),
            tenant_id: current.tenant_id.clone(),
            task_id: current.task_id.clone(),
            command_type: RuntimeCommandType::Kill,
            expected_state_version: 0,
            payload_digest: runtime_command_payload_digest(RuntimeCommandType::Kill),
            requested_by: "user:1".into(),
            requested_at: Utc::now(),
        };
        let resolved = resolver(FactDecision::Granted)
            .resolve(&current, &command)
            .await
            .unwrap_or_else(|error| panic!("kill facts: {error}"));
        assert!(resolved.supervisor_acknowledged);
        assert!(resolved.credential_revoked);
        assert_eq!(resolved.ledger_status, None);
    }

    #[tokio::test]
    async fn kill_contains_and_revokes_before_observational_dependencies() {
        let mut current = state();
        current.status = TaskStatus::Running;
        let command = RuntimeWorkflowCommand {
            schema_version: RUNTIME_COMMAND_SCHEMA_VERSION.into(),
            command_id: "kill:ordered".into(),
            request_idempotency_key: "request:kill:ordered".into(),
            tenant_id: current.tenant_id.clone(),
            task_id: current.task_id.clone(),
            command_type: RuntimeCommandType::Kill,
            expected_state_version: 0,
            payload_digest: runtime_command_payload_digest(RuntimeCommandType::Kill),
            requested_by: "user:1".into(),
            requested_at: Utc::now(),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = ProductionFactResolver::new(
            Arc::new(StaticPort(fact(
                FactKind::PolicyCheckpoint,
                FactDecision::Verified,
            ))),
            Arc::new(StaticPort(fact(FactKind::Approval, FactDecision::Granted))),
            Arc::new(OrderedCredential {
                calls: calls.clone(),
                fact: fact(FactKind::CredentialLease, FactDecision::Active),
            }),
            Arc::new(StaticPort(fact(
                FactKind::ExecutionLedger,
                FactDecision::Verified,
            ))),
            Arc::new(StaticPort(fact(FactKind::Evaluator, FactDecision::Pass))),
            Arc::new(FailingEvidence {
                calls: calls.clone(),
            }),
            Arc::new(OrderedSupervisor {
                calls: calls.clone(),
                fact: fact(FactKind::RuntimeSupervisor, FactDecision::Contained),
            }),
        );

        let resolved = resolver
            .resolve(&current, &command)
            .await
            .unwrap_or_else(|error| panic!("kill facts: {error}"));
        assert!(resolved.supervisor_acknowledged);
        assert!(resolved.credential_revoked);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
