//! Tamper-evident audit chains, offline evidence verification, and governed evaluation.

use agent_trust_contracts::{
    ArtifactRef, EvaluationResult, EvaluationStatus, SchemaVersion, TaskId, TenantId,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use thiserror::Error;
use uuid::Uuid;

pub const EVIDENCE_SCHEMA_VERSION: &str = "agenttrust.evidence.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceEventType {
    TaskCreated,
    PlanGenerated,
    PolicyEvaluated,
    ApprovalDecision,
    CredentialIssued,
    ToolPrepared,
    ToolExecuted,
    Compensation,
    Evaluation,
    SecurityAlert,
    StateTransition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEventDraft {
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub event_type: EvidenceEventType,
    pub actor_subject: String,
    pub source_service: String,
    pub trace_id: String,
    pub span_id: String,
    pub payload_hash: String,
    pub safe_summary: String,
    pub artifact_refs: Vec<ArtifactRef>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceEvent {
    pub schema_version: String,
    pub event_id: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub event_hash: String,
    pub key_id: String,
    pub signature: String,
    pub draft: EvidenceEventDraft,
}

impl SignedEvidenceEvent {
    fn unsigned_bytes(&self) -> Result<Vec<u8>, EvidenceError> {
        let mut value = self.clone();
        value.event_hash.clear();
        value.signature.clear();
        serde_jcs::to_vec(&value).map_err(|_| EvidenceError::Canonicalization)
    }
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn append(&self, event: EvidenceEventDraft)
    -> Result<SignedEvidenceEvent, EvidenceError>;
    async fn task_events(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<SignedEvidenceEvent>, EvidenceError>;
}

pub struct InMemoryAuditChain {
    key_id: String,
    signing_key: SigningKey,
    maximum_events_per_task: usize,
    events: Mutex<BTreeMap<TaskId, Vec<SignedEvidenceEvent>>>,
}

impl InMemoryAuditChain {
    pub fn new(
        key_id: String,
        signing_key: SigningKey,
        maximum_events_per_task: usize,
    ) -> Result<Self, EvidenceError> {
        if key_id.is_empty() || maximum_events_per_task == 0 {
            return Err(EvidenceError::ConfigurationInvalid);
        }
        Ok(Self {
            key_id,
            signing_key,
            maximum_events_per_task,
            events: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[async_trait]
impl AuditSink for InMemoryAuditChain {
    async fn append(
        &self,
        draft: EvidenceEventDraft,
    ) -> Result<SignedEvidenceEvent, EvidenceError> {
        validate_draft(&draft)?;
        let mut chains = self.events.lock();
        let chain = chains.entry(draft.task_id.clone()).or_default();
        if chain.len() >= self.maximum_events_per_task {
            return Err(EvidenceError::CapacityExceeded);
        }
        if chain
            .first()
            .is_some_and(|event| event.draft.tenant_id != draft.tenant_id)
        {
            return Err(EvidenceError::TenantMismatch);
        }
        let mut event = SignedEvidenceEvent {
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            event_id: Uuid::new_v4().to_string(),
            sequence: chain.len() as u64 + 1,
            previous_hash: chain
                .last()
                .map_or_else(|| "0".repeat(64), |event| event.event_hash.clone()),
            event_hash: String::new(),
            key_id: self.key_id.clone(),
            signature: String::new(),
            draft,
        };
        event.event_hash = hex(Sha256::digest(event.unsigned_bytes()?));
        event.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(event.event_hash.as_bytes())
                .to_bytes(),
        );
        chain.push(event.clone());
        Ok(event)
    }

    async fn task_events(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<SignedEvidenceEvent>, EvidenceError> {
        Ok(self.events.lock().get(task_id).cloned().unwrap_or_default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredArtifact {
    pub artifact_ref: ArtifactRef,
    pub sha256: String,
    pub media_type: String,
    pub classification: String,
    pub retention_seconds: u64,
    pub access_policy: String,
    pub bytes: u64,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait ArtifactStore: Send + Sync {
    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: String,
        classification: String,
        retention_seconds: u64,
        access_policy: String,
    ) -> Result<StoredArtifact, EvidenceError>;
    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Vec<u8>, EvidenceError>;
}

pub struct InMemoryArtifactStore {
    maximum_artifact_bytes: usize,
    maximum_artifacts: usize,
    objects: RwLock<BTreeMap<ArtifactRef, (StoredArtifact, Vec<u8>)>>,
}

impl InMemoryArtifactStore {
    pub fn new(maximum_artifact_bytes: usize, maximum_artifacts: usize) -> Self {
        Self {
            maximum_artifact_bytes,
            maximum_artifacts,
            objects: RwLock::new(BTreeMap::new()),
        }
    }
}

#[async_trait]
impl ArtifactStore for InMemoryArtifactStore {
    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: String,
        classification: String,
        retention_seconds: u64,
        access_policy: String,
    ) -> Result<StoredArtifact, EvidenceError> {
        if bytes.is_empty()
            || bytes.len() > self.maximum_artifact_bytes
            || media_type.is_empty()
            || classification.is_empty()
            || retention_seconds == 0
            || contains_secret(&bytes)
        {
            return Err(EvidenceError::ArtifactDenied);
        }
        let digest = hex(Sha256::digest(&bytes));
        let artifact_ref = ArtifactRef(format!("artifact:sha256:{digest}"));
        let mut objects = self.objects.write();
        if objects.len() >= self.maximum_artifacts && !objects.contains_key(&artifact_ref) {
            return Err(EvidenceError::CapacityExceeded);
        }
        let artifact = StoredArtifact {
            artifact_ref: artifact_ref.clone(),
            sha256: digest,
            media_type,
            classification,
            retention_seconds,
            access_policy,
            bytes: bytes.len() as u64,
            created_at: Utc::now(),
        };
        objects.insert(artifact_ref, (artifact.clone(), bytes));
        Ok(artifact)
    }

    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Vec<u8>, EvidenceError> {
        self.objects
            .read()
            .get(artifact_ref)
            .map(|(_, bytes)| bytes.clone())
            .ok_or(EvidenceError::ArtifactNotFound)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidencePackage {
    pub schema_version: String,
    pub package_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub events: Vec<SignedEvidenceEvent>,
    pub artifacts: Vec<StoredArtifact>,
    pub package_hash: String,
    pub built_at: DateTime<Utc>,
}

pub struct EvidenceBuilder<A: AuditSink> {
    audit: Arc<A>,
}

impl<A: AuditSink> EvidenceBuilder<A> {
    pub fn new(audit: Arc<A>) -> Self {
        Self { audit }
    }

    pub async fn build(
        &self,
        tenant_id: TenantId,
        task_id: TaskId,
        artifacts: Vec<StoredArtifact>,
    ) -> Result<EvidencePackage, EvidenceError> {
        let events = self.audit.task_events(&task_id).await?;
        if events.is_empty()
            || events
                .iter()
                .any(|event| event.draft.tenant_id != tenant_id)
        {
            return Err(EvidenceError::ChainIncomplete);
        }
        let mut package = EvidencePackage {
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            package_id: Uuid::new_v4().to_string(),
            tenant_id,
            task_id,
            events,
            artifacts,
            package_hash: String::new(),
            built_at: Utc::now(),
        };
        package.package_hash = package_hash(&package)?;
        Ok(package)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceIntegrityReport {
    pub valid: bool,
    pub verified_events: usize,
    pub verified_artifacts: usize,
    pub findings: Vec<String>,
}

pub struct EvidenceChainVerifier {
    keys: BTreeMap<String, VerifyingKey>,
}

impl EvidenceChainVerifier {
    pub fn new(keys: BTreeMap<String, VerifyingKey>) -> Self {
        Self { keys }
    }

    pub fn verify(&self, package: &EvidencePackage) -> EvidenceIntegrityReport {
        let result = self.verify_inner(package);
        match result {
            Ok(()) => EvidenceIntegrityReport {
                valid: true,
                verified_events: package.events.len(),
                verified_artifacts: package.artifacts.len(),
                findings: vec![],
            },
            Err(error) => EvidenceIntegrityReport {
                valid: false,
                verified_events: 0,
                verified_artifacts: 0,
                findings: vec![error.to_string()],
            },
        }
    }

    fn verify_inner(&self, package: &EvidencePackage) -> Result<(), EvidenceError> {
        if package.schema_version != EVIDENCE_SCHEMA_VERSION
            || package.package_hash != package_hash(package)?
            || package.events.is_empty()
        {
            return Err(EvidenceError::IntegrityInvalid);
        }
        let mut previous = "0".repeat(64);
        for (index, event) in package.events.iter().enumerate() {
            if event.sequence != index as u64 + 1
                || event.previous_hash != previous
                || event.draft.task_id != package.task_id
                || event.draft.tenant_id != package.tenant_id
                || event.event_hash != hex(Sha256::digest(event.unsigned_bytes()?))
            {
                return Err(EvidenceError::IntegrityInvalid);
            }
            let key = self
                .keys
                .get(&event.key_id)
                .ok_or(EvidenceError::UnknownKey)?;
            let signature = Signature::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(&event.signature)
                    .map_err(|_| EvidenceError::SignatureInvalid)?,
            )
            .map_err(|_| EvidenceError::SignatureInvalid)?;
            key.verify(event.event_hash.as_bytes(), &signature)
                .map_err(|_| EvidenceError::SignatureInvalid)?;
            previous.clone_from(&event.event_hash);
        }
        for artifact in &package.artifacts {
            if artifact.artifact_ref.0 != format!("artifact:sha256:{}", artifact.sha256) {
                return Err(EvidenceError::IntegrityInvalid);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationInput {
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub identity_valid: bool,
    pub tool_registered: bool,
    pub policy_allowed: bool,
    pub approval_satisfied: bool,
    pub credential_valid: bool,
    pub trace_complete: bool,
    pub ledger_terminal_known: bool,
    pub unhandled_high_risk_alerts: u32,
    pub evidence_refs: Vec<ArtifactRef>,
    pub domain_input: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainEvaluation {
    pub checks: BTreeMap<String, bool>,
    pub score_millionths: u32,
    pub findings: Vec<String>,
    pub evidence_refs: Vec<ArtifactRef>,
    pub uncertain: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorManifest {
    pub evaluator_id: String,
    pub version: String,
    pub implementation_digest: String,
    pub calibration_dataset_ref: String,
    pub maximum_runtime_ms: u64,
    pub signer_key_id: String,
    pub signature: String,
}

#[async_trait]
pub trait DomainEvaluatorPlugin: Send + Sync {
    fn manifest(&self) -> EvaluatorManifest;
    async fn evaluate(&self, input: &Value) -> Result<DomainEvaluation, EvidenceError>;
}

pub struct EvaluatorRuntime<P: DomainEvaluatorPlugin> {
    plugin: Arc<P>,
}

impl<P: DomainEvaluatorPlugin> EvaluatorRuntime<P> {
    pub fn new(plugin: Arc<P>) -> Self {
        Self { plugin }
    }

    pub async fn evaluate(
        &self,
        input: EvaluationInput,
    ) -> Result<EvaluationResult, EvidenceError> {
        let manifest = self.plugin.manifest();
        validate_manifest(&manifest)?;
        let mut hard_gates = BTreeMap::from([
            ("identity_valid".into(), input.identity_valid),
            ("tool_registered".into(), input.tool_registered),
            ("policy_allowed".into(), input.policy_allowed),
            ("approval_satisfied".into(), input.approval_satisfied),
            ("credential_valid".into(), input.credential_valid),
            ("trace_complete".into(), input.trace_complete),
            ("ledger_terminal_known".into(), input.ledger_terminal_known),
            (
                "no_unhandled_high_risk_alerts".into(),
                input.unhandled_high_risk_alerts == 0,
            ),
        ]);
        let domain = tokio::time::timeout(
            Duration::from_millis(manifest.maximum_runtime_ms),
            self.plugin.evaluate(&input.domain_input),
        )
        .await
        .map_err(|_| EvidenceError::EvaluatorTimeout)??;
        hard_gates.extend(domain.checks.clone());
        let all_pass = hard_gates.values().all(|value| *value);
        let status = if all_pass && !domain.uncertain {
            EvaluationStatus::Pass
        } else if domain.uncertain {
            EvaluationStatus::NeedsHuman
        } else {
            EvaluationStatus::Fail
        };
        let mut evidence_refs = input.evidence_refs;
        evidence_refs.extend(domain.evidence_refs);
        if evidence_refs.is_empty() && status == EvaluationStatus::Pass {
            return Err(EvidenceError::ChainIncomplete);
        }
        Ok(EvaluationResult {
            schema_version: SchemaVersion("agenttrust.evaluation.v1".into()),
            status,
            score_millionths: domain.score_millionths.min(1_000_000),
            hard_gate_results: hard_gates,
            findings: domain.findings,
            evidence_refs,
            evaluator_id: manifest.evaluator_id,
            evaluator_version: manifest.version,
            evaluated_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisputeCase {
    pub dispute_id: String,
    pub task_id: TaskId,
    pub evaluation_hash: String,
    pub reason: String,
    pub opened_by: String,
    pub opened_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct EvaluationDisputeService {
    cases: RwLock<BTreeMap<String, DisputeCase>>,
}

impl EvaluationDisputeService {
    pub fn open(&self, mut case: DisputeCase) -> Result<DisputeCase, EvidenceError> {
        if case.reason.is_empty() || case.opened_by.is_empty() || case.evaluation_hash.len() != 64 {
            return Err(EvidenceError::EvaluationInvalid);
        }
        case.dispute_id = Uuid::new_v4().to_string();
        self.cases
            .write()
            .insert(case.dispute_id.clone(), case.clone());
        Ok(case)
    }
}

fn validate_draft(draft: &EvidenceEventDraft) -> Result<(), EvidenceError> {
    if draft.actor_subject.is_empty()
        || draft.source_service.is_empty()
        || draft.trace_id.is_empty()
        || draft.span_id.is_empty()
        || draft.safe_summary.len() > 512
        || draft.payload_hash.len() != 64
        || !draft
            .payload_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || contains_secret(draft.safe_summary.as_bytes())
    {
        return Err(EvidenceError::EventInvalid);
    }
    Ok(())
}

fn validate_manifest(manifest: &EvaluatorManifest) -> Result<(), EvidenceError> {
    if manifest.evaluator_id.is_empty()
        || manifest.version.is_empty()
        || manifest.calibration_dataset_ref.is_empty()
        || manifest.maximum_runtime_ms == 0
        || manifest.maximum_runtime_ms > 60_000
        || !manifest.implementation_digest.starts_with("sha256:")
    {
        return Err(EvidenceError::EvaluationInvalid);
    }
    Ok(())
}

fn package_hash(package: &EvidencePackage) -> Result<String, EvidenceError> {
    let mut copy = package.clone();
    copy.package_hash.clear();
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(&copy).map_err(|_| EvidenceError::Canonicalization)?,
    )))
}

fn contains_secret(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    [
        "password=",
        "api_key=",
        "authorization: bearer",
        "-----begin private key-----",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("EVIDENCE_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("EVIDENCE_EVENT_INVALID")]
    EventInvalid,
    #[error("EVIDENCE_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[error("EVIDENCE_TENANT_MISMATCH")]
    TenantMismatch,
    #[error("EVIDENCE_CANONICALIZATION_FAILED")]
    Canonicalization,
    #[error("EVIDENCE_CHAIN_INCOMPLETE")]
    ChainIncomplete,
    #[error("EVIDENCE_INTEGRITY_INVALID")]
    IntegrityInvalid,
    #[error("EVIDENCE_UNKNOWN_KEY")]
    UnknownKey,
    #[error("EVIDENCE_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("EVIDENCE_ARTIFACT_DENIED")]
    ArtifactDenied,
    #[error("EVIDENCE_ARTIFACT_NOT_FOUND")]
    ArtifactNotFound,
    #[error("EVALUATOR_TIMEOUT")]
    EvaluatorTimeout,
    #[error("EVALUATION_INVALID")]
    EvaluationInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(
        task_id: TaskId,
        tenant_id: TenantId,
        event_type: EvidenceEventType,
    ) -> EvidenceEventDraft {
        EvidenceEventDraft {
            tenant_id,
            task_id,
            event_type,
            actor_subject: "user:1".into(),
            source_service: "test".into(),
            trace_id: "trace-1".into(),
            span_id: "span-1".into(),
            payload_hash: "a".repeat(64),
            safe_summary: "safe".into(),
            artifact_refs: vec![],
            occurred_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn tamper_delete_and_reorder_are_detected() {
        let key = SigningKey::from_bytes(&[31u8; 32]);
        let audit = Arc::new(
            InMemoryAuditChain::new("evidence-key".into(), key, 10)
                .unwrap_or_else(|_| panic!("audit")),
        );
        let task = TaskId::new();
        let tenant = TenantId::new();
        audit
            .append(draft(
                task.clone(),
                tenant.clone(),
                EvidenceEventType::TaskCreated,
            ))
            .await
            .unwrap_or_else(|_| panic!("event"));
        audit
            .append(draft(
                task.clone(),
                tenant.clone(),
                EvidenceEventType::PolicyEvaluated,
            ))
            .await
            .unwrap_or_else(|_| panic!("event"));
        let package = EvidenceBuilder::new(audit.clone())
            .build(tenant, task, vec![])
            .await
            .unwrap_or_else(|_| panic!("package"));
        let verifier = EvidenceChainVerifier::new(BTreeMap::from([(
            "evidence-key".into(),
            audit.verifying_key(),
        )]));
        assert!(verifier.verify(&package).valid);
        let mut tampered = package.clone();
        tampered.events[0].draft.safe_summary = "changed".into();
        assert!(!verifier.verify(&tampered).valid);
        let mut deleted = package.clone();
        deleted.events.remove(0);
        assert!(!verifier.verify(&deleted).valid);
        let mut reordered = package;
        reordered.events.reverse();
        assert!(!verifier.verify(&reordered).valid);
    }

    struct CodingEvaluator;
    #[async_trait]
    impl DomainEvaluatorPlugin for CodingEvaluator {
        fn manifest(&self) -> EvaluatorManifest {
            EvaluatorManifest {
                evaluator_id: "coding".into(),
                version: "1.0.0".into(),
                implementation_digest: format!("sha256:{}", "b".repeat(64)),
                calibration_dataset_ref: "dataset:coding-v1".into(),
                maximum_runtime_ms: 1000,
                signer_key_id: "publisher".into(),
                signature: "signed-manifest".into(),
            }
        }
        async fn evaluate(&self, input: &Value) -> Result<DomainEvaluation, EvidenceError> {
            Ok(DomainEvaluation {
                checks: BTreeMap::from([(
                    "compile_passed".into(),
                    input
                        .get("compile_passed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                )]),
                score_millionths: 900_000,
                findings: vec![],
                evidence_refs: vec![ArtifactRef("artifact:compile".into())],
                uncertain: false,
            })
        }
    }

    #[tokio::test]
    async fn tool_success_does_not_override_missing_approval_or_failed_compile() {
        let runtime = EvaluatorRuntime::new(Arc::new(CodingEvaluator));
        let base = EvaluationInput {
            tenant_id: TenantId::new(),
            task_id: TaskId::new(),
            identity_valid: true,
            tool_registered: true,
            policy_allowed: true,
            approval_satisfied: false,
            credential_valid: true,
            trace_complete: true,
            ledger_terminal_known: true,
            unhandled_high_risk_alerts: 0,
            evidence_refs: vec![],
            domain_input: serde_json::json!({"compile_passed":true}),
        };
        let result = runtime
            .evaluate(base)
            .await
            .unwrap_or_else(|_| panic!("evaluation"));
        assert_eq!(result.status, EvaluationStatus::Fail);
        let failed = runtime
            .evaluate(EvaluationInput {
                approval_satisfied: true,
                domain_input: serde_json::json!({"compile_passed":false}),
                ..EvaluationInput {
                    tenant_id: TenantId::new(),
                    task_id: TaskId::new(),
                    identity_valid: true,
                    tool_registered: true,
                    policy_allowed: true,
                    approval_satisfied: false,
                    credential_valid: true,
                    trace_complete: true,
                    ledger_terminal_known: true,
                    unhandled_high_risk_alerts: 0,
                    evidence_refs: vec![],
                    domain_input: Value::Null,
                }
            })
            .await
            .unwrap_or_else(|_| panic!("evaluation"));
        assert_eq!(failed.status, EvaluationStatus::Fail);
    }

    #[tokio::test]
    async fn artifact_store_blocks_secret_material() {
        let store = InMemoryArtifactStore::new(1024, 4);
        assert_eq!(
            store
                .put(
                    b"password=secret".to_vec(),
                    "text/plain".into(),
                    "RESTRICTED".into(),
                    60,
                    "tenant-only".into()
                )
                .await
                .err(),
            Some(EvidenceError::ArtifactDenied)
        );
    }
}
