//! Incident containment, safe replay, and release gate engine.

use agent_trust_contracts::{AuthorizationLease, RiskLevel, TaskId, TenantId};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const INCIDENT_SCHEMA_VERSION: &str = "agenttrust.incident-release.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentStatus {
    Detected,
    Triaged,
    Contained,
    Investigating,
    Remediating,
    Recertifying,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Incident {
    pub schema_version: String,
    pub incident_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub detection_id: String,
    pub severity: RiskLevel,
    pub status: IncidentStatus,
    pub owner: String,
    pub scope: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
    pub legal_hold_id: String,
    pub timeline: Vec<IncidentTimelineEntry>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentTimelineEntry {
    pub event_id: String,
    pub from: IncidentStatus,
    pub to: IncidentStatus,
    pub actor: String,
    pub reason_code: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IncidentSnapshot {
    schema_version: String,
    incidents: Vec<Incident>,
    detection_index: BTreeMap<(TenantId, String), String>,
}

pub struct IncidentService {
    maximum_incidents: usize,
    incidents: RwLock<BTreeMap<(TenantId, String), Incident>>,
    detection_index: RwLock<BTreeMap<(TenantId, String), String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentCreateRequest {
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub detection_id: String,
    pub severity: RiskLevel,
    pub owner: String,
    pub scope: BTreeSet<String>,
    pub evidence_refs: BTreeSet<String>,
}

impl IncidentService {
    pub fn new(maximum_incidents: usize) -> Result<Self, IncidentError> {
        if maximum_incidents == 0 {
            return Err(IncidentError::ConfigurationInvalid);
        }
        Ok(Self {
            maximum_incidents,
            incidents: RwLock::new(BTreeMap::new()),
            detection_index: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn create(&self, request: IncidentCreateRequest) -> Result<Incident, IncidentError> {
        if request.detection_id.is_empty()
            || request.owner.is_empty()
            || request.scope.is_empty()
            || request.scope.iter().any(String::is_empty)
            || request.evidence_refs.is_empty()
            || request.evidence_refs.iter().any(String::is_empty)
        {
            return Err(IncidentError::IncidentInvalid);
        }
        if let Some(incident_id) = self
            .detection_index
            .read()
            .get(&(request.tenant_id.clone(), request.detection_id.clone()))
            .cloned()
        {
            return self.get(&request.tenant_id, &incident_id);
        }
        let mut incidents = self.incidents.write();
        if incidents.len() >= self.maximum_incidents {
            return Err(IncidentError::CapacityExceeded);
        }
        let incident_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let incident = Incident {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            incident_id: incident_id.clone(),
            tenant_id: request.tenant_id.clone(),
            task_id: request.task_id,
            detection_id: request.detection_id.clone(),
            severity: request.severity,
            status: IncidentStatus::Detected,
            owner: request.owner,
            scope: request.scope,
            evidence_refs: request.evidence_refs,
            legal_hold_id: format!("incident-hold:{incident_id}"),
            timeline: vec![],
            created_at: now,
            updated_at: now,
        };
        incidents.insert(
            (request.tenant_id.clone(), incident_id.clone()),
            incident.clone(),
        );
        self.detection_index
            .write()
            .insert((request.tenant_id, request.detection_id), incident_id);
        Ok(incident)
    }

    pub fn transition(
        &self,
        tenant: &TenantId,
        incident_id: &str,
        to: IncidentStatus,
        actor: &str,
        reason_code: &str,
    ) -> Result<Incident, IncidentError> {
        if actor.is_empty() || reason_code.is_empty() {
            return Err(IncidentError::IncidentInvalid);
        }
        let mut incidents = self.incidents.write();
        let incident = incidents
            .get_mut(&(tenant.clone(), incident_id.into()))
            .ok_or(IncidentError::NotFound)?;
        if !incident_transition_allowed(incident.status, to) {
            return Err(IncidentError::TransitionDenied);
        }
        let now = Utc::now();
        incident.timeline.push(IncidentTimelineEntry {
            event_id: Uuid::new_v4().to_string(),
            from: incident.status,
            to,
            actor: actor.into(),
            reason_code: reason_code.into(),
            occurred_at: now,
        });
        incident.status = to;
        incident.updated_at = now;
        Ok(incident.clone())
    }

    pub fn get(&self, tenant: &TenantId, incident_id: &str) -> Result<Incident, IncidentError> {
        self.incidents
            .read()
            .get(&(tenant.clone(), incident_id.into()))
            .cloned()
            .ok_or(IncidentError::NotFound)
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, IncidentError> {
        serde_json::to_vec(&IncidentSnapshot {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            incidents: self.incidents.read().values().cloned().collect(),
            detection_index: self.detection_index.read().clone(),
        })
        .map_err(|_| IncidentError::PersistenceFailed)
    }

    pub fn restore(bytes: &[u8], maximum_incidents: usize) -> Result<Self, IncidentError> {
        let snapshot: IncidentSnapshot =
            serde_json::from_slice(bytes).map_err(|_| IncidentError::PersistenceFailed)?;
        if snapshot.schema_version != INCIDENT_SCHEMA_VERSION
            || snapshot.incidents.len() > maximum_incidents
        {
            return Err(IncidentError::PersistenceFailed);
        }
        let incidents = snapshot
            .incidents
            .into_iter()
            .map(|incident| {
                (
                    (incident.tenant_id.clone(), incident.incident_id.clone()),
                    incident,
                )
            })
            .collect();
        Ok(Self {
            maximum_incidents,
            incidents: RwLock::new(incidents),
            detection_index: RwLock::new(snapshot.detection_index),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentReceipt {
    pub schema_version: String,
    pub incident_id: String,
    pub containment_id: String,
    pub task_killed: bool,
    pub credential_revoked: bool,
    pub integrations_isolated: BTreeSet<String>,
    pub artifacts_frozen: bool,
    pub complete: bool,
    pub evidence_refs: BTreeSet<String>,
    pub contained_at: DateTime<Utc>,
}

#[async_trait]
pub trait ContainmentPort: Send + Sync {
    async fn kill_task(
        &self,
        tenant: &TenantId,
        task: &TaskId,
        idempotency_key: &str,
    ) -> Result<String, IncidentError>;
    async fn revoke_credentials(
        &self,
        tenant: &TenantId,
        task: &TaskId,
        idempotency_key: &str,
    ) -> Result<String, IncidentError>;
    async fn isolate_integration(
        &self,
        tenant: &TenantId,
        resource: &str,
        idempotency_key: &str,
    ) -> Result<String, IncidentError>;
    async fn freeze_artifacts(
        &self,
        tenant: &TenantId,
        incident_id: &str,
        idempotency_key: &str,
    ) -> Result<String, IncidentError>;
}

pub struct ContainmentController<P: ContainmentPort> {
    port: Arc<P>,
    receipts: Mutex<BTreeMap<String, ContainmentReceipt>>,
}

impl<P: ContainmentPort> ContainmentController<P> {
    pub fn new(port: Arc<P>) -> Self {
        Self {
            port,
            receipts: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn contain(&self, incident: &Incident) -> Result<ContainmentReceipt, IncidentError> {
        if let Some(receipt) = self.receipts.lock().get(&incident.incident_id).cloned() {
            return Ok(receipt);
        }
        let base = format!("contain:{}", incident.incident_id);
        let mut evidence_refs = BTreeSet::new();
        evidence_refs.insert(
            self.port
                .kill_task(
                    &incident.tenant_id,
                    &incident.task_id,
                    &format!("{base}:kill"),
                )
                .await?,
        );
        evidence_refs.insert(
            self.port
                .revoke_credentials(
                    &incident.tenant_id,
                    &incident.task_id,
                    &format!("{base}:revoke"),
                )
                .await?,
        );
        let mut integrations_isolated = BTreeSet::new();
        for resource in &incident.scope {
            evidence_refs.insert(
                self.port
                    .isolate_integration(
                        &incident.tenant_id,
                        resource,
                        &format!("{base}:isolate:{resource}"),
                    )
                    .await?,
            );
            integrations_isolated.insert(resource.clone());
        }
        evidence_refs.insert(
            self.port
                .freeze_artifacts(
                    &incident.tenant_id,
                    &incident.incident_id,
                    &format!("{base}:freeze"),
                )
                .await?,
        );
        let receipt = ContainmentReceipt {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            incident_id: incident.incident_id.clone(),
            containment_id: Uuid::new_v4().to_string(),
            task_killed: true,
            credential_revoked: true,
            integrations_isolated,
            artifacts_frozen: true,
            complete: true,
            evidence_refs,
            contained_at: Utc::now(),
        };
        self.receipts
            .lock()
            .insert(incident.incident_id.clone(), receipt.clone());
        Ok(receipt)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayMode {
    Logical,
    Sandbox,
    Live,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayPlan {
    pub schema_version: String,
    pub replay_id: String,
    pub incident_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub mode: ReplayMode,
    pub action_hashes: Vec<String>,
    pub resource_refs: Vec<String>,
    pub credential_profile: Option<String>,
    pub authorization_lease: Option<AuthorizationLease>,
    pub approval_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayRun {
    pub schema_version: String,
    pub replay_id: String,
    pub mode: ReplayMode,
    pub side_effect_count: u32,
    pub action_results: Vec<String>,
    pub evidence_digest: String,
    pub completed_at: DateTime<Utc>,
}

#[async_trait]
pub trait ReplayExecutor: Send + Sync {
    async fn execute(&self, plan: &ReplayPlan, action_hash: &str) -> Result<String, IncidentError>;
}

pub struct ReplayEngine<E: ReplayExecutor> {
    executor: Arc<E>,
}

impl<E: ReplayExecutor> ReplayEngine<E> {
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }

    pub async fn run(
        &self,
        plan: &ReplayPlan,
        now: DateTime<Utc>,
    ) -> Result<ReplayRun, IncidentError> {
        validate_replay_plan(plan, now)?;
        let mut results = Vec::new();
        let side_effect_count = match plan.mode {
            ReplayMode::Logical => {
                results.extend(
                    plan.action_hashes
                        .iter()
                        .map(|hash| format!("logical:{hash}:evaluated")),
                );
                0
            }
            ReplayMode::Sandbox | ReplayMode::Live => {
                for action in &plan.action_hashes {
                    results.push(self.executor.execute(plan, action).await?);
                }
                plan.action_hashes.len() as u32
            }
        };
        let evidence_digest = hex(Sha256::digest(
            serde_jcs::to_vec(&(plan, &results)).map_err(|_| IncidentError::Canonicalization)?,
        ));
        Ok(ReplayRun {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            replay_id: plan.replay_id.clone(),
            mode: plan.mode,
            side_effect_count,
            action_results: results,
            evidence_digest,
            completed_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootCauseFinding {
    pub finding_id: String,
    pub category: String,
    pub trigger: String,
    pub control_gap: String,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Remediation {
    pub remediation_id: String,
    pub finding_id: String,
    pub policy_ref: String,
    pub test_ref: String,
    pub owner: String,
    pub due_at: DateTime<Utc>,
}

pub struct RootCauseWorkflow;

impl RootCauseWorkflow {
    pub fn publish(
        findings: &[RootCauseFinding],
        remediations: &[Remediation],
    ) -> Result<String, IncidentError> {
        if findings.is_empty()
            || findings
                .iter()
                .any(|finding| finding.evidence_refs.is_empty())
            || remediations.is_empty()
            || findings.iter().any(|finding| {
                !remediations.iter().any(|remediation| {
                    remediation.finding_id == finding.finding_id
                        && !remediation.policy_ref.is_empty()
                        && !remediation.test_ref.is_empty()
                        && !remediation.owner.is_empty()
                })
            })
        {
            return Err(IncidentError::RootCauseIncomplete);
        }
        Ok(hex(Sha256::digest(
            serde_jcs::to_vec(&(findings, remediations))
                .map_err(|_| IncidentError::Canonicalization)?,
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseGateDefinition {
    pub schema_version: String,
    pub gate_id: String,
    pub version: String,
    pub required_controls: BTreeSet<String>,
    pub maximum_evidence_age_seconds: u64,
    pub definition_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateEvidence {
    pub control_id: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub passed: bool,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseCertificate {
    pub schema_version: String,
    pub certificate_id: String,
    pub release_digest: String,
    pub gate_id: String,
    pub gate_version: String,
    pub definition_digest: String,
    pub evidence_digests: BTreeMap<String, String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub engine_certificate_only: bool,
    pub production_closure: bool,
    pub key_id: String,
    pub signature: String,
}

impl ReleaseCertificate {
    fn signing_bytes(&self) -> Result<Vec<u8>, IncidentError> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| IncidentError::Canonicalization)
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), IncidentError> {
        if now < self.valid_from
            || now >= self.valid_until
            || self.production_closure
            || !self.engine_certificate_only
        {
            return Err(IncidentError::CertificateInvalid);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| IncidentError::CertificateInvalid)?;
        let signature =
            Signature::from_slice(&decoded).map_err(|_| IncidentError::CertificateInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| IncidentError::CertificateInvalid)
    }
}

pub struct ReleaseGateEngine {
    key_id: String,
    signing_key: SigningKey,
}

impl ReleaseGateEngine {
    pub fn new(key_id: String, signing_key: SigningKey) -> Result<Self, IncidentError> {
        if key_id.is_empty() {
            return Err(IncidentError::ConfigurationInvalid);
        }
        Ok(Self {
            key_id,
            signing_key,
        })
    }

    pub fn evaluate(
        &self,
        definition: &ReleaseGateDefinition,
        release_digest: &str,
        evidence: &[GateEvidence],
        now: DateTime<Utc>,
    ) -> Result<ReleaseCertificate, IncidentError> {
        if definition.schema_version != INCIDENT_SCHEMA_VERSION
            || definition.gate_id.is_empty()
            || definition.version.is_empty()
            || definition.required_controls.is_empty()
            || definition.maximum_evidence_age_seconds == 0
            || definition.definition_digest.len() != 64
            || release_digest.len() != 64
        {
            return Err(IncidentError::GateDefinitionInvalid);
        }
        let mut evidence_digests = BTreeMap::new();
        for control in &definition.required_controls {
            let item = evidence
                .iter()
                .find(|item| &item.control_id == control)
                .ok_or(IncidentError::EvidenceMissing)?;
            if !item.passed
                || item.evidence_ref.is_empty()
                || item.evidence_digest.len() != 64
                || now.signed_duration_since(item.collected_at).num_seconds() < 0
                || now.signed_duration_since(item.collected_at).num_seconds() as u64
                    > definition.maximum_evidence_age_seconds
            {
                return Err(IncidentError::EvidenceFailed);
            }
            evidence_digests.insert(control.clone(), item.evidence_digest.clone());
        }
        let mut certificate = ReleaseCertificate {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            certificate_id: Uuid::new_v4().to_string(),
            release_digest: release_digest.into(),
            gate_id: definition.gate_id.clone(),
            gate_version: definition.version.clone(),
            definition_digest: definition.definition_digest.clone(),
            evidence_digests,
            valid_from: now,
            valid_until: now + Duration::days(7),
            engine_certificate_only: true,
            production_closure: false,
            key_id: self.key_id.clone(),
            signature: String::new(),
        };
        certificate.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(&certificate.signing_bytes()?)
                .to_bytes(),
        );
        Ok(certificate)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecertificationTrigger {
    pub schema_version: String,
    pub incident_id: String,
    pub release_digest: String,
    pub root_cause_digest: String,
    pub required_campaigns: BTreeSet<String>,
    pub requested_by: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CampaignAttestation {
    pub campaign_id: String,
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub passed: bool,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecertificationReceipt {
    pub schema_version: String,
    pub recertification_id: String,
    pub incident_id: String,
    pub root_cause_digest: String,
    pub campaign_attestations: BTreeMap<String, CampaignAttestation>,
    pub release_certificate: ReleaseCertificate,
    pub evidence_digest: String,
    pub completed_at: DateTime<Utc>,
}

#[async_trait]
pub trait RecertificationPort: Send + Sync {
    async fn run_campaign(
        &self,
        trigger: &RecertificationTrigger,
        campaign_id: &str,
        idempotency_key: &str,
    ) -> Result<CampaignAttestation, IncidentError>;

    async fn collect_control_evidence(
        &self,
        trigger: &RecertificationTrigger,
        control_id: &str,
    ) -> Result<GateEvidence, IncidentError>;
}

pub struct RecertificationRunner<'a, P: RecertificationPort> {
    port: Arc<P>,
    gate_engine: &'a ReleaseGateEngine,
}

impl<'a, P: RecertificationPort> RecertificationRunner<'a, P> {
    pub fn new(port: Arc<P>, gate_engine: &'a ReleaseGateEngine) -> Self {
        Self { port, gate_engine }
    }

    pub async fn run(
        &self,
        trigger: &RecertificationTrigger,
        definition: &ReleaseGateDefinition,
        now: DateTime<Utc>,
    ) -> Result<RecertificationReceipt, IncidentError> {
        if trigger.schema_version != INCIDENT_SCHEMA_VERSION
            || trigger.incident_id.is_empty()
            || trigger.requested_by.is_empty()
            || trigger.release_digest.len() != 64
            || trigger.root_cause_digest.len() != 64
            || trigger.required_campaigns.is_empty()
            || trigger.required_campaigns.len() > 64
            || trigger.requested_at > now
        {
            return Err(IncidentError::RecertificationInvalid);
        }
        let campaign_controls = trigger
            .required_campaigns
            .iter()
            .map(|campaign| format!("campaign:{campaign}"))
            .collect::<BTreeSet<_>>();
        if !campaign_controls.is_subset(&definition.required_controls) {
            return Err(IncidentError::RecertificationInvalid);
        }

        let mut attestations = BTreeMap::new();
        let mut evidence = Vec::new();
        for campaign in &trigger.required_campaigns {
            let attestation = self
                .port
                .run_campaign(
                    trigger,
                    campaign,
                    &format!("recertify:{}:{campaign}", trigger.incident_id),
                )
                .await?;
            if attestation.campaign_id != *campaign
                || !attestation.passed
                || attestation.evidence_ref.is_empty()
                || attestation.evidence_digest.len() != 64
                || attestation.completed_at < trigger.requested_at
            {
                return Err(IncidentError::RecertificationFailed);
            }
            evidence.push(GateEvidence {
                control_id: format!("campaign:{campaign}"),
                evidence_ref: attestation.evidence_ref.clone(),
                evidence_digest: attestation.evidence_digest.clone(),
                passed: true,
                collected_at: attestation.completed_at,
            });
            attestations.insert(campaign.clone(), attestation);
        }
        for control_id in definition.required_controls.difference(&campaign_controls) {
            let item = self
                .port
                .collect_control_evidence(trigger, control_id)
                .await?;
            if item.control_id != *control_id {
                return Err(IncidentError::RecertificationFailed);
            }
            evidence.push(item);
        }
        let gate_now = std::cmp::max(now, Utc::now());
        if evidence.iter().any(|item| item.collected_at > gate_now) {
            return Err(IncidentError::RecertificationFailed);
        }
        let certificate =
            self.gate_engine
                .evaluate(definition, &trigger.release_digest, &evidence, gate_now)?;
        let completed_at = Utc::now();
        let evidence_digest = hex(Sha256::digest(
            serde_jcs::to_vec(&(
                trigger,
                definition,
                &attestations,
                &certificate,
                completed_at,
            ))
            .map_err(|_| IncidentError::Canonicalization)?,
        ));
        Ok(RecertificationReceipt {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            recertification_id: Uuid::new_v4().to_string(),
            incident_id: trigger.incident_id.clone(),
            root_cause_digest: trigger.root_cause_digest.clone(),
            campaign_attestations: attestations,
            release_certificate: certificate,
            evidence_digest,
            completed_at,
        })
    }
}

fn incident_transition_allowed(from: IncidentStatus, to: IncidentStatus) -> bool {
    matches!(
        (from, to),
        (IncidentStatus::Detected, IncidentStatus::Triaged)
            | (IncidentStatus::Triaged, IncidentStatus::Contained)
            | (IncidentStatus::Contained, IncidentStatus::Investigating)
            | (IncidentStatus::Investigating, IncidentStatus::Remediating)
            | (IncidentStatus::Remediating, IncidentStatus::Recertifying)
            | (IncidentStatus::Recertifying, IncidentStatus::Closed)
    )
}

fn validate_replay_plan(plan: &ReplayPlan, now: DateTime<Utc>) -> Result<(), IncidentError> {
    if plan.schema_version != INCIDENT_SCHEMA_VERSION
        || plan.replay_id.is_empty()
        || plan.incident_id.is_empty()
        || plan.action_hashes.is_empty()
        || plan.action_hashes.iter().any(|hash| hash.len() != 64)
    {
        return Err(IncidentError::ReplayDenied);
    }
    match plan.mode {
        ReplayMode::Logical => {
            if plan.credential_profile.is_some()
                || plan.authorization_lease.is_some()
                || plan.approval_id.is_some()
            {
                return Err(IncidentError::ReplayDenied);
            }
        }
        ReplayMode::Sandbox => {
            if plan.credential_profile.as_deref() != Some("test-only")
                || plan
                    .resource_refs
                    .iter()
                    .any(|resource| !resource.starts_with("sandbox://"))
            {
                return Err(IncidentError::ReplayDenied);
            }
        }
        ReplayMode::Live => {
            let lease = plan
                .authorization_lease
                .as_ref()
                .ok_or(IncidentError::LiveReplayAuthorizationMissing)?;
            if plan.approval_id.as_deref().is_none_or(str::is_empty)
                || lease.task_id != plan.task_id
                || lease.valid_until <= now
                || lease.revocation_epoch == 0
            {
                return Err(IncidentError::LiveReplayAuthorizationMissing);
            }
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
pub enum IncidentError {
    #[error("INCIDENT_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("INCIDENT_INVALID")]
    IncidentInvalid,
    #[error("INCIDENT_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[error("INCIDENT_NOT_FOUND")]
    NotFound,
    #[error("INCIDENT_TRANSITION_DENIED")]
    TransitionDenied,
    #[error("INCIDENT_PERSISTENCE_FAILED")]
    PersistenceFailed,
    #[error("INCIDENT_CONTAINMENT_FAILED")]
    ContainmentFailed,
    #[error("INCIDENT_REPLAY_DENIED")]
    ReplayDenied,
    #[error("INCIDENT_LIVE_REPLAY_AUTHORIZATION_MISSING")]
    LiveReplayAuthorizationMissing,
    #[error("INCIDENT_ROOT_CAUSE_INCOMPLETE")]
    RootCauseIncomplete,
    #[error("INCIDENT_GATE_DEFINITION_INVALID")]
    GateDefinitionInvalid,
    #[error("INCIDENT_EVIDENCE_MISSING")]
    EvidenceMissing,
    #[error("INCIDENT_EVIDENCE_FAILED")]
    EvidenceFailed,
    #[error("INCIDENT_CERTIFICATE_INVALID")]
    CertificateInvalid,
    #[error("INCIDENT_RECERTIFICATION_INVALID")]
    RecertificationInvalid,
    #[error("INCIDENT_RECERTIFICATION_FAILED")]
    RecertificationFailed,
    #[error("INCIDENT_CANONICALIZATION_FAILED")]
    Canonicalization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::{LeaseId, SchemaVersion};
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestPort {
        calls: AtomicU32,
    }

    #[async_trait]
    impl ContainmentPort for TestPort {
        async fn kill_task(
            &self,
            _: &TenantId,
            _: &TaskId,
            key: &str,
        ) -> Result<String, IncidentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("evidence:{key}"))
        }
        async fn revoke_credentials(
            &self,
            _: &TenantId,
            _: &TaskId,
            key: &str,
        ) -> Result<String, IncidentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("evidence:{key}"))
        }
        async fn isolate_integration(
            &self,
            _: &TenantId,
            _: &str,
            key: &str,
        ) -> Result<String, IncidentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("evidence:{key}"))
        }
        async fn freeze_artifacts(
            &self,
            _: &TenantId,
            _: &str,
            key: &str,
        ) -> Result<String, IncidentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("evidence:{key}"))
        }
    }

    struct TestReplay {
        calls: AtomicU32,
    }

    #[async_trait]
    impl ReplayExecutor for TestReplay {
        async fn execute(&self, _: &ReplayPlan, action: &str) -> Result<String, IncidentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("executed:{action}"))
        }
    }

    struct TestRecertificationPort {
        campaign_passes: bool,
    }

    #[async_trait]
    impl RecertificationPort for TestRecertificationPort {
        async fn run_campaign(
            &self,
            _: &RecertificationTrigger,
            campaign_id: &str,
            _: &str,
        ) -> Result<CampaignAttestation, IncidentError> {
            Ok(CampaignAttestation {
                campaign_id: campaign_id.into(),
                evidence_ref: format!("evidence:campaign:{campaign_id}"),
                evidence_digest: "c".repeat(64),
                passed: self.campaign_passes,
                completed_at: Utc::now(),
            })
        }

        async fn collect_control_evidence(
            &self,
            _: &RecertificationTrigger,
            control_id: &str,
        ) -> Result<GateEvidence, IncidentError> {
            Ok(GateEvidence {
                control_id: control_id.into(),
                evidence_ref: format!("evidence:{control_id}"),
                evidence_digest: "e".repeat(64),
                passed: true,
                collected_at: Utc::now(),
            })
        }
    }

    fn incident(service: &IncidentService) -> Incident {
        service
            .create(IncidentCreateRequest {
                tenant_id: TenantId::new(),
                task_id: TaskId::new(),
                detection_id: "detection:1".into(),
                severity: RiskLevel::Critical,
                owner: "soc:1".into(),
                scope: BTreeSet::from(["mcp://server".into()]),
                evidence_refs: BTreeSet::from(["evidence:alert".into()]),
            })
            .unwrap_or_else(|error| panic!("incident: {error}"))
    }

    #[tokio::test]
    async fn alert_storm_and_containment_are_idempotent() {
        let service = IncidentService::new(10).unwrap_or_else(|error| panic!("service: {error}"));
        let first = incident(&service);
        let duplicate = service
            .create(IncidentCreateRequest {
                tenant_id: first.tenant_id.clone(),
                task_id: first.task_id.clone(),
                detection_id: "detection:1".into(),
                severity: RiskLevel::Critical,
                owner: "soc:1".into(),
                scope: BTreeSet::from(["mcp://server".into()]),
                evidence_refs: BTreeSet::from(["evidence:alert".into()]),
            })
            .unwrap_or_else(|error| panic!("duplicate: {error}"));
        assert_eq!(first.incident_id, duplicate.incident_id);
        let port = Arc::new(TestPort {
            calls: AtomicU32::new(0),
        });
        let controller = ContainmentController::new(port.clone());
        let one = controller
            .contain(&first)
            .await
            .unwrap_or_else(|error| panic!("contain: {error}"));
        let two = controller
            .contain(&first)
            .await
            .unwrap_or_else(|error| panic!("retry: {error}"));
        assert_eq!(one, two);
        assert_eq!(port.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn logical_replay_has_zero_side_effects_and_sandbox_rejects_production() {
        let executor = Arc::new(TestReplay {
            calls: AtomicU32::new(0),
        });
        let engine = ReplayEngine::new(executor.clone());
        let tenant = TenantId::new();
        let task = TaskId::new();
        let logical = ReplayPlan {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            replay_id: "replay:1".into(),
            incident_id: "incident:1".into(),
            tenant_id: tenant.clone(),
            task_id: task.clone(),
            mode: ReplayMode::Logical,
            action_hashes: vec!["a".repeat(64)],
            resource_refs: vec![],
            credential_profile: None,
            authorization_lease: None,
            approval_id: None,
            created_at: Utc::now(),
        };
        let run = engine
            .run(&logical, Utc::now())
            .await
            .unwrap_or_else(|error| panic!("logical: {error}"));
        assert_eq!(run.side_effect_count, 0);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        let mut sandbox = logical;
        sandbox.mode = ReplayMode::Sandbox;
        sandbox.credential_profile = Some("test-only".into());
        sandbox.resource_refs = vec!["postgres://production".into()];
        assert_eq!(
            engine.run(&sandbox, Utc::now()).await,
            Err(IncidentError::ReplayDenied)
        );
    }

    #[test]
    fn release_gate_fails_missing_evidence_and_certificate_detects_tamper() {
        let key = SigningKey::from_bytes(&[41_u8; 32]);
        let engine = ReleaseGateEngine::new("gate-key".into(), key.clone())
            .unwrap_or_else(|error| panic!("engine: {error}"));
        let definition = ReleaseGateDefinition {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            gate_id: "domain-pack-gate".into(),
            version: "1.0.0".into(),
            required_controls: BTreeSet::from(["C-AUTHZ".into(), "C-EVIDENCE".into()]),
            maximum_evidence_age_seconds: 3600,
            definition_digest: "d".repeat(64),
        };
        let evidence = vec![GateEvidence {
            control_id: "C-AUTHZ".into(),
            evidence_ref: "artifact:authz".into(),
            evidence_digest: "e".repeat(64),
            passed: true,
            collected_at: Utc::now(),
        }];
        assert_eq!(
            engine.evaluate(&definition, &"r".repeat(64), &evidence, Utc::now()),
            Err(IncidentError::EvidenceMissing)
        );
        let mut complete = evidence;
        complete.push(GateEvidence {
            control_id: "C-EVIDENCE".into(),
            evidence_ref: "artifact:evidence".into(),
            evidence_digest: "f".repeat(64),
            passed: true,
            collected_at: Utc::now(),
        });
        let certificate = engine
            .evaluate(&definition, &"r".repeat(64), &complete, Utc::now())
            .unwrap_or_else(|error| panic!("evaluate: {error}"));
        assert!(certificate.verify(&key.verifying_key(), Utc::now()).is_ok());
        let mut tampered = certificate;
        tampered.release_digest = "x".repeat(64);
        assert_eq!(
            tampered.verify(&key.verifying_key(), Utc::now()),
            Err(IncidentError::CertificateInvalid)
        );
    }

    #[test]
    fn live_replay_requires_fresh_lease_and_approval() {
        let tenant = TenantId::new();
        let task = TaskId::new();
        let plan = ReplayPlan {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            replay_id: "replay:live".into(),
            incident_id: "incident:1".into(),
            tenant_id: tenant,
            task_id: task.clone(),
            mode: ReplayMode::Live,
            action_hashes: vec!["a".repeat(64)],
            resource_refs: vec!["live://resource".into()],
            credential_profile: None,
            authorization_lease: Some(AuthorizationLease {
                schema_version: SchemaVersion("agenttrust.contracts.v1".into()),
                lease_id: LeaseId::new(),
                task_id: task,
                goal_hash: "g".repeat(64),
                plan_hash: "p".repeat(64),
                policy_snapshot: "policy:v2".into(),
                allowed_tools: BTreeSet::new(),
                allowed_resources: BTreeSet::new(),
                revocation_epoch: 2,
                valid_until: Utc::now() + Duration::minutes(10),
            }),
            approval_id: None,
            created_at: Utc::now(),
        };
        assert_eq!(
            validate_replay_plan(&plan, Utc::now()),
            Err(IncidentError::LiveReplayAuthorizationMissing)
        );
    }

    #[tokio::test]
    async fn recertification_runs_campaigns_before_issuing_release_gate_certificate() {
        let now = Utc::now();
        let key = SigningKey::from_bytes(&[42_u8; 32]);
        let engine = ReleaseGateEngine::new("recert-key".into(), key.clone())
            .unwrap_or_else(|error| panic!("engine: {error}"));
        let definition = ReleaseGateDefinition {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            gate_id: "incident-recertification".into(),
            version: "1.0.0".into(),
            required_controls: BTreeSet::from([
                "campaign:security-regression".into(),
                "C-REMEDIATION".into(),
            ]),
            maximum_evidence_age_seconds: 3600,
            definition_digest: "d".repeat(64),
        };
        let trigger = RecertificationTrigger {
            schema_version: INCIDENT_SCHEMA_VERSION.into(),
            incident_id: "incident:1".into(),
            release_digest: "r".repeat(64),
            root_cause_digest: "a".repeat(64),
            required_campaigns: BTreeSet::from(["security-regression".into()]),
            requested_by: "incident-commander:1".into(),
            requested_at: now,
        };
        let runner = RecertificationRunner::new(
            Arc::new(TestRecertificationPort {
                campaign_passes: true,
            }),
            &engine,
        );
        let receipt = runner
            .run(&trigger, &definition, now)
            .await
            .unwrap_or_else(|error| panic!("recertify: {error}"));
        assert!(
            receipt
                .release_certificate
                .verify(&key.verifying_key(), Utc::now())
                .is_ok()
        );

        let failing = RecertificationRunner::new(
            Arc::new(TestRecertificationPort {
                campaign_passes: false,
            }),
            &engine,
        );
        assert_eq!(
            failing.run(&trigger, &definition, now).await,
            Err(IncidentError::RecertificationFailed)
        );
    }
}
