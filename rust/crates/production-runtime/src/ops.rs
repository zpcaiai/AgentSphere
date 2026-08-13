use crate::{config::EvidenceFilesConfig, http::SecureHttpTransport};
use agent_trust_agent_registry_posture::{LifecyclePropagationPort, RegistryError};
use agent_trust_contracts::{ActionHash, TaskId, TenantId};
use agent_trust_enterprise_approval::{ApprovalError, ApprovalNotification, NotificationAdapter};
use agent_trust_enterprise_control::{
    AuthoritativeServicePort, AuthorityView, EnterpriseError, IntegrationConfig, IntegrationPort,
    WebhookEnvelope,
};
use agent_trust_incident_release_gate::{
    CampaignAttestation, ContainmentPort, GateEvidence as IncidentGateEvidence, IncidentError,
    RecertificationPort, RecertificationTrigger,
};
use agent_trust_platform_sre::{
    BackupPort, BackupRequest, DatabaseBackupArtifact, ObjectBackupArtifact, SreError,
};
use agent_trust_policy_administration::{
    DistributionAcknowledgement, PolicyAdminError, PolicyBundle, PolicyDistributionPort,
    PromotionEnvironment,
};
use agent_trust_policy_pep::{PolicyError, RuntimeControlPort};
use agent_trust_production_closure::{
    BatchEvidenceStatus, ClosureError, ClosureScope, EvidenceSourcePort, GateEvidence,
    GateException, ResidualRisk,
};
use async_trait::async_trait;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use std::{collections::BTreeSet, fs, path::Path};

#[derive(Clone)]
pub struct HttpBackupPort {
    transport: SecureHttpTransport,
}
impl HttpBackupPort {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
}
impl BackupPort for HttpBackupPort {
    fn backup_database(
        &self,
        request: &BackupRequest,
        key: &str,
    ) -> Result<DatabaseBackupArtifact, SreError> {
        self.transport
            .post_json_blocking("/v1/backups/database", request, Some(key))
            .map_err(|_| SreError::BackupOperationFailed)
    }
    fn backup_objects(
        &self,
        request: &BackupRequest,
        key: &str,
    ) -> Result<ObjectBackupArtifact, SreError> {
        self.transport
            .post_json_blocking("/v1/backups/objects", request, Some(key))
            .map_err(|_| SreError::BackupOperationFailed)
    }
    fn ledger_head_digest(&self, request: &BackupRequest) -> Result<String, SreError> {
        let response: DigestResponse = self
            .transport
            .post_json_blocking("/v1/backups/ledger-head", request, None)
            .map_err(|_| SreError::BackupOperationFailed)?;
        require_digest(response.digest).map_err(|_| SreError::BackupEvidenceInvalid)
    }
    fn verify_key_recovery(&self, key_version: &str, key: &str) -> Result<String, SreError> {
        let response: EvidenceResponse = self
            .transport
            .post_json_blocking(
                "/v1/backups/key-recovery",
                &json!({"key_version": key_version}),
                Some(key),
            )
            .map_err(|_| SreError::BackupOperationFailed)?;
        if response.evidence_ref.is_empty() {
            Err(SreError::BackupEvidenceInvalid)
        } else {
            Ok(response.evidence_ref)
        }
    }
}

#[derive(Clone)]
pub struct HttpPolicyDistributionPort {
    transport: SecureHttpTransport,
}
impl HttpPolicyDistributionPort {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
}
impl PolicyDistributionPort for HttpPolicyDistributionPort {
    fn publish(
        &self,
        bundle: &PolicyBundle,
        environment: PromotionEnvironment,
        key: &str,
    ) -> Result<DistributionAcknowledgement, PolicyAdminError> {
        self.transport
            .post_json_blocking(
                "/v1/policy/bundles",
                &json!({
                    "bundle": bundle, "environment": environment
                }),
                Some(key),
            )
            .map_err(|_| PolicyAdminError::PublicationFailed)
    }
}

#[derive(Clone)]
pub struct HttpContainmentPort {
    transport: SecureHttpTransport,
}
impl HttpContainmentPort {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
}
#[async_trait]
impl ContainmentPort for HttpContainmentPort {
    async fn kill_task(
        &self,
        tenant: &TenantId,
        task: &TaskId,
        key: &str,
    ) -> Result<String, IncidentError> {
        evidence(
            self.transport
                .post_json(
                    "/v1/containment/tasks/kill",
                    &task_body(tenant, task),
                    Some(key),
                )
                .await,
        )
    }
    async fn revoke_credentials(
        &self,
        tenant: &TenantId,
        task: &TaskId,
        key: &str,
    ) -> Result<String, IncidentError> {
        evidence(
            self.transport
                .post_json(
                    "/v1/containment/credentials/revoke",
                    &task_body(tenant, task),
                    Some(key),
                )
                .await,
        )
    }
    async fn isolate_integration(
        &self,
        tenant: &TenantId,
        resource: &str,
        key: &str,
    ) -> Result<String, IncidentError> {
        evidence(
            self.transport
                .post_json(
                    "/v1/containment/integrations/isolate",
                    &json!({"tenant_id": tenant, "resource": resource}),
                    Some(key),
                )
                .await,
        )
    }
    async fn freeze_artifacts(
        &self,
        tenant: &TenantId,
        incident_id: &str,
        key: &str,
    ) -> Result<String, IncidentError> {
        evidence(
            self.transport
                .post_json(
                    "/v1/containment/artifacts/freeze",
                    &json!({"tenant_id": tenant, "incident_id": incident_id}),
                    Some(key),
                )
                .await,
        )
    }
}

#[derive(Clone)]
pub struct HttpRecertificationPort {
    transport: SecureHttpTransport,
}
impl HttpRecertificationPort {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
}
#[async_trait]
impl RecertificationPort for HttpRecertificationPort {
    async fn run_campaign(
        &self,
        trigger: &RecertificationTrigger,
        campaign_id: &str,
        key: &str,
    ) -> Result<CampaignAttestation, IncidentError> {
        self.transport
            .post_json(
                "/v1/recertification/campaigns",
                &json!({
                    "trigger": trigger, "campaign_id": campaign_id
                }),
                Some(key),
            )
            .await
            .map_err(|_| IncidentError::RecertificationFailed)
    }
    async fn collect_control_evidence(
        &self,
        trigger: &RecertificationTrigger,
        control_id: &str,
    ) -> Result<IncidentGateEvidence, IncidentError> {
        self.transport
            .post_json(
                "/v1/recertification/control-evidence",
                &json!({
                    "trigger": trigger, "control_id": control_id
                }),
                None,
            )
            .await
            .map_err(|_| IncidentError::EvidenceMissing)
    }
}

#[derive(Clone)]
pub struct HttpEnterpriseIntegration {
    transport: SecureHttpTransport,
}
impl HttpEnterpriseIntegration {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
}
impl IntegrationPort for HttpEnterpriseIntegration {
    fn deliver(
        &self,
        config: &IntegrationConfig,
        envelope: &WebhookEnvelope,
        key: &str,
    ) -> Result<String, EnterpriseError> {
        let response: MessageResponse = self
            .transport
            .post_json_blocking(
                "/v1/integrations/deliver",
                &json!({
                    "integration": config, "envelope": envelope
                }),
                Some(key),
            )
            .map_err(|_| EnterpriseError::IntegrationFailed)?;
        nonempty(response.message_id).map_err(|_| EnterpriseError::IntegrationFailed)
    }
}

#[derive(Clone)]
pub struct HttpAuthoritativeService {
    transport: SecureHttpTransport,
    service: String,
}
impl HttpAuthoritativeService {
    pub fn new(transport: SecureHttpTransport, service: String) -> Result<Self, EnterpriseError> {
        if service.is_empty() {
            Err(EnterpriseError::ConfigurationInvalid)
        } else {
            Ok(Self { transport, service })
        }
    }
}
impl AuthoritativeServicePort for HttpAuthoritativeService {
    fn fetch(
        &self,
        tenant: &TenantId,
        resource: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<AuthorityView, EnterpriseError> {
        self.transport
            .post_json_blocking(
                "/v1/authority/query",
                &json!({
                    "service": self.service, "tenant_id": tenant, "resource": resource,
                    "cursor": cursor, "limit": limit
                }),
                None,
            )
            .map_err(|_| EnterpriseError::AuthorityUnavailable)
    }
}

#[derive(Clone)]
pub struct HttpNotificationAdapter {
    transport: SecureHttpTransport,
}
impl HttpNotificationAdapter {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
}
impl NotificationAdapter for HttpNotificationAdapter {
    fn send(&self, notification: &ApprovalNotification) -> Result<String, ApprovalError> {
        let response: MessageResponse = self
            .transport
            .post_json_blocking(
                "/v1/notifications",
                notification,
                Some(&notification.notification_id),
            )
            .map_err(|_| ApprovalError::NotificationFailed)?;
        nonempty(response.message_id).map_err(|_| ApprovalError::NotificationFailed)
    }
}

#[derive(Clone)]
pub struct HttpRuntimeControlPort {
    transport: SecureHttpTransport,
}
impl HttpRuntimeControlPort {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
    async fn command(
        &self,
        command: &str,
        action_hash: &ActionHash,
        code: Option<&str>,
    ) -> Result<(), PolicyError> {
        let response: AcceptedResponse = self
            .transport
            .post_json(
                "/v1/runtime/control",
                &json!({"command": command, "action_hash": action_hash, "alert_code": code}),
                Some(&format!("runtime:{command}:{}", action_hash.0)),
            )
            .await
            .map_err(|_| PolicyError::ObligationFailed)?;
        if response.accepted {
            Ok(())
        } else {
            Err(PolicyError::ObligationFailed)
        }
    }
}
#[async_trait]
impl RuntimeControlPort for HttpRuntimeControlPort {
    async fn pause(&self, action_hash: &ActionHash) -> Result<(), PolicyError> {
        self.command("PAUSE", action_hash, None).await
    }
    async fn kill(&self, action_hash: &ActionHash) -> Result<(), PolicyError> {
        self.command("KILL", action_hash, None).await
    }
    async fn security_alert(
        &self,
        code: &str,
        action_hash: &ActionHash,
    ) -> Result<(), PolicyError> {
        self.command("SECURITY_ALERT", action_hash, Some(code))
            .await
    }
}

#[derive(Clone)]
pub struct HttpLifecyclePropagationPort {
    transport: SecureHttpTransport,
}
impl HttpLifecyclePropagationPort {
    pub fn new(transport: SecureHttpTransport) -> Self {
        Self { transport }
    }
    fn propagate(
        &self,
        operation: &str,
        body: serde_json::Value,
        key: &str,
    ) -> Result<String, RegistryError> {
        let response: EvidenceResponse = self
            .transport
            .post_json_blocking(&format!("/v1/lifecycle/{operation}"), &body, Some(key))
            .map_err(|_| RegistryError::PropagationFailed)?;
        nonempty(response.evidence_ref).map_err(|_| RegistryError::PropagationFailed)
    }
}
impl LifecyclePropagationPort for HttpLifecyclePropagationPort {
    fn revoke_identities(
        &self,
        tenant: &TenantId,
        agent_id: &str,
        identity_refs: &BTreeSet<String>,
        key: &str,
    ) -> Result<String, RegistryError> {
        self.propagate(
            "identities/revoke",
            json!({"tenant_id":tenant,"agent_id":agent_id,"identity_refs":identity_refs}),
            key,
        )
    }
    fn revoke_authorizations(
        &self,
        tenant: &TenantId,
        agent_id: &str,
        key: &str,
    ) -> Result<String, RegistryError> {
        self.propagate(
            "authorizations/revoke",
            json!({"tenant_id":tenant,"agent_id":agent_id}),
            key,
        )
    }
    fn deactivate_packs(
        &self,
        tenant: &TenantId,
        agent_id: &str,
        pack_refs: &BTreeSet<String>,
        key: &str,
    ) -> Result<String, RegistryError> {
        self.propagate(
            "packs/deactivate",
            json!({"tenant_id":tenant,"agent_id":agent_id,"pack_refs":pack_refs}),
            key,
        )
    }
}

#[derive(Clone)]
pub struct FilesystemEvidenceSource {
    files: EvidenceFilesConfig,
}
impl FilesystemEvidenceSource {
    pub fn new(files: EvidenceFilesConfig) -> Self {
        Self { files }
    }
}
impl EvidenceSourcePort for FilesystemEvidenceSource {
    fn batch_statuses(&self, _: &ClosureScope) -> Result<Vec<BatchEvidenceStatus>, ClosureError> {
        let values: Vec<BatchEvidenceStatus> = read_json(&self.files.batch_statuses)?;
        let unique = values
            .iter()
            .map(|item| item.batch)
            .collect::<BTreeSet<_>>();
        if unique.len() != values.len() || values.iter().any(|item| !(1..=35).contains(&item.batch))
        {
            return Err(ClosureError::ConfigurationInvalid);
        }
        Ok(values)
    }
    fn gate_evidence(&self, scope: &ClosureScope) -> Result<Vec<GateEvidence>, ClosureError> {
        let values: Vec<GateEvidence> = read_json(&self.files.gate_evidence)?;
        let digest = scope.digest()?;
        if values.iter().any(|item| item.scope_digest != digest) {
            return Err(ClosureError::ScopeInvalid);
        }
        Ok(values)
    }
    fn residual_risks(&self, _: &ClosureScope) -> Result<Vec<ResidualRisk>, ClosureError> {
        read_json(&self.files.residual_risks)
    }
    fn exceptions(&self, _: &ClosureScope) -> Result<Vec<GateException>, ClosureError> {
        read_json(&self.files.exceptions)
    }
}

#[derive(Deserialize)]
struct EvidenceResponse {
    evidence_ref: String,
}
#[derive(Deserialize)]
struct MessageResponse {
    message_id: String,
}
#[derive(Deserialize)]
struct DigestResponse {
    digest: String,
}
#[derive(Deserialize)]
struct AcceptedResponse {
    accepted: bool,
}

fn task_body(tenant: &TenantId, task: &TaskId) -> serde_json::Value {
    json!({"tenant_id": tenant, "task_id": task})
}
fn evidence(
    result: Result<EvidenceResponse, crate::http::TransportError>,
) -> Result<String, IncidentError> {
    let response = result.map_err(|_| IncidentError::ContainmentFailed)?;
    nonempty(response.evidence_ref).map_err(|_| IncidentError::ContainmentFailed)
}
fn nonempty(value: String) -> Result<String, ()> {
    if value.is_empty() { Err(()) } else { Ok(value) }
}
fn require_digest(value: String) -> Result<String, ()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value)
    } else {
        Err(())
    }
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, ClosureError> {
    let metadata = fs::metadata(path).map_err(|_| ClosureError::ConfigurationInvalid)?;
    if !metadata.is_file() || metadata.len() > 32 * 1024 * 1024 {
        return Err(ClosureError::ConfigurationInvalid);
    }
    let bytes = fs::read(path).map_err(|_| ClosureError::ConfigurationInvalid)?;
    serde_json::from_slice(&bytes).map_err(|_| ClosureError::ConfigurationInvalid)
}
