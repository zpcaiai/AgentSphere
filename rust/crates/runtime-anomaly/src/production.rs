//! Strict outbound mTLS adapters for the Runtime Anomaly authority.

use crate::AuthorizationAdjustment;
use crate::authority::*;
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{
    AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION, ActionHash, ArtifactRef,
    AuthorityEvidenceControlBinding, AuthorityEvidenceEventRequest,
    AuthorityEvidenceSourceKind, EVIDENCE_EVENT_SCHEMA_VERSION, EvidenceEventDraft,
    EvidenceEventType, ExecutionId, IdempotencyKey, SignedAuthorityEvidenceReceipt, TaskId,
    TenantId,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use reqwest::{Certificate, Identity, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct RuntimeAnomalyEndpoint {
    pub origin: Url,
    pub token_file: PathBuf,
    pub readiness_schema: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeAnomalyDependencyConfig {
    pub orchestrator: RuntimeAnomalyEndpoint,
    pub supervisor: RuntimeAnomalyEndpoint,
    pub credential_authority: RuntimeAnomalyEndpoint,
    pub incident_authority: RuntimeAnomalyEndpoint,
    pub evidence_authority: RuntimeAnomalyEndpoint,
    pub evidence_client_identity: String,
    pub evidence_keyring: RuntimeAnomalyEvidenceKeyring,
    pub maximum_response_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyringDocument {
    schema_version: String,
    keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeAnomalyEvidenceKeyring {
    keys: Arc<BTreeMap<String, VerifyingKey>>,
}

impl RuntimeAnomalyEvidenceKeyring {
    pub fn from_json(raw: &[u8]) -> Result<Self, RuntimeAnomalyAuthorityError> {
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
        let document: EvidenceKeyringDocument = serde_json::from_slice(raw)
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != "agenttrust.ed25519-public-keyring.v1"
            || document.keys.is_empty()
            || document.keys.len() > 1_024
        {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
        let mut keys = BTreeMap::new();
        for (key_id, encoded) in document.keys {
            if key_id.is_empty() || key_id.len() > 128 {
                return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
            }
            let bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?
                .try_into()
                .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
            if keys.insert(key_id, key).is_some() {
                return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
            }
        }
        Ok(Self { keys: Arc::new(keys) })
    }

    fn key(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }
}

#[derive(Clone)]
pub struct HttpsRuntimeAnomalyRuntime {
    client: reqwest::Client,
    dependencies: RuntimeAnomalyDependencyConfig,
}

impl HttpsRuntimeAnomalyRuntime {
    pub fn new(
        ca_file: &Path,
        certificate_file: &Path,
        private_key_file: &Path,
        dependencies: RuntimeAnomalyDependencyConfig,
    ) -> Result<Self, RuntimeAnomalyAuthorityError> {
        validate_file(ca_file, false, 4_194_304)?;
        validate_file(certificate_file, false, 4_194_304)?;
        validate_file(private_key_file, true, 4_194_304)?;
        if !(4_096..=4_194_304).contains(&dependencies.maximum_response_bytes) {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
        for endpoint in [
            &dependencies.orchestrator,
            &dependencies.supervisor,
            &dependencies.credential_authority,
            &dependencies.incident_authority,
            &dependencies.evidence_authority,
        ] {
            validate_https_root(&endpoint.origin)?;
            validate_file(&endpoint.token_file, true, 8_194)?;
            if endpoint.readiness_schema.is_empty() || endpoint.readiness_schema.len() > 256 {
                return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
            }
        }
        if dependencies.evidence_client_identity.len() > 512
            || !(dependencies.evidence_client_identity.starts_with("DNS:")
                || dependencies.evidence_client_identity.starts_with("URI:"))
            || dependencies
                .evidence_client_identity
                .contains(char::is_whitespace)
        {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
        let ca = std::fs::read(ca_file)
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        let certificate = Certificate::from_pem(&ca)
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        let mut identity_pem = std::fs::read(certificate_file)
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        let mut private_key = std::fs::read(private_key_file)
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        identity_pem.extend_from_slice(&private_key);
        private_key.zeroize();
        let identity_result = Identity::from_pem(&identity_pem);
        identity_pem.zeroize();
        let identity = identity_result
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(certificate)
            .identity(identity)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(8)
            .build()
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        Ok(Self { client, dependencies })
    }

    async fn all_ready(&self) -> bool {
        let (orchestrator, supervisor, credential, incident, evidence) = tokio::join!(
            dependency_ready(&self.client, &self.dependencies.orchestrator),
            dependency_ready(&self.client, &self.dependencies.supervisor),
            dependency_ready(&self.client, &self.dependencies.credential_authority),
            dependency_ready(&self.client, &self.dependencies.incident_authority),
            dependency_ready(&self.client, &self.dependencies.evidence_authority),
        );
        orchestrator && supervisor && credential && incident && evidence
    }
}

#[async_trait]
impl RuntimeAnomalyOrchestratorPort for HttpsRuntimeAnomalyRuntime {
    async fn ready(&self) -> bool {
        dependency_ready(&self.client, &self.dependencies.orchestrator).await
    }

    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &agent_trust_gateway::InboundEnvelope,
    ) -> Result<RuntimeAnomalyActionReceipt, RuntimeAnomalyAuthorityError> {
        let token = read_token(&self.dependencies.orchestrator.token_file)?;
        let url = self
            .dependencies
            .orchestrator
            .origin
            .join("v1/actions")
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
            .header("x-agenttrust-tenant-id", &tenant.0)
            .header(
                "idempotency-key",
                envelope
                    .idempotency_key
                    .as_deref()
                    .ok_or(RuntimeAnomalyAuthorityError::RequestInvalid)?,
            )
            .json(envelope)
            .send()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
        if !response.status().is_success() {
            return Err(RuntimeAnomalyAuthorityError::OutcomeUnknown);
        }
        bounded_json(response, self.dependencies.maximum_response_bytes).await
    }
}

#[async_trait]
impl RuntimeAnomalyEffectsPort for HttpsRuntimeAnomalyRuntime {
    async fn ready(&self) -> bool {
        self.all_ready().await
    }

    async fn apply_response(
        &self,
        binding: &RuntimeAnomalyExecutionBinding,
        command: &crate::ResponseCommand,
    ) -> Result<RuntimeResponseReceipt, RuntimeAnomalyAuthorityError> {
        let command_digest = canonical_digest(command)?;
        let supervisor = call_response_dependency(
            &self.client,
            &self.dependencies.supervisor,
            binding,
            command,
            &command_digest,
            self.dependencies.maximum_response_bytes,
        )
        .await?;
        let credential = if command.adjustment == AuthorizationAdjustment::RevokeCredential {
            Some(
                call_response_dependency(
                    &self.client,
                    &self.dependencies.credential_authority,
                    binding,
                    command,
                    &command_digest,
                    self.dependencies.maximum_response_bytes,
                )
                .await?,
            )
        } else {
            None
        };
        let incident = if matches!(
            command.adjustment,
            AuthorizationAdjustment::Pause
                | AuthorizationAdjustment::RevokeLease
                | AuthorizationAdjustment::RevokeCredential
                | AuthorizationAdjustment::Kill
        ) {
            Some(
                call_response_dependency(
                    &self.client,
                    &self.dependencies.incident_authority,
                    binding,
                    command,
                    &command_digest,
                    self.dependencies.maximum_response_bytes,
                )
                .await?,
            )
        } else {
            None
        };
        Ok(RuntimeResponseReceipt {
            schema_version: ANOMALY_RESPONSE_RECEIPT_SCHEMA.into(),
            tenant_id: parse_uuid(&binding.tenant_id.0)?,
            response_id: parse_uuid(&command.response_id)?,
            task_id: parse_uuid(&command.task_id.0)?,
            command_digest,
            adjustment: command.adjustment,
            supervisor_receipt_digest: Some(supervisor.receipt_digest),
            credential_receipt_digest: credential.map(|value| value.receipt_digest),
            incident_receipt_digest: incident.map(|value| value.receipt_digest),
            safe_status: "CONTROLLED_RESPONSE_APPLIED".into(),
        })
    }

    async fn publish_evidence(
        &self,
        tenant: &TenantId,
        event_id: Uuid,
        idempotency_key: &str,
        payload: &Value,
        payload_digest: &str,
    ) -> Result<AnomalyEvidenceReceipt, RuntimeAnomalyAuthorityError> {
        if canonical_digest(payload)? != payload_digest {
            return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
        }
        let token = read_token(&self.dependencies.evidence_authority.token_file)?;
        let url = self
            .dependencies
            .evidence_authority
            .origin
            .join("v1/evidence/authority-events")
            .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
        let task_id = required_uuid_field(payload, "task_id")?;
        let event_kind = required_string_field(payload, "event_kind", 128)?;
        let (source_kind, control_binding, event_type, actor_subject) =
            if event_kind == "SIGNAL_INGESTED" {
                (
                    AuthorityEvidenceSourceKind::AuthenticatedEvent,
                    None,
                    EvidenceEventType::SecurityAlert,
                    required_string_field(payload, "source_id", 512)?.to_string(),
                )
            } else {
                (
                    AuthorityEvidenceSourceKind::GovernedAction,
                    Some(control_binding(payload)?),
                    EvidenceEventType::StateTransition,
                    self.dependencies.evidence_client_identity.clone(),
                )
            };
        let occurred_at = required_timestamp_field(payload, "evidence_occurred_at")?;
        let body = AuthorityEvidenceEventRequest {
            schema_version: AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            task_id: TaskId(task_id.to_string()),
            authority_event_id: event_id.to_string(),
            idempotency_key: IdempotencyKey(idempotency_key.into()),
            source_kind,
            control_binding,
            event: EvidenceEventDraft {
                schema_version: EVIDENCE_EVENT_SCHEMA_VERSION.into(),
                tenant_id: tenant.clone(),
                task_id: TaskId(task_id.to_string()),
                event_type,
                actor_subject,
                source_service: self.dependencies.evidence_client_identity.clone(),
                trace_id: required_trace_id(payload, event_id),
                span_id: event_id.to_string(),
                payload_hash: payload_digest.into(),
                safe_summary: if source_kind == AuthorityEvidenceSourceKind::GovernedAction {
                    "Runtime anomaly governed action persisted".into()
                } else {
                    "Authenticated runtime risk signal persisted".into()
                },
                artifact_refs: Vec::<ArtifactRef>::new(),
                occurred_at: occurred_at.clone(),
            },
            requested_at: occurred_at,
        };
        body.request_digest()
            .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
            .header("x-agenttrust-tenant-id", &tenant.0)
            .header("idempotency-key", idempotency_key)
            .header("x-agenttrust-authority-event-id", event_id.to_string())
            .header("x-agenttrust-payload-digest", payload_digest)
            .json(&body)
            .send()
            .await
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        if !response.status().is_success() {
            return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
        }
        let receipt: SignedAuthorityEvidenceReceipt =
            bounded_json(response, self.dependencies.maximum_response_bytes).await?;
        let key = self
            .dependencies
            .evidence_keyring
            .key(&receipt.key_id)
            .ok_or(RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        receipt
            .verify(key, Utc::now())
            .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
        if receipt.tenant_id != body.tenant_id
            || receipt.task_id != body.task_id
            || receipt.authority_event_id != body.authority_event_id
            || receipt.idempotency_key != body.idempotency_key
            || receipt.source_kind != body.source_kind
            || receipt.payload_digest != payload_digest
            || receipt.event.draft != body.event
        {
            return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
        }
        Ok(AnomalyEvidenceReceipt {
            schema_version: ANOMALY_EVIDENCE_RECEIPT_SCHEMA.into(),
            evidence_ref: receipt.evidence_ref,
            evidence_digest: receipt.evidence_digest,
            idempotency_key: receipt.idempotency_key.0,
        })
    }
}

fn required_uuid_field(
    payload: &Value,
    key: &str,
) -> Result<Uuid, RuntimeAnomalyAuthorityError> {
    let value = required_string_field(payload, key, 36)?;
    let parsed = Uuid::parse_str(value).map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    Ok(parsed)
}

fn required_string_field<'a>(
    payload: &'a Value,
    key: &str,
    maximum: usize,
) -> Result<&'a str, RuntimeAnomalyAuthorityError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .ok_or(RuntimeAnomalyAuthorityError::RequestInvalid)
}

fn required_digest_field(
    payload: &Value,
    key: &str,
) -> Result<String, RuntimeAnomalyAuthorityError> {
    let value = required_string_field(payload, key, 64)?;
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(RuntimeAnomalyAuthorityError::RequestInvalid);
    }
    Ok(value.into())
}

fn control_binding(
    payload: &Value,
) -> Result<AuthorityEvidenceControlBinding, RuntimeAnomalyAuthorityError> {
    let binding = AuthorityEvidenceControlBinding {
        action_hash: ActionHash(required_digest_field(payload, "action_hash")?),
        ledger_execution_id: ExecutionId(
            required_uuid_field(payload, "ledger_execution_id")?.to_string(),
        ),
        ledger_event_id: required_uuid_field(payload, "ledger_event_id")?.to_string(),
        ledger_event_digest: required_digest_field(payload, "ledger_event_digest")?,
        fence_digest: required_digest_field(payload, "fence_digest")?,
        policy_decision_id: required_string_field(payload, "policy_decision_id", 256)?.into(),
        policy_decision_digest: required_digest_field(payload, "policy_decision_digest")?,
        authorization_evidence_ref: required_string_field(
            payload,
            "authorization_evidence_ref",
            2_048,
        )?
        .into(),
        authorization_evidence_digest: required_digest_field(
            payload,
            "authorization_evidence_digest",
        )?,
    };
    binding
        .validate()
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)?;
    Ok(binding)
}

fn required_trace_id(payload: &Value, fallback: Uuid) -> String {
    ["trace_id", "command_id", "event_id"]
        .into_iter()
        .find_map(|key| {
            payload
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 256)
        })
        .map(str::to_string)
        .unwrap_or_else(|| fallback.to_string())
}

fn required_timestamp_field(
    payload: &Value,
    key: &str,
) -> Result<DateTime<Utc>, RuntimeAnomalyAuthorityError> {
    let value = required_string_field(payload, key, 64)?;
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyReadiness {
    schema_version: String,
    ready: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct ControlledResponseRequest<'a> {
    schema_version: &'static str,
    tenant_id: &'a TenantId,
    action_hash: &'a str,
    ledger_execution_id: Uuid,
    ledger_event_id: Uuid,
    ledger_event_digest: &'a str,
    fence_digest: &'a str,
    policy_decision_id: &'a str,
    policy_decision_digest: &'a str,
    authorization_evidence_ref: &'a str,
    authorization_evidence_digest: &'a str,
    idempotency_key: &'a str,
    command_digest: &'a str,
    command: &'a crate::ResponseCommand,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownstreamResponseReceipt {
    schema_version: String,
    response_id: String,
    command_digest: String,
    receipt_digest: String,
    safe_status: String,
}

async fn call_response_dependency(
    client: &reqwest::Client,
    endpoint: &RuntimeAnomalyEndpoint,
    binding: &RuntimeAnomalyExecutionBinding,
    command: &crate::ResponseCommand,
    command_digest: &str,
    maximum_response_bytes: usize,
) -> Result<DownstreamResponseReceipt, RuntimeAnomalyAuthorityError> {
    let token = read_token(&endpoint.token_file)?;
    let url = endpoint
        .origin
        .join("v1/runtime-responses")
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    let body = ControlledResponseRequest {
        schema_version: "agenttrust.controlled-runtime-response.v1",
        tenant_id: &binding.tenant_id,
        action_hash: &binding.action_hash,
        ledger_execution_id: binding.ledger_execution_id,
        ledger_event_id: binding.ledger_event_id,
        ledger_event_digest: &binding.ledger_event_digest,
        fence_digest: &binding.fence_digest,
        policy_decision_id: &binding.policy_decision_id,
        policy_decision_digest: &binding.policy_decision_digest,
        authorization_evidence_ref: &binding.authorization_evidence_ref,
        authorization_evidence_digest: &binding.authorization_evidence_digest,
        idempotency_key: &binding.idempotency_key,
        command_digest,
        command,
    };
    let response = client
        .post(url)
        .bearer_auth(token)
        .header("x-agenttrust-tenant-id", &binding.tenant_id.0)
        .header("idempotency-key", &binding.idempotency_key)
        .json(&body)
        .send()
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::OutcomeUnknown)?;
    if !response.status().is_success() {
        return Err(RuntimeAnomalyAuthorityError::OutcomeUnknown);
    }
    let receipt: DownstreamResponseReceipt = bounded_json(response, maximum_response_bytes).await?;
    if receipt.schema_version != "agenttrust.controlled-runtime-response-receipt.v1"
        || receipt.response_id != command.response_id
        || receipt.command_digest != command_digest
        || !digest(&receipt.receipt_digest)
        || !identifier(&receipt.safe_status, 128)
    {
        return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
    }
    Ok(receipt)
}

async fn dependency_ready(client: &reqwest::Client, endpoint: &RuntimeAnomalyEndpoint) -> bool {
    let Ok(token) = read_token(&endpoint.token_file) else {
        return false;
    };
    let Ok(url) = endpoint.origin.join("ready") else {
        return false;
    };
    let Ok(response) = client.get(url).bearer_auth(token).send().await else {
        return false;
    };
    if !response.status().is_success()
        || response.content_length().is_some_and(|value| value > 4_096)
    {
        return false;
    }
    let Ok(bytes) = read_bounded_body(response, 4_096).await else {
        return false;
    };
    if bytes.is_empty() || bytes.len() > 4_096 {
        return false;
    }
    serde_json::from_slice::<DependencyReadiness>(&bytes).is_ok_and(|value| {
        value.schema_version == endpoint.readiness_schema && value.ready
    })
}

async fn bounded_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    maximum: usize,
) -> Result<T, RuntimeAnomalyAuthorityError> {
    if response
        .content_length()
        .is_some_and(|value| value > maximum as u64)
    {
        return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
    }
    let bytes = read_bounded_body(response, maximum)
        .await
        .map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RuntimeAnomalyAuthorityError::DependencyUnavailable);
    }
    serde_json::from_slice(&bytes).map_err(|_| RuntimeAnomalyAuthorityError::DependencyUnavailable)
}

fn read_token(path: &Path) -> Result<String, RuntimeAnomalyAuthorityError> {
    validate_file(path, true, 8_194)?;
    let metadata = std::fs::metadata(path)
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute() || !metadata.is_file() || metadata.len() > 8_194 {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
    }
    let value = std::fs::read_to_string(path)
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    let token = value.trim_end_matches(['\r', '\n']);
    if !(16..=8_192).contains(&token.len())
        || token.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(token.len()) > 2
    {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
    }
    Ok(token.into())
}

fn validate_file(
    path: &Path,
    private: bool,
    maximum_size: u64,
) -> Result<(), RuntimeAnomalyAuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| RuntimeAnomalyAuthorityError::ConfigurationInvalid)?;
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_size
    {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        let effective_uid = nix::unistd::Uid::effective().as_raw();
        let effective_gid = nix::unistd::Gid::effective().as_raw();
        let allowed = 0o400 | if metadata.gid() == effective_gid { 0o040 } else { 0 };
        let private_ok = ((metadata.uid() == effective_uid && mode & 0o400 != 0)
            || (metadata.gid() == effective_gid && mode & 0o040 != 0))
            && mode & !allowed == 0;
        if metadata.nlink() != 1 || (private && !private_ok) || (!private && mode & 0o022 != 0) {
            return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
        }
    }
    Ok(())
}

fn validate_https_root(value: &Url) -> Result<(), RuntimeAnomalyAuthorityError> {
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.path() != "/"
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err(RuntimeAnomalyAuthorityError::ConfigurationInvalid);
    }
    Ok(())
}

fn canonical_digest<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, RuntimeAnomalyAuthorityError> {
    serde_jcs::to_vec(value)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)
}

fn parse_uuid(value: &str) -> Result<Uuid, RuntimeAnomalyAuthorityError> {
    Uuid::parse_str(value)
        .filter(|parsed| !parsed.is_nil() && parsed.to_string() == value)
        .map_err(|_| RuntimeAnomalyAuthorityError::RequestInvalid)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}
