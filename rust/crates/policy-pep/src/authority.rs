//! Production PEP authority composition. Every allowing value comes from a signed,
//! independently authenticated authority or from deterministic local validation.

use crate::activation::PolicyBundleKeyring;
use crate::postgres::{PepClaimResult, PostgresPepStore, canonical_digest};
use crate::{
    EnforcementOutcome, EnforcementRequest, ExecutionAuthorizationContext, MinimalApprovalKernel,
    PolicyDecisionPointPort, PolicyEnforcementPoint, PolicyError, validate_policy_decision,
};
use agent_trust_action_ir::{
    CanonicalAction, PolicyInput, RuntimeContext, TrajectoryRiskSnapshot, hash as action_hash,
    to_policy_input,
};
use agent_trust_contracts::{
    APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION, AUTHORITATIVE_FACT_SNAPSHOT_SCHEMA_VERSION, ActionHash,
    ApprovalGrantReceipt, AuthoritativeFactKind, AuthoritativeFactRef, AuthoritativeFactSnapshot,
    Decision, EffectClass, EnforcementStage, ExecutionAuthorization, ExecutionId, ExecutionStatus,
    IdempotencyKey, PEP_FINAL_AUTHORIZATION_REQUEST_SCHEMA_VERSION,
    PEP_PRE_APPROVAL_ENVELOPE_SCHEMA_VERSION, PEP_PRE_APPROVAL_KEY_USAGE,
    PEP_PRE_APPROVAL_REQUEST_SCHEMA_VERSION, PEP_PRE_EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
    PRE_APPROVAL_OUTCOME_SCHEMA_VERSION, PepFinalAuthorizationRequest, PepPreApprovalEnvelope,
    PepPreApprovalRequest, PepPreExecutionAuthorization, PolicyDecision, PolicyEnvironment,
    ResourceVersion, RiskLevel, SchemaVersion, SignedApprovalConsumptionReceipt,
    SignedAuthoritativeFactEnvelope, SignedPreApprovalOutcome,
    SignedWorkloadCredentialBindingReceipt, TenantId, ToolRef,
    WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE, WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION,
    WorkloadCredentialBindingRequest, WorkloadCredentialIssuance,
};
use agent_trust_identity::CredentialHandle;
use agent_trust_registry::{
    CapabilityDescriptor, CapabilityQuery, RegistryError, RegistrySnapshot, ResolvedToolSnapshot,
    ToolRegistry, validate_schema_instance,
};
use agent_trust_transaction_ledger::{CompensationPlan, CompensationStep};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use futures::future::try_join_all;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

pub const PEP_AUTHORITY_READINESS_SCHEMA: &str = "agenttrust.pep-readiness.v1";
pub const FACT_QUERY_SCHEMA: &str = "agenttrust.authoritative-fact-query.v1";
pub const LEDGER_VERIFICATION_SCHEMA: &str = "agenttrust.ledger-verification-receipt.v1";
pub const LEDGER_VERIFICATION_KEY_USAGE: &str = "LEDGER_EXECUTION_VERIFICATION";

pub type PreApprovalRequest = PepPreApprovalRequest<CanonicalAction, ResolvedToolSnapshot>;
pub type PreApprovalResponse = PepPreApprovalEnvelope<CompensationPlan>;
pub type FinalAuthorizationRequest =
    PepFinalAuthorizationRequest<CanonicalAction, ResolvedToolSnapshot, PolicyInput>;
pub type FinalAuthorizationResponse =
    PepPreExecutionAuthorization<ResolvedToolSnapshot, CredentialHandle>;

/// Durable replay material. Raw workload credentials are intentionally excluded; a replay
/// rehydrates the exact handle through the credential authority's idempotency contract.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct PersistedFinalAuthorizationResponse {
    schema_version: String,
    authorization: ExecutionAuthorization,
    tool: ResolvedToolSnapshot,
    credential_binding_receipt: SignedWorkloadCredentialBindingReceipt,
    target_profile: String,
    approval: Option<agent_trust_contracts::MinimalApprovalGrant>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PepAuthorityError {
    #[error("PEP_REQUEST_INVALID")]
    RequestInvalid,
    #[error("PEP_RESPONSE_INVALID")]
    ResponseInvalid,
    #[error("PEP_AUTHORIZATION_DENIED")]
    AuthorizationDenied,
    #[error("PEP_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("PEP_IDEMPOTENCY_IN_PROGRESS")]
    IdempotencyInProgress,
    #[error("PEP_IDEMPOTENCY_INDETERMINATE")]
    IdempotencyIndeterminate,
    #[error("PEP_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("PEP_DEPENDENCY_RESPONSE_INVALID")]
    DependencyResponseInvalid,
    #[error("PEP_PERSISTENCE_UNAVAILABLE")]
    PersistenceUnavailable,
    #[error("PEP_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBindingsDocument {
    pub schema_version: String,
    pub identity: AuthorityEndpointDefinition,
    pub resource_state: AuthorityEndpointDefinition,
    pub budget: AuthorityEndpointDefinition,
    pub trajectory_risk: AuthorityEndpointDefinition,
    pub registry: AuthorityEndpointDefinition,
    pub environment: AuthorityEndpointDefinition,
    pub pdp: AuthorityEndpointDefinition,
    pub pdp_activation: AuthorityEndpointDefinition,
    pub approval: AuthorityEndpointDefinition,
    pub ledger: AuthorityEndpointDefinition,
    pub credential: AuthorityEndpointDefinition,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEndpointDefinition {
    pub endpoint: String,
    pub readiness_endpoint: String,
    pub scope: String,
    pub token_file: PathBuf,
    pub ca_file: PathBuf,
    pub client_certificate_file: PathBuf,
    pub client_private_key_file: PathBuf,
    pub issuer: Option<String>,
    pub key_id: Option<String>,
    pub key_usage: Option<String>,
    pub verifying_key_file: Option<PathBuf>,
    pub timeout_ms: u64,
    pub maximum_response_bytes: usize,
}

#[derive(Clone)]
pub(crate) struct OutboundAuthorityClient {
    client: reqwest::Client,
    endpoint: Url,
    readiness_endpoint: Url,
    token: Arc<str>,
    token_sha256: Arc<str>,
    scope: Arc<str>,
    maximum_response_bytes: usize,
    signer: Option<AuthoritySigner>,
}

#[derive(Clone)]
pub(crate) struct AuthoritySigner {
    pub(crate) issuer: Arc<str>,
    pub(crate) key_id: Arc<str>,
    pub(crate) key_usage: Arc<str>,
    pub(crate) verifying_key: VerifyingKey,
}

impl OutboundAuthorityClient {
    pub(crate) fn from_definition(
        definition: &AuthorityEndpointDefinition,
        signature_required: bool,
    ) -> Result<Self, PepAuthorityError> {
        let endpoint = strict_https_url(&definition.endpoint)?;
        let readiness_endpoint = strict_https_url(&definition.readiness_endpoint)?;
        if definition.scope.is_empty()
            || definition.scope.len() > 256
            || definition.timeout_ms == 0
            || definition.timeout_ms > 30_000
            || definition.maximum_response_bytes == 0
            || definition.maximum_response_bytes > 1_048_576
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        let token = read_secret(&definition.token_file)?;
        let token_sha256 = hex(Sha256::digest(token.as_bytes()));
        let ca = secure_read(&definition.ca_file, false, 1_048_576)?;
        let mut identity = secure_read(&definition.client_certificate_file, false, 1_048_576)?;
        if !identity.ends_with(b"\n") {
            identity.push(b'\n');
        }
        identity.extend(secure_read(
            &definition.client_private_key_file,
            true,
            1_048_576,
        )?);
        let client = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_millis(definition.timeout_ms))
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca)
                    .map_err(|_| PepAuthorityError::ConfigurationInvalid)?,
            )
            .identity(
                reqwest::Identity::from_pem(&identity)
                    .map_err(|_| PepAuthorityError::ConfigurationInvalid)?,
            )
            .build()
            .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
        let signer = match (
            &definition.issuer,
            &definition.key_id,
            &definition.key_usage,
            &definition.verifying_key_file,
        ) {
            (Some(issuer), Some(key_id), Some(key_usage), Some(path)) => Some(AuthoritySigner {
                issuer: validate_identifier(issuer)?.into(),
                key_id: validate_identifier(key_id)?.into(),
                key_usage: validate_identifier(key_usage)?.into(),
                verifying_key: read_verifying_key(path)?,
            }),
            (None, None, None, None) if !signature_required => None,
            _ => return Err(PepAuthorityError::ConfigurationInvalid),
        };
        Ok(Self {
            client,
            endpoint,
            readiness_endpoint,
            token: token.into(),
            token_sha256: token_sha256.into(),
            scope: definition.scope.clone().into(),
            maximum_response_bytes: definition.maximum_response_bytes,
            signer,
        })
    }

    async fn post<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        tenant: &TenantId,
        body: &T,
    ) -> Result<R, PepAuthorityError> {
        self.post_idempotent(tenant, body, None).await
    }

    pub(crate) async fn post_idempotent<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        tenant: &TenantId,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, PepAuthorityError> {
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(self.token.as_ref())
            .header("Accept", "application/json")
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("X-AgentTrust-Scope", self.scope.as_ref())
            .header("X-AgentTrust-Token-SHA256", self.token_sha256.as_ref())
            .json(body);
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("Idempotency-Key", idempotency_key);
        }
        let response = request
            .send()
            .await
            .map_err(|_| PepAuthorityError::DependencyUnavailable)?;
        bounded_json(response, self.maximum_response_bytes).await
    }

    async fn get_approval_receipt(
        &self,
        tenant: &TenantId,
        consumption_ref: &str,
    ) -> Result<SignedApprovalConsumptionReceipt, PepAuthorityError> {
        let mut endpoint = self.endpoint.clone();
        endpoint
            .path_segments_mut()
            .map_err(|_| PepAuthorityError::ConfigurationInvalid)?
            .pop_if_empty()
            .push(consumption_ref);
        let response = self
            .client
            .get(endpoint)
            .bearer_auth(self.token.as_ref())
            .header("Accept", "application/json")
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("X-AgentTrust-Scope", self.scope.as_ref())
            .header("X-AgentTrust-Token-SHA256", self.token_sha256.as_ref())
            .send()
            .await
            .map_err(|_| PepAuthorityError::DependencyUnavailable)?;
        bounded_json(response, self.maximum_response_bytes).await
    }

    pub(crate) async fn ready(&self) -> bool {
        let response = tokio::time::timeout(
            Duration::from_millis(700),
            self.client
                .get(self.readiness_endpoint.clone())
                .bearer_auth(self.token.as_ref())
                .header("X-AgentTrust-Scope", self.scope.as_ref())
                .header("X-AgentTrust-Token-SHA256", self.token_sha256.as_ref())
                .send(),
        )
        .await;
        let Ok(Ok(response)) = response else {
            return false;
        };
        bounded_json::<ReadinessResponse>(response, 65_536)
            .await
            .is_ok_and(|value| value.ready && !value.schema_version.is_empty())
    }

    pub(crate) fn signer(&self) -> Result<&AuthoritySigner, PepAuthorityError> {
        self.signer
            .as_ref()
            .ok_or(PepAuthorityError::ConfigurationInvalid)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadinessResponse {
    schema_version: String,
    ready: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct FactQuery {
    schema_version: String,
    tenant_id: TenantId,
    task_id: String,
    step_id: String,
    agent_instance_id: String,
    action_hash: ActionHash,
    tool: ToolRef,
    tool_snapshot_hash: String,
    resource: String,
    requested_resource_version: String,
    execution_plan_hash: Option<String>,
    deployment: String,
    region: String,
    simulation: bool,
    requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFact {
    subject: String,
    uses_dev_verifier: bool,
    revocation_epoch: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceStateFact {
    version: String,
    fresh: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetFact {
    remaining_microunits: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrajectoryRiskFact {
    version: String,
    accumulated_resources: Vec<String>,
    anomaly_score_millionths: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFact {
    tool_id: String,
    tool_version: String,
    snapshot_hash: String,
    registry_revision: u64,
    active: bool,
    revoked: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentFact {
    deployment: String,
    region: String,
    simulation: bool,
}

#[derive(Clone)]
struct FactAuthoritySet {
    sources: BTreeMap<AuthoritativeFactKind, OutboundAuthorityClient>,
}

impl FactAuthoritySet {
    async fn fetch(
        &self,
        request: &PreApprovalRequest,
        now: DateTime<Utc>,
    ) -> Result<AuthoritativeFactSnapshot, PepAuthorityError> {
        let tenant = &request.action.environment.tenant_id;
        let expected_resource_version = resource_version(&request.action);
        let query = FactQuery {
            schema_version: FACT_QUERY_SCHEMA.into(),
            tenant_id: tenant.clone(),
            task_id: request.action.task_id.0.clone(),
            step_id: request.action.step_id.0.clone(),
            agent_instance_id: request.action.agent.agent_instance_id.0.clone(),
            action_hash: request.action_hash.clone(),
            tool: request.action.tool.clone(),
            tool_snapshot_hash: request.tool.snapshot_hash.clone(),
            resource: request.action.resource.locator.clone(),
            requested_resource_version: expected_resource_version.clone(),
            execution_plan_hash: request
                .action
                .extensions
                .get("x-plan-hash")
                .and_then(Value::as_str)
                .map(str::to_owned),
            deployment: request.action.environment.deployment.clone(),
            region: request.action.environment.region.clone(),
            simulation: request.action.environment.simulation,
            requested_at: now,
        };
        let futures = self.sources.iter().map(|(kind, client)| {
            let kind = *kind;
            let client = client.clone();
            let query = query.clone();
            async move {
                let envelope: SignedAuthoritativeFactEnvelope =
                    client.post(&query.tenant_id, &query).await?;
                let signer = client.signer()?;
                if envelope.issuer != signer.issuer.as_ref()
                    || envelope.key_id != signer.key_id.as_ref()
                    || envelope.key_usage != signer.key_usage.as_ref()
                    || envelope.authority_uri != client.endpoint.as_str()
                {
                    return Err(PepAuthorityError::DependencyResponseInvalid);
                }
                envelope
                    .verify(
                        &signer.verifying_key,
                        kind,
                        &query.tenant_id,
                        &query.action_hash,
                        Utc::now(),
                    )
                    .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
                Ok::<_, PepAuthorityError>((kind, envelope))
            }
        });
        let facts = try_join_all(futures)
            .await?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        if facts.len() != 6 {
            return Err(PepAuthorityError::DependencyResponseInvalid);
        }
        let identity: IdentityFact = payload(&facts, AuthoritativeFactKind::Identity)?;
        let resource: ResourceStateFact = payload(&facts, AuthoritativeFactKind::ResourceState)?;
        let budget: BudgetFact = payload(&facts, AuthoritativeFactKind::Budget)?;
        let trajectory: TrajectoryRiskFact =
            payload(&facts, AuthoritativeFactKind::TrajectoryRisk)?;
        let registry: RegistryFact = payload(&facts, AuthoritativeFactKind::Registry)?;
        let environment: EnvironmentFact = payload(&facts, AuthoritativeFactKind::Environment)?;
        if identity.subject != request.action.agent.owner_subject
            || identity.subject.is_empty()
            || identity.subject.len() > 512
            || (request
                .action
                .environment
                .deployment
                .eq_ignore_ascii_case("production")
                && identity.uses_dev_verifier)
            || resource.version != expected_resource_version
            || !resource.fresh
            || trajectory.version.is_empty()
            || trajectory.version.len() > 256
            || trajectory.accumulated_resources.len() > 4_096
            || trajectory
                .accumulated_resources
                .iter()
                .any(|value| value.is_empty() || value.len() > 2_048)
            || trajectory.anomaly_score_millionths > 1_000_000
            || registry.tool_id != request.tool.tool_id.0
            || registry.tool_version != request.tool.tool_version.0
            || registry.snapshot_hash != request.tool.snapshot_hash
            || registry.registry_revision != request.tool.registry_revision
            || !registry.active
            || registry.revoked
            || environment.deployment != request.action.environment.deployment
            || environment.region != request.action.environment.region
            || environment.simulation != request.action.environment.simulation
        {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let captured_at = Utc::now();
        let expires_at = facts
            .values()
            .map(|fact| fact.valid_until)
            .min()
            .ok_or(PepAuthorityError::DependencyResponseInvalid)?
            .min(captured_at + chrono::Duration::minutes(2));
        if expires_at <= captured_at {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let fact_refs = facts
            .into_values()
            .map(|fact| AuthoritativeFactRef {
                kind: fact.kind,
                status: fact.status,
                uri: fact.authority_uri,
                digest: fact.digest,
                version: fact.version,
                observed_at: fact.observed_at,
                valid_until: fact.valid_until,
            })
            .collect();
        let mut snapshot = AuthoritativeFactSnapshot {
            schema_version: SchemaVersion(AUTHORITATIVE_FACT_SNAPSHOT_SCHEMA_VERSION.into()),
            tenant_id: tenant.clone(),
            action_hash: request.action_hash.clone(),
            identity_subject: Some(identity.subject),
            identity_uses_dev_verifier: Some(identity.uses_dev_verifier),
            identity_revocation_epoch: Some(identity.revocation_epoch),
            resource_state_version: Some(ResourceVersion(resource.version)),
            resource_state_fresh: Some(resource.fresh),
            budget_remaining_microunits: Some(budget.remaining_microunits),
            trajectory_risk_version: Some(trajectory.version),
            accumulated_resources: Some(trajectory.accumulated_resources),
            anomaly_score_millionths: Some(trajectory.anomaly_score_millionths),
            fact_refs,
            captured_at,
            expires_at,
            snapshot_digest: String::new(),
        };
        snapshot
            .seal()
            .map_err(|_| PepAuthorityError::DependencyResponseInvalid)?;
        snapshot
            .require_verified()
            .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
        Ok(snapshot)
    }

    async fn ready(&self) -> bool {
        futures::future::join_all(self.sources.values().map(OutboundAuthorityClient::ready))
            .await
            .into_iter()
            .all(|ready| ready)
    }
}

fn payload<T: DeserializeOwned>(
    facts: &BTreeMap<AuthoritativeFactKind, SignedAuthoritativeFactEnvelope>,
    kind: AuthoritativeFactKind,
) -> Result<T, PepAuthorityError> {
    serde_json::from_value(
        facts
            .get(&kind)
            .ok_or(PepAuthorityError::DependencyResponseInvalid)?
            .payload
            .clone(),
    )
    .map_err(|_| PepAuthorityError::DependencyResponseInvalid)
}

#[derive(Clone)]
struct ProductionPdp {
    client: OutboundAuthorityClient,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PdpRequest<'a> {
    schema_version: &'static str,
    input: &'a PolicyInput,
    stage: EnforcementStage,
    active_policy_bundle_hash: &'a str,
    active_policy_version: &'a str,
    environment: PolicyEnvironment,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PdpResponse {
    result: PolicyDecision,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct GovernancePdpRequest<'a, T: Serialize + ?Sized> {
    schema_version: &'static str,
    input: &'a T,
    stage: &'a str,
    active_policy_bundle_hash: &'a str,
    active_policy_version: &'a str,
    environment: PolicyEnvironment,
}

#[async_trait]
impl PolicyDecisionPointPort for ProductionPdp {
    async fn evaluate(
        &self,
        input: &PolicyInput,
        stage: EnforcementStage,
    ) -> Result<PolicyDecision, PolicyError> {
        let _ = (input, stage);
        // Production evaluation is only legal through `evaluate_bound`, which supplies the
        // database-authoritative tenant/environment bundle binding.
        Err(PolicyError::PdpUnavailable)
    }
}

impl ProductionPdp {
    async fn evaluate_bound(
        &self,
        input: &PolicyInput,
        stage: EnforcementStage,
        active: &crate::postgres::ActivePolicyBundle,
    ) -> Result<PolicyDecision, PolicyError> {
        let response: PdpResponse = self
            .client
            .post(
                &input.environment.tenant_id,
                &PdpRequest {
                    schema_version: "agenttrust.pdp-request.v2",
                    input,
                    stage,
                    active_policy_bundle_hash: &active.bundle_digest,
                    active_policy_version: &active.policy_version,
                    environment: active.environment,
                },
            )
            .await
            .map_err(|_| PolicyError::PdpUnavailable)?;
        Ok(response.result)
    }

    async fn evaluate_governance<T: Serialize + ?Sized>(
        &self,
        input: &T,
        stage: &str,
        tenant: &TenantId,
        active: &crate::postgres::ActivePolicyBundle,
    ) -> Result<PolicyDecision, PepAuthorityError> {
        if !matches!(stage, "GOVERNANCE_APPROVAL" | "GOVERNANCE_QUERY") {
            return Err(PepAuthorityError::RequestInvalid);
        }
        let response: PdpResponse = self
            .client
            .post(
                tenant,
                &GovernancePdpRequest {
                    schema_version: "agenttrust.governance-pdp-request.v1",
                    input,
                    stage,
                    active_policy_bundle_hash: &active.bundle_digest,
                    active_policy_version: &active.policy_version,
                    environment: active.environment,
                },
            )
            .await?;
        Ok(response.result)
    }
}

#[derive(Clone)]
struct BoundDecisionPdp {
    decision: PolicyDecision,
}

#[async_trait]
impl PolicyDecisionPointPort for BoundDecisionPdp {
    async fn evaluate(
        &self,
        input: &PolicyInput,
        _: EnforcementStage,
    ) -> Result<PolicyDecision, PolicyError> {
        if crate::policy_input_hash(input)? != self.decision.input_hash {
            return Err(PolicyError::InputHashMismatch);
        }
        Ok(self.decision.clone())
    }
}

#[derive(Clone)]
struct AuthorityBackedRegistry {
    tenant: TenantId,
    snapshot: ResolvedToolSnapshot,
}

#[async_trait]
impl ToolRegistry for AuthorityBackedRegistry {
    async fn resolve_exact(
        &self,
        tenant: &TenantId,
        tool: &ToolRef,
    ) -> Result<ResolvedToolSnapshot, RegistryError> {
        if tenant != &self.tenant
            || tool.tool_id != self.snapshot.tool_id
            || tool.tool_version != self.snapshot.tool_version
        {
            return Err(RegistryError::ToolNotFound);
        }
        Ok(self.snapshot.clone())
    }

    async fn validate_arguments(
        &self,
        snapshot: &ResolvedToolSnapshot,
        arguments: &serde_json::Map<String, Value>,
    ) -> Result<(), RegistryError> {
        if snapshot.snapshot_hash != self.snapshot.snapshot_hash {
            return Err(RegistryError::ManifestHashMismatch);
        }
        validate_schema_instance(
            &snapshot.input_schema,
            &Value::Object(arguments.clone()),
            false,
        )
    }

    async fn validate_output(
        &self,
        _: &ResolvedToolSnapshot,
        _: &Value,
    ) -> Result<(), RegistryError> {
        Err(RegistryError::UnavailableFailClosed)
    }

    async fn discover_capabilities(
        &self,
        _: CapabilityQuery,
    ) -> Result<Vec<CapabilityDescriptor>, RegistryError> {
        Err(RegistryError::UnavailableFailClosed)
    }

    async fn snapshot(
        &self,
        _: &TenantId,
        _: &[ToolRef],
    ) -> Result<RegistrySnapshot, RegistryError> {
        Err(RegistryError::UnavailableFailClosed)
    }

    async fn is_revoked(&self, tool: &ToolRef, digest: &str) -> Result<bool, RegistryError> {
        Ok(tool.tool_id != self.snapshot.tool_id
            || tool.tool_version != self.snapshot.tool_version
            || digest != self.snapshot.implementation.digest)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerVerificationRequest {
    schema_version: String,
    tenant_id: TenantId,
    execution_id: ExecutionId,
    ledger_event_id: String,
    ledger_event_digest: String,
    action_hash: ActionHash,
    idempotency_key: String,
    fence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedLedgerVerificationReceipt {
    schema_version: String,
    tenant_id: TenantId,
    execution_id: ExecutionId,
    ledger_event_id: String,
    ledger_event_digest: String,
    action_hash: ActionHash,
    idempotency_key: String,
    fence_digest: String,
    status: ExecutionStatus,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    issuer: String,
    key_id: String,
    key_usage: String,
    signature: String,
}

#[derive(Clone)]
pub struct PepAuthority {
    pub(crate) store: Arc<PostgresPepStore>,
    facts: FactAuthoritySet,
    pdp: ProductionPdp,
    pub(crate) pdp_activation: OutboundAuthorityClient,
    approval: OutboundAuthorityClient,
    ledger: OutboundAuthorityClient,
    credential: OutboundAuthorityClient,
    pub(crate) issuer: String,
    pub(crate) key_id: String,
    pub(crate) signing_key: SigningKey,
    pub(crate) policy_bundle_keys: PolicyBundleKeyring,
}

impl PepAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn from_bindings(
        store: Arc<PostgresPepStore>,
        document: AuthorityBindingsDocument,
        issuer: String,
        key_id: String,
        signing_key: SigningKey,
        policy_bundle_keys: PolicyBundleKeyring,
    ) -> Result<Self, PepAuthorityError> {
        if document.schema_version != "agenttrust.pep-authority-bindings.v1"
            || validate_identifier(&issuer).is_err()
            || validate_identifier(&key_id).is_err()
            || !policy_bundle_keys.ready()
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        let mut sources = BTreeMap::new();
        for (kind, definition) in [
            (AuthoritativeFactKind::Identity, &document.identity),
            (
                AuthoritativeFactKind::ResourceState,
                &document.resource_state,
            ),
            (AuthoritativeFactKind::Budget, &document.budget),
            (
                AuthoritativeFactKind::TrajectoryRisk,
                &document.trajectory_risk,
            ),
            (AuthoritativeFactKind::Registry, &document.registry),
            (AuthoritativeFactKind::Environment, &document.environment),
        ] {
            let client = OutboundAuthorityClient::from_definition(definition, true)?;
            if client.signer()?.key_usage.as_ref() != "AUTHORITATIVE_FACT" {
                return Err(PepAuthorityError::ConfigurationInvalid);
            }
            sources.insert(kind, client);
        }
        let pdp = ProductionPdp {
            client: OutboundAuthorityClient::from_definition(&document.pdp, false)?,
        };
        let pdp_activation =
            OutboundAuthorityClient::from_definition(&document.pdp_activation, true)?;
        if pdp_activation.signer()?.key_usage.as_ref()
            != agent_trust_contracts::PDP_POLICY_ACTIVATION_ACK_KEY_USAGE
            || pdp_activation.scope.as_ref() != "pdp:policy-activate"
            || pdp_activation.endpoint.path() != "/v1/policies/activations"
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        let approval = OutboundAuthorityClient::from_definition(&document.approval, true)?;
        let ledger = OutboundAuthorityClient::from_definition(&document.ledger, true)?;
        let credential = OutboundAuthorityClient::from_definition(&document.credential, true)?;
        let mut authority_token_digests = BTreeSet::new();
        if sources
            .values()
            .chain([
                &pdp.client,
                &pdp_activation,
                &approval,
                &ledger,
                &credential,
            ])
            .any(|client| !authority_token_digests.insert(client.token_sha256.clone()))
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        if ledger.signer()?.key_usage.as_ref() != LEDGER_VERIFICATION_KEY_USAGE
            || credential.signer()?.key_usage.as_ref() != WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE
            || credential.scope.as_ref() != "credentials:issue"
            || credential.endpoint.path() != "/v1/credentials/issue"
        {
            return Err(PepAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            store,
            facts: FactAuthoritySet { sources },
            pdp,
            pdp_activation,
            approval,
            ledger,
            credential,
            issuer,
            key_id,
            signing_key,
            policy_bundle_keys,
        })
    }

    pub fn bindings_from_file(path: &Path) -> Result<AuthorityBindingsDocument, PepAuthorityError> {
        let raw = secure_read(path, true, 1_048_576)?;
        serde_json::from_slice(&raw).map_err(|_| PepAuthorityError::ConfigurationInvalid)
    }

    pub async fn preapprove(
        &self,
        request: PreApprovalRequest,
    ) -> Result<PreApprovalResponse, PepAuthorityError> {
        let now = Utc::now();
        validate_preapproval_request(&request, now)?;
        let tenant = request.action.environment.tenant_id.clone();
        let environment =
            PolicyEnvironment::from_deployment(&request.action.environment.deployment)
                .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
        let active = self
            .store
            .active_policy_bundle(&tenant, environment)
            .await?;
        let request_digest = canonical_digest(&request)?;
        if let Some(replay) = self
            .store
            .replay(
                &tenant,
                "PRE_APPROVAL",
                &request.idempotency_key,
                &request_digest,
            )
            .await?
        {
            self.validate_preapproval_response(&replay, Utc::now())?;
            if replay.signed_outcome.decision.policy_bundle_hash != active.bundle_digest
                || replay.signed_outcome.decision.policy_version.0 != active.policy_version
            {
                return Err(PepAuthorityError::AuthorizationDenied);
            }
            return Ok(replay);
        }
        let facts = self.facts.fetch(&request, now).await?;
        let policy_input = policy_input_from_facts(&request.action, &request.tool, &facts, &[])?;
        let decision = self
            .pdp
            .evaluate_bound(&policy_input, EnforcementStage::PreApproval, &active)
            .await
            .map_err(policy_error)?;
        let policy_input_hash = crate::policy_input_hash(&policy_input).map_err(policy_error)?;
        let decision_verified_at = Utc::now();
        validate_policy_decision(
            &decision,
            &policy_input_hash,
            decision_verified_at,
            &active.bundle_digest,
        )
        .map_err(policy_error)?;
        let (owner, decision) = match self
            .store
            .begin_claim::<PreApprovalResponse, PolicyDecision>(
                &tenant,
                "PRE_APPROVAL",
                &request.idempotency_key,
                &request_digest,
                &decision,
            )
            .await?
        {
            PepClaimResult::Replay(response) => {
                self.validate_preapproval_response(&response, Utc::now())?;
                return Ok(response);
            }
            PepClaimResult::Acquired { owner, context } => (owner, context),
        };
        let enforcement_time = Utc::now();
        validate_policy_decision(
            &decision,
            &policy_input_hash,
            enforcement_time,
            &active.bundle_digest,
        )
        .map_err(policy_error)?;
        let current = self
            .store
            .active_policy_bundle(&tenant, environment)
            .await?;
        if current.activation_id != active.activation_id
            || current.bundle_digest != active.bundle_digest
            || decision.policy_version.0 != active.policy_version
        {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let engine = self.engine(
            &request.tool,
            &tenant,
            decision.clone(),
            &active.bundle_digest,
        );
        let outcome = engine
            .enforce(EnforcementRequest {
                stage: EnforcementStage::PreApproval,
                action: request.action.clone(),
                action_hash: request.action_hash.clone(),
                tool: request.tool.clone(),
                policy_input,
                approval: None,
                idempotency_key: Some(request.idempotency_key.clone()),
                execution_context: None,
                identity_uses_dev_verifier: facts
                    .identity_uses_dev_verifier
                    .ok_or(PepAuthorityError::AuthorizationDenied)?,
                resource_state_fresh: facts
                    .resource_state_fresh
                    .ok_or(PepAuthorityError::AuthorizationDenied)?,
                now: enforcement_time,
            })
            .await
            .map_err(policy_error)?;
        let (decision, approval_required) = match outcome {
            EnforcementOutcome::Denied { decision } => {
                self.store
                    .persist_denial(
                        &tenant,
                        "PRE_APPROVAL",
                        &request.idempotency_key,
                        &request_digest,
                        &owner,
                        &request.action_hash.0,
                        &decision,
                    )
                    .await?;
                return Err(PepAuthorityError::AuthorizationDenied);
            }
            EnforcementOutcome::PreApprovalPassed { decision, .. } => (decision, false),
            EnforcementOutcome::ApprovalRequired { decision } => (decision, true),
            _ => return Err(PepAuthorityError::ResponseInvalid),
        };
        let issued_at = Utc::now();
        let compensation_plan = compensation_plan(&request, issued_at)?;
        let plan_digest = compensation_plan
            .as_ref()
            .map(canonical_digest)
            .transpose()?;
        let expires_at = (issued_at + chrono::Duration::seconds(60))
            .min(facts.expires_at)
            .min(decision.expires_at);
        if expires_at <= issued_at {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let mut signed_outcome = SignedPreApprovalOutcome {
            schema_version: SchemaVersion(PRE_APPROVAL_OUTCOME_SCHEMA_VERSION.into()),
            tenant_id: tenant.clone(),
            task_id: request.action.task_id.clone(),
            step_id: request.action.step_id.clone(),
            action_hash: request.action_hash.clone(),
            tool_id: request.tool.tool_id.clone(),
            tool_version: request.tool.tool_version.clone(),
            tool_snapshot_hash: request.tool.snapshot_hash.clone(),
            stage: EnforcementStage::PreApproval,
            idempotency_key: agent_trust_contracts::IdempotencyKey(request.idempotency_key.clone()),
            request_digest: request_digest.clone(),
            fact_snapshot: facts,
            fact_snapshot_digest: String::new(),
            execution_plan_digest: plan_digest,
            approval_required,
            decision: decision.clone(),
            issued_at,
            expires_at,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            key_usage: PEP_PRE_APPROVAL_KEY_USAGE.into(),
            signature: String::new(),
        };
        signed_outcome
            .sign(&self.signing_key)
            .map_err(|_| PepAuthorityError::ResponseInvalid)?;
        let response = PreApprovalResponse {
            schema_version: PEP_PRE_APPROVAL_ENVELOPE_SCHEMA_VERSION.into(),
            signed_outcome,
            compensation_plan,
        };
        self.validate_preapproval_response(&response, Utc::now())?;
        self.store
            .persist(
                &tenant,
                "PRE_APPROVAL",
                &request.idempotency_key,
                &request_digest,
                &owner,
                &request.action_hash.0,
                &response,
                &decision,
                None,
            )
            .await
    }

    pub async fn authorize(
        &self,
        request: FinalAuthorizationRequest,
    ) -> Result<FinalAuthorizationResponse, PepAuthorityError> {
        let now = Utc::now();
        validate_final_request(&request, now)?;
        let tenant = request.action.environment.tenant_id.clone();
        let environment =
            PolicyEnvironment::from_deployment(&request.action.environment.deployment)
                .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
        let active = self
            .store
            .active_policy_bundle(&tenant, environment)
            .await?;
        let request_digest = canonical_digest(&request)?;
        request
            .preapproval
            .verify(&self.signing_key.verifying_key(), now)
            .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
        let preapproval_digest = canonical_digest(&request.preapproval)?;
        validate_preapproval_binding(&request)?;
        if let Some(replay) = self
            .store
            .replay::<PersistedFinalAuthorizationResponse>(
                &tenant,
                "PRE_EXECUTION",
                &request.idempotency_key,
                &request_digest,
            )
            .await?
        {
            if replay.authorization.policy_bundle_hash != active.bundle_digest
                || replay.authorization.policy_version.0 != active.policy_version
            {
                return Err(PepAuthorityError::AuthorizationDenied);
            }
            return self.rehydrate_final_response(&request, replay).await;
        }
        let approval = self.verify_approval(&request).await?;
        let prior_approvals = approval
            .iter()
            .map(|grant| grant.approval_id.0.clone())
            .collect::<Vec<_>>();
        let expected_input = policy_input_from_facts(
            &request.action,
            &request.tool,
            &request.preapproval.fact_snapshot,
            &prior_approvals,
        )?;
        if canonical_digest(&expected_input)? != canonical_digest(&request.policy_input)? {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let ledger = self.verify_ledger(&request).await?;
        let decision = self
            .pdp
            .evaluate_bound(
                &request.policy_input,
                EnforcementStage::PreExecution,
                &active,
            )
            .await
            .map_err(policy_error)?;
        let decision_verified_at = Utc::now();
        validate_policy_decision(
            &decision,
            &crate::policy_input_hash(&request.policy_input).map_err(policy_error)?,
            decision_verified_at,
            &active.bundle_digest,
        )
        .map_err(policy_error)?;
        let (owner, decision) = match self
            .store
            .begin_claim::<PersistedFinalAuthorizationResponse, PolicyDecision>(
                &tenant,
                "PRE_EXECUTION",
                &request.idempotency_key,
                &request_digest,
                &decision,
            )
            .await?
        {
            PepClaimResult::Replay(response) => {
                return self.rehydrate_final_response(&request, response).await;
            }
            PepClaimResult::Acquired { owner, context } => (owner, context),
        };
        let enforcement_time = Utc::now();
        validate_policy_decision(
            &decision,
            &crate::policy_input_hash(&request.policy_input).map_err(policy_error)?,
            enforcement_time,
            &active.bundle_digest,
        )
        .map_err(policy_error)?;
        let current = self
            .store
            .active_policy_bundle(&tenant, environment)
            .await?;
        if current.activation_id != active.activation_id
            || current.bundle_digest != active.bundle_digest
            || decision.policy_version.0 != active.policy_version
        {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        if !matches!(
            decision.decision,
            Decision::Allow | Decision::RequireApproval
        ) {
            self.store
                .persist_denial(
                    &tenant,
                    "PRE_EXECUTION",
                    &request.idempotency_key,
                    &request_digest,
                    &owner,
                    &request.action_hash.0,
                    &decision,
                )
                .await?;
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        let credential = self
            .issue_credential(&request, &decision.decision_id)
            .await?;
        let authorization_time = Utc::now();
        let engine = self.engine(
            &request.tool,
            &tenant,
            decision.clone(),
            &active.bundle_digest,
        );
        let outcome = engine
            .enforce(EnforcementRequest {
                stage: EnforcementStage::PreExecution,
                action: request.action.clone(),
                action_hash: request.action_hash.clone(),
                tool: request.tool.clone(),
                policy_input: request.policy_input.clone(),
                approval: approval.clone(),
                idempotency_key: Some(request.idempotency_key.clone()),
                execution_context: Some(ExecutionAuthorizationContext {
                    ledger_execution_id: request.ledger_execution_id.clone(),
                    ledger_event_id: request.ledger_event_id.clone(),
                    ledger_event_digest: request.ledger_event_digest.clone(),
                    fence_digest: request.fence_digest.clone(),
                    target_profile: credential.binding_receipt.claims.target_profile.clone(),
                    preapproval_digest,
                    approval_consumption_ref: request.approval_consumption_ref.clone(),
                    approval_receipt_digest: request.approval_receipt_digest.clone(),
                    workload_credential_id: credential.binding_receipt.claims.credential_id.clone(),
                    workload_credential_claims_digest: credential
                        .binding_receipt
                        .claims_digest
                        .clone(),
                    workload_credential_audience: credential
                        .binding_receipt
                        .claims
                        .audience
                        .clone(),
                    workload_credential_revocation_epoch: credential
                        .binding_receipt
                        .claims
                        .revocation_epoch,
                }),
                identity_uses_dev_verifier: request
                    .preapproval
                    .fact_snapshot
                    .identity_uses_dev_verifier
                    .ok_or(PepAuthorityError::AuthorizationDenied)?,
                resource_state_fresh: request
                    .preapproval
                    .fact_snapshot
                    .resource_state_fresh
                    .ok_or(PepAuthorityError::AuthorizationDenied)?,
                now: authorization_time,
            })
            .await
            .map_err(policy_error)?;
        let mut authorization = match outcome {
            EnforcementOutcome::ExecutionAuthorized { authorization, .. } => *authorization,
            EnforcementOutcome::Denied { decision } => {
                self.store
                    .persist_denial(
                        &tenant,
                        "PRE_EXECUTION",
                        &request.idempotency_key,
                        &request_digest,
                        &owner,
                        &request.action_hash.0,
                        &decision,
                    )
                    .await?;
                return Err(PepAuthorityError::AuthorizationDenied);
            }
            _ => return Err(PepAuthorityError::AuthorizationDenied),
        };
        authorization.expires_at = authorization
            .expires_at
            .min(request.preapproval.expires_at)
            .min(decision.expires_at)
            .min(credential.binding_receipt.claims.expires_at)
            .min(ledger.valid_until);
        if authorization.expires_at <= authorization_time {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        authorization
            .sign(&self.signing_key)
            .map_err(|_| PepAuthorityError::ResponseInvalid)?;
        let response = FinalAuthorizationResponse {
            schema_version: PEP_PRE_EXECUTION_AUTHORIZATION_SCHEMA_VERSION.into(),
            authorization: authorization.clone(),
            tool: request.tool.clone(),
            workload_credential: credential.workload_credential.clone(),
            credential_binding_receipt: credential.binding_receipt.clone(),
            target_profile: credential.binding_receipt.claims.target_profile.clone(),
            approval,
        };
        let persisted = PersistedFinalAuthorizationResponse {
            schema_version: response.schema_version.clone(),
            authorization: response.authorization.clone(),
            tool: response.tool.clone(),
            credential_binding_receipt: response.credential_binding_receipt.clone(),
            target_profile: response.target_profile.clone(),
            approval: response.approval.clone(),
        };
        self.store
            .persist(
                &tenant,
                "PRE_EXECUTION",
                &request.idempotency_key,
                &request_digest,
                &owner,
                &request.action_hash.0,
                &persisted,
                &decision,
                Some(&authorization),
            )
            .await?;
        Ok(response)
    }

    pub async fn ready(&self) -> bool {
        self.store.ready().await
            && self.facts.ready().await
            && self.pdp.client.ready().await
            && self.pdp_activation.ready().await
            && self.policy_bundle_keys.ready()
            && self.approval.ready().await
            && self.ledger.ready().await
            && self.credential.ready().await
    }

    pub(crate) async fn evaluate_governance_policy<T: Serialize + ?Sized>(
        &self,
        input: &T,
        stage: &str,
        tenant: &TenantId,
    ) -> Result<(PolicyDecision, String), PepAuthorityError> {
        let active = self
            .store
            .active_policy_bundle(tenant, PolicyEnvironment::Production)
            .await?;
        let decision = self
            .pdp
            .evaluate_governance(input, stage, tenant, &active)
            .await?;
        if decision.policy_bundle_hash != active.bundle_digest
            || decision.policy_version.0 != active.policy_version
        {
            return Err(PepAuthorityError::DependencyResponseInvalid);
        }
        Ok((decision, active.bundle_digest))
    }

    fn validate_preapproval_response(
        &self,
        response: &PreApprovalResponse,
        now: DateTime<Utc>,
    ) -> Result<(), PepAuthorityError> {
        let compensation_digest = response
            .compensation_plan
            .as_ref()
            .map(canonical_digest)
            .transpose()?;
        if response.schema_version != PEP_PRE_APPROVAL_ENVELOPE_SCHEMA_VERSION
            || response.signed_outcome.execution_plan_digest != compensation_digest
        {
            return Err(PepAuthorityError::PersistenceUnavailable);
        }
        response
            .signed_outcome
            .verify(&self.signing_key.verifying_key(), now)
            .map_err(|_| PepAuthorityError::AuthorizationDenied)
    }

    fn engine(
        &self,
        tool: &ResolvedToolSnapshot,
        tenant: &TenantId,
        decision: PolicyDecision,
        active_bundle_digest: &str,
    ) -> PolicyEnforcementPoint<AuthorityBackedRegistry, BoundDecisionPdp> {
        PolicyEnforcementPoint::new(
            Arc::new(AuthorityBackedRegistry {
                tenant: tenant.clone(),
                snapshot: tool.clone(),
            }),
            Arc::new(BoundDecisionPdp { decision }),
            Arc::new(MinimalApprovalKernel::default()),
            self.issuer.clone(),
            self.key_id.clone(),
            self.signing_key.clone(),
            active_bundle_digest.to_string(),
        )
    }

    async fn verify_approval(
        &self,
        request: &FinalAuthorizationRequest,
    ) -> Result<Option<agent_trust_contracts::MinimalApprovalGrant>, PepAuthorityError> {
        if !request.preapproval.approval_required {
            if request.approval.is_some()
                || request.approval_consumption_ref.is_some()
                || request.approval_receipt_digest.is_some()
            {
                return Err(PepAuthorityError::AuthorizationDenied);
            }
            return Ok(None);
        }
        let approval = request
            .approval
            .clone()
            .ok_or(PepAuthorityError::AuthorizationDenied)?;
        let consumption_ref = request
            .approval_consumption_ref
            .as_deref()
            .ok_or(PepAuthorityError::AuthorizationDenied)?;
        let expected_wire_digest = request
            .approval_receipt_digest
            .as_deref()
            .ok_or(PepAuthorityError::AuthorizationDenied)?;
        let receipt = self
            .approval
            .get_approval_receipt(&request.action.environment.tenant_id, consumption_ref)
            .await?;
        let signer = self.approval.signer()?;
        if receipt.issuer != signer.issuer.as_ref() || receipt.key_id != signer.key_id.as_ref() {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        receipt
            .verify(&receipt.issuer, &receipt.key_id, &signer.verifying_key)
            .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
        let mut signing_material = receipt.clone();
        signing_material.signature.clear();
        let payload_digest = canonical_digest(&signing_material)?;
        let expected_ref = format!(
            "urn:agenttrust:approval-consumption:{}:sha256:{}:kid:{}:sig:{}",
            receipt.receipt_id, payload_digest, receipt.key_id, receipt.signature
        );
        let wire = ApprovalGrantReceipt {
            schema_version: APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION.into(),
            grant: receipt.grant.clone(),
            consumed_at: receipt.consumed_at,
            remaining_uses: receipt.remaining_uses,
            consumption_ref: expected_ref.clone(),
        };
        let execution_plan_hash = request
            .action
            .extensions
            .get("x-plan-hash")
            .and_then(Value::as_str)
            .ok_or(PepAuthorityError::AuthorizationDenied)?;
        let parameter_hash = canonical_digest(request.action.arguments())?;
        let maximum_risk = request
            .action
            .risk
            .declared_risk
            .max(request.tool.risk_level)
            .max(request.preapproval.decision.risk_summary);
        if expected_ref != consumption_ref
            || canonical_digest(&wire)? != expected_wire_digest
            || receipt.tenant_id != request.action.environment.tenant_id.0
            || receipt.request.tenant_id != request.action.environment.tenant_id.0
            || receipt.grant.tenant_id != request.action.environment.tenant_id
            || receipt.grant.to_minimal_grant() != approval
            || approval.action_hash != request.action_hash
            || approval.task_id != request.action.task_id
            || approval.step_id != request.action.step_id
            || approval.policy_version != request.preapproval.decision.policy_version
            || approval.resource_version.0 != resource_version(&request.action)
            || receipt.request.plan_hash != execution_plan_hash
            || receipt.request.parameter_hash != parameter_hash
            || receipt.request.resource != request.action.resource.locator
            || receipt.request.environment != request.action.environment.deployment
            || receipt.request.maximum_risk != maximum_risk
            || receipt.consumed_at > Utc::now() + chrono::Duration::seconds(30)
            || now_outside(approval.expires_at)
        {
            return Err(PepAuthorityError::AuthorizationDenied);
        }
        Ok(Some(approval))
    }

    async fn verify_ledger(
        &self,
        request: &FinalAuthorizationRequest,
    ) -> Result<SignedLedgerVerificationReceipt, PepAuthorityError> {
        let query = LedgerVerificationRequest {
            schema_version: "agenttrust.ledger-verification-request.v1".into(),
            tenant_id: request.action.environment.tenant_id.clone(),
            execution_id: request.ledger_execution_id.clone(),
            ledger_event_id: request.ledger_event_id.clone(),
            ledger_event_digest: request.ledger_event_digest.clone(),
            action_hash: request.action_hash.clone(),
            idempotency_key: request.idempotency_key.clone(),
            fence_digest: request.fence_digest.clone(),
        };
        let receipt: SignedLedgerVerificationReceipt =
            self.ledger.post(&query.tenant_id, &query).await?;
        let signer = self.ledger.signer()?;
        verify_ledger_receipt(&receipt, &query, signer, Utc::now())?;
        Ok(receipt)
    }

    async fn issue_credential(
        &self,
        request: &FinalAuthorizationRequest,
        policy_decision_id: &str,
    ) -> Result<WorkloadCredentialIssuance<CredentialHandle>, PepAuthorityError> {
        let credential_idempotency_key = IdempotencyKey(format!(
            "pep-credential:{}",
            hex(Sha256::digest(
                format!(
                    "{}:{}:{}",
                    request.action.environment.tenant_id.0,
                    request.idempotency_key,
                    request.action_hash.0
                )
                .as_bytes()
            ))
        ));
        let query = WorkloadCredentialBindingRequest {
            schema_version: WORKLOAD_CREDENTIAL_BINDING_REQUEST_SCHEMA_VERSION.into(),
            idempotency_key: credential_idempotency_key.clone(),
            tenant_id: request.action.environment.tenant_id.clone(),
            agent_instance_id: request.action.agent.agent_instance_id.clone(),
            task_id: request.action.task_id.clone(),
            step_id: request.action.step_id.clone(),
            action_hash: request.action_hash.clone(),
            policy_decision_id: policy_decision_id.to_string(),
            tool_id: request.tool.tool_id.clone(),
            credential_profile: request.tool.credential_profile.clone(),
            operation: request.action.intent.operation.clone(),
            resource: request.action.resource.locator.clone(),
            target_profile: request.tool.executor_profile.clone(),
            audience: "tool-proxy".into(),
            revocation_epoch: request
                .preapproval
                .fact_snapshot
                .identity_revocation_epoch
                .ok_or(PepAuthorityError::AuthorizationDenied)?,
            ttl_seconds: 60,
            max_uses: 1,
        };
        query
            .validate()
            .map_err(|_| PepAuthorityError::RequestInvalid)?;
        let issuance: WorkloadCredentialIssuance<CredentialHandle> = self
            .credential
            .post_idempotent(
                &query.tenant_id,
                &query,
                Some(&credential_idempotency_key.0),
            )
            .await?;
        let signer = self.credential.signer()?;
        verify_credential_receipt(
            &issuance.binding_receipt,
            &query,
            &issuance.workload_credential.0,
            signer,
            Utc::now(),
        )?;
        Ok(issuance)
    }

    async fn rehydrate_final_response(
        &self,
        request: &FinalAuthorizationRequest,
        persisted: PersistedFinalAuthorizationResponse,
    ) -> Result<FinalAuthorizationResponse, PepAuthorityError> {
        persisted
            .authorization
            .verify(&self.signing_key.verifying_key(), Utc::now())
            .map_err(|_| PepAuthorityError::PersistenceUnavailable)?;
        if persisted.schema_version != PEP_PRE_EXECUTION_AUTHORIZATION_SCHEMA_VERSION
            || persisted.authorization.tenant_id != request.action.environment.tenant_id
            || persisted.authorization.action_hash != request.action_hash
            || persisted.authorization.idempotency_key.0 != request.idempotency_key
            || persisted.authorization.tool_id != request.tool.tool_id
            || persisted.authorization.tool_version != request.tool.tool_version
            || persisted.authorization.tool_snapshot_hash != request.tool.snapshot_hash
            || persisted.authorization.ledger_execution_id != request.ledger_execution_id
            || persisted.authorization.ledger_event_id != request.ledger_event_id
            || persisted.authorization.ledger_event_digest != request.ledger_event_digest
            || persisted.authorization.fence_digest != request.fence_digest
            || persisted.authorization.preapproval_digest != canonical_digest(&request.preapproval)?
            || persisted.authorization.approval_consumption_ref != request.approval_consumption_ref
            || persisted.authorization.approval_receipt_digest != request.approval_receipt_digest
            || persisted.tool != request.tool
            || persisted.approval != request.approval
        {
            return Err(PepAuthorityError::PersistenceUnavailable);
        }
        let issuance = self
            .issue_credential(request, &persisted.authorization.policy_decision_id)
            .await?;
        if issuance.binding_receipt != persisted.credential_binding_receipt
            || issuance.binding_receipt.claims.credential_id
                != persisted.authorization.workload_credential_id
            || issuance.binding_receipt.claims_digest
                != persisted.authorization.workload_credential_claims_digest
            || issuance.binding_receipt.claims.audience
                != persisted.authorization.workload_credential_audience
            || issuance.binding_receipt.claims.revocation_epoch
                != persisted.authorization.workload_credential_revocation_epoch
            || issuance.binding_receipt.claims.target_profile != persisted.target_profile
        {
            return Err(PepAuthorityError::DependencyResponseInvalid);
        }
        Ok(FinalAuthorizationResponse {
            schema_version: persisted.schema_version,
            authorization: persisted.authorization,
            tool: persisted.tool,
            workload_credential: issuance.workload_credential,
            credential_binding_receipt: issuance.binding_receipt,
            target_profile: persisted.target_profile,
            approval: persisted.approval,
        })
    }
}

fn validate_preapproval_request(
    request: &PreApprovalRequest,
    now: DateTime<Utc>,
) -> Result<(), PepAuthorityError> {
    if request.schema_version != PEP_PRE_APPROVAL_REQUEST_SCHEMA_VERSION
        || !idempotency_key(&request.idempotency_key)
        || request.requested_at > now + chrono::Duration::seconds(30)
        || request.requested_at < now - chrono::Duration::minutes(5)
        || action_hash(&request.action).map_err(|_| PepAuthorityError::RequestInvalid)?
            != request.action_hash
        || request.action.tool.tool_id != request.tool.tool_id
        || request.action.tool.tool_version != request.tool.tool_version
        || request.tool.schema_version != agent_trust_registry::REGISTRY_SCHEMA_VERSION
        || !digest(&request.tool.snapshot_hash)
        || request.tool.registry_revision == 0
        || request.action.environment.tenant_id != request.action.agent.tenant_id
        || request.action.environment.tenant_id != request.action.resource.tenant_id
        || Uuid::parse_str(&request.action.environment.tenant_id.0).is_err()
        || Uuid::parse_str(&request.action.task_id.0).is_err()
        || Uuid::parse_str(&request.action.step_id.0).is_err()
        || Uuid::parse_str(&request.action.agent.agent_instance_id.0).is_err()
        || validate_schema_instance(
            &request.tool.input_schema,
            &Value::Object(request.action.payload.data.clone()),
            false,
        )
        .is_err()
    {
        return Err(PepAuthorityError::RequestInvalid);
    }
    let is_write = request.tool.effect_class != EffectClass::Pure;
    let execution_plan_hash = request
        .action
        .extensions
        .get("x-plan-hash")
        .and_then(Value::as_str);
    if (is_write
        && (request.action.current_state_version.is_none()
            || execution_plan_hash.is_none_or(|value| !digest(value))))
        || (request.tool.risk_level >= RiskLevel::High
            && request.action.current_state_version.is_none())
        || (request.tool.effect_class == EffectClass::Irreversible
            && request.tool.approval_profile == "none")
        || request
            .action
            .credential_refs
            .iter()
            .any(|reference| reference.profile == "inline")
    {
        return Err(PepAuthorityError::AuthorizationDenied);
    }
    Ok(())
}

fn validate_final_request(
    request: &FinalAuthorizationRequest,
    now: DateTime<Utc>,
) -> Result<(), PepAuthorityError> {
    let preapproval_request = PreApprovalRequest {
        schema_version: PEP_PRE_APPROVAL_REQUEST_SCHEMA_VERSION.into(),
        action: request.action.clone(),
        action_hash: request.action_hash.clone(),
        tool: request.tool.clone(),
        idempotency_key: request.idempotency_key.clone(),
        requested_at: request.requested_at,
    };
    validate_preapproval_request(&preapproval_request, now)?;
    if request.schema_version != PEP_FINAL_AUTHORIZATION_REQUEST_SCHEMA_VERSION
        || request.stage != EnforcementStage::PreExecution
        || Uuid::parse_str(&request.ledger_execution_id.0).is_err()
        || Uuid::parse_str(&request.ledger_event_id).is_err()
        || !digest(&request.ledger_event_digest)
        || !digest(&request.fence_digest)
    {
        return Err(PepAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn validate_preapproval_binding(
    request: &FinalAuthorizationRequest,
) -> Result<(), PepAuthorityError> {
    let preapproval = &request.preapproval;
    let expected_resource_version = resource_version(&request.action);
    if preapproval.schema_version.0 != PRE_APPROVAL_OUTCOME_SCHEMA_VERSION
        || preapproval.tenant_id != request.action.environment.tenant_id
        || preapproval.task_id != request.action.task_id
        || preapproval.step_id != request.action.step_id
        || preapproval.action_hash != request.action_hash
        || preapproval.tool_id != request.tool.tool_id
        || preapproval.tool_version != request.tool.tool_version
        || preapproval.tool_snapshot_hash != request.tool.snapshot_hash
        || preapproval.idempotency_key.0 != request.idempotency_key
        || preapproval.fact_snapshot.action_hash != request.action_hash
        || preapproval.fact_snapshot.tenant_id != request.action.environment.tenant_id
        || preapproval
            .fact_snapshot
            .resource_state_version
            .as_ref()
            .map(|value| value.0.as_str())
            != Some(expected_resource_version.as_str())
        || preapproval.fact_snapshot.identity_subject.as_deref()
            != Some(request.action.agent.owner_subject.as_str())
    {
        return Err(PepAuthorityError::AuthorizationDenied);
    }
    Ok(())
}

fn policy_input_from_facts(
    action: &CanonicalAction,
    tool: &ResolvedToolSnapshot,
    facts: &AuthoritativeFactSnapshot,
    prior_approvals: &[String],
) -> Result<PolicyInput, PepAuthorityError> {
    facts
        .require_verified()
        .map_err(|_| PepAuthorityError::AuthorizationDenied)?;
    to_policy_input(
        action,
        &tool.policy_snapshot(),
        &RuntimeContext {
            identity_subject: facts
                .identity_subject
                .clone()
                .ok_or(PepAuthorityError::AuthorizationDenied)?,
            prior_approvals: prior_approvals.to_vec(),
            budget_remaining_microunits: facts
                .budget_remaining_microunits
                .ok_or(PepAuthorityError::AuthorizationDenied)?,
        },
        &TrajectoryRiskSnapshot {
            version: facts
                .trajectory_risk_version
                .clone()
                .ok_or(PepAuthorityError::AuthorizationDenied)?,
            accumulated_resources: facts
                .accumulated_resources
                .clone()
                .ok_or(PepAuthorityError::AuthorizationDenied)?,
            anomaly_score_millionths: facts
                .anomaly_score_millionths
                .ok_or(PepAuthorityError::AuthorizationDenied)?,
        },
    )
    .map_err(|_| PepAuthorityError::RequestInvalid)
}

fn compensation_plan(
    request: &PreApprovalRequest,
    now: DateTime<Utc>,
) -> Result<Option<CompensationPlan>, PepAuthorityError> {
    match (request.tool.effect_class, &request.tool.compensation) {
        (EffectClass::Compensatable, Some(binding)) => Ok(Some(CompensationPlan {
            plan_id: Uuid::new_v4().to_string(),
            forward_action_hash: request.action_hash.clone(),
            steps: vec![CompensationStep {
                step_id: Uuid::new_v4().to_string(),
                tool: binding.tool.clone(),
                arguments_hash: canonical_digest(request.action.arguments())?,
                required_current_version: Some(ResourceVersion(resource_version(&request.action))),
                expected_current_value: None,
            }],
            created_at: now,
        })),
        (EffectClass::Compensatable, None) => Err(PepAuthorityError::AuthorizationDenied),
        (_, Some(_)) => Err(PepAuthorityError::AuthorizationDenied),
        (_, None) => Ok(None),
    }
}

fn verify_ledger_receipt(
    receipt: &SignedLedgerVerificationReceipt,
    request: &LedgerVerificationRequest,
    signer: &AuthoritySigner,
    now: DateTime<Utc>,
) -> Result<(), PepAuthorityError> {
    if receipt.schema_version != LEDGER_VERIFICATION_SCHEMA
        || receipt.tenant_id != request.tenant_id
        || receipt.execution_id != request.execution_id
        || receipt.ledger_event_id != request.ledger_event_id
        || receipt.ledger_event_digest != request.ledger_event_digest
        || receipt.action_hash != request.action_hash
        || receipt.idempotency_key != request.idempotency_key
        || receipt.fence_digest != request.fence_digest
        || receipt.status != ExecutionStatus::Prepared
        || receipt.issuer != signer.issuer.as_ref()
        || receipt.key_id != signer.key_id.as_ref()
        || receipt.key_usage != LEDGER_VERIFICATION_KEY_USAGE
        || receipt.observed_at > now
        || receipt.valid_until <= now
        || receipt.valid_until - receipt.observed_at > chrono::Duration::minutes(2)
    {
        return Err(PepAuthorityError::AuthorizationDenied);
    }
    verify_signature(receipt, &receipt.signature, &signer.verifying_key)
}

fn verify_credential_receipt(
    receipt: &SignedWorkloadCredentialBindingReceipt,
    request: &WorkloadCredentialBindingRequest,
    credential_handle: &str,
    signer: &AuthoritySigner,
    now: DateTime<Utc>,
) -> Result<(), PepAuthorityError> {
    if receipt.issuer != signer.issuer.as_ref()
        || receipt.key_id != signer.key_id.as_ref()
        || receipt.key_usage != WORKLOAD_CREDENTIAL_BINDING_KEY_USAGE
    {
        return Err(PepAuthorityError::AuthorizationDenied);
    }
    receipt
        .verify(&signer.verifying_key, request, credential_handle, now)
        .map_err(|_| PepAuthorityError::AuthorizationDenied)
}

fn verify_signature<T>(
    value: &T,
    signature: &str,
    key: &VerifyingKey,
) -> Result<(), PepAuthorityError>
where
    T: Serialize + Clone + ClearSignature,
{
    let mut unsigned = value.clone();
    unsigned.clear_signature();
    let raw = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| PepAuthorityError::DependencyResponseInvalid)?;
    let signature =
        Signature::from_slice(&raw).map_err(|_| PepAuthorityError::DependencyResponseInvalid)?;
    key.verify(
        &serde_jcs::to_vec(&unsigned).map_err(|_| PepAuthorityError::DependencyResponseInvalid)?,
        &signature,
    )
    .map_err(|_| PepAuthorityError::AuthorizationDenied)
}

trait ClearSignature {
    fn clear_signature(&mut self);
}

impl ClearSignature for SignedLedgerVerificationReceipt {
    fn clear_signature(&mut self) {
        self.signature.clear();
    }
}

async fn bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<T, PepAuthorityError> {
    if matches!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED
            | reqwest::StatusCode::FORBIDDEN
            | reqwest::StatusCode::CONFLICT
            | reqwest::StatusCode::UNPROCESSABLE_ENTITY
    ) {
        return Err(PepAuthorityError::AuthorizationDenied);
    }
    if !response.status().is_success()
        || response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            != Some("application/json")
        || response
            .content_length()
            .is_some_and(|length| length as usize > maximum_bytes)
    {
        return Err(PepAuthorityError::DependencyUnavailable);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| PepAuthorityError::DependencyUnavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(PepAuthorityError::DependencyResponseInvalid);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(PepAuthorityError::DependencyResponseInvalid);
    }
    serde_json::from_slice(&bytes).map_err(|_| PepAuthorityError::DependencyResponseInvalid)
}

fn strict_https_url(value: &str) -> Result<Url, PepAuthorityError> {
    let url = Url::parse(value).map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().is_empty()
    {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    Ok(url)
}

fn validate_identifier(value: &str) -> Result<String, PepAuthorityError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
    {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    Ok(value.to_string())
}

fn read_secret(path: &Path) -> Result<String, PepAuthorityError> {
    let raw = secure_read(path, true, 65_536)?;
    let value = std::str::from_utf8(&raw)
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?
        .trim();
    if value.is_empty() || value.contains(char::is_whitespace) || value.len() > 8_192 {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    Ok(value.to_string())
}

pub(crate) fn read_verifying_key(path: &Path) -> Result<VerifyingKey, PepAuthorityError> {
    let encoded = read_secret(path)?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| PepAuthorityError::ConfigurationInvalid)
}

pub fn read_signing_key(path: &Path) -> Result<SigningKey, PepAuthorityError> {
    let encoded = read_secret(path)?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub(crate) fn secure_read(
    path: &Path,
    private: bool,
    maximum: u64,
) -> Result<Vec<u8>, PepAuthorityError> {
    if !path.is_absolute() {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| PepAuthorityError::ConfigurationInvalid)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
        || !secure_mode(&metadata, private)
    {
        return Err(PepAuthorityError::ConfigurationInvalid);
    }
    std::fs::read(path).map_err(|_| PepAuthorityError::ConfigurationInvalid)
}

#[cfg(unix)]
fn secure_mode(metadata: &std::fs::Metadata, private: bool) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mode = metadata.permissions().mode() & 0o7777;
    if !private {
        return mode & 0o022 == 0;
    }
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let allowed = 0o400 | if metadata.gid() == gid { 0o040 } else { 0 };
    ((metadata.uid() == uid && mode & 0o400 != 0) || (metadata.gid() == gid && mode & 0o040 != 0))
        && mode & !allowed == 0
}

#[cfg(not(unix))]
fn secure_mode(_: &std::fs::Metadata, _: bool) -> bool {
    false
}

fn policy_error(error: PolicyError) -> PepAuthorityError {
    match error {
        PolicyError::PdpUnavailable => PepAuthorityError::DependencyUnavailable,
        PolicyError::DecisionInvalid | PolicyError::InputHashMismatch => {
            PepAuthorityError::DependencyResponseInvalid
        }
        _ => PepAuthorityError::AuthorizationDenied,
    }
}

fn resource_version(action: &CanonicalAction) -> String {
    action
        .current_state_version
        .clone()
        .or_else(|| {
            action
                .resource
                .version
                .as_ref()
                .map(|value| value.0.clone())
        })
        .unwrap_or_else(|| "unversioned-read".into())
}

fn now_outside(expires_at: DateTime<Utc>) -> bool {
    Utc::now() >= expires_at
}

fn idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_requires_https_without_url_credentials() {
        assert!(strict_https_url("https://identity.example/v1/facts").is_ok());
        assert!(strict_https_url("http://identity.example/v1/facts").is_err());
        assert!(strict_https_url("https://user@identity.example/v1/facts").is_err());
    }

    #[test]
    fn idempotency_key_is_strictly_bounded() {
        assert!(idempotency_key("action:one"));
        assert!(!idempotency_key("contains whitespace"));
        assert!(!idempotency_key(&"a".repeat(129)));
    }
}
