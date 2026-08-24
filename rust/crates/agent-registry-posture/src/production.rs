//! PostgreSQL-backed production authority for Agent Registry and posture facts.
//!
//! The in-memory domain types in `lib.rs` remain useful for deterministic rule tests.  This
//! module is the only store used by the production server: every mutation is tenant-scoped,
//! request-digested, advisory-locked, durably idempotent, and appended to the immutable audit
//! chain and outbox in the same database transaction.

use crate::{LifecycleState, ObservationSource, PostureKind, RegistryError, RelationshipKind};
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::TenantId;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use reqwest::{Certificate, Client, Identity, StatusCode};
use ring::hmac;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const REGISTRATION_REQUEST_SCHEMA: &str = "agenttrust.agent-registration-request.v1";
pub const OWNERSHIP_ASSIGNMENT_SCHEMA: &str = "agenttrust.ownership-assignment.v1";
pub const OWNERSHIP_CONFIRMATION_SCHEMA: &str = "agenttrust.ownership-confirmation.v1";
pub const DISCOVERY_INGEST_SCHEMA: &str = "agenttrust.discovery-ingest.v1";
pub const BOM_SCHEMA: &str = "agenttrust.agent-bom.v1";
pub const BOM_UPDATE_SCHEMA: &str = "agenttrust.agent-bom-update-request.v1";
pub const RELATIONSHIP_REQUEST_SCHEMA: &str = "agenttrust.relationship-edge-request.v1";
pub const POSTURE_EVALUATION_SCHEMA: &str = "agenttrust.posture-evaluation-request.v1";
pub const LIFECYCLE_REQUEST_SCHEMA: &str = "agenttrust.agent-lifecycle-request.v1";
pub const MUTATION_RECEIPT_SCHEMA: &str = "agenttrust.agent-registry-mutation-receipt.v1";
pub const AGENT_VIEW_SCHEMA: &str = "agenttrust.agent-inventory-item.v1";
pub const AGENT_PAGE_SCHEMA: &str = "agenttrust.authoritative-agent-page.v1";
pub const POSTURE_VIEW_SCHEMA: &str = "agenttrust.posture-finding-view.v1";
pub const RELATIONSHIP_VIEW_SCHEMA: &str = "agenttrust.relationship-edge-view.v1";
pub const POSTURE_PAGE_SCHEMA: &str = "agenttrust.authoritative-posture-page.v1";
pub const RELATIONSHIP_PAGE_SCHEMA: &str = "agenttrust.authoritative-relationship-page.v1";
pub const CURSOR_SCHEMA: &str = "agenttrust.agent-registry-cursor.v1";
pub const GOVERNANCE_CONTEXT_SCHEMA: &str = "agenttrust.governed-authority-context.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceContext {
    pub schema_version: String,
    pub action_hash: String,
    pub policy_decision_id: String,
    pub policy_decision_digest: String,
    pub execution_id: String,
    pub ledger_entry_id: String,
    pub ledger_entry_digest: String,
    pub authorization_evidence_ref: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwnershipRole {
    Owner,
    Sponsor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BomComponent {
    pub kind: String,
    pub name: String,
    pub version: String,
    pub digest: String,
    pub supply_chain_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentBomDocument {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub components: Vec<BomComponent>,
    pub bom_digest: String,
    pub generated_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct BomDigestMaterial<'a> {
    schema_version: &'a str,
    tenant_id: &'a TenantId,
    agent_id: &'a str,
    components: &'a [BomComponent],
    generated_at: DateTime<Utc>,
}

impl AgentBomDocument {
    pub fn expected_digest(&self) -> Result<String, RegistryError> {
        canonical_digest(&BomDigestMaterial {
            schema_version: &self.schema_version,
            tenant_id: &self.tenant_id,
            agent_id: &self.agent_id,
            components: &self.components,
            generated_at: self.generated_at,
        })
    }

    fn validate(
        &self,
        tenant: &TenantId,
        agent_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), RegistryError> {
        let kinds = [
            "MODEL",
            "TOOL",
            "PACK",
            "PROMPT",
            "MEMORY",
            "KNOWLEDGE",
            "RUNTIME",
            "MCP_SERVER",
        ];
        let mut unique = BTreeSet::new();
        if self.schema_version != BOM_SCHEMA
            || &self.tenant_id != tenant
            || self.agent_id != agent_id
            || self.components.is_empty()
            || self.components.len() > 10_000
            || self.generated_at > now + Duration::minutes(5)
            || !lower_digest(&self.bom_digest)
        {
            return Err(RegistryError::AssetInvalid);
        }
        for component in &self.components {
            if !kinds.contains(&component.kind.as_str())
                || !bounded_text(&component.name, 256)
                || !bounded_text(&component.version, 256)
                || !lower_digest(&component.digest)
                || component
                    .supply_chain_digest
                    .as_ref()
                    .is_some_and(|digest| !lower_digest(digest))
                || !unique.insert((component.kind.clone(), component.name.clone()))
            {
                return Err(RegistryError::AssetInvalid);
            }
            if component.kind == "PACK" && component.supply_chain_digest.is_none() {
                return Err(RegistryError::AssetInvalid);
            }
        }
        if self.expected_digest()? != self.bom_digest {
            return Err(RegistryError::AssetInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub display_name: String,
    pub owner_subject: String,
    pub sponsor_subject: String,
    pub ownership_review_due_at: DateTime<Utc>,
    pub environment: String,
    pub agent_type: String,
    pub endpoints: BTreeSet<String>,
    pub identity_refs: BTreeSet<String>,
    pub tool_refs: BTreeSet<String>,
    pub pack_refs: BTreeSet<String>,
    pub requested_permissions: BTreeSet<String>,
    pub approved_permissions: BTreeSet<String>,
    pub bom: AgentBomDocument,
    pub last_activity_at: DateTime<Utc>,
    pub provenance_ref: String,
    pub provenance_digest: String,
    pub governance: GovernanceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnershipAssignmentRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub owner_subject: String,
    pub sponsor_subject: String,
    pub review_due_at: DateTime<Utc>,
    pub directory_evidence_digest: String,
    pub governance: GovernanceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnershipConfirmationRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub ownership_version: u64,
    pub role: OwnershipRole,
    pub subject: String,
    pub confirmation_digest: String,
    pub governance: GovernanceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryIngestRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub observation_id: String,
    pub source: ObservationSource,
    pub collector_id: String,
    pub endpoint: String,
    pub claimed_agent_id: Option<String>,
    pub protocol: String,
    pub observed_component_digests: BTreeMap<String, String>,
    pub observed_at: DateTime<Utc>,
    pub payload_digest: String,
    pub provenance_ref: String,
    pub governance: GovernanceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelationshipEdgeRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub kind: RelationshipKind,
    pub evidence_digest: String,
    pub governance: GovernanceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostureEvaluationRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub inactivity_days: u32,
    pub revoked_activity_grace_seconds: u32,
    pub governance: GovernanceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub target: LifecycleState,
    pub reason_code: String,
    pub governance: GovernanceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BomUpdateRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub bom: AgentBomDocument,
    pub governance: GovernanceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MutationReceipt {
    pub schema_version: String,
    pub operation: String,
    pub resource_id: String,
    pub changed: bool,
    pub state: String,
    pub external_evidence_refs: BTreeSet<String>,
    pub event_ref: String,
    pub event_digest: String,
    pub governance_digest: String,
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentInventoryItem {
    pub schema_version: String,
    pub agent_id: String,
    pub display_name: String,
    pub owner_subject: String,
    pub sponsor_subject: String,
    pub ownership_status: String,
    pub environment: String,
    pub lifecycle: LifecycleState,
    pub agent_type: String,
    pub bom_digest: String,
    pub endpoint_count: u32,
    pub identity_count: u32,
    pub tool_count: u32,
    pub pack_count: u32,
    pub open_findings: u32,
    pub highest_risk: Option<String>,
    pub last_activity_at: DateTime<Utc>,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeAgentPage {
    pub schema_version: String,
    pub authoritative: bool,
    pub tenant_id: TenantId,
    pub resource: String,
    pub items: Vec<AgentInventoryItem>,
    pub next_cursor: Option<String>,
    pub data_digest: String,
}

#[derive(Serialize)]
struct AgentPageMaterial<'a> {
    schema_version: &'static str,
    authoritative: bool,
    tenant_id: &'a TenantId,
    resource: &'a str,
    items: &'a [AgentInventoryItem],
    next_cursor: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostureFindingView {
    pub schema_version: String,
    pub finding_id: String,
    pub agent_id: Option<String>,
    pub observation_id: Option<String>,
    pub kind: PostureKind,
    pub severity: String,
    pub reason_code: String,
    pub evidence_digest: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelationshipEdgeView {
    pub schema_version: String,
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub kind: RelationshipKind,
    pub evidence_digest: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativePosturePage {
    pub schema_version: String,
    pub authoritative: bool,
    pub tenant_id: TenantId,
    pub items: Vec<PostureFindingView>,
    pub next_cursor: Option<String>,
    pub data_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeRelationshipPage {
    pub schema_version: String,
    pub authoritative: bool,
    pub tenant_id: TenantId,
    pub root: String,
    pub maximum_depth: u32,
    pub items: Vec<RelationshipEdgeView>,
    pub data_digest: String,
}

#[derive(Serialize)]
struct QueryPageMaterial<'a, T: Serialize> {
    schema_version: &'static str,
    authoritative: bool,
    tenant_id: &'a TenantId,
    items: &'a [T],
    next_cursor: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct LifecycleConvergenceInput {
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub identity_refs: BTreeSet<String>,
    pub pack_refs: BTreeSet<String>,
    pub target: LifecycleState,
    pub reason_code: String,
    pub idempotency_key: String,
    pub governance: GovernanceContext,
}

#[async_trait]
pub trait ProductionLifecyclePort: Send + Sync {
    async fn ready(&self) -> bool;
    async fn converge(
        &self,
        input: &LifecycleConvergenceInput,
    ) -> Result<BTreeSet<String>, RegistryError>;
}

#[derive(Clone)]
pub struct HttpLifecyclePropagationPort {
    client: Client,
    base_url: Url,
    identity_token: Arc<Zeroizing<String>>,
    authorization_token: Arc<Zeroizing<String>>,
    pack_token: Arc<Zeroizing<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalEvidenceReceipt {
    evidence_ref: String,
}

impl HttpLifecyclePropagationPort {
    pub fn new(
        base_url: Url,
        ca_pem: &[u8],
        client_identity_pem: &[u8],
        identity_token: String,
        authorization_token: String,
        pack_token: String,
    ) -> Result<Self, RegistryError> {
        if base_url.scheme() != "https"
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || !base_url.path().trim_matches('/').is_empty()
            || [&identity_token, &authorization_token, &pack_token]
                .iter()
                .any(|token| !valid_secret(token))
            || identity_token == authorization_token
            || identity_token == pack_token
            || authorization_token == pack_token
        {
            return Err(RegistryError::ProductionTrustNotConfigured);
        }
        let ca = Certificate::from_pem(ca_pem)
            .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
        let identity = Identity::from_pem(client_identity_pem)
            .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
        let client = Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(identity)
            .connect_timeout(StdDuration::from_secs(5))
            .timeout(StdDuration::from_secs(15))
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
        Ok(Self {
            client,
            base_url,
            identity_token: Arc::new(Zeroizing::new(identity_token)),
            authorization_token: Arc::new(Zeroizing::new(authorization_token)),
            pack_token: Arc::new(Zeroizing::new(pack_token)),
        })
    }

    async fn propagate(
        &self,
        path: &str,
        token: &str,
        tenant: &TenantId,
        key: &str,
        body: &Value,
    ) -> Result<String, RegistryError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| RegistryError::ProductionTrustNotConfigured)?;
        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("X-AgentTrust-Tenant-Id", &tenant.0)
            .header("Idempotency-Key", key)
            .json(body)
            .send()
            .await
            .map_err(|_| RegistryError::PropagationFailed)?;
        if !response.status().is_success() {
            return Err(RegistryError::PropagationFailed);
        }
        let bytes = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| RegistryError::PropagationFailed)?;
        if bytes.is_empty() {
            return Err(RegistryError::PropagationFailed);
        }
        let receipt: ExternalEvidenceReceipt =
            serde_json::from_slice(&bytes).map_err(|_| RegistryError::PropagationFailed)?;
        if !valid_evidence_ref(&receipt.evidence_ref) {
            return Err(RegistryError::PropagationFailed);
        }
        Ok(receipt.evidence_ref)
    }
}

#[async_trait]
impl ProductionLifecyclePort for HttpLifecyclePropagationPort {
    async fn ready(&self) -> bool {
        let Ok(url) = self.base_url.join("/ready") else {
            return false;
        };
        self.client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::OK)
    }

    async fn converge(
        &self,
        input: &LifecycleConvergenceInput,
    ) -> Result<BTreeSet<String>, RegistryError> {
        let revoke = matches!(
            input.target,
            LifecycleState::Suspended | LifecycleState::Retired | LifecycleState::Revoked
        );
        let deactivate = matches!(
            input.target,
            LifecycleState::Retired | LifecycleState::Revoked
        );
        if !revoke {
            return Ok(BTreeSet::new());
        }
        let identity_key = format!("{}:identity", input.idempotency_key);
        let authorization_key = format!("{}:authorization", input.idempotency_key);
        let pack_key = format!("{}:pack", input.idempotency_key);
        let identity_body = serde_json::json!({
            "tenant_id":input.tenant_id,
            "agent_id":input.agent_id,
            "identity_refs":input.identity_refs,
            "reason_code":input.reason_code,
            "governance":input.governance
        });
        let authorization_body = serde_json::json!({
            "tenant_id":input.tenant_id,
            "agent_id":input.agent_id,
            "reason_code":input.reason_code,
            "governance":input.governance
        });
        let pack_body = serde_json::json!({
            "tenant_id":input.tenant_id,
            "agent_id":input.agent_id,
            "pack_refs":input.pack_refs,
            "reason_code":input.reason_code,
            "governance":input.governance
        });
        let mut refs = BTreeSet::new();
        if deactivate {
            let (identity, authorization, pack) = tokio::try_join!(
                self.propagate(
                    "/v1/lifecycle/identities/revoke",
                    self.identity_token.as_str(),
                    &input.tenant_id,
                    &identity_key,
                    &identity_body,
                ),
                self.propagate(
                    "/v1/lifecycle/authorizations/revoke",
                    self.authorization_token.as_str(),
                    &input.tenant_id,
                    &authorization_key,
                    &authorization_body,
                ),
                self.propagate(
                    "/v1/lifecycle/packs/deactivate",
                    self.pack_token.as_str(),
                    &input.tenant_id,
                    &pack_key,
                    &pack_body,
                )
            )?;
            refs.extend([identity, authorization, pack]);
        } else {
            let (identity, authorization) = tokio::try_join!(
                self.propagate(
                    "/v1/lifecycle/identities/revoke",
                    self.identity_token.as_str(),
                    &input.tenant_id,
                    &identity_key,
                    &identity_body,
                ),
                self.propagate(
                    "/v1/lifecycle/authorizations/revoke",
                    self.authorization_token.as_str(),
                    &input.tenant_id,
                    &authorization_key,
                    &authorization_body,
                )
            )?;
            refs.extend([identity, authorization]);
        }
        let expected = (if revoke { 2 } else { 0 }) + (if deactivate { 1 } else { 0 });
        if refs.len() != expected {
            return Err(RegistryError::PropagationFailed);
        }
        Ok(refs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    schema_version: String,
    tenant_id: String,
    resource: String,
    after: String,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct CursorCodec {
    key: Arc<Zeroizing<Vec<u8>>>,
    ttl: Duration,
}

impl CursorCodec {
    pub fn new(key: Vec<u8>, ttl: Duration) -> Result<Self, RegistryError> {
        if key.len() < 32
            || key.len() > 64
            || ttl < Duration::minutes(1)
            || ttl > Duration::hours(24)
        {
            return Err(RegistryError::ProductionTrustNotConfigured);
        }
        Ok(Self {
            key: Arc::new(Zeroizing::new(key)),
            ttl,
        })
    }

    pub fn encode(
        &self,
        tenant: &TenantId,
        resource: &str,
        after: &str,
        now: DateTime<Utc>,
    ) -> Result<String, RegistryError> {
        let payload = CursorPayload {
            schema_version: CURSOR_SCHEMA.into(),
            tenant_id: tenant.0.clone(),
            resource: resource.into(),
            after: after.into(),
            expires_at: now + self.ttl,
        };
        let encoded = serde_jcs::to_vec(&payload).map_err(|_| RegistryError::CursorInvalid)?;
        if encoded.len() > 4_000 {
            return Err(RegistryError::CursorInvalid);
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.key.as_slice());
        let tag = hmac::sign(&key, &encoded);
        let mut envelope = encoded;
        envelope.extend_from_slice(tag.as_ref());
        Ok(URL_SAFE_NO_PAD.encode(envelope))
    }

    pub fn decode(
        &self,
        cursor: &str,
        tenant: &TenantId,
        resource: &str,
        now: DateTime<Utc>,
    ) -> Result<String, RegistryError> {
        if cursor.is_empty() || cursor.len() > 5_462 || !cursor.bytes().all(base64url_byte) {
            return Err(RegistryError::CursorInvalid);
        }
        let envelope = URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| RegistryError::CursorInvalid)?;
        if envelope.len() <= 32 || envelope.len() > 4_032 {
            return Err(RegistryError::CursorInvalid);
        }
        let split = envelope.len() - 32;
        let (payload, supplied_tag) = envelope.split_at(split);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.key.as_slice());
        hmac::verify(&key, payload, supplied_tag).map_err(|_| RegistryError::CursorInvalid)?;
        let parsed: CursorPayload =
            serde_json::from_slice(payload).map_err(|_| RegistryError::CursorInvalid)?;
        if parsed.schema_version != CURSOR_SCHEMA
            || parsed.tenant_id != tenant.0
            || parsed.resource != resource
            || parsed.expires_at <= now
            || !valid_agent_id(&parsed.after)
        {
            return Err(RegistryError::CursorInvalid);
        }
        Ok(parsed.after)
    }
}

#[derive(Clone)]
pub struct PostgresAgentRegistryAuthority {
    pool: PgPool,
    lifecycle: Arc<dyn ProductionLifecyclePort>,
    cursor: CursorCodec,
}

impl PostgresAgentRegistryAuthority {
    pub fn new(
        pool: PgPool,
        lifecycle: Arc<dyn ProductionLifecyclePort>,
        cursor: CursorCodec,
    ) -> Self {
        Self {
            pool,
            lifecycle,
            cursor,
        }
    }

    async fn tenant_transaction<'a>(
        &'a self,
        tenant: &TenantId,
    ) -> Result<(Uuid, Transaction<'a, Postgres>), RegistryError> {
        let tenant_uuid = parse_tenant(tenant)?;
        let mut transaction = self.pool.begin().await.map_err(store_error)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&tenant.0)
            .execute(&mut *transaction)
            .await
            .map_err(store_error)?;
        Ok((tenant_uuid, transaction))
    }

    pub async fn ready(&self, tenants: &BTreeSet<TenantId>, include_dependencies: bool) -> bool {
        if tenants.is_empty() {
            return false;
        }
        for tenant in tenants {
            let Ok((tenant_uuid, mut transaction)) = self.tenant_transaction(tenant).await else {
                return false;
            };
            let row = sqlx::query(
                "SELECT (SELECT count(*)=13 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                         WHERE n.nspname='public' AND c.relkind='r' AND c.relname IN (\
                           'agent_assets','agent_discovery_facts','agent_posture_findings','agent_boms',\
                           'agent_ownership_confirmations','agent_relationship_edges',\
                           'agent_relationship_supersessions','agent_posture_resolutions',\
                           'agent_lifecycle_records','agent_registry_idempotency',\
                           'agent_registry_audit_heads','agent_registry_audit_events','agent_registry_outbox'\
                         )) AS tables_complete,\
                        (SELECT count(*)=13 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                         WHERE n.nspname='public' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity \
                           AND c.relname IN (\
                             'agent_assets','agent_discovery_facts','agent_posture_findings','agent_boms',\
                             'agent_ownership_confirmations','agent_relationship_edges',\
                             'agent_relationship_supersessions','agent_posture_resolutions',\
                             'agent_lifecycle_records','agent_registry_idempotency',\
                             'agent_registry_audit_heads','agent_registry_audit_events','agent_registry_outbox'\
                           )) AS force_rls_complete,\
                        (SELECT count(*)=13 FROM pg_policies \
                         WHERE schemaname='public' AND policyname='tenant_isolation' \
                           AND cmd='ALL' AND permissive='PERMISSIVE' \
                           AND qual LIKE '%current_setting%app.tenant_id%' \
                           AND with_check LIKE '%current_setting%app.tenant_id%' \
                           AND tablename IN (\
                             'agent_assets','agent_discovery_facts','agent_posture_findings','agent_boms',\
                             'agent_ownership_confirmations','agent_relationship_edges',\
                             'agent_relationship_supersessions','agent_posture_resolutions',\
                             'agent_lifecycle_records','agent_registry_idempotency',\
                             'agent_registry_audit_heads','agent_registry_audit_events','agent_registry_outbox'\
                           )) AS tenant_policies_complete,\
                        (SELECT count(*)=8 FROM information_schema.columns \
                         WHERE table_schema='public' AND table_name='agent_registry_audit_events' \
                           AND column_name IN ('governance_digest','action_hash','policy_decision_id',\
                             'policy_decision_digest','execution_id','ledger_entry_id',\
                             'ledger_entry_digest','authorization_evidence_ref')) AS governance_columns_complete,\
                        (SELECT count(*) FROM agent_assets WHERE tenant_id=$1 AND NOT COALESCE(\
                           length(display_name) BETWEEN 1 AND 256 AND length(owner_subject) BETWEEN 1 AND 512 \
                           AND length(sponsor_subject) BETWEEN 1 AND 512 AND owner_subject<>sponsor_subject \
                           AND ownership_version>0 AND ownership_review_due_at>registered_at \
                           AND environment IN ('DEVELOPMENT','STAGING','PRODUCTION') \
                           AND length(agent_type) BETWEEN 1 AND 128 AND bom_digest ~ '^[a-f0-9]{64}$' \
                           AND CASE WHEN jsonb_typeof(endpoints)='array' THEN jsonb_array_length(endpoints) BETWEEN 1 AND 100 ELSE false END \
                           AND CASE WHEN jsonb_typeof(identity_refs)='array' THEN jsonb_array_length(identity_refs) BETWEEN 1 AND 1000 ELSE false END \
                           AND CASE WHEN jsonb_typeof(tool_refs)='array' THEN jsonb_array_length(tool_refs)<=1000 ELSE false END \
                           AND CASE WHEN jsonb_typeof(pack_refs)='array' THEN jsonb_array_length(pack_refs)<=1000 ELSE false END \
                           AND CASE WHEN jsonb_typeof(requested_permissions)='array' THEN jsonb_array_length(requested_permissions)<=2000 ELSE false END \
                           AND CASE WHEN jsonb_typeof(approved_permissions)='array' THEN jsonb_array_length(approved_permissions)<=2000 ELSE false END \
                           AND jsonb_typeof(bom)='object' AND last_activity_at IS NOT NULL \
                           AND length(registered_by) BETWEEN 1 AND 512 \
                           AND registration_source IN ('EXPLICIT_REGISTRATION','GOVERNED_IMPORT') \
                           AND jsonb_typeof(registration_provenance)='object' AND record_version>0, false)) \
                         AS incomplete_assets,\
                        (SELECT count(*) FROM agent_discovery_facts WHERE tenant_id=$1 AND NOT COALESCE(\
                           source IN ('PROTOCOL_DISCOVERY','NETWORK_OBSERVATION','LOG_OBSERVATION','IMPORT') \
                           AND endpoint IS NOT NULL AND protocol IS NOT NULL \
                           AND jsonb_typeof(component_digests)='object' AND provenance_ref IS NOT NULL \
                           AND observation_key ~ '^[a-f0-9]{64}$' AND observation_digest ~ '^[a-f0-9]{64}$' \
                           AND ingested_by IS NOT NULL AND ingested_at IS NOT NULL \
                           AND trust_state='UNTRUSTED_OBSERVATION' AND reconciled_agent_id IS NULL, false)) \
                         AS incomplete_discovery,\
                        (SELECT count(*) FROM agent_posture_findings WHERE tenant_id=$1 AND NOT COALESCE(\
                           posture IN ('SHADOW','ORPHAN','DORMANT','OVERPRIVILEGED','DRIFTED','REVOKED_BUT_ACTIVE') \
                           AND severity IN ('LOW','MEDIUM','HIGH','CRITICAL') \
                           AND length(reason_code) BETWEEN 1 AND 128 AND evidence_digest ~ '^[a-f0-9]{64}$' \
                           AND condition_key ~ '^[a-f0-9]{64}$' AND finding_key ~ '^[a-f0-9]{64}$' \
                           AND detected_at IS NOT NULL AND (agent_id IS NOT NULL OR observation_id IS NOT NULL), false)) \
                         AS incomplete_findings",
            )
            .bind(tenant_uuid)
            .fetch_one(&mut *transaction)
            .await;
            let Ok(row) = row else {
                return false;
            };
            if !row.try_get::<bool, _>("tables_complete").unwrap_or(false)
                || !row
                    .try_get::<bool, _>("force_rls_complete")
                    .unwrap_or(false)
                || !row
                    .try_get::<bool, _>("tenant_policies_complete")
                    .unwrap_or(false)
                || !row
                    .try_get::<bool, _>("governance_columns_complete")
                    .unwrap_or(false)
                || row.try_get::<i64, _>("incomplete_assets").unwrap_or(1) != 0
                || row.try_get::<i64, _>("incomplete_discovery").unwrap_or(1) != 0
                || row.try_get::<i64, _>("incomplete_findings").unwrap_or(1) != 0
                || transaction.commit().await.is_err()
            {
                return false;
            }
        }
        !include_dependencies || self.lifecycle.ready().await
    }

    pub async fn lifecycle_ready(&self) -> bool {
        self.lifecycle.ready().await
    }

    pub async fn list_agents(
        &self,
        tenant: &TenantId,
        resource: &str,
        cursor: Option<&str>,
        limit: u32,
        now: DateTime<Utc>,
    ) -> Result<AuthoritativeAgentPage, RegistryError> {
        if !valid_dashboard_resource(resource) || !(1..=100).contains(&limit) {
            return Err(RegistryError::QueryDenied);
        }
        let after = match cursor {
            Some(value) => self.cursor.decode(value, tenant, resource, now)?,
            None => String::new(),
        };
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        let rows = sqlx::query(
            "SELECT a.agent_id,a.display_name,a.owner_subject,a.sponsor_subject,\
                    CASE WHEN a.ownership_confirmed_at IS NULL THEN 'PENDING' ELSE 'CONFIRMED' END AS ownership_status,\
                    a.environment,a.lifecycle,a.agent_type,a.bom_digest,\
                    jsonb_array_length(a.endpoints) AS endpoint_count,\
                    jsonb_array_length(a.identity_refs) AS identity_count,\
                    jsonb_array_length(a.tool_refs) AS tool_count,\
                    jsonb_array_length(a.pack_refs) AS pack_count,\
                    (SELECT count(*) FROM agent_posture_findings f WHERE f.tenant_id=a.tenant_id AND f.agent_id=a.agent_id AND f.open \
                     AND NOT EXISTS (SELECT 1 FROM agent_posture_resolutions r WHERE r.tenant_id=f.tenant_id AND r.finding_id=f.finding_id)) AS open_findings,\
                    (SELECT f.severity FROM agent_posture_findings f WHERE f.tenant_id=a.tenant_id AND f.agent_id=a.agent_id AND f.open \
                     AND NOT EXISTS (SELECT 1 FROM agent_posture_resolutions r WHERE r.tenant_id=f.tenant_id AND r.finding_id=f.finding_id) \
                     ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC,f.detected_at DESC LIMIT 1) AS highest_risk,\
                    a.last_activity_at,a.registered_at,a.updated_at\
             FROM agent_assets a WHERE a.tenant_id=$1 AND a.agent_id>$2\
             ORDER BY a.agent_id LIMIT $3",
        )
        .bind(tenant_uuid)
        .bind(&after)
        .bind(i64::from(limit) + 1)
        .fetch_all(&mut *transaction)
        .await
        .map_err(store_error)?;
        transaction.commit().await.map_err(store_error)?;
        let has_more = rows.len() > limit as usize;
        let mut items = rows
            .into_iter()
            .take(limit as usize)
            .map(agent_view_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if has_more {
            let last = items.last().ok_or(RegistryError::StoreFailure)?;
            Some(self.cursor.encode(tenant, resource, &last.agent_id, now)?)
        } else {
            None
        };
        let material = AgentPageMaterial {
            schema_version: AGENT_PAGE_SCHEMA,
            authoritative: true,
            tenant_id: tenant,
            resource,
            items: &items,
            next_cursor: next_cursor.as_deref(),
        };
        let data_digest = canonical_digest(&material)?;
        Ok(AuthoritativeAgentPage {
            schema_version: AGENT_PAGE_SCHEMA.into(),
            authoritative: true,
            tenant_id: tenant.clone(),
            resource: resource.into(),
            items: std::mem::take(&mut items),
            next_cursor,
            data_digest,
        })
    }
}

impl PostgresAgentRegistryAuthority {
    pub async fn register(
        &self,
        request: &RegistrationRequest,
        idempotency_key: &str,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<MutationReceipt, RegistryError> {
        validate_registration(request, actor_subject, idempotency_key, now)?;
        let request_digest = canonical_digest(request)?;
        let governance_digest = canonical_digest(&request.governance)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_request(&mut transaction, &request.tenant_id, idempotency_key).await?;
        if let Some(receipt) = load_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "REGISTER_AGENT",
            &request_digest,
        )
        .await?
        {
            transaction.commit().await.map_err(store_error)?;
            return Ok(receipt);
        }
        let endpoints = serde_json::to_value(&request.endpoints).map_err(json_error)?;
        let identity_refs = serde_json::to_value(&request.identity_refs).map_err(json_error)?;
        let tool_refs = serde_json::to_value(&request.tool_refs).map_err(json_error)?;
        let pack_refs = serde_json::to_value(&request.pack_refs).map_err(json_error)?;
        let requested_permissions =
            serde_json::to_value(&request.requested_permissions).map_err(json_error)?;
        let approved_permissions =
            serde_json::to_value(&request.approved_permissions).map_err(json_error)?;
        let bom = serde_json::to_value(&request.bom).map_err(json_error)?;
        let insert = sqlx::query(
            "INSERT INTO agent_assets \
             (tenant_id,agent_id,display_name,owner_subject,sponsor_subject,ownership_version,\
              ownership_confirmed_at,ownership_review_due_at,lifecycle,environment,agent_type,\
              endpoints,identity_refs,tool_refs,pack_refs,requested_permissions,approved_permissions,\
              bom,bom_digest,last_activity_at,registered_at,updated_at,registered_by,\
              registration_source,registration_provenance,record_version) \
             VALUES ($1,$2,$3,$4,$5,1,NULL,$6,'DRAFT',$7,$8,$9,$10,$11,$12,$13,$14,\
                     $15,$16,$17,$18,$18,$19,'EXPLICIT_REGISTRATION',$20,1)",
        )
        .bind(tenant_uuid)
        .bind(&request.agent_id)
        .bind(&request.display_name)
        .bind(&request.owner_subject)
        .bind(&request.sponsor_subject)
        .bind(request.ownership_review_due_at)
        .bind(&request.environment)
        .bind(&request.agent_type)
        .bind(endpoints)
        .bind(identity_refs)
        .bind(tool_refs)
        .bind(pack_refs)
        .bind(requested_permissions)
        .bind(approved_permissions)
        .bind(&bom)
        .bind(&request.bom.bom_digest)
        .bind(request.last_activity_at)
        .bind(now)
        .bind(actor_subject)
        .bind(serde_json::json!({
            "ref":request.provenance_ref,
            "digest":request.provenance_digest
        }))
        .execute(&mut *transaction)
        .await;
        if let Err(error) = insert {
            return Err(unique_or_store(error, RegistryError::RegistrationConflict));
        }
        sqlx::query(
            "INSERT INTO agent_boms \
             (tenant_id,agent_id,bom_digest,bom,generated_at,recorded_at,recorded_by,request_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(tenant_uuid)
        .bind(&request.agent_id)
        .bind(&request.bom.bom_digest)
        .bind(bom)
        .bind(request.bom.generated_at)
        .bind(now)
        .bind(actor_subject)
        .bind(&request_digest)
        .execute(&mut *transaction)
        .await
        .map_err(store_error)?;
        append_registration_relationships(
            &mut transaction,
            tenant_uuid,
            request,
            &request_digest,
            now,
        )
        .await?;
        let result = serde_json::json!({
            "agent_id":request.agent_id,
            "lifecycle":"DRAFT",
            "ownership_status":"PENDING",
            "ownership_version":1,
            "bom_digest":request.bom.bom_digest,
            "discovery_trust_promoted":false
        });
        let (event_ref, event_digest) = append_audit(
            &mut transaction,
            tenant_uuid,
            &request.tenant_id,
            "AGENT_REGISTERED",
            &request.agent_id,
            actor_subject,
            &request_digest,
            &request.governance,
            &result,
            now,
        )
        .await?;
        let receipt = MutationReceipt {
            schema_version: MUTATION_RECEIPT_SCHEMA.into(),
            operation: "REGISTER_AGENT".into(),
            resource_id: request.agent_id.clone(),
            changed: true,
            state: "DRAFT".into(),
            external_evidence_refs: BTreeSet::new(),
            event_ref,
            event_digest,
            governance_digest,
            result,
        };
        store_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "REGISTER_AGENT",
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(store_error)?;
        Ok(receipt)
    }

    pub async fn ingest_discovery(
        &self,
        request: &DiscoveryIngestRequest,
        idempotency_key: &str,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<MutationReceipt, RegistryError> {
        validate_discovery(request, actor_subject, idempotency_key, now)?;
        let request_digest = canonical_digest(request)?;
        let governance_digest = canonical_digest(&request.governance)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_request(&mut transaction, &request.tenant_id, idempotency_key).await?;
        if let Some(receipt) = load_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "INGEST_DISCOVERY",
            &request_digest,
        )
        .await?
        {
            transaction.commit().await.map_err(store_error)?;
            return Ok(receipt);
        }
        let observation_uuid = Uuid::parse_str(&request.observation_id)
            .map_err(|_| RegistryError::ObservationInvalid)?;
        let observation_key = canonical_digest(&serde_json::json!({
            "source":observation_source_text(request.source),
            "collector_id":request.collector_id,
            "endpoint":request.endpoint,
            "protocol":request.protocol,
            "claimed_agent_id":request.claimed_agent_id
        }))?;
        let inserted = sqlx::query(
            "INSERT INTO agent_discovery_facts \
             (tenant_id,fact_id,observed_agent_ref,collector_id,observation_digest,observed_at,\
              reconciled_agent_id,source,endpoint,protocol,component_digests,provenance_ref,\
              observation_key,ingested_by,ingested_at,trust_state) \
             VALUES ($1,$2,$3,$4,$5,$6,NULL,$7,$8,$9,$10,$11,$12,$13,$14,'UNTRUSTED_OBSERVATION')",
        )
        .bind(tenant_uuid)
        .bind(observation_uuid)
        .bind(request.claimed_agent_id.as_deref().unwrap_or("UNCLAIMED"))
        .bind(&request.collector_id)
        .bind(&request.payload_digest)
        .bind(request.observed_at)
        .bind(observation_source_text(request.source))
        .bind(&request.endpoint)
        .bind(&request.protocol)
        .bind(serde_json::to_value(&request.observed_component_digests).map_err(json_error)?)
        .bind(&request.provenance_ref)
        .bind(&observation_key)
        .bind(actor_subject)
        .bind(now)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = inserted {
            return Err(unique_or_store(error, RegistryError::ObservationConflict));
        }
        let result = serde_json::json!({
            "observation_id":request.observation_id,
            "trust_state":"UNTRUSTED_OBSERVATION",
            "trust_promoted":false,
            "reconciled_agent_id":Value::Null,
            "observation_digest":request.payload_digest
        });
        let (event_ref, event_digest) = append_audit(
            &mut transaction,
            tenant_uuid,
            &request.tenant_id,
            "DISCOVERY_OBSERVATION_INGESTED",
            &request.observation_id,
            actor_subject,
            &request_digest,
            &request.governance,
            &result,
            now,
        )
        .await?;
        let receipt = MutationReceipt {
            schema_version: MUTATION_RECEIPT_SCHEMA.into(),
            operation: "INGEST_DISCOVERY".into(),
            resource_id: request.observation_id.clone(),
            changed: true,
            state: "UNTRUSTED_OBSERVATION".into(),
            external_evidence_refs: BTreeSet::new(),
            event_ref,
            event_digest,
            governance_digest,
            result,
        };
        store_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "INGEST_DISCOVERY",
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(store_error)?;
        Ok(receipt)
    }

    pub async fn assign_ownership(
        &self,
        request: &OwnershipAssignmentRequest,
        idempotency_key: &str,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<MutationReceipt, RegistryError> {
        validate_ownership_assignment(request, actor_subject, idempotency_key, now)?;
        let request_digest = canonical_digest(request)?;
        let governance_digest = canonical_digest(&request.governance)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_request(&mut transaction, &request.tenant_id, idempotency_key).await?;
        if let Some(receipt) = load_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "ASSIGN_OWNERSHIP",
            &request_digest,
        )
        .await?
        {
            transaction.commit().await.map_err(store_error)?;
            return Ok(receipt);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "agent-registry-ownership:{}:{}",
                request.tenant_id.0, request.agent_id
            ))
            .execute(&mut *transaction)
            .await
            .map_err(store_error)?;
        let row = sqlx::query(
            "UPDATE agent_assets SET owner_subject=$3,sponsor_subject=$4,\
                    ownership_version=ownership_version+1,ownership_confirmed_at=NULL,\
                    ownership_review_due_at=$5,updated_at=$6,record_version=record_version+1 \
             WHERE tenant_id=$1 AND agent_id=$2 \
             RETURNING ownership_version,lifecycle",
        )
        .bind(tenant_uuid)
        .bind(&request.agent_id)
        .bind(&request.owner_subject)
        .bind(&request.sponsor_subject)
        .bind(request.review_due_at)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(store_error)?
        .ok_or(RegistryError::NotFound)?;
        let ownership_version: i64 = row.try_get("ownership_version").map_err(store_error)?;
        let lifecycle: String = row.try_get("lifecycle").map_err(store_error)?;
        supersede_ownership_relationships(
            &mut transaction,
            tenant_uuid,
            request,
            actor_subject,
            &request_digest,
            now,
        )
        .await?;
        let result = serde_json::json!({
            "agent_id":request.agent_id,
            "ownership_version":ownership_version,
            "ownership_status":"PENDING",
            "directory_evidence_digest":request.directory_evidence_digest
        });
        let (event_ref, event_digest) = append_audit(
            &mut transaction,
            tenant_uuid,
            &request.tenant_id,
            "AGENT_OWNERSHIP_ASSIGNED",
            &request.agent_id,
            actor_subject,
            &request_digest,
            &request.governance,
            &result,
            now,
        )
        .await?;
        let receipt = MutationReceipt {
            schema_version: MUTATION_RECEIPT_SCHEMA.into(),
            operation: "ASSIGN_OWNERSHIP".into(),
            resource_id: request.agent_id.clone(),
            changed: true,
            state: lifecycle,
            external_evidence_refs: BTreeSet::new(),
            event_ref,
            event_digest,
            governance_digest,
            result,
        };
        store_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "ASSIGN_OWNERSHIP",
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(store_error)?;
        Ok(receipt)
    }

    pub async fn confirm_ownership(
        &self,
        request: &OwnershipConfirmationRequest,
        idempotency_key: &str,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<MutationReceipt, RegistryError> {
        validate_ownership_confirmation(request, actor_subject, idempotency_key)?;
        let request_digest = canonical_digest(request)?;
        let governance_digest = canonical_digest(&request.governance)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_request(&mut transaction, &request.tenant_id, idempotency_key).await?;
        if let Some(receipt) = load_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "CONFIRM_OWNERSHIP",
            &request_digest,
        )
        .await?
        {
            transaction.commit().await.map_err(store_error)?;
            return Ok(receipt);
        }
        let row = sqlx::query(
            "SELECT owner_subject,sponsor_subject,ownership_version,lifecycle \
             FROM agent_assets WHERE tenant_id=$1 AND agent_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&request.agent_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(store_error)?
        .ok_or(RegistryError::NotFound)?;
        let owner: String = row.try_get("owner_subject").map_err(store_error)?;
        let sponsor: String = row.try_get("sponsor_subject").map_err(store_error)?;
        let version: i64 = row.try_get("ownership_version").map_err(store_error)?;
        let lifecycle: String = row.try_get("lifecycle").map_err(store_error)?;
        let expected_subject = match request.role {
            OwnershipRole::Owner => &owner,
            OwnershipRole::Sponsor => &sponsor,
        };
        if request.ownership_version
            != u64::try_from(version).map_err(|_| RegistryError::StoreFailure)?
            || expected_subject != &request.subject
            || request.confirmation_digest != expected_confirmation_digest(request)?
        {
            return Err(RegistryError::OwnershipInvalid);
        }
        let inserted = sqlx::query(
            "INSERT INTO agent_ownership_confirmations \
             (tenant_id,agent_id,ownership_version,role,subject,confirmation_digest,confirmed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(tenant_uuid)
        .bind(&request.agent_id)
        .bind(version)
        .bind(ownership_role_text(request.role))
        .bind(&request.subject)
        .bind(&request.confirmation_digest)
        .bind(now)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = inserted {
            return Err(unique_or_store(error, RegistryError::RegistrationConflict));
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM agent_ownership_confirmations \
             WHERE tenant_id=$1 AND agent_id=$2 AND ownership_version=$3",
        )
        .bind(tenant_uuid)
        .bind(&request.agent_id)
        .bind(version)
        .fetch_one(&mut *transaction)
        .await
        .map_err(store_error)?;
        if count == 2 {
            sqlx::query(
                "UPDATE agent_assets SET ownership_confirmed_at=$3,updated_at=$3,\
                        record_version=record_version+1 WHERE tenant_id=$1 AND agent_id=$2",
            )
            .bind(tenant_uuid)
            .bind(&request.agent_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(store_error)?;
        }
        let status = if count == 2 { "CONFIRMED" } else { "PENDING" };
        let result = serde_json::json!({
            "agent_id":request.agent_id,
            "ownership_version":version,
            "confirmed_role":ownership_role_text(request.role),
            "ownership_status":status
        });
        let (event_ref, event_digest) = append_audit(
            &mut transaction,
            tenant_uuid,
            &request.tenant_id,
            "AGENT_OWNERSHIP_CONFIRMED",
            &request.agent_id,
            actor_subject,
            &request_digest,
            &request.governance,
            &result,
            now,
        )
        .await?;
        let receipt = MutationReceipt {
            schema_version: MUTATION_RECEIPT_SCHEMA.into(),
            operation: "CONFIRM_OWNERSHIP".into(),
            resource_id: request.agent_id.clone(),
            changed: true,
            state: lifecycle,
            external_evidence_refs: BTreeSet::new(),
            event_ref,
            event_digest,
            governance_digest,
            result,
        };
        store_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "CONFIRM_OWNERSHIP",
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(store_error)?;
        Ok(receipt)
    }

    pub async fn update_bom(
        &self,
        request: &BomUpdateRequest,
        idempotency_key: &str,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<MutationReceipt, RegistryError> {
        validate_actor_and_key(actor_subject, idempotency_key)?;
        parse_tenant(&request.tenant_id)?;
        if request.schema_version != BOM_UPDATE_SCHEMA || !valid_agent_id(&request.agent_id) {
            return Err(RegistryError::AssetInvalid);
        }
        validate_governance(&request.governance)?;
        request
            .bom
            .validate(&request.tenant_id, &request.agent_id, now)?;
        let request_digest = canonical_digest(request)?;
        let governance_digest = canonical_digest(&request.governance)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_request(&mut transaction, &request.tenant_id, idempotency_key).await?;
        if let Some(receipt) = load_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "UPDATE_BOM",
            &request_digest,
        )
        .await?
        {
            transaction.commit().await.map_err(store_error)?;
            return Ok(receipt);
        }
        let bom_value = serde_json::to_value(&request.bom).map_err(json_error)?;
        let inserted = sqlx::query(
            "INSERT INTO agent_boms \
             (tenant_id,agent_id,bom_digest,bom,generated_at,recorded_at,recorded_by,request_digest) \
             SELECT $1,$2,$3,$4,$5,$6,$7,$8 \
             WHERE EXISTS (SELECT 1 FROM agent_assets WHERE tenant_id=$1 AND agent_id=$2)",
        )
        .bind(tenant_uuid)
        .bind(&request.agent_id)
        .bind(&request.bom.bom_digest)
        .bind(&bom_value)
        .bind(request.bom.generated_at)
        .bind(now)
        .bind(actor_subject)
        .bind(&request_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|error| unique_or_store(error, RegistryError::RegistrationConflict))?;
        if inserted.rows_affected() != 1 {
            return Err(RegistryError::NotFound);
        }
        sqlx::query(
            "UPDATE agent_assets SET bom=$3,bom_digest=$4,updated_at=$5,\
                    record_version=record_version+1 WHERE tenant_id=$1 AND agent_id=$2",
        )
        .bind(tenant_uuid)
        .bind(&request.agent_id)
        .bind(bom_value)
        .bind(&request.bom.bom_digest)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(store_error)?;
        let result = serde_json::json!({
            "agent_id":request.agent_id,
            "bom_digest":request.bom.bom_digest
        });
        let (event_ref, event_digest) = append_audit(
            &mut transaction,
            tenant_uuid,
            &request.tenant_id,
            "AGENT_BOM_UPDATED",
            &request.agent_id,
            actor_subject,
            &request_digest,
            &request.governance,
            &result,
            now,
        )
        .await?;
        let receipt = MutationReceipt {
            schema_version: MUTATION_RECEIPT_SCHEMA.into(),
            operation: "UPDATE_BOM".into(),
            resource_id: request.agent_id.clone(),
            changed: true,
            state: "BOM_RECORDED".into(),
            external_evidence_refs: BTreeSet::new(),
            event_ref,
            event_digest,
            governance_digest,
            result,
        };
        store_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "UPDATE_BOM",
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(store_error)?;
        Ok(receipt)
    }

    pub async fn add_relationship(
        &self,
        request: &RelationshipEdgeRequest,
        idempotency_key: &str,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<MutationReceipt, RegistryError> {
        validate_relationship(request, actor_subject, idempotency_key)?;
        let request_digest = canonical_digest(request)?;
        let governance_digest = canonical_digest(&request.governance)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_request(&mut transaction, &request.tenant_id, idempotency_key).await?;
        if let Some(receipt) = load_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "ADD_RELATIONSHIP",
            &request_digest,
        )
        .await?
        {
            transaction.commit().await.map_err(store_error)?;
            return Ok(receipt);
        }
        let edge_uuid =
            Uuid::parse_str(&request.edge_id).map_err(|_| RegistryError::RelationshipInvalid)?;
        sqlx::query(
            "INSERT INTO agent_relationship_edges \
             (tenant_id,edge_id,from_ref,to_ref,relationship_kind,evidence_digest,created_at,created_by,request_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(tenant_uuid)
        .bind(edge_uuid)
        .bind(&request.from)
        .bind(&request.to)
        .bind(relationship_kind_text(request.kind))
        .bind(&request.evidence_digest)
        .bind(now)
        .bind(actor_subject)
        .bind(&request_digest)
        .execute(&mut *transaction)
        .await
        .map_err(|error| unique_or_store(error, RegistryError::RegistrationConflict))?;
        let result = serde_json::json!({
            "edge_id":request.edge_id,
            "from":request.from,
            "to":request.to,
            "kind":relationship_kind_text(request.kind)
        });
        let (event_ref, event_digest) = append_audit(
            &mut transaction,
            tenant_uuid,
            &request.tenant_id,
            "AGENT_RELATIONSHIP_ADDED",
            &request.edge_id,
            actor_subject,
            &request_digest,
            &request.governance,
            &result,
            now,
        )
        .await?;
        let receipt = MutationReceipt {
            schema_version: MUTATION_RECEIPT_SCHEMA.into(),
            operation: "ADD_RELATIONSHIP".into(),
            resource_id: request.edge_id.clone(),
            changed: true,
            state: "ACTIVE".into(),
            external_evidence_refs: BTreeSet::new(),
            event_ref,
            event_digest,
            governance_digest,
            result,
        };
        store_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "ADD_RELATIONSHIP",
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(store_error)?;
        Ok(receipt)
    }

    pub async fn transition_lifecycle(
        &self,
        request: &LifecycleRequest,
        idempotency_key: &str,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<MutationReceipt, RegistryError> {
        validate_lifecycle_request(request, actor_subject, idempotency_key)?;
        let request_digest = canonical_digest(request)?;
        let governance_digest = canonical_digest(&request.governance)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_request(&mut transaction, &request.tenant_id, idempotency_key).await?;
        if let Some(receipt) = load_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "TRANSITION_LIFECYCLE",
            &request_digest,
        )
        .await?
        {
            transaction.commit().await.map_err(store_error)?;
            return Ok(receipt);
        }
        let row = sqlx::query(
            "SELECT lifecycle,ownership_confirmed_at,ownership_review_due_at,identity_refs,\
                    pack_refs,requested_permissions,approved_permissions,bom \
             FROM agent_assets WHERE tenant_id=$1 AND agent_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&request.agent_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(store_error)?
        .ok_or(RegistryError::NotFound)?;
        let current_text: String = row.try_get("lifecycle").map_err(store_error)?;
        let current = parse_lifecycle(&current_text)?;
        if current != request.target && !production_lifecycle_allowed(current, request.target) {
            return Err(RegistryError::LifecycleDenied);
        }
        let bom_value: Value = row.try_get("bom").map_err(store_error)?;
        let bom: AgentBomDocument =
            serde_json::from_value(bom_value).map_err(|_| RegistryError::StoreFailure)?;
        if request.target == LifecycleState::Active {
            let confirmed: Option<DateTime<Utc>> =
                row.try_get("ownership_confirmed_at").map_err(store_error)?;
            let review_due: DateTime<Utc> = row
                .try_get("ownership_review_due_at")
                .map_err(store_error)?;
            let requested =
                json_string_set(row.try_get("requested_permissions").map_err(store_error)?)?;
            let approved =
                json_string_set(row.try_get("approved_permissions").map_err(store_error)?)?;
            if confirmed.is_none() || review_due <= now || !requested.is_subset(&approved) {
                return Err(RegistryError::LifecycleDenied);
            }
            bom.validate(&request.tenant_id, &request.agent_id, now)?;
        }
        let changed = current != request.target;
        let identity_refs = json_string_set(row.try_get("identity_refs").map_err(store_error)?)?;
        let pack_refs = json_string_set(row.try_get("pack_refs").map_err(store_error)?)?;
        let external_evidence_refs = if changed
            && matches!(
                request.target,
                LifecycleState::Suspended | LifecycleState::Retired | LifecycleState::Revoked
            ) {
            self.lifecycle
                .converge(&LifecycleConvergenceInput {
                    tenant_id: request.tenant_id.clone(),
                    agent_id: request.agent_id.clone(),
                    identity_refs,
                    pack_refs,
                    target: request.target,
                    reason_code: request.reason_code.clone(),
                    idempotency_key: idempotency_key.into(),
                    governance: request.governance.clone(),
                })
                .await?
        } else {
            BTreeSet::new()
        };
        if changed {
            sqlx::query(
                "UPDATE agent_assets SET lifecycle=$3,updated_at=$4,record_version=record_version+1 \
                 WHERE tenant_id=$1 AND agent_id=$2",
            )
            .bind(tenant_uuid)
            .bind(&request.agent_id)
            .bind(lifecycle_text(request.target))
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(store_error)?;
        }
        let result = serde_json::json!({
            "agent_id":request.agent_id,
            "from":lifecycle_text(current),
            "to":lifecycle_text(request.target),
            "reason_code":request.reason_code,
            "converged":true,
            "external_evidence_refs":external_evidence_refs
        });
        let (event_ref, event_digest) = append_audit(
            &mut transaction,
            tenant_uuid,
            &request.tenant_id,
            "AGENT_LIFECYCLE_TRANSITIONED",
            &request.agent_id,
            actor_subject,
            &request_digest,
            &request.governance,
            &result,
            now,
        )
        .await?;
        sqlx::query(
            "INSERT INTO agent_lifecycle_records \
             (tenant_id,record_id,agent_id,from_state,to_state,reason_code,external_evidence_refs,\
              event_ref,event_digest,changed,transitioned_at,transitioned_by,request_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(tenant_uuid)
        .bind(Uuid::new_v4())
        .bind(&request.agent_id)
        .bind(lifecycle_text(current))
        .bind(lifecycle_text(request.target))
        .bind(&request.reason_code)
        .bind(serde_json::to_value(&external_evidence_refs).map_err(json_error)?)
        .bind(&event_ref)
        .bind(&event_digest)
        .bind(changed)
        .bind(now)
        .bind(actor_subject)
        .bind(&request_digest)
        .execute(&mut *transaction)
        .await
        .map_err(store_error)?;
        let receipt = MutationReceipt {
            schema_version: MUTATION_RECEIPT_SCHEMA.into(),
            operation: "TRANSITION_LIFECYCLE".into(),
            resource_id: request.agent_id.clone(),
            changed,
            state: lifecycle_text(request.target).into(),
            external_evidence_refs,
            event_ref,
            event_digest,
            governance_digest,
            result,
        };
        store_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "TRANSITION_LIFECYCLE",
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(store_error)?;
        Ok(receipt)
    }

    pub async fn evaluate_posture(
        &self,
        request: &PostureEvaluationRequest,
        idempotency_key: &str,
        actor_subject: &str,
        now: DateTime<Utc>,
    ) -> Result<MutationReceipt, RegistryError> {
        validate_posture_request(request, actor_subject, idempotency_key)?;
        let request_digest = canonical_digest(request)?;
        let governance_digest = canonical_digest(&request.governance)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(&request.tenant_id).await?;
        lock_request(&mut transaction, &request.tenant_id, idempotency_key).await?;
        if let Some(receipt) = load_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "EVALUATE_POSTURE",
            &request_digest,
        )
        .await?
        {
            transaction.commit().await.map_err(store_error)?;
            return Ok(receipt);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("agent-registry-posture:{}", request.tenant_id.0))
            .execute(&mut *transaction)
            .await
            .map_err(store_error)?;
        let asset_rows = sqlx::query(
            "SELECT agent_id,lifecycle,ownership_confirmed_at,ownership_review_due_at,\
                    last_activity_at,requested_permissions,approved_permissions,bom,bom_digest \
             FROM agent_assets WHERE tenant_id=$1 ORDER BY agent_id LIMIT 10001",
        )
        .bind(tenant_uuid)
        .fetch_all(&mut *transaction)
        .await
        .map_err(store_error)?;
        let observation_rows = sqlx::query(
            "SELECT fact_id,observed_agent_ref,observation_digest,component_digests \
             FROM agent_discovery_facts WHERE tenant_id=$1 ORDER BY fact_id LIMIT 10001",
        )
        .bind(tenant_uuid)
        .fetch_all(&mut *transaction)
        .await
        .map_err(store_error)?;
        if asset_rows.len() > 10_000 || observation_rows.len() > 10_000 {
            return Err(RegistryError::CapacityExceeded);
        }
        let mut assets = BTreeMap::new();
        let mut candidates = Vec::new();
        for row in asset_rows {
            let agent_id: String = row.try_get("agent_id").map_err(store_error)?;
            let lifecycle_text_value: String = row.try_get("lifecycle").map_err(store_error)?;
            let lifecycle = parse_lifecycle(&lifecycle_text_value)?;
            let ownership_confirmed: Option<DateTime<Utc>> =
                row.try_get("ownership_confirmed_at").map_err(store_error)?;
            let ownership_review_due: DateTime<Utc> = row
                .try_get("ownership_review_due_at")
                .map_err(store_error)?;
            let last_activity: DateTime<Utc> =
                row.try_get("last_activity_at").map_err(store_error)?;
            let requested =
                json_string_set(row.try_get("requested_permissions").map_err(store_error)?)?;
            let approved =
                json_string_set(row.try_get("approved_permissions").map_err(store_error)?)?;
            let bom_value: Value = row.try_get("bom").map_err(store_error)?;
            let bom: AgentBomDocument =
                serde_json::from_value(bom_value).map_err(|_| RegistryError::StoreFailure)?;
            let bom_digest: String = row.try_get("bom_digest").map_err(store_error)?;
            if ownership_confirmed.is_none() || ownership_review_due <= now {
                candidates.push(FindingCandidate::agent(
                    &agent_id,
                    PostureKind::Orphan,
                    "HIGH",
                    "OWNERSHIP_MISSING_OR_EXPIRED",
                    &bom_digest,
                ));
            }
            if lifecycle == LifecycleState::Active
                && last_activity < now - Duration::days(i64::from(request.inactivity_days))
            {
                candidates.push(FindingCandidate::agent(
                    &agent_id,
                    PostureKind::Dormant,
                    "MEDIUM",
                    "DORMANT_ACTIVE_AGENT",
                    &bom_digest,
                ));
            }
            if !requested.is_subset(&approved) {
                candidates.push(FindingCandidate::agent(
                    &agent_id,
                    PostureKind::Overprivileged,
                    "CRITICAL",
                    "PERMISSION_SCOPE_DRIFT",
                    &bom_digest,
                ));
            }
            if lifecycle == LifecycleState::Revoked
                && last_activity
                    > now - Duration::seconds(i64::from(request.revoked_activity_grace_seconds))
            {
                candidates.push(FindingCandidate::agent(
                    &agent_id,
                    PostureKind::RevokedButActive,
                    "CRITICAL",
                    "REVOKED_AGENT_ACTIVITY",
                    &bom_digest,
                ));
            }
            assets.insert(agent_id, bom);
        }
        for row in observation_rows {
            let observation_id: Uuid = row.try_get("fact_id").map_err(store_error)?;
            let claimed: String = row.try_get("observed_agent_ref").map_err(store_error)?;
            let evidence_digest: String = row.try_get("observation_digest").map_err(store_error)?;
            let components_value: Value = row.try_get("component_digests").map_err(store_error)?;
            let components: BTreeMap<String, String> = serde_json::from_value(components_value)
                .map_err(|_| RegistryError::StoreFailure)?;
            let registered = claimed != "UNCLAIMED" && assets.contains_key(&claimed);
            if !registered {
                candidates.push(FindingCandidate::observation(
                    observation_id.to_string(),
                    PostureKind::Shadow,
                    "HIGH",
                    "DISCOVERY_NOT_REGISTRATION",
                    &evidence_digest,
                ));
                continue;
            }
            let bom = assets.get(&claimed).ok_or(RegistryError::StoreFailure)?;
            let known = bom
                .components
                .iter()
                .flat_map(|component| {
                    [
                        (component.name.clone(), component.digest.clone()),
                        (
                            format!("{}:{}", component.kind, component.name),
                            component.digest.clone(),
                        ),
                    ]
                })
                .collect::<BTreeMap<_, _>>();
            if components
                .iter()
                .any(|(component, digest)| known.get(component) != Some(digest))
            {
                candidates.push(FindingCandidate {
                    agent_id: Some(claimed),
                    observation_id: Some(observation_id.to_string()),
                    kind: PostureKind::Drifted,
                    severity: "HIGH",
                    reason_code: "OBSERVED_BOM_COMPONENT_DRIFT",
                    evidence_digest,
                });
            }
        }
        if candidates.len() > 1_000 {
            return Err(RegistryError::CapacityExceeded);
        }
        let mut created = Vec::new();
        let mut current_keys = BTreeSet::new();
        for candidate in candidates {
            let condition_key = canonical_digest(&serde_json::json!({
                "agent_id":candidate.agent_id,
                "observation_id":candidate.observation_id,
                "kind":posture_kind_text(candidate.kind),
                "reason_code":candidate.reason_code,
                "evidence_digest":candidate.evidence_digest
            }))?;
            current_keys.insert(condition_key.clone());
            let already_open: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM agent_posture_findings f \
                 WHERE f.tenant_id=$1 AND f.condition_key=$2 AND f.open \
                   AND NOT EXISTS (SELECT 1 FROM agent_posture_resolutions r \
                                   WHERE r.tenant_id=f.tenant_id AND r.finding_id=f.finding_id))",
            )
            .bind(tenant_uuid)
            .bind(&condition_key)
            .fetch_one(&mut *transaction)
            .await
            .map_err(store_error)?;
            if already_open {
                continue;
            }
            let finding_key = canonical_digest(&serde_json::json!({
                "condition_key":condition_key,
                "evaluation_request_digest":request_digest
            }))?;
            let finding_id = Uuid::new_v4();
            let inserted = sqlx::query(
                "INSERT INTO agent_posture_findings \
                 (tenant_id,finding_id,agent_id,observation_id,posture,severity,reason_code,\
                  evidence_digest,condition_key,finding_key,open,created_at,detected_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,$11,$11) \
                 ON CONFLICT (tenant_id,finding_key) DO NOTHING",
            )
            .bind(tenant_uuid)
            .bind(finding_id)
            .bind(candidate.agent_id.as_deref())
            .bind(
                candidate
                    .observation_id
                    .as_deref()
                    .and_then(|value| Uuid::parse_str(value).ok()),
            )
            .bind(posture_kind_text(candidate.kind))
            .bind(candidate.severity)
            .bind(candidate.reason_code)
            .bind(&candidate.evidence_digest)
            .bind(&condition_key)
            .bind(&finding_key)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(store_error)?;
            if inserted.rows_affected() == 1 {
                created.push(PostureFindingView {
                    schema_version: POSTURE_VIEW_SCHEMA.into(),
                    finding_id: finding_id.to_string(),
                    agent_id: candidate.agent_id,
                    observation_id: candidate.observation_id,
                    kind: candidate.kind,
                    severity: candidate.severity.into(),
                    reason_code: candidate.reason_code.into(),
                    evidence_digest: candidate.evidence_digest,
                    detected_at: now,
                });
            }
        }
        let unresolved = sqlx::query(
            "SELECT f.finding_id,f.condition_key FROM agent_posture_findings f \
             WHERE f.tenant_id=$1 AND f.open AND f.condition_key IS NOT NULL \
               AND NOT EXISTS (SELECT 1 FROM agent_posture_resolutions r \
                               WHERE r.tenant_id=f.tenant_id AND r.finding_id=f.finding_id) \
             ORDER BY f.finding_id LIMIT 10001",
        )
        .bind(tenant_uuid)
        .fetch_all(&mut *transaction)
        .await
        .map_err(store_error)?;
        if unresolved.len() > 10_000 {
            return Err(RegistryError::CapacityExceeded);
        }
        let mut resolved_count = 0_u32;
        for row in unresolved {
            let finding_id: Uuid = row.try_get("finding_id").map_err(store_error)?;
            let condition_key: String = row.try_get("condition_key").map_err(store_error)?;
            if !current_keys.contains(&condition_key) {
                sqlx::query(
                    "INSERT INTO agent_posture_resolutions \
                     (tenant_id,resolution_id,finding_id,reason_code,resolved_at,resolved_by,request_digest) \
                     VALUES ($1,$2,$3,'RESOLVED_BY_CURRENT_POSTURE_EVALUATION',$4,$5,$6)",
                )
                .bind(tenant_uuid)
                .bind(Uuid::new_v4())
                .bind(finding_id)
                .bind(now)
                .bind(actor_subject)
                .bind(&request_digest)
                .execute(&mut *transaction)
                .await
                .map_err(store_error)?;
                resolved_count = resolved_count
                    .checked_add(1)
                    .ok_or(RegistryError::CapacityExceeded)?;
            }
        }
        let finding_digest = canonical_digest(&created)?;
        let result = serde_json::json!({
            "created_count":created.len(),
            "resolved_count":resolved_count,
            "created_findings_digest":finding_digest,
            "evaluated_asset_count":assets.len(),
            "trust_promotions":0
        });
        let (event_ref, event_digest) = append_audit(
            &mut transaction,
            tenant_uuid,
            &request.tenant_id,
            "AGENT_POSTURE_EVALUATED",
            &request.tenant_id.0,
            actor_subject,
            &request_digest,
            &request.governance,
            &result,
            now,
        )
        .await?;
        let receipt = MutationReceipt {
            schema_version: MUTATION_RECEIPT_SCHEMA.into(),
            operation: "EVALUATE_POSTURE".into(),
            resource_id: request.tenant_id.0.clone(),
            changed: !created.is_empty() || resolved_count > 0,
            state: "EVALUATED".into(),
            external_evidence_refs: BTreeSet::new(),
            event_ref,
            event_digest,
            governance_digest,
            result,
        };
        store_replay(
            &mut transaction,
            tenant_uuid,
            idempotency_key,
            "EVALUATE_POSTURE",
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(store_error)?;
        Ok(receipt)
    }

    pub async fn list_findings(
        &self,
        tenant: &TenantId,
        cursor: Option<&str>,
        limit: u32,
        now: DateTime<Utc>,
    ) -> Result<AuthoritativePosturePage, RegistryError> {
        if !(1..=100).contains(&limit) {
            return Err(RegistryError::QueryDenied);
        }
        let after = match cursor {
            Some(value) => self.cursor.decode(value, tenant, "posture", now)?,
            None => "00000000-0000-0000-0000-000000000000".into(),
        };
        let after_uuid = Uuid::parse_str(&after).map_err(|_| RegistryError::CursorInvalid)?;
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        let rows = sqlx::query(
            "SELECT finding_id,agent_id,observation_id,posture,severity,reason_code,\
                    evidence_digest,detected_at FROM agent_posture_findings \
             WHERE tenant_id=$1 AND finding_id>$2 AND open \
               AND NOT EXISTS (SELECT 1 FROM agent_posture_resolutions r \
                               WHERE r.tenant_id=agent_posture_findings.tenant_id \
                                 AND r.finding_id=agent_posture_findings.finding_id) \
             ORDER BY finding_id LIMIT $3",
        )
        .bind(tenant_uuid)
        .bind(after_uuid)
        .bind(i64::from(limit) + 1)
        .fetch_all(&mut *transaction)
        .await
        .map_err(store_error)?;
        transaction.commit().await.map_err(store_error)?;
        let has_more = rows.len() > limit as usize;
        let items = rows
            .into_iter()
            .take(limit as usize)
            .map(posture_view_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if has_more {
            Some(self.cursor.encode(
                tenant,
                "posture",
                &items.last().ok_or(RegistryError::StoreFailure)?.finding_id,
                now,
            )?)
        } else {
            None
        };
        let material = QueryPageMaterial {
            schema_version: POSTURE_PAGE_SCHEMA,
            authoritative: true,
            tenant_id: tenant,
            items: &items,
            next_cursor: next_cursor.as_deref(),
        };
        let data_digest = canonical_digest(&material)?;
        Ok(AuthoritativePosturePage {
            schema_version: POSTURE_PAGE_SCHEMA.into(),
            authoritative: true,
            tenant_id: tenant.clone(),
            items,
            next_cursor,
            data_digest,
        })
    }

    pub async fn query_relationship_graph(
        &self,
        tenant: &TenantId,
        root: &str,
        maximum_depth: u32,
        limit: u32,
    ) -> Result<AuthoritativeRelationshipPage, RegistryError> {
        if !bounded_text(root, 1024)
            || !(1..=5).contains(&maximum_depth)
            || !(1..=100).contains(&limit)
        {
            return Err(RegistryError::QueryDenied);
        }
        let (tenant_uuid, mut transaction) = self.tenant_transaction(tenant).await?;
        let rows = sqlx::query(
            "WITH RECURSIVE graph(edge_id,from_ref,to_ref,relationship_kind,evidence_digest,created_at,depth,path) AS (\
               SELECT edge_id,from_ref,to_ref,relationship_kind,evidence_digest,created_at,1,ARRAY[from_ref,to_ref] \
               FROM agent_relationship_edges e WHERE e.tenant_id=$1 AND (e.from_ref=$2 OR e.to_ref=$2) \
                 AND NOT EXISTS (SELECT 1 FROM agent_relationship_supersessions s \
                                 WHERE s.tenant_id=e.tenant_id AND s.edge_id=e.edge_id)\
               UNION ALL \
               SELECT e.edge_id,e.from_ref,e.to_ref,e.relationship_kind,e.evidence_digest,e.created_at,g.depth+1,\
                      g.path || CASE WHEN e.from_ref=ANY(g.path) THEN e.to_ref ELSE e.from_ref END \
               FROM graph g JOIN agent_relationship_edges e ON e.tenant_id=$1 \
                    AND (e.from_ref=g.from_ref OR e.from_ref=g.to_ref OR e.to_ref=g.from_ref OR e.to_ref=g.to_ref) \
               WHERE g.depth<$3 AND NOT (e.from_ref=ANY(g.path) AND e.to_ref=ANY(g.path)) \
                 AND NOT EXISTS (SELECT 1 FROM agent_relationship_supersessions s \
                                 WHERE s.tenant_id=e.tenant_id AND s.edge_id=e.edge_id)\
             ) SELECT DISTINCT ON (edge_id) edge_id,from_ref,to_ref,relationship_kind,evidence_digest,created_at \
               FROM graph ORDER BY edge_id LIMIT $4",
        )
        .bind(tenant_uuid)
        .bind(root)
        .bind(i32::try_from(maximum_depth).map_err(|_| RegistryError::QueryDenied)?)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(store_error)?;
        transaction.commit().await.map_err(store_error)?;
        let items = rows
            .into_iter()
            .map(relationship_view_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let digest = canonical_digest(&serde_json::json!({
            "schema_version":RELATIONSHIP_PAGE_SCHEMA,
            "authoritative":true,
            "tenant_id":tenant,
            "root":root,
            "maximum_depth":maximum_depth,
            "items":&items
        }))?;
        Ok(AuthoritativeRelationshipPage {
            schema_version: RELATIONSHIP_PAGE_SCHEMA.into(),
            authoritative: true,
            tenant_id: tenant.clone(),
            root: root.into(),
            maximum_depth,
            items,
            data_digest: digest,
        })
    }
}

struct FindingCandidate {
    agent_id: Option<String>,
    observation_id: Option<String>,
    kind: PostureKind,
    severity: &'static str,
    reason_code: &'static str,
    evidence_digest: String,
}

impl FindingCandidate {
    fn agent(
        agent_id: &str,
        kind: PostureKind,
        severity: &'static str,
        reason_code: &'static str,
        evidence_digest: &str,
    ) -> Self {
        Self {
            agent_id: Some(agent_id.into()),
            observation_id: None,
            kind,
            severity,
            reason_code,
            evidence_digest: evidence_digest.into(),
        }
    }

    fn observation(
        observation_id: String,
        kind: PostureKind,
        severity: &'static str,
        reason_code: &'static str,
        evidence_digest: &str,
    ) -> Self {
        Self {
            agent_id: None,
            observation_id: Some(observation_id),
            kind,
            severity,
            reason_code,
            evidence_digest: evidence_digest.into(),
        }
    }
}

#[derive(Serialize)]
struct ConfirmationDigestMaterial<'a> {
    schema_version: &'a str,
    tenant_id: &'a TenantId,
    agent_id: &'a str,
    ownership_version: u64,
    role: OwnershipRole,
    subject: &'a str,
    governance_digest: &'a str,
}

pub fn expected_confirmation_digest(
    request: &OwnershipConfirmationRequest,
) -> Result<String, RegistryError> {
    let governance_digest = canonical_digest(&request.governance)?;
    canonical_digest(&ConfirmationDigestMaterial {
        schema_version: &request.schema_version,
        tenant_id: &request.tenant_id,
        agent_id: &request.agent_id,
        ownership_version: request.ownership_version,
        role: request.role,
        subject: &request.subject,
        governance_digest: &governance_digest,
    })
}

fn validate_registration(
    request: &RegistrationRequest,
    actor: &str,
    key: &str,
    now: DateTime<Utc>,
) -> Result<(), RegistryError> {
    validate_actor_and_key(actor, key)?;
    parse_tenant(&request.tenant_id)?;
    validate_governance(&request.governance)?;
    if request.schema_version != REGISTRATION_REQUEST_SCHEMA
        || !valid_agent_id(&request.agent_id)
        || !bounded_text(&request.display_name, 256)
        || !bounded_subject(&request.owner_subject)
        || !bounded_subject(&request.sponsor_subject)
        || request.owner_subject == request.sponsor_subject
        || request.ownership_review_due_at <= now
        || request.ownership_review_due_at > now + Duration::days(366)
        || !matches!(
            request.environment.as_str(),
            "DEVELOPMENT" | "STAGING" | "PRODUCTION"
        )
        || !bounded_identifier(&request.agent_type, 128)
        || request.endpoints.is_empty()
        || request.endpoints.len() > 100
        || request.endpoints.iter().any(|value| !valid_endpoint(value))
        || request.identity_refs.is_empty()
        || !valid_string_set(&request.identity_refs, 1_000, 512)
        || !valid_string_set(&request.tool_refs, 1_000, 512)
        || !valid_string_set(&request.pack_refs, 1_000, 512)
        || !valid_string_set(&request.requested_permissions, 2_000, 512)
        || !valid_string_set(&request.approved_permissions, 2_000, 512)
        || request.last_activity_at > now + Duration::minutes(5)
        || !bounded_text(&request.provenance_ref, 2_048)
        || !lower_digest(&request.provenance_digest)
    {
        return Err(RegistryError::AssetInvalid);
    }
    request
        .bom
        .validate(&request.tenant_id, &request.agent_id, now)
}

fn validate_discovery(
    request: &DiscoveryIngestRequest,
    actor: &str,
    key: &str,
    now: DateTime<Utc>,
) -> Result<(), RegistryError> {
    validate_actor_and_key(actor, key)?;
    parse_tenant(&request.tenant_id)?;
    validate_governance(&request.governance)?;
    if request.schema_version != DISCOVERY_INGEST_SCHEMA
        || Uuid::parse_str(&request.observation_id)
            .ok()
            .is_none_or(|value| value.to_string() != request.observation_id)
        || !bounded_identifier(&request.collector_id, 256)
        || !valid_endpoint(&request.endpoint)
        || request
            .claimed_agent_id
            .as_ref()
            .is_some_and(|value| !valid_agent_id(value))
        || !bounded_identifier(&request.protocol, 64)
        || request.observed_component_digests.len() > 10_000
        || request
            .observed_component_digests
            .iter()
            .any(|(name, digest)| !bounded_text(name, 512) || !lower_digest(digest))
        || request.observed_at > now + Duration::minutes(5)
        || request.observed_at < now - Duration::days(365)
        || !lower_digest(&request.payload_digest)
        || !bounded_text(&request.provenance_ref, 2_048)
    {
        return Err(RegistryError::ObservationInvalid);
    }
    Ok(())
}

fn validate_ownership_assignment(
    request: &OwnershipAssignmentRequest,
    actor: &str,
    key: &str,
    now: DateTime<Utc>,
) -> Result<(), RegistryError> {
    validate_actor_and_key(actor, key)?;
    parse_tenant(&request.tenant_id)?;
    validate_governance(&request.governance)?;
    if request.schema_version != OWNERSHIP_ASSIGNMENT_SCHEMA
        || !valid_agent_id(&request.agent_id)
        || !bounded_subject(&request.owner_subject)
        || !bounded_subject(&request.sponsor_subject)
        || request.owner_subject == request.sponsor_subject
        || request.review_due_at <= now
        || request.review_due_at > now + Duration::days(366)
        || !lower_digest(&request.directory_evidence_digest)
    {
        return Err(RegistryError::OwnershipInvalid);
    }
    Ok(())
}

fn validate_ownership_confirmation(
    request: &OwnershipConfirmationRequest,
    actor: &str,
    key: &str,
) -> Result<(), RegistryError> {
    validate_actor_and_key(actor, key)?;
    parse_tenant(&request.tenant_id)?;
    validate_governance(&request.governance)?;
    if request.schema_version != OWNERSHIP_CONFIRMATION_SCHEMA
        || !valid_agent_id(&request.agent_id)
        || request.ownership_version == 0
        || !bounded_subject(&request.subject)
        || actor != request.subject
        || !lower_digest(&request.confirmation_digest)
    {
        return Err(RegistryError::OwnershipInvalid);
    }
    Ok(())
}

fn validate_relationship(
    request: &RelationshipEdgeRequest,
    actor: &str,
    key: &str,
) -> Result<(), RegistryError> {
    validate_actor_and_key(actor, key)?;
    parse_tenant(&request.tenant_id)?;
    validate_governance(&request.governance)?;
    if request.schema_version != RELATIONSHIP_REQUEST_SCHEMA
        || Uuid::parse_str(&request.edge_id)
            .ok()
            .is_none_or(|value| value.to_string() != request.edge_id)
        || !bounded_text(&request.from, 1_024)
        || !bounded_text(&request.to, 1_024)
        || request.from == request.to
        || !lower_digest(&request.evidence_digest)
    {
        return Err(RegistryError::RelationshipInvalid);
    }
    Ok(())
}

fn validate_posture_request(
    request: &PostureEvaluationRequest,
    actor: &str,
    key: &str,
) -> Result<(), RegistryError> {
    validate_actor_and_key(actor, key)?;
    parse_tenant(&request.tenant_id)?;
    validate_governance(&request.governance)?;
    if request.schema_version != POSTURE_EVALUATION_SCHEMA
        || !(1..=365).contains(&request.inactivity_days)
        || !(1..=86_400).contains(&request.revoked_activity_grace_seconds)
    {
        return Err(RegistryError::QueryDenied);
    }
    Ok(())
}

fn validate_lifecycle_request(
    request: &LifecycleRequest,
    actor: &str,
    key: &str,
) -> Result<(), RegistryError> {
    validate_actor_and_key(actor, key)?;
    parse_tenant(&request.tenant_id)?;
    validate_governance(&request.governance)?;
    if request.schema_version != LIFECYCLE_REQUEST_SCHEMA
        || !valid_agent_id(&request.agent_id)
        || !bounded_identifier(&request.reason_code, 128)
    {
        return Err(RegistryError::LifecycleDenied);
    }
    Ok(())
}

fn validate_governance(governance: &GovernanceContext) -> Result<(), RegistryError> {
    if governance.schema_version != GOVERNANCE_CONTEXT_SCHEMA
        || !lower_digest(&governance.action_hash)
        || !bounded_identifier(&governance.policy_decision_id, 256)
        || !lower_digest(&governance.policy_decision_digest)
        || Uuid::parse_str(&governance.execution_id)
            .ok()
            .is_none_or(|value| value.to_string() != governance.execution_id)
        || Uuid::parse_str(&governance.ledger_entry_id)
            .ok()
            .is_none_or(|value| value.to_string() != governance.ledger_entry_id)
        || !lower_digest(&governance.ledger_entry_digest)
        || !valid_evidence_ref(&governance.authorization_evidence_ref)
    {
        return Err(RegistryError::QueryDenied);
    }
    Ok(())
}

fn validate_actor_and_key(actor: &str, key: &str) -> Result<(), RegistryError> {
    if !bounded_subject(actor) || !valid_idempotency_key(key) {
        Err(RegistryError::IdempotencyInvalid)
    } else {
        Ok(())
    }
}

async fn lock_request(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    key: &str,
) -> Result<(), RegistryError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("agent-registry:{}:{key}", tenant.0))
        .execute(&mut **transaction)
        .await
        .map_err(store_error)?;
    Ok(())
}

async fn load_replay<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    key: &str,
    operation: &str,
    request_digest: &str,
) -> Result<Option<T>, RegistryError> {
    let row = sqlx::query(
        "SELECT operation,request_digest,response,response_digest \
         FROM agent_registry_idempotency WHERE tenant_id=$1 AND idempotency_key=$2",
    )
    .bind(tenant_uuid)
    .bind(key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(store_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_operation: String = row.try_get("operation").map_err(store_error)?;
    let stored_request_digest: String = row.try_get("request_digest").map_err(store_error)?;
    let response: Value = row.try_get("response").map_err(store_error)?;
    let response_digest: String = row.try_get("response_digest").map_err(store_error)?;
    if stored_operation != operation
        || stored_request_digest != request_digest
        || canonical_digest(&response)? != response_digest
    {
        return Err(RegistryError::IdempotencyConflict);
    }
    serde_json::from_value(response)
        .map(Some)
        .map_err(|_| RegistryError::StoreFailure)
}

async fn store_replay<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    key: &str,
    operation: &str,
    request_digest: &str,
    response: &T,
    now: DateTime<Utc>,
) -> Result<(), RegistryError> {
    let response = serde_json::to_value(response).map_err(json_error)?;
    let response_digest = canonical_digest(&response)?;
    sqlx::query(
        "INSERT INTO agent_registry_idempotency \
         (tenant_id,idempotency_key,operation,request_digest,response,response_digest,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(tenant_uuid)
    .bind(key)
    .bind(operation)
    .bind(request_digest)
    .bind(response)
    .bind(response_digest)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(store_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn append_audit(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    tenant: &TenantId,
    event_type: &str,
    resource_id: &str,
    actor_subject: &str,
    request_digest: &str,
    governance: &GovernanceContext,
    safe_payload: &Value,
    now: DateTime<Utc>,
) -> Result<(String, String), RegistryError> {
    validate_governance(governance)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("agent-registry-audit:{}", tenant.0))
        .execute(&mut **transaction)
        .await
        .map_err(store_error)?;
    let head = sqlx::query(
        "SELECT sequence,chain_hash FROM agent_registry_audit_heads \
         WHERE tenant_id=$1 FOR UPDATE",
    )
    .bind(tenant_uuid)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(store_error)?;
    let (previous_sequence, previous_hash) = match head {
        Some(row) => (
            row.try_get::<i64, _>("sequence").map_err(store_error)?,
            row.try_get::<String, _>("chain_hash")
                .map_err(store_error)?,
        ),
        None => (0, "0".repeat(64)),
    };
    let sequence = previous_sequence
        .checked_add(1)
        .ok_or(RegistryError::StoreFailure)?;
    let payload_digest = canonical_digest(safe_payload)?;
    let governance_digest = canonical_digest(governance)?;
    let event_id = Uuid::new_v4();
    let event_digest = canonical_digest(&serde_json::json!({
        "schema_version":"agenttrust.agent-registry-audit-event.v1",
        "tenant_id":tenant,
        "event_id":event_id,
        "sequence":sequence,
        "event_type":event_type,
        "resource_id":resource_id,
        "actor_subject":actor_subject,
        "governance_digest":&governance_digest,
        "action_hash":&governance.action_hash,
        "policy_decision_id":&governance.policy_decision_id,
        "policy_decision_digest":&governance.policy_decision_digest,
        "execution_id":&governance.execution_id,
        "ledger_entry_id":&governance.ledger_entry_id,
        "ledger_entry_digest":&governance.ledger_entry_digest,
        "authorization_evidence_ref":&governance.authorization_evidence_ref,
        "request_digest":request_digest,
        "payload_digest":&payload_digest,
        "previous_hash":&previous_hash,
        "created_at":now.to_rfc3339_opts(SecondsFormat::Nanos, true)
    }))?;
    let event_ref = format!("agent-registry-event://{}/{event_id}", tenant.0);
    sqlx::query(
        "INSERT INTO agent_registry_audit_events \
         (tenant_id,event_id,sequence,event_type,resource_id,actor_subject,governance_digest,\
          action_hash,policy_decision_id,policy_decision_digest,execution_id,ledger_entry_id,\
          ledger_entry_digest,authorization_evidence_ref,request_digest,payload_digest,\
          previous_hash,event_hash,event_ref,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
    )
    .bind(tenant_uuid)
    .bind(event_id)
    .bind(sequence)
    .bind(event_type)
    .bind(resource_id)
    .bind(actor_subject)
    .bind(&governance_digest)
    .bind(&governance.action_hash)
    .bind(&governance.policy_decision_id)
    .bind(&governance.policy_decision_digest)
    .bind(Uuid::parse_str(&governance.execution_id).map_err(|_| RegistryError::QueryDenied)?)
    .bind(Uuid::parse_str(&governance.ledger_entry_id).map_err(|_| RegistryError::QueryDenied)?)
    .bind(&governance.ledger_entry_digest)
    .bind(&governance.authorization_evidence_ref)
    .bind(request_digest)
    .bind(&payload_digest)
    .bind(&previous_hash)
    .bind(&event_digest)
    .bind(&event_ref)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(store_error)?;
    sqlx::query(
        "INSERT INTO agent_registry_audit_heads(tenant_id,sequence,chain_hash,updated_at) \
         VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id) DO UPDATE \
         SET sequence=EXCLUDED.sequence,chain_hash=EXCLUDED.chain_hash,updated_at=EXCLUDED.updated_at",
    )
    .bind(tenant_uuid)
    .bind(sequence)
    .bind(&event_digest)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(store_error)?;
    let outbox_payload = serde_json::json!({
        "schema_version":"agenttrust.agent-registry-outbox-event.v1",
        "tenant_id":tenant,
        "event_ref":&event_ref,
        "event_digest":&event_digest,
        "event_type":event_type,
        "resource_id":resource_id,
        "request_digest":request_digest,
        "payload":safe_payload,
        "payload_digest":&payload_digest,
        "governance_digest":&governance_digest,
        "action_hash":&governance.action_hash,
        "policy_decision_id":&governance.policy_decision_id,
        "policy_decision_digest":&governance.policy_decision_digest,
        "execution_id":&governance.execution_id,
        "ledger_entry_id":&governance.ledger_entry_id,
        "ledger_entry_digest":&governance.ledger_entry_digest,
        "authorization_evidence_ref":&governance.authorization_evidence_ref,
        "sequence":sequence
    });
    let outbox_payload_digest = canonical_digest(&outbox_payload)?;
    sqlx::query(
        "INSERT INTO agent_registry_outbox \
         (tenant_id,outbox_id,event_id,event_type,payload,payload_digest,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(tenant_uuid)
    .bind(Uuid::new_v4())
    .bind(event_id)
    .bind(event_type)
    .bind(outbox_payload)
    .bind(outbox_payload_digest)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(store_error)?;
    Ok((event_ref, event_digest))
}

async fn append_registration_relationships(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    request: &RegistrationRequest,
    request_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), RegistryError> {
    let from = format!("agent:{}", request.agent_id);
    let mut edges = vec![
        (format!("subject:{}", request.owner_subject), "OWNS"),
        (
            format!("subject:{}", request.sponsor_subject),
            "SPONSORED_BY",
        ),
    ];
    edges.extend(
        request
            .tool_refs
            .iter()
            .map(|value| (format!("tool:{value}"), "USES_TOOL")),
    );
    edges.extend(
        request
            .pack_refs
            .iter()
            .map(|value| (format!("pack:{value}"), "USES_PACK")),
    );
    if edges.len() > 2_002 {
        return Err(RegistryError::CapacityExceeded);
    }
    for (to, kind) in edges {
        sqlx::query(
            "INSERT INTO agent_relationship_edges \
             (tenant_id,edge_id,from_ref,to_ref,relationship_kind,evidence_digest,created_at,created_by,request_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(tenant_uuid)
        .bind(Uuid::new_v4())
        .bind(&from)
        .bind(to)
        .bind(kind)
        .bind(request_digest)
        .bind(now)
        .bind("SYSTEM:REGISTRATION_GRAPH")
        .bind(request_digest)
        .execute(&mut **transaction)
        .await
        .map_err(store_error)?;
    }
    Ok(())
}

async fn supersede_ownership_relationships(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_uuid: Uuid,
    request: &OwnershipAssignmentRequest,
    actor_subject: &str,
    request_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), RegistryError> {
    let from = format!("agent:{}", request.agent_id);
    let existing = sqlx::query(
        "SELECT e.edge_id FROM agent_relationship_edges e \
         WHERE e.tenant_id=$1 AND e.from_ref=$2 \
           AND e.relationship_kind IN ('OWNS','SPONSORED_BY') \
           AND NOT EXISTS (SELECT 1 FROM agent_relationship_supersessions s \
                           WHERE s.tenant_id=e.tenant_id AND s.edge_id=e.edge_id) \
         ORDER BY e.edge_id",
    )
    .bind(tenant_uuid)
    .bind(&from)
    .fetch_all(&mut **transaction)
    .await
    .map_err(store_error)?;
    for row in existing {
        let edge_id: Uuid = row.try_get("edge_id").map_err(store_error)?;
        sqlx::query(
            "INSERT INTO agent_relationship_supersessions \
             (tenant_id,supersession_id,edge_id,superseded_at,superseded_by,request_digest) \
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(tenant_uuid)
        .bind(Uuid::new_v4())
        .bind(edge_id)
        .bind(now)
        .bind(actor_subject)
        .bind(request_digest)
        .execute(&mut **transaction)
        .await
        .map_err(store_error)?;
    }
    for (target, kind) in [
        (format!("subject:{}", request.owner_subject), "OWNS"),
        (
            format!("subject:{}", request.sponsor_subject),
            "SPONSORED_BY",
        ),
    ] {
        sqlx::query(
            "INSERT INTO agent_relationship_edges \
             (tenant_id,edge_id,from_ref,to_ref,relationship_kind,evidence_digest,created_at,created_by,request_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(tenant_uuid)
        .bind(Uuid::new_v4())
        .bind(&from)
        .bind(target)
        .bind(kind)
        .bind(&request.directory_evidence_digest)
        .bind(now)
        .bind(actor_subject)
        .bind(request_digest)
        .execute(&mut **transaction)
        .await
        .map_err(store_error)?;
    }
    Ok(())
}

fn agent_view_from_row(row: sqlx::postgres::PgRow) -> Result<AgentInventoryItem, RegistryError> {
    Ok(AgentInventoryItem {
        schema_version: AGENT_VIEW_SCHEMA.into(),
        agent_id: row.try_get("agent_id").map_err(store_error)?,
        display_name: row.try_get("display_name").map_err(store_error)?,
        owner_subject: row.try_get("owner_subject").map_err(store_error)?,
        sponsor_subject: row.try_get("sponsor_subject").map_err(store_error)?,
        ownership_status: row.try_get("ownership_status").map_err(store_error)?,
        environment: row.try_get("environment").map_err(store_error)?,
        lifecycle: parse_lifecycle(&row.try_get::<String, _>("lifecycle").map_err(store_error)?)?,
        agent_type: row.try_get("agent_type").map_err(store_error)?,
        bom_digest: row.try_get("bom_digest").map_err(store_error)?,
        endpoint_count: u32::try_from(
            row.try_get::<i32, _>("endpoint_count")
                .map_err(store_error)?,
        )
        .map_err(|_| RegistryError::StoreFailure)?,
        identity_count: u32::try_from(
            row.try_get::<i32, _>("identity_count")
                .map_err(store_error)?,
        )
        .map_err(|_| RegistryError::StoreFailure)?,
        tool_count: u32::try_from(row.try_get::<i32, _>("tool_count").map_err(store_error)?)
            .map_err(|_| RegistryError::StoreFailure)?,
        pack_count: u32::try_from(row.try_get::<i32, _>("pack_count").map_err(store_error)?)
            .map_err(|_| RegistryError::StoreFailure)?,
        open_findings: u32::try_from(
            row.try_get::<i64, _>("open_findings")
                .map_err(store_error)?,
        )
        .map_err(|_| RegistryError::StoreFailure)?,
        highest_risk: row.try_get("highest_risk").map_err(store_error)?,
        last_activity_at: row.try_get("last_activity_at").map_err(store_error)?,
        registered_at: row.try_get("registered_at").map_err(store_error)?,
        updated_at: row.try_get("updated_at").map_err(store_error)?,
    })
}

fn posture_view_from_row(row: sqlx::postgres::PgRow) -> Result<PostureFindingView, RegistryError> {
    Ok(PostureFindingView {
        schema_version: POSTURE_VIEW_SCHEMA.into(),
        finding_id: row
            .try_get::<Uuid, _>("finding_id")
            .map_err(store_error)?
            .to_string(),
        agent_id: row.try_get("agent_id").map_err(store_error)?,
        observation_id: row
            .try_get::<Option<Uuid>, _>("observation_id")
            .map_err(store_error)?
            .map(|value| value.to_string()),
        kind: parse_posture_kind(&row.try_get::<String, _>("posture").map_err(store_error)?)?,
        severity: row.try_get("severity").map_err(store_error)?,
        reason_code: row.try_get("reason_code").map_err(store_error)?,
        evidence_digest: row.try_get("evidence_digest").map_err(store_error)?,
        detected_at: row.try_get("detected_at").map_err(store_error)?,
    })
}

fn relationship_view_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<RelationshipEdgeView, RegistryError> {
    Ok(RelationshipEdgeView {
        schema_version: RELATIONSHIP_VIEW_SCHEMA.into(),
        edge_id: row
            .try_get::<Uuid, _>("edge_id")
            .map_err(store_error)?
            .to_string(),
        from: row.try_get("from_ref").map_err(store_error)?,
        to: row.try_get("to_ref").map_err(store_error)?,
        kind: parse_relationship_kind(
            &row.try_get::<String, _>("relationship_kind")
                .map_err(store_error)?,
        )?,
        evidence_digest: row.try_get("evidence_digest").map_err(store_error)?,
        created_at: row.try_get("created_at").map_err(store_error)?,
    })
}

fn json_string_set(value: Value) -> Result<BTreeSet<String>, RegistryError> {
    let values: BTreeSet<String> =
        serde_json::from_value(value).map_err(|_| RegistryError::StoreFailure)?;
    if !valid_string_set(&values, 2_000, 512) {
        return Err(RegistryError::StoreFailure);
    }
    Ok(values)
}

fn parse_tenant(tenant: &TenantId) -> Result<Uuid, RegistryError> {
    Uuid::parse_str(&tenant.0)
        .ok()
        .filter(|value| value.to_string() == tenant.0)
        .ok_or(RegistryError::TenantMismatch)
}

fn lifecycle_text(value: LifecycleState) -> &'static str {
    match value {
        LifecycleState::Draft => "DRAFT",
        LifecycleState::Active => "ACTIVE",
        LifecycleState::Suspended => "SUSPENDED",
        LifecycleState::Retired => "RETIRED",
        LifecycleState::Revoked => "REVOKED",
    }
}

fn parse_lifecycle(value: &str) -> Result<LifecycleState, RegistryError> {
    match value {
        "DRAFT" => Ok(LifecycleState::Draft),
        "ACTIVE" => Ok(LifecycleState::Active),
        "SUSPENDED" => Ok(LifecycleState::Suspended),
        "RETIRED" => Ok(LifecycleState::Retired),
        "REVOKED" => Ok(LifecycleState::Revoked),
        _ => Err(RegistryError::StoreFailure),
    }
}

fn production_lifecycle_allowed(from: LifecycleState, to: LifecycleState) -> bool {
    matches!(
        (from, to),
        (LifecycleState::Draft, LifecycleState::Active)
            | (LifecycleState::Active, LifecycleState::Suspended)
            | (LifecycleState::Suspended, LifecycleState::Active)
            | (
                LifecycleState::Active | LifecycleState::Suspended,
                LifecycleState::Retired
            )
            | (_, LifecycleState::Revoked)
    )
}

fn observation_source_text(value: ObservationSource) -> &'static str {
    match value {
        ObservationSource::ProtocolDiscovery => "PROTOCOL_DISCOVERY",
        ObservationSource::NetworkObservation => "NETWORK_OBSERVATION",
        ObservationSource::LogObservation => "LOG_OBSERVATION",
        ObservationSource::Import => "IMPORT",
    }
}

fn ownership_role_text(value: OwnershipRole) -> &'static str {
    match value {
        OwnershipRole::Owner => "OWNER",
        OwnershipRole::Sponsor => "SPONSOR",
    }
}

fn relationship_kind_text(value: RelationshipKind) -> &'static str {
    match value {
        RelationshipKind::UsesTool => "USES_TOOL",
        RelationshipKind::UsesPack => "USES_PACK",
        RelationshipKind::Owns => "OWNS",
        RelationshipKind::SponsoredBy => "SPONSORED_BY",
        RelationshipKind::ObservedAt => "OBSERVED_AT",
        RelationshipKind::DelegatesTo => "DELEGATES_TO",
    }
}

fn parse_relationship_kind(value: &str) -> Result<RelationshipKind, RegistryError> {
    match value {
        "USES_TOOL" => Ok(RelationshipKind::UsesTool),
        "USES_PACK" => Ok(RelationshipKind::UsesPack),
        "OWNS" => Ok(RelationshipKind::Owns),
        "SPONSORED_BY" => Ok(RelationshipKind::SponsoredBy),
        "OBSERVED_AT" => Ok(RelationshipKind::ObservedAt),
        "DELEGATES_TO" => Ok(RelationshipKind::DelegatesTo),
        _ => Err(RegistryError::StoreFailure),
    }
}

fn posture_kind_text(value: PostureKind) -> &'static str {
    match value {
        PostureKind::Shadow => "SHADOW",
        PostureKind::Orphan => "ORPHAN",
        PostureKind::Dormant => "DORMANT",
        PostureKind::Overprivileged => "OVERPRIVILEGED",
        PostureKind::Drifted => "DRIFTED",
        PostureKind::RevokedButActive => "REVOKED_BUT_ACTIVE",
    }
}

fn parse_posture_kind(value: &str) -> Result<PostureKind, RegistryError> {
    match value {
        "SHADOW" => Ok(PostureKind::Shadow),
        "ORPHAN" => Ok(PostureKind::Orphan),
        "DORMANT" => Ok(PostureKind::Dormant),
        "OVERPRIVILEGED" => Ok(PostureKind::Overprivileged),
        "DRIFTED" => Ok(PostureKind::Drifted),
        "REVOKED_BUT_ACTIVE" => Ok(PostureKind::RevokedButActive),
        _ => Err(RegistryError::StoreFailure),
    }
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, RegistryError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| RegistryError::PersistenceFailed)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn valid_secret(value: &str) -> bool {
    !value.is_empty() && value.len() <= 8_192 && !value.contains(char::is_whitespace)
}

fn valid_evidence_ref(value: &str) -> bool {
    value
        .strip_prefix("evidence://")
        .is_some_and(|suffix| !suffix.is_empty())
        && bounded_text(value, 2_048)
        && !value.contains('?')
        && !value.contains('#')
        && !value.chars().any(char::is_whitespace)
}

fn valid_agent_id(value: &str) -> bool {
    bounded_identifier(value, 256)
}

fn bounded_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn bounded_subject(value: &str) -> bool {
    bounded_text(value, 512) && !value.chars().any(char::is_whitespace)
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(|character| character.is_control())
}

fn valid_string_set(values: &BTreeSet<String>, maximum_items: usize, maximum_len: usize) -> bool {
    values.len() <= maximum_items && values.iter().all(|value| bounded_text(value, maximum_len))
}

fn valid_endpoint(value: &str) -> bool {
    if !bounded_text(value, 2_048) {
        return false;
    }
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    matches!(
        parsed.scheme(),
        "https" | "mcp" | "a2a" | "agui" | "mqtt" | "mqtts" | "opc.tcp" | "modbus"
    ) && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
}

fn valid_dashboard_resource(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

fn base64url_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || value == b'_' || value == b'-'
}

fn store_error<E>(_error: E) -> RegistryError {
    RegistryError::StoreFailure
}

fn unique_or_store(error: sqlx::Error, conflict: RegistryError) -> RegistryError {
    match &error {
        sqlx::Error::Database(database) if database.code().as_deref() == Some("23505") => conflict,
        _ => RegistryError::StoreFailure,
    }
}

fn json_error<E>(_error: E) -> RegistryError {
    RegistryError::PersistenceFailed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_is_tenant_resource_expiry_and_tamper_bound() {
        let codec = CursorCodec::new(vec![19_u8; 32], Duration::minutes(15))
            .unwrap_or_else(|error| panic!("cursor codec: {error}"));
        let tenant = TenantId(Uuid::new_v4().to_string());
        let other = TenantId(Uuid::new_v4().to_string());
        let now = Utc::now();
        let cursor = codec
            .encode(&tenant, "summary", "agent-100", now)
            .unwrap_or_else(|error| panic!("cursor encode: {error}"));
        assert_eq!(
            codec
                .decode(&cursor, &tenant, "summary", now)
                .unwrap_or_else(|error| panic!("cursor decode: {error}")),
            "agent-100"
        );
        assert_eq!(
            codec.decode(&cursor, &other, "summary", now),
            Err(RegistryError::CursorInvalid)
        );
        assert_eq!(
            codec.decode(&cursor, &tenant, "other", now),
            Err(RegistryError::CursorInvalid)
        );
        assert_eq!(
            codec.decode(&cursor, &tenant, "summary", now + Duration::minutes(16)),
            Err(RegistryError::CursorInvalid)
        );
        let mut tampered = cursor.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered =
            String::from_utf8(tampered).unwrap_or_else(|error| panic!("cursor utf8: {error}"));
        assert_eq!(
            codec.decode(&tampered, &tenant, "summary", now),
            Err(RegistryError::CursorInvalid)
        );
    }

    #[test]
    fn pack_bom_requires_supply_chain_digest_and_canonical_digest() {
        let tenant = TenantId(Uuid::new_v4().to_string());
        let now = Utc::now();
        let mut bom = AgentBomDocument {
            schema_version: BOM_SCHEMA.into(),
            tenant_id: tenant.clone(),
            agent_id: "agent-1".into(),
            components: vec![BomComponent {
                kind: "PACK".into(),
                name: "coding".into(),
                version: "1.0.0".into(),
                digest: "a".repeat(64),
                supply_chain_digest: None,
            }],
            bom_digest: String::new(),
            generated_at: now,
        };
        bom.bom_digest = bom
            .expected_digest()
            .unwrap_or_else(|error| panic!("digest: {error}"));
        assert_eq!(
            bom.validate(&tenant, "agent-1", now),
            Err(RegistryError::AssetInvalid)
        );
        bom.components[0].supply_chain_digest = Some("b".repeat(64));
        bom.bom_digest = bom
            .expected_digest()
            .unwrap_or_else(|error| panic!("digest: {error}"));
        assert!(bom.validate(&tenant, "agent-1", now).is_ok());
    }

    #[test]
    fn governance_rejects_noncanonical_or_incomplete_authority_bindings() {
        let mut governance = GovernanceContext {
            schema_version: GOVERNANCE_CONTEXT_SCHEMA.into(),
            action_hash: "a".repeat(64),
            policy_decision_id: "decision:1".into(),
            policy_decision_digest: "b".repeat(64),
            execution_id: Uuid::new_v4().to_string(),
            ledger_entry_id: Uuid::new_v4().to_string(),
            ledger_entry_digest: "c".repeat(64),
            authorization_evidence_ref: "evidence://authorization/decision-1".into(),
        };
        assert!(validate_governance(&governance).is_ok());
        governance.authorization_evidence_ref = "https://evidence.invalid/decision-1".into();
        assert_eq!(
            validate_governance(&governance),
            Err(RegistryError::QueryDenied)
        );
        governance.authorization_evidence_ref = "evidence://authorization/decision-1".into();
        governance.execution_id = Uuid::new_v4().to_string().to_uppercase();
        assert_eq!(
            validate_governance(&governance),
            Err(RegistryError::QueryDenied)
        );
        governance.execution_id = Uuid::new_v4().to_string();
        governance.action_hash = "A".repeat(64);
        assert_eq!(
            validate_governance(&governance),
            Err(RegistryError::QueryDenied)
        );
    }
}
