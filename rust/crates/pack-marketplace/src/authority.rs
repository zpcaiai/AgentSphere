//! PostgreSQL-backed Pack Marketplace authority.
//!
//! Human commands never mutate marketplace state directly. They are converted to Canonical
//! Action IR and submitted to the durable orchestrator. Only the runtime executor route can
//! apply a mutation, and only when the request is bound to an accepted ingress record, a PEP
//! decision, an immutable ledger entry, a resource-version fence, and an idempotency key.

use crate::PublisherTrust;
use crate::principal::VerifiedHumanPrincipal;
use agent_trust_action_ir::{
    ActionDraft, CredentialRef, NormalizationContext, TypedPayload, hash as action_hash, normalize,
};
use agent_trust_contracts::{
    ActionId, AgentIdentity, AgentInstanceId, CONTRACT_SCHEMA_VERSION, DataClassification,
    DataContext, ExecutionEnvironment, ExpectedOutcome, Intent, ResourceSelector, RiskContext,
    RiskLevel, SchemaVersion, StepId, TaskId, TenantId, ToolId, ToolRef, ToolVersion,
};
use agent_trust_gateway::{
    GATEWAY_SCHEMA_VERSION, IdentityContext, InboundEnvelope, IngressProtocol, TenantContext,
    TraceContext,
};
use agent_trust_incident_release_gate::ReleaseCertificate;
use agent_trust_pack_supply_chain::{
    ArtifactVerifier, DomainPackManifest, PackPermissionDeclaration, PackSdk, PermissionDiff,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const MARKETPLACE_COMMAND_SCHEMA: &str = "agenttrust.marketplace-command.v1";
pub const MARKETPLACE_EXECUTOR_REQUEST_SCHEMA: &str = "agenttrust.marketplace-executor-request.v1";
pub const MARKETPLACE_ACTION_RECEIPT_SCHEMA: &str = "agenttrust.marketplace-action-receipt.v1";
pub const MARKETPLACE_MUTATION_RESULT_SCHEMA: &str = "agenttrust.marketplace-mutation-result.v1";
pub const MARKETPLACE_READINESS_SCHEMA: &str = "agenttrust.pack-marketplace-readiness.v1";
pub const AUTHORITATIVE_PACK_PAGE_SCHEMA: &str = "agenttrust.authoritative-pack-page.v1";
pub const RELEASE_GATE_KEYRING_SCHEMA: &str = "agenttrust.pack-release-gate-keyring.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MarketplaceAuthorityError {
    #[error("MARKETPLACE_REQUEST_INVALID")]
    RequestInvalid,
    #[error("MARKETPLACE_PRINCIPAL_DENIED")]
    PrincipalDenied,
    #[error("MARKETPLACE_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("MARKETPLACE_STATE_CONFLICT")]
    StateConflict,
    #[error("MARKETPLACE_REVIEW_SEPARATION_REQUIRED")]
    ReviewSeparationRequired,
    #[error("MARKETPLACE_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("MARKETPLACE_COMPATIBILITY_DENIED")]
    CompatibilityDenied,
    #[error("MARKETPLACE_ENTITLEMENT_DENIED")]
    EntitlementDenied,
    #[error("MARKETPLACE_REGION_DENIED")]
    RegionDenied,
    #[error("MARKETPLACE_TRUST_DENIED")]
    TrustDenied,
    #[error("MARKETPLACE_RISK_DENIED")]
    RiskDenied,
    #[error("MARKETPLACE_NOT_FOUND")]
    NotFound,
    #[error("MARKETPLACE_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
    #[error("MARKETPLACE_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("MARKETPLACE_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MarketplaceRouteKind {
    Publisher,
    Listing,
    Lifecycle,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ListingVisibility {
    Private,
    Tenant,
}

impl ListingVisibility {
    fn as_str(self) -> &'static str {
        match self {
            Self::Private => "PRIVATE",
            Self::Tenant => "TENANT",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MarketplaceRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl MarketplaceRisk {
    fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunningTaskResponse {
    Pause,
    Kill,
    AllowToFinish,
}

impl RunningTaskResponse {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "PAUSE",
            Self::Kill => "KILL",
            Self::AllowToFinish => "ALLOW_TO_FINISH",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MarketplaceCommand {
    OnboardPublisher {
        publisher_id: String,
        publisher_subject: String,
        identity_digest: String,
        responsibility_contact: String,
        home_region: String,
    },
    VerifyPublisherKey {
        publisher_id: String,
        key_id: String,
        algorithm: String,
        public_key: String,
        key_fingerprint: String,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        review_digest: String,
    },
    SetPublisherTrust {
        publisher_id: String,
        trust: PublisherTrust,
        reason_digest: String,
    },
    ConfigureTenantCatalog {
        control_plane_version: String,
        region: String,
        entitlements: BTreeSet<String>,
        allowed_compatibility: BTreeSet<String>,
        minimum_publisher_trust: PublisherTrust,
        maximum_risk: MarketplaceRisk,
    },
    SubmitRelease {
        release_id: Uuid,
        manifest: DomainPackManifest,
        release_certificate: ReleaseCertificate,
        visibility: ListingVisibility,
        entitlement: String,
        allowed_regions: BTreeSet<String>,
        risk_rating: MarketplaceRisk,
        minimum_publisher_trust: PublisherTrust,
        minimum_control_plane_version: String,
    },
    ReviewRelease {
        release_id: Uuid,
        decision: ReviewDecision,
        review_digest: String,
    },
    RequestInstallation {
        installation_id: Uuid,
        release_id: Uuid,
        environment: String,
        request_reason_digest: String,
    },
    ApproveInstallation {
        installation_id: Uuid,
        decision: ReviewDecision,
        approval_digest: String,
    },
    Install {
        installation_id: Uuid,
        artifact_receipt_digest: String,
    },
    Activate {
        installation_id: Uuid,
        production_certificate_digest: Option<String>,
    },
    PlanUpgrade {
        plan_id: Uuid,
        current_installation_id: Uuid,
        target_installation_id: Uuid,
        migration_digest: String,
        rollback_digest: String,
        canary_percent: u8,
    },
    RecordCanary {
        plan_id: Uuid,
        passed: bool,
        observed_samples: u32,
        evidence_ref: String,
        evidence_digest: String,
    },
    Upgrade {
        plan_id: Uuid,
        production_certificate_digest: Option<String>,
    },
    Rollback {
        installation_id: Uuid,
        reason_digest: String,
    },
    Deactivate {
        installation_id: Uuid,
        reason_digest: String,
    },
    RevokeRelease {
        release_id: Uuid,
        reason_code: String,
        reason_digest: String,
        running_task_response: RunningTaskResponse,
    },
}

impl MarketplaceCommand {
    pub fn route_kind(&self) -> MarketplaceRouteKind {
        match self {
            Self::OnboardPublisher { .. }
            | Self::VerifyPublisherKey { .. }
            | Self::SetPublisherTrust { .. } => MarketplaceRouteKind::Publisher,
            Self::ConfigureTenantCatalog { .. }
            | Self::SubmitRelease { .. }
            | Self::ReviewRelease { .. }
            | Self::RevokeRelease { .. } => MarketplaceRouteKind::Listing,
            Self::RequestInstallation { .. }
            | Self::ApproveInstallation { .. }
            | Self::Install { .. }
            | Self::Activate { .. }
            | Self::PlanUpgrade { .. }
            | Self::RecordCanary { .. }
            | Self::Upgrade { .. }
            | Self::Rollback { .. }
            | Self::Deactivate { .. } => MarketplaceRouteKind::Lifecycle,
        }
    }

    pub fn operation(&self) -> &'static str {
        match self {
            Self::OnboardPublisher { .. } => "ONBOARD_PUBLISHER",
            Self::VerifyPublisherKey { .. } => "VERIFY_PUBLISHER_KEY",
            Self::SetPublisherTrust { .. } => "SET_PUBLISHER_TRUST",
            Self::ConfigureTenantCatalog { .. } => "CONFIGURE_TENANT_CATALOG",
            Self::SubmitRelease { .. } => "SUBMIT_RELEASE",
            Self::ReviewRelease { .. } => "REVIEW_RELEASE",
            Self::RequestInstallation { .. } => "REQUEST_INSTALLATION",
            Self::ApproveInstallation { .. } => "APPROVE_INSTALLATION",
            Self::Install { .. } => "INSTALL",
            Self::Activate { .. } => "ACTIVATE",
            Self::PlanUpgrade { .. } => "PLAN_UPGRADE",
            Self::RecordCanary { .. } => "RECORD_CANARY",
            Self::Upgrade { .. } => "UPGRADE",
            Self::Rollback { .. } => "ROLLBACK",
            Self::Deactivate { .. } => "DEACTIVATE",
            Self::RevokeRelease { .. } => "REVOKE_RELEASE",
        }
    }

    fn required_role(&self) -> &'static str {
        match self {
            Self::OnboardPublisher { .. } => "marketplace-publisher-admin",
            Self::VerifyPublisherKey { .. } => "marketplace-publisher-reviewer",
            Self::SetPublisherTrust { .. } => "marketplace-publisher-admin",
            Self::ConfigureTenantCatalog { .. } => "marketplace-admin",
            Self::SubmitRelease { .. } => "marketplace-publisher",
            Self::ReviewRelease { .. } => "marketplace-release-reviewer",
            Self::RequestInstallation { .. } => "marketplace-installer",
            Self::ApproveInstallation { .. } => "marketplace-install-reviewer",
            Self::Install { .. } => "marketplace-installer",
            Self::Activate { .. } => "marketplace-operator",
            Self::PlanUpgrade { .. } => "marketplace-operator",
            Self::RecordCanary { .. } => "marketplace-canary-controller",
            Self::Upgrade { .. } | Self::Rollback { .. } | Self::Deactivate { .. } => {
                "marketplace-operator"
            }
            Self::RevokeRelease { .. } => "marketplace-security-admin",
        }
    }

    fn action_risk(&self) -> RiskLevel {
        match self {
            Self::OnboardPublisher { .. }
            | Self::ConfigureTenantCatalog { .. }
            | Self::RequestInstallation { .. }
            | Self::Install { .. }
            | Self::PlanUpgrade { .. }
            | Self::RecordCanary { .. } => RiskLevel::Medium,
            Self::VerifyPublisherKey { .. }
            | Self::SubmitRelease { .. }
            | Self::ReviewRelease { .. }
            | Self::ApproveInstallation { .. }
            | Self::Deactivate { .. } => RiskLevel::High,
            Self::SetPublisherTrust { .. }
            | Self::Activate { .. }
            | Self::Upgrade { .. }
            | Self::Rollback { .. }
            | Self::RevokeRelease { .. } => RiskLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceCommandRequest {
    pub schema_version: String,
    pub tenant_id: Uuid,
    pub command_id: Uuid,
    pub resource_id: String,
    pub expected_resource_version: u64,
    pub command: MarketplaceCommand,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceActionReceipt {
    pub schema_version: String,
    pub action_id: String,
    pub task_id: String,
    pub accepted: bool,
    pub execution_pending: bool,
    pub ingress_digest: String,
    pub ledger_evidence_ref: String,
    pub ledger_evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceExecutorRequest {
    pub schema_version: String,
    pub command: MarketplaceCommandRequest,
    pub principal_subject: String,
    pub principal_assertion_digest: String,
    pub approval_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceExecutionBinding {
    pub tenant_id: TenantId,
    pub action_hash: String,
    pub policy_decision_id: String,
    pub policy_decision_digest: String,
    pub ledger_entry_id: String,
    pub ledger_entry_digest: String,
    pub ledger_execution_id: Uuid,
    pub fence_digest: String,
    pub resource_version: u64,
    pub authorization_evidence_ref: String,
    pub authorization_evidence_digest: String,
    pub idempotency_key: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceMutationResult {
    pub schema_version: String,
    pub command_id: Uuid,
    pub resource_id: String,
    pub operation: String,
    pub resource_version: u64,
    pub state: String,
    pub artifact_digest: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativePackItem {
    pub release_id: Uuid,
    pub pack_id: String,
    pub version: String,
    pub pack_digest: String,
    pub publisher_id: String,
    pub visibility: String,
    pub entitlement: String,
    pub allowed_regions: Vec<String>,
    pub risk_rating: String,
    pub compatibility: Vec<String>,
    pub certificate_digest: String,
    pub review_status: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeInstallationItem {
    pub installation_id: Uuid,
    pub release_id: Uuid,
    pub pack_id: String,
    pub version: String,
    pub environment: String,
    pub state: String,
    pub permission_expansion: bool,
    pub previous_installation_id: Option<Uuid>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativePackPage {
    pub schema_version: String,
    pub authoritative: bool,
    pub tenant_id: TenantId,
    pub releases: Vec<AuthoritativePackItem>,
    pub installations: Vec<AuthoritativeInstallationItem>,
    pub next_after_pack_id: Option<String>,
    pub data_digest: String,
}

#[derive(Debug, Clone)]
pub struct MarketplaceAuthorityConfig {
    pub service_agent_id: AgentInstanceId,
    pub organization_id: String,
    pub agent_version: String,
    pub region: String,
    pub tool_id: ToolId,
    pub tool_version: ToolVersion,
    pub credential_profile: String,
    pub service_subject: String,
}

impl MarketplaceAuthorityConfig {
    fn validate(&self) -> Result<(), MarketplaceAuthorityError> {
        if canonical_uuid(&self.service_agent_id.0)
            && identifier(&self.organization_id, 256)
            && identifier(&self.agent_version, 128)
            && identifier(&self.region, 128)
            && identifier(&self.tool_id.0, 256)
            && identifier(&self.tool_version.0, 128)
            && identifier(&self.credential_profile, 128)
            && identifier(&self.service_subject, 256)
        {
            Ok(())
        } else {
            Err(MarketplaceAuthorityError::ConfigurationInvalid)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseGateKeyringDocument {
    schema_version: String,
    required_gate_id: String,
    keys: Vec<ReleaseGateKeyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseGateKeyDocument {
    key_id: String,
    algorithm: String,
    usage: String,
    status: String,
    public_key: String,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct ReleaseGateKey {
    key: VerifyingKey,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct ReleaseGateKeyring {
    required_gate_id: String,
    keys: BTreeMap<String, ReleaseGateKey>,
}

impl ReleaseGateKeyring {
    pub fn from_file(
        path: &Path,
        required_gate_id: &str,
    ) -> Result<Self, MarketplaceAuthorityError> {
        if !path.is_absolute() || !identifier(required_gate_id, 128) {
            return Err(MarketplaceAuthorityError::ConfigurationInvalid);
        }
        let raw =
            std::fs::read(path).map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
        if raw.is_empty() || raw.len() > 1_048_576 {
            return Err(MarketplaceAuthorityError::ConfigurationInvalid);
        }
        let document: ReleaseGateKeyringDocument = serde_json::from_slice(&raw)
            .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
        if document.schema_version != RELEASE_GATE_KEYRING_SCHEMA
            || document.required_gate_id != required_gate_id
            || document.keys.is_empty()
            || document.keys.len() > 128
        {
            return Err(MarketplaceAuthorityError::ConfigurationInvalid);
        }
        let now = Utc::now();
        let mut keys = BTreeMap::new();
        let mut usable = false;
        for entry in document.keys {
            if !identifier(&entry.key_id, 128)
                || entry.algorithm != "Ed25519"
                || entry.usage != "RELEASE_GATE_CERTIFICATE"
                || !matches!(entry.status.as_str(), "ACTIVE" | "VERIFY_ONLY")
                || entry.not_before >= entry.expires_at
            {
                return Err(MarketplaceAuthorityError::ConfigurationInvalid);
            }
            let bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(entry.public_key)
                .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?
                .try_into()
                .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| MarketplaceAuthorityError::ConfigurationInvalid)?;
            usable |= entry.status == "ACTIVE" && now >= entry.not_before && now < entry.expires_at;
            if keys
                .insert(
                    entry.key_id,
                    ReleaseGateKey {
                        key,
                        not_before: entry.not_before,
                        expires_at: entry.expires_at,
                    },
                )
                .is_some()
            {
                return Err(MarketplaceAuthorityError::ConfigurationInvalid);
            }
        }
        if !usable {
            return Err(MarketplaceAuthorityError::ConfigurationInvalid);
        }
        Ok(Self {
            required_gate_id: document.required_gate_id,
            keys,
        })
    }

    pub fn verify(
        &self,
        certificate: &ReleaseCertificate,
        pack_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<String, MarketplaceAuthorityError> {
        let entry = self
            .keys
            .get(&certificate.key_id)
            .ok_or(MarketplaceAuthorityError::SignatureInvalid)?;
        if certificate.gate_id != self.required_gate_id
            || certificate.release_digest != pack_digest
            || certificate.valid_from < entry.not_before
            || certificate.valid_until > entry.expires_at
        {
            return Err(MarketplaceAuthorityError::SignatureInvalid);
        }
        certificate
            .verify(&entry.key, now)
            .map_err(|_| MarketplaceAuthorityError::SignatureInvalid)?;
        canonical_digest(certificate)
    }
}

#[derive(Debug, Clone)]
pub struct PreparedMarketplaceIngress {
    pub envelope: InboundEnvelope,
    pub receipt: Option<MarketplaceActionReceipt>,
}

#[async_trait]
pub trait MarketplaceOrchestratorPort: Send + Sync {
    async fn submit(
        &self,
        tenant: &TenantId,
        envelope: &InboundEnvelope,
    ) -> Result<MarketplaceActionReceipt, MarketplaceAuthorityError>;
}

#[derive(Clone)]
pub struct MarketplaceIngressAuthority {
    store: PostgresMarketplaceAuthorityStore,
    orchestrator: Arc<dyn MarketplaceOrchestratorPort>,
    config: MarketplaceAuthorityConfig,
}

impl MarketplaceIngressAuthority {
    pub fn new(
        store: PostgresMarketplaceAuthorityStore,
        orchestrator: Arc<dyn MarketplaceOrchestratorPort>,
        config: MarketplaceAuthorityConfig,
    ) -> Result<Self, MarketplaceAuthorityError> {
        config.validate()?;
        Ok(Self {
            store,
            orchestrator,
            config,
        })
    }

    pub async fn submit(
        &self,
        principal: &VerifiedHumanPrincipal,
        request: MarketplaceCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
        expected_route: MarketplaceRouteKind,
    ) -> Result<MarketplaceActionReceipt, MarketplaceAuthorityError> {
        validate_command(
            principal,
            &request,
            request_digest,
            idempotency_key,
            expected_route,
        )?;
        let tenant = TenantId(request.tenant_id.to_string());
        if self
            .store
            .current_resource_version(&tenant, &request.resource_id)
            .await?
            != request.expected_resource_version
        {
            return Err(MarketplaceAuthorityError::StateConflict);
        }
        let envelope = canonical_marketplace_action(principal, &request, &self.config)?;
        let prepared = self
            .store
            .prepare_ingress(
                principal,
                &request,
                request_digest,
                idempotency_key,
                envelope,
            )
            .await?;
        if let Some(receipt) = prepared.receipt {
            return Ok(receipt);
        }
        let receipt = self
            .orchestrator
            .submit(&tenant, &prepared.envelope)
            .await?;
        self.store
            .complete_ingress(&tenant, idempotency_key, &receipt)
            .await
    }

    pub async fn ready(&self) -> bool {
        self.store.ready().await
    }

    pub async fn authoritative_page(
        &self,
        tenant: &TenantId,
        query: Option<&str>,
        after: Option<&str>,
        limit: i64,
    ) -> Result<AuthoritativePackPage, MarketplaceAuthorityError> {
        self.store
            .authoritative_page(tenant, query, after, limit)
            .await
    }
}

fn validate_command(
    principal: &VerifiedHumanPrincipal,
    request: &MarketplaceCommandRequest,
    request_digest: &str,
    idempotency_key: &str,
    expected_route: MarketplaceRouteKind,
) -> Result<(), MarketplaceAuthorityError> {
    if request.schema_version != MARKETPLACE_COMMAND_SCHEMA
        || request.tenant_id.to_string() != principal.tenant_id.0
        || request.command_id.is_nil()
        || !identifier(&request.resource_id, 256)
        || !principal.roles.contains(request.command.required_role())
        || request.command.route_kind() != expected_route
        || !digest(request_digest)
        || !valid_idempotency_key(idempotency_key)
        || request.requested_at > Utc::now() + Duration::minutes(5)
        || request.requested_at < Utc::now() - Duration::hours(24)
        || serde_json::to_vec(request).map_or(true, |value| value.len() > 1_048_576)
        || !command_shape(request)
    {
        return Err(MarketplaceAuthorityError::PrincipalDenied);
    }
    Ok(())
}

fn command_shape(request: &MarketplaceCommandRequest) -> bool {
    match &request.command {
        MarketplaceCommand::OnboardPublisher {
            publisher_id,
            publisher_subject,
            identity_digest,
            responsibility_contact,
            home_region,
        } => {
            request.resource_id == publisher_id.as_str()
                && identifier(publisher_id, 128)
                && identifier(publisher_subject, 256)
                && digest(identity_digest)
                && bounded_contact(responsibility_contact)
                && identifier(home_region, 128)
        }
        MarketplaceCommand::VerifyPublisherKey {
            publisher_id,
            key_id,
            algorithm,
            public_key,
            key_fingerprint,
            not_before,
            expires_at,
            review_digest,
        } => {
            request.resource_id == publisher_id.as_str()
                && identifier(publisher_id, 128)
                && identifier(key_id, 128)
                && algorithm == "Ed25519"
                && (40..=128).contains(&public_key.len())
                && digest(key_fingerprint)
                && digest(review_digest)
                && not_before < expires_at
                && *expires_at <= Utc::now() + Duration::days(730)
        }
        MarketplaceCommand::SetPublisherTrust {
            publisher_id,
            trust,
            reason_digest,
        } => {
            request.resource_id == publisher_id.as_str()
                && identifier(publisher_id, 128)
                && matches!(trust, PublisherTrust::Suspended | PublisherTrust::Revoked)
                && digest(reason_digest)
        }
        MarketplaceCommand::ConfigureTenantCatalog {
            control_plane_version,
            region,
            entitlements,
            allowed_compatibility,
            minimum_publisher_trust,
            ..
        } => {
            request.resource_id == "tenant-catalog"
                && semver(control_plane_version).is_some()
                && identifier(region, 128)
                && bounded_set(entitlements, 256, 256)
                && bounded_set(allowed_compatibility, 256, 256)
                && matches!(minimum_publisher_trust, PublisherTrust::Verified)
        }
        MarketplaceCommand::SubmitRelease {
            release_id,
            manifest,
            entitlement,
            allowed_regions,
            minimum_publisher_trust,
            minimum_control_plane_version,
            ..
        } => {
            request.resource_id == release_id.to_string()
                && !release_id.is_nil()
                && PackSdk::validate(manifest).is_ok()
                && identifier(entitlement, 128)
                && bounded_set(allowed_regions, 64, 128)
                && matches!(minimum_publisher_trust, PublisherTrust::Verified)
                && semver(minimum_control_plane_version).is_some()
                && immutable_artifact_refs(&manifest.artifact_refs)
        }
        MarketplaceCommand::ReviewRelease {
            release_id,
            review_digest,
            ..
        } => request.resource_id == release_id.to_string() && digest(review_digest),
        MarketplaceCommand::RequestInstallation {
            installation_id,
            release_id,
            environment,
            request_reason_digest,
        } => {
            request.resource_id == installation_id.to_string()
                && !installation_id.is_nil()
                && !release_id.is_nil()
                && matches!(
                    environment.as_str(),
                    "development" | "staging" | "canary" | "production"
                )
                && digest(request_reason_digest)
        }
        MarketplaceCommand::ApproveInstallation {
            installation_id,
            approval_digest,
            ..
        } => request.resource_id == installation_id.to_string() && digest(approval_digest),
        MarketplaceCommand::Install {
            installation_id,
            artifact_receipt_digest,
        } => request.resource_id == installation_id.to_string() && digest(artifact_receipt_digest),
        MarketplaceCommand::Activate {
            installation_id,
            production_certificate_digest,
        } => {
            request.resource_id == installation_id.to_string()
                && production_certificate_digest.as_deref().is_none_or(digest)
        }
        MarketplaceCommand::PlanUpgrade {
            plan_id,
            current_installation_id,
            target_installation_id,
            migration_digest,
            rollback_digest,
            canary_percent,
        } => {
            request.resource_id == plan_id.to_string()
                && !plan_id.is_nil()
                && current_installation_id != target_installation_id
                && digest(migration_digest)
                && digest(rollback_digest)
                && (1..=50).contains(canary_percent)
        }
        MarketplaceCommand::RecordCanary {
            plan_id,
            observed_samples,
            evidence_ref,
            evidence_digest,
            ..
        } => {
            request.resource_id == plan_id.to_string()
                && *observed_samples > 0
                && *observed_samples <= 10_000_000
                && evidence_ref.starts_with("urn:agenttrust:")
                && evidence_ref.len() <= 2048
                && digest(evidence_digest)
        }
        MarketplaceCommand::Upgrade {
            plan_id,
            production_certificate_digest,
        } => {
            request.resource_id == plan_id.to_string()
                && production_certificate_digest.as_deref().is_none_or(digest)
        }
        MarketplaceCommand::Rollback {
            installation_id,
            reason_digest,
        }
        | MarketplaceCommand::Deactivate {
            installation_id,
            reason_digest,
        } => request.resource_id == installation_id.to_string() && digest(reason_digest),
        MarketplaceCommand::RevokeRelease {
            release_id,
            reason_code,
            reason_digest,
            ..
        } => {
            request.resource_id == release_id.to_string()
                && identifier(reason_code, 128)
                && digest(reason_digest)
        }
    }
}

fn canonical_marketplace_action(
    principal: &VerifiedHumanPrincipal,
    request: &MarketplaceCommandRequest,
    config: &MarketplaceAuthorityConfig,
) -> Result<InboundEnvelope, MarketplaceAuthorityError> {
    let now = Utc::now();
    let tenant = TenantId(request.tenant_id.to_string());
    let task_id = TaskId::new();
    let executor = MarketplaceExecutorRequest {
        schema_version: MARKETPLACE_EXECUTOR_REQUEST_SCHEMA.into(),
        command: request.clone(),
        principal_subject: principal.subject.clone(),
        principal_assertion_digest: principal.assertion_digest.clone(),
        approval_ids: principal.approval_ids.clone(),
    };
    let data = serde_json::to_value(&executor)
        .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?
        .as_object()
        .cloned()
        .ok_or(MarketplaceAuthorityError::RequestInvalid)?;
    let plan_hash = canonical_digest(&json!({
        "operation": request.command.operation(),
        "resource_id": request.resource_id,
        "resource_version": request.expected_resource_version,
        "command": request.command,
    }))?;
    let mut extensions = BTreeMap::new();
    extensions.insert("x-plan-hash".into(), Value::String(plan_hash));
    extensions.insert(
        "x-human-principal-assertion-digest".into(),
        Value::String(principal.assertion_digest.clone()),
    );
    let operation = request.command.operation().to_ascii_lowercase();
    let locator = format!("marketplace/{}", request.resource_id);
    let draft = ActionDraft {
        schema_version: SchemaVersion(agent_trust_action_ir::ACTION_SCHEMA_VERSION.into()),
        action_id: ActionId(request.command_id.to_string()),
        task_id: task_id.clone(),
        step_id: StepId::new(),
        agent: AgentIdentity {
            schema_version: SchemaVersion(CONTRACT_SCHEMA_VERSION.into()),
            agent_type: "pack-marketplace-authority".into(),
            agent_instance_id: config.service_agent_id.clone(),
            organization_id: config.organization_id.clone(),
            tenant_id: tenant.clone(),
            owner_subject: principal.subject.clone(),
            model_provider: "none".into(),
            model_id: "deterministic-pack-lifecycle".into(),
            agent_version: config.agent_version.clone(),
            deployment_environment: "production".into(),
            trust_level: "attested".into(),
            auth_context_ref: format!("human-assertion://{}", principal.jti),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        },
        intent: Intent {
            goal_hash: canonical_digest(request)?,
            operation: operation.clone(),
            justification_code: "PACK_LIFECYCLE_GOVERNANCE".into(),
            safe_summary: Some(format!("{} pack resource", request.command.operation())),
        },
        tool: ToolRef {
            tool_id: config.tool_id.clone(),
            tool_version: config.tool_version.clone(),
        },
        payload: TypedPayload {
            type_id: "marketplace.lifecycle.mutation.v1".into(),
            schema_version: "1".into(),
            data,
        },
        resource: ResourceSelector {
            scheme: "database".into(),
            tenant_id: tenant.clone(),
            locator,
            version: None,
        },
        environment: ExecutionEnvironment {
            tenant_id: tenant.clone(),
            deployment: "production".into(),
            region: config.region.clone(),
            zone: None,
            simulation: false,
        },
        current_state_version: Some(request.expected_resource_version.to_string()),
        risk: RiskContext {
            declared_risk: request.command.action_risk(),
            trajectory_risk_ref: None,
            scope_delta: 1,
            automation_allowed: false,
        },
        data: DataContext {
            classification: DataClassification::Confidential,
            jurisdiction: config.region.clone(),
            export_constraints: vec!["TENANT_BOUND".into(), "PACK_METADATA_ONLY".into()],
        },
        expected_outcome: ExpectedOutcome {
            metric: "marketplace_resource_version_persisted".into(),
            operator: "eq".into(),
            target: Value::Bool(true),
        },
        credential_refs: vec![CredentialRef {
            profile: config.credential_profile.clone(),
            resource_prefix: "marketplace/".into(),
            operations: vec![operation],
        }],
        requested_at: request.requested_at,
        extensions,
    };
    let mut normalization = NormalizationContext::default();
    normalization
        .payload_types
        .register("marketplace.lifecycle.mutation.v1", "1");
    let action =
        normalize(draft, &normalization).map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
    action_hash(&action).map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
    let payload =
        serde_json::to_vec(&action).map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
    Ok(InboundEnvelope {
        request_id: Uuid::new_v4().to_string(),
        trace_context: TraceContext {
            trace_id: Uuid::new_v4().to_string(),
            parent_span_id: None,
            invalid_input_replaced: false,
        },
        identity_context: IdentityContext {
            subject: config.service_subject.clone(),
            tenant_id: tenant.clone(),
            agent_instance_id: config.service_agent_id.clone(),
            owner_subject: principal.subject.clone(),
            trust_level: "attested".into(),
        },
        tenant_context: TenantContext {
            tenant_id: tenant,
            quota_profile: "pack-marketplace".into(),
        },
        protocol: IngressProtocol::Http,
        content_type: "application/json".into(),
        schema_version: GATEWAY_SCHEMA_VERSION.into(),
        idempotency_key: None,
        received_at: now,
        payload_hash: hex::encode(Sha256::digest(&payload)),
        payload,
    })
}

#[derive(Clone)]
pub struct PostgresMarketplaceAuthorityStore {
    pool: PgPool,
}

impl PostgresMarketplaceAuthorityStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT current_setting('transaction_read_only')='off' \
                    AND count(*)=15 \
                    AND bool_and(c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity) \
                    AND (SELECT count(*)=15 FROM pg_catalog.pg_policies p \
                         WHERE p.schemaname='public' AND p.policyname='tenant_isolation' \
                           AND p.tablename=ANY(ARRAY[\
                            'marketplace_publishers','marketplace_publisher_keys','marketplace_pack_names',\
                            'marketplace_tenant_catalog','marketplace_releases','marketplace_installations',\
                            'marketplace_upgrade_plans','marketplace_canary_results','marketplace_revocations',\
                            'marketplace_resource_versions','marketplace_principal_assertion_replay',\
                            'marketplace_action_ingress','marketplace_authority_executions',\
                            'marketplace_evidence_events','marketplace_evidence_outbox'])) \
             FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace \
             WHERE n.nspname='public' AND c.relname=ANY(ARRAY[\
              'marketplace_publishers','marketplace_publisher_keys','marketplace_pack_names',\
              'marketplace_tenant_catalog','marketplace_releases','marketplace_installations',\
              'marketplace_upgrade_plans','marketplace_canary_results','marketplace_revocations',\
              'marketplace_resource_versions','marketplace_principal_assertion_replay',\
              'marketplace_action_ingress','marketplace_authority_executions',\
              'marketplace_evidence_events','marketplace_evidence_outbox'])",
        )
            .fetch_one(&self.pool)
            .await
            .is_ok_and(|ready| ready)
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, MarketplaceAuthorityError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(parse_tenant(tenant)?.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        Ok(tx)
    }

    pub async fn current_resource_version(
        &self,
        tenant: &TenantId,
        resource_id: &str,
    ) -> Result<u64, MarketplaceAuthorityError> {
        let mut tx = self.begin_tenant(tenant).await?;
        let value = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM marketplace_resource_versions \
             WHERE tenant_id=$1 AND resource_id=$2",
        )
        .bind(parse_tenant(tenant)?)
        .bind(resource_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        tx.commit()
            .await
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        u64::try_from(value).map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)
    }

    pub async fn prepare_ingress(
        &self,
        principal: &VerifiedHumanPrincipal,
        request: &MarketplaceCommandRequest,
        request_digest: &str,
        idempotency_key: &str,
        mut envelope: InboundEnvelope,
    ) -> Result<PreparedMarketplaceIngress, MarketplaceAuthorityError> {
        envelope.idempotency_key = Some(idempotency_key.to_string());
        let tenant = TenantId(request.tenant_id.to_string());
        let action: agent_trust_action_ir::CanonicalAction =
            serde_json::from_slice(&envelope.payload)
                .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
        let envelope_value = serde_json::to_value(&envelope)
            .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
        let mut tx = self.begin_tenant(&tenant).await?;
        sqlx::query(
            "INSERT INTO marketplace_principal_assertion_replay \
             (tenant_id,jti,assertion_digest,request_digest,expires_at) VALUES ($1,$2,$3,$4,$5) \
             ON CONFLICT (tenant_id,jti) DO NOTHING",
        )
        .bind(request.tenant_id)
        .bind(
            Uuid::parse_str(&principal.jti)
                .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?,
        )
        .bind(&principal.assertion_digest)
        .bind(request_digest)
        .bind(principal.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        let replay = sqlx::query(
            "SELECT assertion_digest,request_digest FROM marketplace_principal_assertion_replay \
             WHERE tenant_id=$1 AND jti=$2 FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(
            Uuid::parse_str(&principal.jti)
                .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        if replay.get::<String, _>("assertion_digest") != principal.assertion_digest
            || replay.get::<String, _>("request_digest") != request_digest
        {
            return Err(MarketplaceAuthorityError::IdempotencyConflict);
        }
        sqlx::query(
            "INSERT INTO marketplace_action_ingress \
             (tenant_id,idempotency_key,request_digest,action_id,task_id,resource_id,principal_subject,\
              principal_assertion_digest,envelope,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'PREPARED') \
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
        )
        .bind(request.tenant_id)
        .bind(idempotency_key)
        .bind(request_digest)
        .bind(Uuid::parse_str(&action.action_id.0).map_err(|_| MarketplaceAuthorityError::RequestInvalid)?)
        .bind(Uuid::parse_str(&action.task_id.0).map_err(|_| MarketplaceAuthorityError::RequestInvalid)?)
        .bind(&request.resource_id)
        .bind(&principal.subject)
        .bind(&principal.assertion_digest)
        .bind(&envelope_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        let row = sqlx::query(
            "SELECT request_digest,envelope,receipt FROM marketplace_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        if row.get::<String, _>("request_digest") != request_digest
            || row.get::<Value, _>("envelope") != envelope_value
        {
            return Err(MarketplaceAuthorityError::IdempotencyConflict);
        }
        let receipt = row
            .get::<Option<Value>, _>("receipt")
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        Ok(PreparedMarketplaceIngress { envelope, receipt })
    }

    pub async fn complete_ingress(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        receipt: &MarketplaceActionReceipt,
    ) -> Result<MarketplaceActionReceipt, MarketplaceAuthorityError> {
        if receipt.schema_version != MARKETPLACE_ACTION_RECEIPT_SCHEMA
            || !receipt.accepted
            || !receipt.execution_pending
            || !digest(&receipt.ingress_digest)
            || !digest(&receipt.ledger_evidence_digest)
            || !safe_reference(&receipt.ledger_evidence_ref)
        {
            return Err(MarketplaceAuthorityError::DependencyUnavailable);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let value = serde_json::to_value(receipt)
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT action_id,task_id,receipt FROM marketplace_action_ingress \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?;
        if row.get::<Uuid, _>("action_id").to_string() != receipt.action_id
            || row.get::<Uuid, _>("task_id").to_string() != receipt.task_id
        {
            return Err(MarketplaceAuthorityError::DependencyUnavailable);
        }
        if let Some(existing) = row.get::<Option<Value>, _>("receipt") {
            if existing != value {
                return Err(MarketplaceAuthorityError::IdempotencyConflict);
            }
        } else {
            let updated = sqlx::query(
                "UPDATE marketplace_action_ingress SET state='ACCEPTED',receipt=$3,updated_at=now() \
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
            )
            .bind(tenant_uuid)
            .bind(idempotency_key)
            .bind(&value)
            .execute(&mut *tx)
            .await
            .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?
            .rows_affected();
            if updated != 1 {
                return Err(MarketplaceAuthorityError::OutcomeUnknown);
            }
        }
        tx.commit()
            .await
            .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?;
        Ok(receipt.clone())
    }

    pub async fn authoritative_page(
        &self,
        tenant: &TenantId,
        query: Option<&str>,
        after: Option<&str>,
        limit: i64,
    ) -> Result<AuthoritativePackPage, MarketplaceAuthorityError> {
        if !(1..=200).contains(&limit)
            || query.is_some_and(|value| value.len() > 128 || value.chars().any(char::is_control))
            || after.is_some_and(|value| !identifier(value, 128))
        {
            return Err(MarketplaceAuthorityError::RequestInvalid);
        }
        let tenant_uuid = parse_tenant(tenant)?;
        let mut tx = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT release_id,pack_id,version,pack_digest,publisher_id,visibility,entitlement,\
                    allowed_regions,risk_rating,manifest->'compatibility' AS compatibility,\
                    certificate_digest,review_status,updated_at \
             FROM marketplace_releases WHERE tenant_id=$1 AND pack_id > COALESCE($2,'') \
               AND ($3::text IS NULL OR pack_id ILIKE '%' || $3 || '%') \
             ORDER BY pack_id,version LIMIT $4",
        )
        .bind(tenant_uuid)
        .bind(after)
        .bind(query)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        let mut releases = rows
            .iter()
            .take(limit as usize)
            .map(|row| AuthoritativePackItem {
                release_id: row.get("release_id"),
                pack_id: row.get("pack_id"),
                version: row.get("version"),
                pack_digest: row.get("pack_digest"),
                publisher_id: row.get("publisher_id"),
                visibility: row.get("visibility"),
                entitlement: row.get("entitlement"),
                allowed_regions: row.get("allowed_regions"),
                risk_rating: row.get("risk_rating"),
                compatibility: serde_json::from_value(row.get("compatibility")).unwrap_or_default(),
                certificate_digest: row.get("certificate_digest"),
                review_status: row.get("review_status"),
                updated_at: row.get("updated_at"),
            })
            .collect::<Vec<_>>();
        let installation_rows = sqlx::query(
            "SELECT installation_id,release_id,pack_id,version,environment,state,\
                    permission_expansion,previous_installation_id,updated_at \
             FROM marketplace_installations WHERE tenant_id=$1 \
             ORDER BY updated_at DESC LIMIT $2",
        )
        .bind(tenant_uuid)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        let installations = installation_rows
            .into_iter()
            .map(|row| AuthoritativeInstallationItem {
                installation_id: row.get("installation_id"),
                release_id: row.get("release_id"),
                pack_id: row.get("pack_id"),
                version: row.get("version"),
                environment: row.get("environment"),
                state: row.get("state"),
                permission_expansion: row.get("permission_expansion"),
                previous_installation_id: row.get("previous_installation_id"),
                updated_at: row.get("updated_at"),
            })
            .collect::<Vec<_>>();
        let next_after_pack_id = (rows.len() > limit as usize)
            .then(|| releases.last().map(|item| item.pack_id.clone()))
            .flatten();
        let material = json!({
            "schema_version": AUTHORITATIVE_PACK_PAGE_SCHEMA,
            "authoritative": true,
            "tenant_id": tenant,
            "releases": releases,
            "installations": installations,
            "next_after_pack_id": next_after_pack_id,
        });
        let data_digest = canonical_digest(&material)?;
        tx.commit()
            .await
            .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        Ok(AuthoritativePackPage {
            schema_version: AUTHORITATIVE_PACK_PAGE_SCHEMA.into(),
            authoritative: true,
            tenant_id: tenant.clone(),
            releases: std::mem::take(&mut releases),
            installations,
            next_after_pack_id,
            data_digest,
        })
    }
}

#[derive(Clone)]
pub struct MarketplaceExecutor {
    store: PostgresMarketplaceAuthorityStore,
    release_gate_keyring: Arc<ReleaseGateKeyring>,
}

impl MarketplaceExecutor {
    pub fn new(
        store: PostgresMarketplaceAuthorityStore,
        release_gate_keyring: Arc<ReleaseGateKeyring>,
    ) -> Self {
        Self {
            store,
            release_gate_keyring,
        }
    }

    pub async fn execute(
        &self,
        binding: MarketplaceExecutionBinding,
        request: MarketplaceExecutorRequest,
    ) -> Result<MarketplaceMutationResult, MarketplaceAuthorityError> {
        validate_execution(&binding, &request)?;
        let tenant_uuid = parse_tenant(&binding.tenant_id)?;
        let request_digest = canonical_digest(&request)?;
        let request_value = serde_json::to_value(&request)
            .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
        let mut tx = self.store.begin_tenant(&binding.tenant_id).await?;

        let ingress = sqlx::query(
            "SELECT state,principal_subject,principal_assertion_digest FROM marketplace_action_ingress \
             WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(request.command.command_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
        .ok_or(MarketplaceAuthorityError::PrincipalDenied)?;
        if ingress.get::<String, _>("state") != "ACCEPTED"
            || ingress.get::<String, _>("principal_subject") != request.principal_subject
            || ingress.get::<String, _>("principal_assertion_digest")
                != request.principal_assertion_digest
        {
            return Err(MarketplaceAuthorityError::PrincipalDenied);
        }

        sqlx::query(
            "INSERT INTO marketplace_authority_executions \
             (tenant_id,idempotency_key,request_digest,action_id,action_hash,policy_decision_id,\
              policy_decision_digest,ledger_entry_id,ledger_entry_digest,ledger_execution_id,\
              fence_digest,resource_id,resource_version,authorization_evidence_ref,authorization_evidence_digest,trace_id,request,state) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'PREPARED') \
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .bind(&request_digest)
        .bind(request.command.command_id)
        .bind(&binding.action_hash)
        .bind(&binding.policy_decision_id)
        .bind(&binding.policy_decision_digest)
        .bind(&binding.ledger_entry_id)
        .bind(&binding.ledger_entry_digest)
        .bind(binding.ledger_execution_id)
        .bind(&binding.fence_digest)
        .bind(&request.command.resource_id)
        .bind(i64::try_from(binding.resource_version).map_err(|_| MarketplaceAuthorityError::RequestInvalid)?)
        .bind(&binding.authorization_evidence_ref)
        .bind(&binding.authorization_evidence_digest)
        .bind(&binding.trace_id)
        .bind(&request_value)
        .execute(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::IdempotencyConflict)?;
        let existing = sqlx::query(
            "SELECT request_digest,action_hash,policy_decision_id,policy_decision_digest,\
                    ledger_entry_id,ledger_entry_digest,ledger_execution_id,fence_digest,\
                    resource_id,resource_version,authorization_evidence_ref,authorization_evidence_digest,request,state,safe_result \
             FROM marketplace_authority_executions \
             WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
        if existing.get::<String, _>("request_digest") != request_digest
            || existing.get::<String, _>("action_hash") != binding.action_hash
            || existing.get::<String, _>("policy_decision_id") != binding.policy_decision_id
            || existing.get::<String, _>("policy_decision_digest") != binding.policy_decision_digest
            || existing.get::<String, _>("ledger_entry_id") != binding.ledger_entry_id
            || existing.get::<String, _>("ledger_entry_digest") != binding.ledger_entry_digest
            || existing.get::<Uuid, _>("ledger_execution_id") != binding.ledger_execution_id
            || existing.get::<String, _>("fence_digest") != binding.fence_digest
            || existing.get::<String, _>("resource_id") != request.command.resource_id
            || existing.get::<i64, _>("resource_version")
                != i64::try_from(binding.resource_version)
                    .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?
            || existing.get::<String, _>("authorization_evidence_ref")
                != binding.authorization_evidence_ref
            || existing.get::<String, _>("authorization_evidence_digest")
                != binding.authorization_evidence_digest
            || existing.get::<Value, _>("request") != request_value
        {
            return Err(MarketplaceAuthorityError::IdempotencyConflict);
        }
        if existing.get::<String, _>("state") == "SUCCEEDED" {
            let result = serde_json::from_value(
                existing
                    .get::<Option<Value>, _>("safe_result")
                    .ok_or(MarketplaceAuthorityError::OutcomeUnknown)?,
            )
            .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?;
            tx.commit()
                .await
                .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?;
            return Ok(result);
        }
        if existing.get::<String, _>("state") != "PREPARED" {
            return Err(MarketplaceAuthorityError::OutcomeUnknown);
        }
        let transitioned = sqlx::query(
            "UPDATE marketplace_authority_executions SET state='EXECUTING',updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='PREPARED'",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .execute(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?
        .rows_affected();
        if transitioned != 1 {
            return Err(MarketplaceAuthorityError::OutcomeUnknown);
        }

        let current = sqlx::query_scalar::<_, i64>(
            "SELECT resource_version FROM marketplace_resource_versions \
             WHERE tenant_id=$1 AND resource_id=$2 FOR UPDATE",
        )
        .bind(tenant_uuid)
        .bind(&request.command.resource_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
        .unwrap_or(0);
        if current
            != i64::try_from(request.command.expected_resource_version)
                .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?
            || binding.resource_version != request.command.expected_resource_version
        {
            return Err(MarketplaceAuthorityError::StateConflict);
        }
        let (state, artifact_digest) = self.apply_operation(&mut tx, tenant_uuid, &request).await?;
        let next_version = current
            .checked_add(1)
            .ok_or(MarketplaceAuthorityError::StateConflict)?;
        sqlx::query(
            "INSERT INTO marketplace_resource_versions \
             (tenant_id,resource_id,resource_version,action_hash,policy_decision_id,ledger_entry_id,\
              ledger_execution_id,fence_digest) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
             ON CONFLICT (tenant_id,resource_id) DO UPDATE SET \
             resource_version=EXCLUDED.resource_version,action_hash=EXCLUDED.action_hash,\
             policy_decision_id=EXCLUDED.policy_decision_id,ledger_entry_id=EXCLUDED.ledger_entry_id,\
             ledger_execution_id=EXCLUDED.ledger_execution_id,fence_digest=EXCLUDED.fence_digest,\
             updated_at=now()",
        )
        .bind(tenant_uuid)
        .bind(&request.command.resource_id)
        .bind(next_version)
        .bind(&binding.action_hash)
        .bind(&binding.policy_decision_id)
        .bind(&binding.ledger_entry_id)
        .bind(binding.ledger_execution_id)
        .bind(&binding.fence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?;

        let event_id = Uuid::new_v4();
        let evidence_payload = json!({
            "schema_version": "agenttrust.marketplace-lifecycle-evidence.v1",
            "event_id": event_id,
            "tenant_id": tenant_uuid,
            "resource_id": request.command.resource_id,
            "command_id": request.command.command_id,
            "operation": request.command.command.operation(),
            "principal_subject": request.principal_subject,
            "principal_assertion_digest": request.principal_assertion_digest,
            "action_hash": binding.action_hash,
            "policy_decision_id": binding.policy_decision_id,
            "policy_decision_digest": binding.policy_decision_digest,
            "ledger_entry_id": binding.ledger_entry_id,
            "ledger_entry_digest": binding.ledger_entry_digest,
            "ledger_execution_id": binding.ledger_execution_id,
            "fence_digest": binding.fence_digest,
            "authorization_evidence_ref": binding.authorization_evidence_ref,
            "authorization_evidence_digest": binding.authorization_evidence_digest,
            "resource_version": next_version,
            "artifact_digest": artifact_digest,
            "state": state,
            "trace_id": binding.trace_id,
            "recorded_at": Utc::now(),
        });
        let evidence_digest = canonical_digest(&evidence_payload)?;
        let evidence_ref = format!(
            "urn:agenttrust:marketplace-evidence:{}:{}:sha256:{}",
            tenant_uuid, event_id, evidence_digest
        );
        sqlx::query(
            "INSERT INTO marketplace_evidence_events \
             (tenant_id,event_id,resource_id,event_type,actor_subject,payload,payload_digest,evidence_ref) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(tenant_uuid)
        .bind(event_id)
        .bind(&request.command.resource_id)
        .bind(format!("MARKETPLACE_{}", request.command.command.operation()))
        .bind(&request.principal_subject)
        .bind(&evidence_payload)
        .bind(&evidence_digest)
        .bind(&evidence_ref)
        .execute(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?;
        sqlx::query(
            "INSERT INTO marketplace_evidence_outbox \
             (tenant_id,event_id,event_type,aggregate_id,payload,payload_digest) \
             VALUES ($1,$2,'MARKETPLACE_LIFECYCLE_EVIDENCE',$3,$4,$5)",
        )
        .bind(tenant_uuid)
        .bind(event_id)
        .bind(&request.command.resource_id)
        .bind(&evidence_payload)
        .bind(&evidence_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?;
        let result = MarketplaceMutationResult {
            schema_version: MARKETPLACE_MUTATION_RESULT_SCHEMA.into(),
            command_id: request.command.command_id,
            resource_id: request.command.resource_id.clone(),
            operation: request.command.command.operation().into(),
            resource_version: u64::try_from(next_version)
                .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?,
            state,
            artifact_digest,
            evidence_ref,
        };
        let result_value =
            serde_json::to_value(&result).map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?;
        let result_digest = canonical_digest(&result)?;
        let completed = sqlx::query(
            "UPDATE marketplace_authority_executions SET state='SUCCEEDED',safe_result=$3,\
             safe_result_digest=$4,updated_at=now() \
             WHERE tenant_id=$1 AND idempotency_key=$2 AND state='EXECUTING'",
        )
        .bind(tenant_uuid)
        .bind(&binding.idempotency_key)
        .bind(&result_value)
        .bind(&result_digest)
        .execute(&mut *tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?
        .rows_affected();
        if completed != 1 {
            return Err(MarketplaceAuthorityError::OutcomeUnknown);
        }
        tx.commit()
            .await
            .map_err(|_| MarketplaceAuthorityError::OutcomeUnknown)?;
        Ok(result)
    }

    async fn apply_operation(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        request: &MarketplaceExecutorRequest,
    ) -> Result<(String, String), MarketplaceAuthorityError> {
        match &request.command.command {
            MarketplaceCommand::OnboardPublisher { .. } => {
                onboard_publisher(tx, tenant, request).await
            }
            MarketplaceCommand::VerifyPublisherKey { .. } => {
                verify_publisher_key(tx, tenant, request).await
            }
            MarketplaceCommand::SetPublisherTrust { .. } => {
                set_publisher_trust(tx, tenant, request).await
            }
            MarketplaceCommand::ConfigureTenantCatalog { .. } => {
                configure_catalog(tx, tenant, request).await
            }
            MarketplaceCommand::SubmitRelease { .. } => {
                submit_release(tx, tenant, request, &self.release_gate_keyring).await
            }
            MarketplaceCommand::ReviewRelease { .. } => review_release(tx, tenant, request).await,
            MarketplaceCommand::RequestInstallation { .. } => {
                request_installation(tx, tenant, request).await
            }
            MarketplaceCommand::ApproveInstallation { .. } => {
                approve_installation(tx, tenant, request).await
            }
            MarketplaceCommand::Install { .. } => install_pack(tx, tenant, request).await,
            MarketplaceCommand::Activate { .. } => activate_pack(tx, tenant, request).await,
            MarketplaceCommand::PlanUpgrade { .. } => plan_upgrade(tx, tenant, request).await,
            MarketplaceCommand::RecordCanary { .. } => record_canary(tx, tenant, request).await,
            MarketplaceCommand::Upgrade { .. } => upgrade_pack(tx, tenant, request).await,
            MarketplaceCommand::Rollback { .. } => rollback_pack(tx, tenant, request).await,
            MarketplaceCommand::Deactivate { .. } => deactivate_pack(tx, tenant, request).await,
            MarketplaceCommand::RevokeRelease { .. } => revoke_release(tx, tenant, request).await,
        }
    }
}

async fn onboard_publisher(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::OnboardPublisher {
        publisher_id,
        publisher_subject,
        identity_digest,
        responsibility_contact,
        home_region,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    if publisher_subject == &request.principal_subject {
        return Err(MarketplaceAuthorityError::ReviewSeparationRequired);
    }
    sqlx::query(
        "INSERT INTO marketplace_publishers \
         (tenant_id,publisher_id,owner_subject,identity_digest,responsibility_contact,home_region,trust_status) \
         VALUES ($1,$2,$3,$4,$5,$6,'UNTRUSTED')",
    )
    .bind(tenant)
    .bind(publisher_id)
    .bind(publisher_subject)
    .bind(identity_digest)
    .bind(responsibility_contact)
    .bind(home_region)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok(("UNTRUSTED".into(), identity_digest.clone()))
}

async fn verify_publisher_key(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::VerifyPublisherKey {
        publisher_id,
        key_id,
        public_key,
        key_fingerprint,
        not_before,
        expires_at,
        review_digest,
        ..
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let publisher = sqlx::query(
        "SELECT owner_subject,trust_status FROM marketplace_publishers \
         WHERE tenant_id=$1 AND publisher_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(publisher_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::NotFound)?;
    if publisher.get::<String, _>("owner_subject") == request.principal_subject
        || publisher.get::<String, _>("trust_status") == "REVOKED"
    {
        return Err(MarketplaceAuthorityError::ReviewSeparationRequired);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(public_key)
        .map_err(|_| MarketplaceAuthorityError::SignatureInvalid)?;
    let bytes: [u8; 32] = raw
        .clone()
        .try_into()
        .map_err(|_| MarketplaceAuthorityError::SignatureInvalid)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| MarketplaceAuthorityError::SignatureInvalid)?;
    if hex::encode(Sha256::digest(&raw)) != key_fingerprint.as_str() {
        return Err(MarketplaceAuthorityError::SignatureInvalid);
    }
    sqlx::query(
        "INSERT INTO marketplace_publisher_keys \
         (tenant_id,publisher_id,key_id,algorithm,public_key,key_fingerprint,status,not_before,expires_at,reviewed_by,review_digest) \
         VALUES ($1,$2,$3,'Ed25519',$4,$5,'ACTIVE',$6,$7,$8,$9)",
    )
    .bind(tenant)
    .bind(publisher_id)
    .bind(key_id)
    .bind(raw)
    .bind(key_fingerprint)
    .bind(not_before)
    .bind(expires_at)
    .bind(&request.principal_subject)
    .bind(review_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    sqlx::query(
        "UPDATE marketplace_publishers SET trust_status='VERIFIED',verified_by=$3,verified_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND publisher_id=$2 AND trust_status IN ('UNTRUSTED','SUSPENDED')",
    )
    .bind(tenant)
    .bind(publisher_id)
    .bind(&request.principal_subject)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok(("VERIFIED".into(), key_fingerprint.clone()))
}

async fn set_publisher_trust(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::SetPublisherTrust {
        publisher_id,
        trust,
        reason_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let state = match trust {
        PublisherTrust::Suspended => "SUSPENDED",
        PublisherTrust::Revoked => "REVOKED",
        _ => return Err(MarketplaceAuthorityError::RequestInvalid),
    };
    let changed = sqlx::query(
        "UPDATE marketplace_publishers SET trust_status=$3,revoked_at=CASE WHEN $3='REVOKED' THEN now() ELSE NULL END,updated_at=now() \
         WHERE tenant_id=$1 AND publisher_id=$2 AND trust_status <> 'REVOKED' AND trust_status <> $3",
    )
    .bind(tenant)
    .bind(publisher_id)
    .bind(state)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?
    .rows_affected();
    if changed != 1 {
        return Err(MarketplaceAuthorityError::NotFound);
    }
    if state == "REVOKED" {
        sqlx::query(
            "UPDATE marketplace_publisher_keys SET status='REVOKED',revoked_at=now() \
             WHERE tenant_id=$1 AND publisher_id=$2 AND status IN ('ACTIVE','VERIFY_ONLY')",
        )
        .bind(tenant)
        .bind(publisher_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
        sqlx::query(
            "UPDATE marketplace_releases SET review_status='REVOKED',revoked_at=now(),updated_at=now() \
             WHERE tenant_id=$1 AND publisher_id=$2 AND review_status IN ('SUBMITTED','PUBLISHED')",
        )
        .bind(tenant)
        .bind(publisher_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
        sqlx::query(
            "UPDATE marketplace_installations i SET state='REVOKED',revoked_at=now(),updated_at=now() \
             FROM marketplace_releases r WHERE i.tenant_id=$1 AND r.tenant_id=i.tenant_id \
             AND r.release_id=i.release_id AND r.publisher_id=$2 \
             AND i.state IN ('PENDING_APPROVAL','APPROVED','INSTALLED','ACTIVE','INACTIVE')",
        )
        .bind(tenant)
        .bind(publisher_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    }
    Ok((state.into(), reason_digest.clone()))
}

async fn configure_catalog(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::ConfigureTenantCatalog {
        control_plane_version,
        region,
        entitlements,
        allowed_compatibility,
        minimum_publisher_trust,
        maximum_risk,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let entitlements = entitlements.iter().cloned().collect::<Vec<_>>();
    let compatibility = allowed_compatibility.iter().cloned().collect::<Vec<_>>();
    let trust = publisher_trust_string(*minimum_publisher_trust)?;
    sqlx::query(
        "INSERT INTO marketplace_tenant_catalog \
         (tenant_id,control_plane_version,region,entitlements,allowed_compatibility,minimum_publisher_trust,maximum_risk,configured_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id) DO UPDATE SET \
         control_plane_version=EXCLUDED.control_plane_version,region=EXCLUDED.region,\
         entitlements=EXCLUDED.entitlements,allowed_compatibility=EXCLUDED.allowed_compatibility,\
         minimum_publisher_trust=EXCLUDED.minimum_publisher_trust,maximum_risk=EXCLUDED.maximum_risk,\
         configured_by=EXCLUDED.configured_by,updated_at=now()",
    )
    .bind(tenant)
    .bind(control_plane_version)
    .bind(region)
    .bind(&entitlements)
    .bind(&compatibility)
    .bind(trust)
    .bind(maximum_risk.as_str())
    .bind(&request.principal_subject)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    let artifact = canonical_digest(&json!({
        "control_plane_version": control_plane_version,
        "region": region,
        "entitlements": entitlements,
        "allowed_compatibility": compatibility,
        "minimum_publisher_trust": trust,
        "maximum_risk": maximum_risk,
    }))?;
    Ok(("CONFIGURED".into(), artifact))
}

async fn submit_release(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
    release_gate_keyring: &ReleaseGateKeyring,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::SubmitRelease {
        release_id,
        manifest,
        release_certificate,
        visibility,
        entitlement,
        allowed_regions,
        risk_rating,
        minimum_publisher_trust,
        minimum_control_plane_version,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let publisher = sqlx::query(
        "SELECT owner_subject,trust_status FROM marketplace_publishers \
         WHERE tenant_id=$1 AND publisher_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(&manifest.publisher_identity)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::TrustDenied)?;
    if publisher.get::<String, _>("owner_subject") != request.principal_subject
        || publisher.get::<String, _>("trust_status") != "VERIFIED"
    {
        return Err(MarketplaceAuthorityError::TrustDenied);
    }
    let key = sqlx::query(
        "SELECT public_key FROM marketplace_publisher_keys WHERE tenant_id=$1 AND publisher_id=$2 \
         AND key_id=$3 AND status='ACTIVE' AND not_before <= now() AND expires_at > now() FOR UPDATE",
    )
    .bind(tenant)
    .bind(&manifest.publisher_identity)
    .bind(&manifest.signature.key_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::SignatureInvalid)?;
    let public_key: Vec<u8> = key.get("public_key");
    let bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| MarketplaceAuthorityError::SignatureInvalid)?;
    let verifying_key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| MarketplaceAuthorityError::SignatureInvalid)?;
    let verifier = ArtifactVerifier::default();
    verifier.authorize_publisher(
        manifest.signature.key_id.clone(),
        manifest.publisher_identity.clone(),
        verifying_key,
    );
    verifier
        .verify_pack(manifest)
        .map_err(|_| MarketplaceAuthorityError::SignatureInvalid)?;
    let certificate_digest =
        release_gate_keyring.verify(release_certificate, &manifest.digest, Utc::now())?;
    let permission_digest = canonical_digest(&manifest.permissions)?;
    let manifest_value =
        serde_json::to_value(manifest).map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
    let certificate_value = serde_json::to_value(release_certificate)
        .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
    let regions = allowed_regions.iter().cloned().collect::<Vec<_>>();
    let trust = publisher_trust_string(*minimum_publisher_trust)?;
    sqlx::query(
        "INSERT INTO marketplace_pack_names (tenant_id,pack_id,publisher_id) \
         VALUES ($1,$2,$3) ON CONFLICT (tenant_id,pack_id) DO NOTHING",
    )
    .bind(tenant)
    .bind(&manifest.pack_id)
    .bind(&manifest.publisher_identity)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    let namespace_owner = sqlx::query_scalar::<_, String>(
        "SELECT publisher_id FROM marketplace_pack_names WHERE tenant_id=$1 AND pack_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(&manifest.pack_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
    if namespace_owner != manifest.publisher_identity {
        return Err(MarketplaceAuthorityError::StateConflict);
    }
    sqlx::query(
        "INSERT INTO marketplace_releases \
         (tenant_id,release_id,pack_id,version,publisher_id,manifest,pack_digest,permission_digest,\
          release_certificate,certificate_digest,visibility,entitlement,allowed_regions,risk_rating,\
          minimum_publisher_trust,minimum_control_plane_version,review_status,submitted_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'SUBMITTED',$17)",
    )
    .bind(tenant)
    .bind(release_id)
    .bind(&manifest.pack_id)
    .bind(&manifest.version)
    .bind(&manifest.publisher_identity)
    .bind(&manifest_value)
    .bind(&manifest.digest)
    .bind(&permission_digest)
    .bind(&certificate_value)
    .bind(&certificate_digest)
    .bind(visibility.as_str())
    .bind(entitlement)
    .bind(&regions)
    .bind(risk_rating.as_str())
    .bind(trust)
    .bind(minimum_control_plane_version)
    .bind(&request.principal_subject)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok(("SUBMITTED".into(), manifest.digest.clone()))
}

async fn review_release(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::ReviewRelease {
        release_id,
        decision,
        review_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let row = sqlx::query(
        "SELECT r.pack_digest,p.owner_subject FROM marketplace_releases r \
         JOIN marketplace_publishers p ON p.tenant_id=r.tenant_id AND p.publisher_id=r.publisher_id \
         WHERE r.tenant_id=$1 AND r.release_id=$2 AND r.review_status='SUBMITTED' FOR UPDATE OF r,p",
    )
    .bind(tenant)
    .bind(release_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::NotFound)?;
    if row.get::<String, _>("owner_subject") == request.principal_subject {
        return Err(MarketplaceAuthorityError::ReviewSeparationRequired);
    }
    let state = match decision {
        ReviewDecision::Approve => "PUBLISHED",
        ReviewDecision::Reject => "REJECTED",
    };
    let updated = sqlx::query(
        "UPDATE marketplace_releases SET review_status=$3,reviewed_by=$4,review_digest=$5,\
         published_at=CASE WHEN $3='PUBLISHED' THEN now() ELSE NULL END,updated_at=now() \
         WHERE tenant_id=$1 AND release_id=$2 AND review_status='SUBMITTED'",
    )
    .bind(tenant)
    .bind(release_id)
    .bind(state)
    .bind(&request.principal_subject)
    .bind(review_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?
    .rows_affected();
    if updated != 1 {
        return Err(MarketplaceAuthorityError::StateConflict);
    }
    Ok((state.into(), row.get("pack_digest")))
}

async fn request_installation(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::RequestInstallation {
        installation_id,
        release_id,
        environment,
        request_reason_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let release = sqlx::query(
        "SELECT r.pack_id,r.version,r.pack_digest,r.permission_digest,r.manifest,r.entitlement,\
                r.allowed_regions,r.risk_rating,r.minimum_publisher_trust,r.minimum_control_plane_version,\
                p.trust_status FROM marketplace_releases r JOIN marketplace_publishers p \
         ON p.tenant_id=r.tenant_id AND p.publisher_id=r.publisher_id \
         WHERE r.tenant_id=$1 AND r.release_id=$2 AND r.review_status='PUBLISHED' FOR UPDATE OF r,p",
    )
    .bind(tenant)
    .bind(release_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::NotFound)?;
    let catalog = sqlx::query(
        "SELECT control_plane_version,region,entitlements,allowed_compatibility,minimum_publisher_trust,maximum_risk \
         FROM marketplace_tenant_catalog WHERE tenant_id=$1 FOR UPDATE",
    )
    .bind(tenant)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::CompatibilityDenied)?;
    let manifest: DomainPackManifest = serde_json::from_value(release.get("manifest"))
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
    require_catalog_compatibility(&release, &catalog, &manifest)?;
    let active_manifest = sqlx::query_scalar::<_, Value>(
        "SELECT r.manifest FROM marketplace_installations i JOIN marketplace_releases r \
         ON r.tenant_id=i.tenant_id AND r.release_id=i.release_id \
         WHERE i.tenant_id=$1 AND i.pack_id=$2 AND i.environment=$3 AND i.state='ACTIVE' \
         FOR UPDATE OF i,r",
    )
    .bind(tenant)
    .bind(release.get::<String, _>("pack_id"))
    .bind(environment)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
    let old_permissions = active_manifest
        .map(serde_json::from_value::<DomainPackManifest>)
        .transpose()
        .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
        .map(|value| value.permissions)
        .unwrap_or_else(PackPermissionDeclaration::default);
    let permission_diff = PermissionDiff::compute(&old_permissions, &manifest.permissions);
    let permission_expansion = permission_diff.expands_privilege();
    let diff_value = serde_json::to_value(&permission_diff)
        .map_err(|_| MarketplaceAuthorityError::RequestInvalid)?;
    sqlx::query(
        "INSERT INTO marketplace_installations \
         (tenant_id,installation_id,release_id,pack_id,version,pack_digest,environment,requester_subject,\
          request_reason_digest,permission_digest,permission_diff,permission_expansion,state) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'PENDING_APPROVAL')",
    )
    .bind(tenant)
    .bind(installation_id)
    .bind(release_id)
    .bind(release.get::<String, _>("pack_id"))
    .bind(release.get::<String, _>("version"))
    .bind(release.get::<String, _>("pack_digest"))
    .bind(environment)
    .bind(&request.principal_subject)
    .bind(request_reason_digest)
    .bind(release.get::<String, _>("permission_digest"))
    .bind(&diff_value)
    .bind(permission_expansion)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok((
        "PENDING_APPROVAL".into(),
        canonical_digest(&permission_diff)?,
    ))
}

fn require_catalog_compatibility(
    release: &sqlx::postgres::PgRow,
    catalog: &sqlx::postgres::PgRow,
    manifest: &DomainPackManifest,
) -> Result<(), MarketplaceAuthorityError> {
    let current = semver(&catalog.get::<String, _>("control_plane_version"))
        .ok_or(MarketplaceAuthorityError::CompatibilityDenied)?;
    let minimum = semver(&release.get::<String, _>("minimum_control_plane_version"))
        .ok_or(MarketplaceAuthorityError::CompatibilityDenied)?;
    let allowed = catalog
        .get::<Vec<String>, _>("allowed_compatibility")
        .into_iter()
        .collect::<BTreeSet<_>>();
    if current < minimum || !manifest.compatibility.is_subset(&allowed) {
        return Err(MarketplaceAuthorityError::CompatibilityDenied);
    }
    if !catalog
        .get::<Vec<String>, _>("entitlements")
        .contains(&release.get::<String, _>("entitlement"))
    {
        return Err(MarketplaceAuthorityError::EntitlementDenied);
    }
    if !release
        .get::<Vec<String>, _>("allowed_regions")
        .contains(&catalog.get::<String, _>("region"))
    {
        return Err(MarketplaceAuthorityError::RegionDenied);
    }
    if release.get::<String, _>("trust_status") != "VERIFIED"
        || release.get::<String, _>("minimum_publisher_trust") != "VERIFIED"
        || catalog.get::<String, _>("minimum_publisher_trust") != "VERIFIED"
    {
        return Err(MarketplaceAuthorityError::TrustDenied);
    }
    let release_risk = MarketplaceRisk::parse(&release.get::<String, _>("risk_rating"))
        .ok_or(MarketplaceAuthorityError::RiskDenied)?;
    let maximum_risk = MarketplaceRisk::parse(&catalog.get::<String, _>("maximum_risk"))
        .ok_or(MarketplaceAuthorityError::RiskDenied)?;
    if release_risk > maximum_risk {
        return Err(MarketplaceAuthorityError::RiskDenied);
    }
    Ok(())
}

async fn approve_installation(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::ApproveInstallation {
        installation_id,
        decision,
        approval_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let row = sqlx::query(
        "SELECT i.requester_subject,r.publisher_id,p.owner_subject FROM marketplace_installations i \
         JOIN marketplace_releases r ON r.tenant_id=i.tenant_id AND r.release_id=i.release_id \
         JOIN marketplace_publishers p ON p.tenant_id=r.tenant_id AND p.publisher_id=r.publisher_id \
         WHERE i.tenant_id=$1 AND i.installation_id=$2 AND i.state='PENDING_APPROVAL' FOR UPDATE OF i,r,p",
    )
    .bind(tenant)
    .bind(installation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::NotFound)?;
    if row.get::<String, _>("requester_subject") == request.principal_subject
        || row.get::<String, _>("owner_subject") == request.principal_subject
    {
        return Err(MarketplaceAuthorityError::ReviewSeparationRequired);
    }
    let state = match decision {
        ReviewDecision::Approve => "APPROVED",
        ReviewDecision::Reject => "REJECTED",
    };
    sqlx::query(
        "UPDATE marketplace_installations SET state=$3,approved_by=$4,approval_digest=$5,approved_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='PENDING_APPROVAL'",
    )
    .bind(tenant)
    .bind(installation_id)
    .bind(state)
    .bind(&request.principal_subject)
    .bind(approval_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok((state.into(), approval_digest.clone()))
}

async fn install_pack(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::Install {
        installation_id,
        artifact_receipt_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let changed = sqlx::query(
        "UPDATE marketplace_installations SET state='INSTALLED',artifact_receipt_digest=$3,installed_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='APPROVED'",
    )
    .bind(tenant)
    .bind(installation_id)
    .bind(artifact_receipt_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?
    .rows_affected();
    if changed != 1 {
        return Err(MarketplaceAuthorityError::StateConflict);
    }
    Ok(("INSTALLED".into(), artifact_receipt_digest.clone()))
}

async fn activate_pack(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::Activate {
        installation_id,
        production_certificate_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let row = sqlx::query(
        "SELECT i.pack_id,i.environment,i.state,r.pack_digest,r.certificate_digest,r.review_status,p.trust_status \
         FROM marketplace_installations i JOIN marketplace_releases r \
         ON r.tenant_id=i.tenant_id AND r.release_id=i.release_id JOIN marketplace_publishers p \
         ON p.tenant_id=r.tenant_id AND p.publisher_id=r.publisher_id \
         WHERE i.tenant_id=$1 AND i.installation_id=$2 FOR UPDATE OF i,r,p",
    )
    .bind(tenant)
    .bind(installation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::NotFound)?;
    if row.get::<String, _>("state") != "INSTALLED"
        || row.get::<String, _>("review_status") != "PUBLISHED"
        || row.get::<String, _>("trust_status") != "VERIFIED"
    {
        return Err(MarketplaceAuthorityError::StateConflict);
    }
    let required_certificate_digest: String = row.get("certificate_digest");
    if row.get::<String, _>("environment") == "production"
        && production_certificate_digest.as_deref() != Some(required_certificate_digest.as_str())
    {
        return Err(MarketplaceAuthorityError::SignatureInvalid);
    }
    let previous = sqlx::query_scalar::<_, Uuid>(
        "SELECT installation_id FROM marketplace_installations WHERE tenant_id=$1 AND pack_id=$2 \
         AND environment=$3 AND state='ACTIVE' FOR UPDATE",
    )
    .bind(tenant)
    .bind(row.get::<String, _>("pack_id"))
    .bind(row.get::<String, _>("environment"))
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
    if let Some(previous_id) = previous {
        sqlx::query(
            "UPDATE marketplace_installations SET state='INACTIVE',deactivated_at=now(),updated_at=now() \
             WHERE tenant_id=$1 AND installation_id=$2 AND state='ACTIVE'",
        )
        .bind(tenant)
        .bind(previous_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    }
    let changed = sqlx::query(
        "UPDATE marketplace_installations SET state='ACTIVE',previous_installation_id=$3,\
         production_certificate_digest=$4,activated_at=now(),deactivated_at=NULL,updated_at=now() \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='INSTALLED'",
    )
    .bind(tenant)
    .bind(installation_id)
    .bind(previous)
    .bind(production_certificate_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?
    .rows_affected();
    if changed != 1 {
        return Err(MarketplaceAuthorityError::StateConflict);
    }
    Ok(("ACTIVE".into(), row.get("pack_digest")))
}

async fn plan_upgrade(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::PlanUpgrade {
        plan_id,
        current_installation_id,
        target_installation_id,
        migration_digest,
        rollback_digest,
        canary_percent,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let current = sqlx::query(
        "SELECT pack_id,version,environment FROM marketplace_installations \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='ACTIVE' FOR UPDATE",
    )
    .bind(tenant)
    .bind(current_installation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::NotFound)?;
    let target = sqlx::query(
        "SELECT pack_id,version,environment,permission_expansion FROM marketplace_installations \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='INSTALLED' FOR UPDATE",
    )
    .bind(tenant)
    .bind(target_installation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::NotFound)?;
    let current_version = current.get::<String, _>("version");
    let target_version = target.get::<String, _>("version");
    if current.get::<String, _>("pack_id") != target.get::<String, _>("pack_id")
        || current.get::<String, _>("environment") != target.get::<String, _>("environment")
        || semver(&target_version) <= semver(&current_version)
    {
        return Err(MarketplaceAuthorityError::CompatibilityDenied);
    }
    sqlx::query(
        "INSERT INTO marketplace_upgrade_plans \
         (tenant_id,plan_id,pack_id,environment,current_installation_id,target_installation_id,\
          current_version,target_version,permission_expansion,migration_digest,rollback_digest,canary_percent,state,planned_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'PLANNED',$13)",
    )
    .bind(tenant)
    .bind(plan_id)
    .bind(current.get::<String, _>("pack_id"))
    .bind(current.get::<String, _>("environment"))
    .bind(current_installation_id)
    .bind(target_installation_id)
    .bind(current_version)
    .bind(target_version)
    .bind(target.get::<bool, _>("permission_expansion"))
    .bind(migration_digest)
    .bind(rollback_digest)
    .bind(i16::from(*canary_percent))
    .bind(&request.principal_subject)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok((
        "PLANNED".into(),
        canonical_digest(&json!({
            "migration_digest": migration_digest,
            "rollback_digest": rollback_digest,
            "canary_percent": canary_percent,
        }))?,
    ))
}

async fn record_canary(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::RecordCanary {
        plan_id,
        passed,
        observed_samples,
        evidence_ref,
        evidence_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM marketplace_upgrade_plans WHERE tenant_id=$1 AND plan_id=$2 AND state='PLANNED' FOR UPDATE",
    )
    .bind(tenant)
    .bind(plan_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?;
    if exists.is_none() {
        return Err(MarketplaceAuthorityError::StateConflict);
    }
    sqlx::query(
        "INSERT INTO marketplace_canary_results \
         (tenant_id,canary_id,plan_id,passed,observed_samples,evidence_ref,evidence_digest,recorded_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(tenant)
    .bind(Uuid::new_v4())
    .bind(plan_id)
    .bind(passed)
    .bind(i64::from(*observed_samples))
    .bind(evidence_ref)
    .bind(evidence_digest)
    .bind(&request.principal_subject)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    let state = if *passed {
        "CANARY_PASSED"
    } else {
        "CANARY_FAILED"
    };
    sqlx::query(
        "UPDATE marketplace_upgrade_plans SET state=$3,updated_at=now() \
         WHERE tenant_id=$1 AND plan_id=$2 AND state='PLANNED'",
    )
    .bind(tenant)
    .bind(plan_id)
    .bind(state)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok((state.into(), evidence_digest.clone()))
}

async fn upgrade_pack(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::Upgrade {
        plan_id,
        production_certificate_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let plan = sqlx::query(
        "SELECT current_installation_id,target_installation_id FROM marketplace_upgrade_plans \
         WHERE tenant_id=$1 AND plan_id=$2 AND state='CANARY_PASSED' FOR UPDATE",
    )
    .bind(tenant)
    .bind(plan_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::StateConflict)?;
    let current_id: Uuid = plan.get("current_installation_id");
    let target_id: Uuid = plan.get("target_installation_id");
    let target = sqlx::query(
        "SELECT i.pack_digest,i.environment,r.review_status,r.certificate_digest,p.trust_status FROM marketplace_installations i \
         JOIN marketplace_releases r ON r.tenant_id=i.tenant_id AND r.release_id=i.release_id \
         JOIN marketplace_publishers p ON p.tenant_id=r.tenant_id AND p.publisher_id=r.publisher_id \
         WHERE i.tenant_id=$1 AND i.installation_id=$2 AND i.state='INSTALLED' FOR UPDATE OF i,r,p",
    )
    .bind(tenant)
    .bind(target_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::StateConflict)?;
    if target.get::<String, _>("review_status") != "PUBLISHED"
        || target.get::<String, _>("trust_status") != "VERIFIED"
    {
        return Err(MarketplaceAuthorityError::TrustDenied);
    }
    let required_certificate_digest: String = target.get("certificate_digest");
    if target.get::<String, _>("environment") == "production"
        && production_certificate_digest.as_deref() != Some(required_certificate_digest.as_str())
    {
        return Err(MarketplaceAuthorityError::SignatureInvalid);
    }
    let old = sqlx::query(
        "UPDATE marketplace_installations SET state='INACTIVE',deactivated_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='ACTIVE'",
    )
    .bind(tenant)
    .bind(current_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?
    .rows_affected();
    let new = sqlx::query(
        "UPDATE marketplace_installations SET state='ACTIVE',previous_installation_id=$3,\
         production_certificate_digest=$4,activated_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='INSTALLED'",
    )
    .bind(tenant)
    .bind(target_id)
    .bind(current_id)
    .bind(production_certificate_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?
    .rows_affected();
    if old != 1 || new != 1 {
        return Err(MarketplaceAuthorityError::StateConflict);
    }
    sqlx::query(
        "UPDATE marketplace_upgrade_plans SET state='COMPLETED',completed_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND plan_id=$2 AND state='CANARY_PASSED'",
    )
    .bind(tenant)
    .bind(plan_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok(("ACTIVE".into(), target.get("pack_digest")))
}

async fn rollback_pack(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::Rollback {
        installation_id,
        reason_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let current = sqlx::query(
        "SELECT previous_installation_id FROM marketplace_installations \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='ACTIVE' FOR UPDATE",
    )
    .bind(tenant)
    .bind(installation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::StateConflict)?;
    let previous_id = current
        .get::<Option<Uuid>, _>("previous_installation_id")
        .ok_or(MarketplaceAuthorityError::StateConflict)?;
    let previous = sqlx::query(
        "SELECT i.pack_digest,r.review_status,p.trust_status FROM marketplace_installations i \
         JOIN marketplace_releases r ON r.tenant_id=i.tenant_id AND r.release_id=i.release_id \
         JOIN marketplace_publishers p ON p.tenant_id=r.tenant_id AND p.publisher_id=r.publisher_id \
         WHERE i.tenant_id=$1 AND i.installation_id=$2 AND i.state='INACTIVE' FOR UPDATE OF i,r,p",
    )
    .bind(tenant)
    .bind(previous_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::StateConflict)?;
    if previous.get::<String, _>("review_status") != "PUBLISHED"
        || previous.get::<String, _>("trust_status") != "VERIFIED"
    {
        return Err(MarketplaceAuthorityError::TrustDenied);
    }
    sqlx::query(
        "UPDATE marketplace_installations SET state='ROLLED_BACK',deactivated_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='ACTIVE'",
    )
    .bind(tenant)
    .bind(installation_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    sqlx::query(
        "UPDATE marketplace_installations SET state='ACTIVE',activated_at=now(),deactivated_at=NULL,updated_at=now() \
         WHERE tenant_id=$1 AND installation_id=$2 AND state='INACTIVE'",
    )
    .bind(tenant)
    .bind(previous_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    sqlx::query(
        "UPDATE marketplace_upgrade_plans SET state='ROLLED_BACK',rollback_reason_digest=$3,rolled_back_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND target_installation_id=$2 AND state='COMPLETED'",
    )
    .bind(tenant)
    .bind(installation_id)
    .bind(reason_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok(("ROLLED_BACK".into(), previous.get("pack_digest")))
}

async fn deactivate_pack(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::Deactivate {
        installation_id,
        reason_digest,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let changed = sqlx::query(
        "UPDATE marketplace_installations SET state='INACTIVE',deactivation_reason_digest=$3,\
         deactivated_at=now(),updated_at=now() WHERE tenant_id=$1 AND installation_id=$2 AND state='ACTIVE'",
    )
    .bind(tenant)
    .bind(installation_id)
    .bind(reason_digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?
    .rows_affected();
    if changed != 1 {
        return Err(MarketplaceAuthorityError::StateConflict);
    }
    Ok(("INACTIVE".into(), reason_digest.clone()))
}

async fn revoke_release(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request: &MarketplaceExecutorRequest,
) -> Result<(String, String), MarketplaceAuthorityError> {
    let MarketplaceCommand::RevokeRelease {
        release_id,
        reason_code,
        reason_digest,
        running_task_response,
    } = &request.command.command
    else {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    };
    let release = sqlx::query(
        "SELECT pack_id,version,pack_digest FROM marketplace_releases \
         WHERE tenant_id=$1 AND release_id=$2 AND review_status IN ('SUBMITTED','PUBLISHED') FOR UPDATE",
    )
    .bind(tenant)
    .bind(release_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::DependencyUnavailable)?
    .ok_or(MarketplaceAuthorityError::NotFound)?;
    sqlx::query(
        "UPDATE marketplace_releases SET review_status='REVOKED',revoked_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND release_id=$2",
    )
    .bind(tenant)
    .bind(release_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    sqlx::query(
        "INSERT INTO marketplace_revocations \
         (tenant_id,notice_id,release_id,pack_id,version,pack_digest,reason_code,reason_digest,running_task_response,revoked_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(tenant)
    .bind(Uuid::new_v4())
    .bind(release_id)
    .bind(release.get::<String, _>("pack_id"))
    .bind(release.get::<String, _>("version"))
    .bind(release.get::<String, _>("pack_digest"))
    .bind(reason_code)
    .bind(reason_digest)
    .bind(running_task_response.as_str())
    .bind(&request.principal_subject)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    sqlx::query(
        "UPDATE marketplace_installations SET state='REVOKED',revoked_at=now(),updated_at=now() \
         WHERE tenant_id=$1 AND release_id=$2 \
         AND state IN ('PENDING_APPROVAL','APPROVED','INSTALLED','ACTIVE','INACTIVE')",
    )
    .bind(tenant)
    .bind(release_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| MarketplaceAuthorityError::StateConflict)?;
    Ok(("REVOKED".into(), release.get("pack_digest")))
}

fn validate_execution(
    binding: &MarketplaceExecutionBinding,
    request: &MarketplaceExecutorRequest,
) -> Result<(), MarketplaceAuthorityError> {
    if request.schema_version != MARKETPLACE_EXECUTOR_REQUEST_SCHEMA
        || request.command.schema_version != MARKETPLACE_COMMAND_SCHEMA
        || binding.tenant_id.0 != request.command.tenant_id.to_string()
        || !identifier(&request.principal_subject, 256)
        || !digest(&request.principal_assertion_digest)
        || !digest(&binding.action_hash)
        || !identifier(&binding.policy_decision_id, 256)
        || !digest(&binding.policy_decision_digest)
        || !identifier(&binding.ledger_entry_id, 256)
        || !digest(&binding.ledger_entry_digest)
        || !digest(&binding.fence_digest)
        || !safe_reference(&binding.authorization_evidence_ref)
        || !digest(&binding.authorization_evidence_digest)
        || !valid_idempotency_key(&binding.idempotency_key)
        || !identifier(&binding.trace_id, 256)
        || binding.resource_version != request.command.expected_resource_version
        || !command_shape(&request.command)
    {
        return Err(MarketplaceAuthorityError::RequestInvalid);
    }
    Ok(())
}

fn publisher_trust_string(
    value: PublisherTrust,
) -> Result<&'static str, MarketplaceAuthorityError> {
    match value {
        PublisherTrust::Untrusted => Ok("UNTRUSTED"),
        PublisherTrust::Verified => Ok("VERIFIED"),
        PublisherTrust::Suspended => Ok("SUSPENDED"),
        PublisherTrust::Revoked => Ok("REVOKED"),
    }
}

fn immutable_artifact_refs(values: &BTreeSet<String>) -> bool {
    !values.is_empty()
        && values.len() <= 256
        && values.iter().all(|value| {
            value.len() <= 2_048
                && value.contains("sha256:")
                && !value.to_ascii_lowercase().ends_with(":latest")
                && !value.chars().any(char::is_control)
        })
}

fn semver(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    (parts.next().is_none()
        && value
            .split('.')
            .all(|part| !part.is_empty() && (part == "0" || !part.starts_with('0'))))
    .then_some((major, minor, patch))
}

fn bounded_set(values: &BTreeSet<String>, maximum_items: usize, maximum_length: usize) -> bool {
    !values.is_empty()
        && values.len() <= maximum_items
        && values.iter().all(|value| {
            !value.is_empty()
                && value.len() <= maximum_length
                && !value.chars().any(char::is_control)
        })
}

fn bounded_contact(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 320
        && value.contains('@')
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn safe_reference(value: &str) -> bool {
    value.starts_with("urn:agenttrust:")
        && value.len() <= 2_048
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn parse_tenant(tenant: &TenantId) -> Result<Uuid, MarketplaceAuthorityError> {
    Uuid::parse_str(&tenant.0)
        .ok()
        .filter(|value| value.to_string() == tenant.0)
        .ok_or(MarketplaceAuthorityError::RequestInvalid)
}

fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Result<String, MarketplaceAuthorityError> {
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(value).map_err(|_| MarketplaceAuthorityError::RequestInvalid)?,
    )))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn valid_idempotency_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_routes_and_roles_are_closed() {
        let command = MarketplaceCommand::Deactivate {
            installation_id: Uuid::nil(),
            reason_digest: "a".repeat(64),
        };
        assert_eq!(command.route_kind(), MarketplaceRouteKind::Lifecycle);
        assert_eq!(command.required_role(), "marketplace-operator");
        assert_eq!(command.operation(), "DEACTIVATE");
    }

    #[test]
    fn semver_is_strict_and_orderable() {
        assert_eq!(semver("1.2.3"), Some((1, 2, 3)));
        assert!(semver("1.02.3").is_none());
        assert!(semver("latest").is_none());
        assert!(semver("2.0.0") > semver("1.99.99"));
    }

    #[test]
    fn artifact_references_must_be_immutable() {
        assert!(immutable_artifact_refs(&BTreeSet::from([
            "oci://registry.example/pack@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
        ])));
        assert!(!immutable_artifact_refs(&BTreeSet::from([
            "oci://registry.example/pack:latest".into()
        ])));
    }
}
