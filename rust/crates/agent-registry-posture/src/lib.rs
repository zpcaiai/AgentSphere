//! Enterprise Agent inventory, discovery provenance, BOM, lifecycle, and posture facts.

pub mod production;
pub mod server;

use agent_trust_contracts::{RiskLevel, TenantId};
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const AGENT_REGISTRY_SCHEMA_VERSION: &str = "agenttrust.agent-registry.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    Draft,
    Active,
    Suspended,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ownership {
    pub owner_subject: String,
    pub sponsor_subject: String,
    pub confirmed_at: DateTime<Utc>,
    pub review_due_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentBom {
    pub schema_version: String,
    pub agent_id: String,
    pub components: BTreeMap<String, String>,
    pub bom_digest: String,
    pub generated_at: DateTime<Utc>,
}

impl AgentBom {
    pub fn compute_digest(&self) -> String {
        let joined = self
            .components
            .iter()
            .map(|(kind, digest)| format!("{kind}:{digest}"))
            .collect::<Vec<_>>()
            .join("\n");
        hex(Sha256::digest(joined.as_bytes()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentAsset {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub display_name: String,
    pub ownership: Ownership,
    pub environment: String,
    pub lifecycle: LifecycleState,
    pub agent_type: String,
    pub endpoints: BTreeSet<String>,
    pub identity_refs: BTreeSet<String>,
    pub tool_refs: BTreeSet<String>,
    pub pack_refs: BTreeSet<String>,
    pub requested_permissions: BTreeSet<String>,
    pub approved_permissions: BTreeSet<String>,
    pub bom: AgentBom,
    pub last_activity_at: DateTime<Utc>,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationSource {
    ProtocolDiscovery,
    NetworkObservation,
    LogObservation,
    Import,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryObservation {
    pub schema_version: String,
    pub observation_id: String,
    pub tenant_id: TenantId,
    pub source: ObservationSource,
    pub collector_id: String,
    pub endpoint: String,
    pub claimed_agent_id: Option<String>,
    pub protocol: String,
    pub observed_component_digests: BTreeMap<String, String>,
    pub observed_at: DateTime<Utc>,
    pub payload_digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PostureKind {
    Shadow,
    Orphan,
    Dormant,
    Overprivileged,
    Drifted,
    RevokedButActive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostureFinding {
    pub schema_version: String,
    pub finding_id: String,
    pub tenant_id: TenantId,
    pub agent_id: Option<String>,
    pub observation_id: Option<String>,
    pub kind: PostureKind,
    pub severity: RiskLevel,
    pub reason_code: String,
    pub evidence_digest: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecyclePropagationReceipt {
    pub schema_version: String,
    pub agent_id: String,
    pub lifecycle: LifecycleState,
    pub identity_revocation_required: bool,
    pub authorization_revocation_required: bool,
    pub pack_deactivation_required: bool,
    pub event_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoverySignal {
    pub tenant_id: TenantId,
    pub endpoint: String,
    pub claimed_agent_id: Option<String>,
    pub protocol: String,
    pub component_digests: BTreeMap<String, String>,
    pub canonical_payload: String,
    pub observed_at: DateTime<Utc>,
}

pub struct DiscoveryCollector {
    collector_id: String,
    allowed_protocols: BTreeSet<String>,
}

impl DiscoveryCollector {
    pub fn new(
        collector_id: impl Into<String>,
        allowed_protocols: BTreeSet<String>,
    ) -> Result<Self, RegistryError> {
        let collector_id = collector_id.into();
        if collector_id.is_empty() || allowed_protocols.is_empty() {
            return Err(RegistryError::ConfigurationInvalid);
        }
        Ok(Self {
            collector_id,
            allowed_protocols,
        })
    }

    pub fn collect(&self, signal: DiscoverySignal) -> Result<DiscoveryObservation, RegistryError> {
        self.collect_as(ObservationSource::ProtocolDiscovery, signal)
    }

    /// Collector SDK entrypoint for network, log and governed import adapters.  The returned
    /// object is always an observation fact; callers cannot obtain registration or trust state
    /// from any discovery source.
    pub fn collect_as(
        &self,
        source: ObservationSource,
        signal: DiscoverySignal,
    ) -> Result<DiscoveryObservation, RegistryError> {
        let endpoint_scheme_allowed = ["mcp://", "a2a://", "agui://", "https://"]
            .iter()
            .any(|prefix| signal.endpoint.starts_with(prefix));
        if !self.allowed_protocols.contains(&signal.protocol)
            || !endpoint_scheme_allowed
            || signal.canonical_payload.is_empty()
            || signal
                .component_digests
                .values()
                .any(|digest| !is_sha256(digest))
        {
            return Err(RegistryError::ObservationInvalid);
        }
        let payload_digest = hex(Sha256::digest(signal.canonical_payload.as_bytes()));
        Ok(DiscoveryObservation {
            schema_version: AGENT_REGISTRY_SCHEMA_VERSION.into(),
            observation_id: Uuid::new_v4().to_string(),
            tenant_id: signal.tenant_id,
            source,
            collector_id: self.collector_id.clone(),
            endpoint: signal.endpoint,
            claimed_agent_id: signal.claimed_agent_id,
            protocol: signal.protocol,
            observed_component_digests: signal.component_digests,
            observed_at: signal.observed_at,
            payload_digest,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnershipCandidate {
    pub subject: String,
    pub provenance: String,
    pub confidence_millionths: u32,
}

pub struct OwnershipResolver;

impl OwnershipResolver {
    pub fn resolve(
        candidates: &[OwnershipCandidate],
        sponsor_subject: &str,
        confirmed_by: &str,
        now: DateTime<Utc>,
        review_after: Duration,
    ) -> Result<Ownership, RegistryError> {
        if candidates.is_empty()
            || candidates.len() > 100
            || sponsor_subject.is_empty()
            || confirmed_by.is_empty()
            || review_after <= Duration::zero()
            || candidates.iter().any(|candidate| {
                candidate.subject.is_empty()
                    || candidate.provenance.is_empty()
                    || candidate.confidence_millionths > 1_000_000
            })
        {
            return Err(RegistryError::OwnershipInvalid);
        }
        let maximum = candidates
            .iter()
            .map(|candidate| candidate.confidence_millionths)
            .max()
            .ok_or(RegistryError::OwnershipInvalid)?;
        let strongest = candidates
            .iter()
            .filter(|candidate| candidate.confidence_millionths == maximum)
            .collect::<Vec<_>>();
        if maximum < 800_000 || strongest.len() != 1 {
            return Err(RegistryError::OwnershipAmbiguous);
        }
        Ok(Ownership {
            owner_subject: strongest[0].subject.clone(),
            sponsor_subject: sponsor_subject.into(),
            confirmed_at: now,
            review_due_at: now + review_after,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationshipKind {
    UsesTool,
    UsesPack,
    Owns,
    SponsoredBy,
    ObservedAt,
    DelegatesTo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelationshipEdge {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub kind: RelationshipKind,
    pub evidence_digest: String,
}

pub struct RelationshipGraph {
    maximum_edges: usize,
    edges: RwLock<BTreeMap<(TenantId, String), RelationshipEdge>>,
}

impl RelationshipGraph {
    pub fn new(maximum_edges: usize) -> Result<Self, RegistryError> {
        if maximum_edges == 0 {
            return Err(RegistryError::ConfigurationInvalid);
        }
        Ok(Self {
            maximum_edges,
            edges: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn add(&self, edge: RelationshipEdge) -> Result<(), RegistryError> {
        if edge.schema_version != AGENT_REGISTRY_SCHEMA_VERSION
            || edge.edge_id.is_empty()
            || edge.from.is_empty()
            || edge.to.is_empty()
            || edge.from == edge.to
            || !is_sha256(&edge.evidence_digest)
        {
            return Err(RegistryError::RelationshipInvalid);
        }
        let key = (edge.tenant_id.clone(), edge.edge_id.clone());
        let mut edges = self.edges.write();
        if let Some(existing) = edges.get(&key) {
            return if existing == &edge {
                Ok(())
            } else {
                Err(RegistryError::RegistrationConflict)
            };
        }
        if edges.len() >= self.maximum_edges {
            return Err(RegistryError::CapacityExceeded);
        }
        edges.insert(key, edge);
        Ok(())
    }

    pub fn query(
        &self,
        tenant: &TenantId,
        root: &str,
        maximum_depth: usize,
        limit: usize,
    ) -> Result<Vec<RelationshipEdge>, RegistryError> {
        if root.is_empty() || maximum_depth == 0 || maximum_depth > 5 || limit == 0 || limit > 100 {
            return Err(RegistryError::QueryDenied);
        }
        let edges = self.edges.read();
        let mut frontier = BTreeSet::from([root.to_string()]);
        let mut visited = frontier.clone();
        let mut result = Vec::new();
        for _ in 0..maximum_depth {
            let mut next = BTreeSet::new();
            for edge in edges.values().filter(|edge| {
                &edge.tenant_id == tenant
                    && (frontier.contains(&edge.from) || frontier.contains(&edge.to))
            }) {
                if result.len() == limit {
                    return Ok(result);
                }
                if !result
                    .iter()
                    .any(|item: &RelationshipEdge| item.edge_id == edge.edge_id)
                {
                    result.push(edge.clone());
                }
                for node in [&edge.from, &edge.to] {
                    if visited.insert(node.clone()) {
                        next.insert(node.clone());
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistrySnapshot {
    schema_version: String,
    assets: Vec<AgentAsset>,
    observations: Vec<DiscoveryObservation>,
}

pub struct AgentRegistry {
    maximum_assets: usize,
    maximum_observations: usize,
    assets: RwLock<BTreeMap<(TenantId, String), AgentAsset>>,
    observations: RwLock<BTreeMap<(TenantId, String), DiscoveryObservation>>,
}

impl AgentRegistry {
    pub fn new(maximum_assets: usize, maximum_observations: usize) -> Result<Self, RegistryError> {
        if maximum_assets == 0 || maximum_observations == 0 {
            return Err(RegistryError::ConfigurationInvalid);
        }
        Ok(Self {
            maximum_assets,
            maximum_observations,
            assets: RwLock::new(BTreeMap::new()),
            observations: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn register(&self, asset: AgentAsset) -> Result<AgentAsset, RegistryError> {
        validate_asset(&asset)?;
        let key = (asset.tenant_id.clone(), asset.agent_id.clone());
        let mut assets = self.assets.write();
        if let Some(existing) = assets.get(&key) {
            if existing.bom.bom_digest == asset.bom.bom_digest
                && existing.ownership == asset.ownership
            {
                return Ok(existing.clone());
            }
            return Err(RegistryError::RegistrationConflict);
        }
        if assets.len() >= self.maximum_assets {
            return Err(RegistryError::CapacityExceeded);
        }
        assets.insert(key, asset.clone());
        Ok(asset)
    }

    pub fn ingest_observation(
        &self,
        observation: DiscoveryObservation,
    ) -> Result<DiscoveryObservation, RegistryError> {
        validate_observation(&observation)?;
        let key = (
            observation.tenant_id.clone(),
            observation.observation_id.clone(),
        );
        let mut observations = self.observations.write();
        if let Some(existing) = observations.get(&key) {
            if existing.payload_digest == observation.payload_digest {
                return Ok(existing.clone());
            }
            return Err(RegistryError::ObservationConflict);
        }
        if observations.len() >= self.maximum_observations {
            return Err(RegistryError::CapacityExceeded);
        }
        observations.insert(key, observation.clone());
        Ok(observation)
    }

    pub fn get(&self, tenant: &TenantId, agent_id: &str) -> Result<AgentAsset, RegistryError> {
        self.assets
            .read()
            .get(&(tenant.clone(), agent_id.into()))
            .cloned()
            .ok_or(RegistryError::NotFound)
    }

    pub fn search(
        &self,
        tenant: &TenantId,
        cursor: usize,
        limit: usize,
    ) -> Result<Vec<AgentAsset>, RegistryError> {
        if limit == 0 || limit > 100 {
            return Err(RegistryError::QueryDenied);
        }
        Ok(self
            .assets
            .read()
            .iter()
            .filter(|((asset_tenant, _), _)| asset_tenant == tenant)
            .skip(cursor)
            .take(limit)
            .map(|(_, asset)| asset.clone())
            .collect())
    }

    pub fn transition_lifecycle(
        &self,
        tenant: &TenantId,
        agent_id: &str,
        to: LifecycleState,
    ) -> Result<LifecyclePropagationReceipt, RegistryError> {
        let mut assets = self.assets.write();
        let asset = assets
            .get_mut(&(tenant.clone(), agent_id.into()))
            .ok_or(RegistryError::NotFound)?;
        if !lifecycle_allowed(asset.lifecycle, to) {
            return Err(RegistryError::LifecycleDenied);
        }
        asset.lifecycle = to;
        let revoke = matches!(
            to,
            LifecycleState::Suspended | LifecycleState::Retired | LifecycleState::Revoked
        );
        let digest = hex(Sha256::digest(
            format!("{}:{to:?}:{}", asset.agent_id, Utc::now()).as_bytes(),
        ));
        Ok(LifecyclePropagationReceipt {
            schema_version: AGENT_REGISTRY_SCHEMA_VERSION.into(),
            agent_id: asset.agent_id.clone(),
            lifecycle: to,
            identity_revocation_required: revoke,
            authorization_revocation_required: revoke,
            pack_deactivation_required: matches!(
                to,
                LifecycleState::Retired | LifecycleState::Revoked
            ),
            event_digest: digest,
        })
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, RegistryError> {
        serde_json::to_vec(&RegistrySnapshot {
            schema_version: AGENT_REGISTRY_SCHEMA_VERSION.into(),
            assets: self.assets.read().values().cloned().collect(),
            observations: self.observations.read().values().cloned().collect(),
        })
        .map_err(|_| RegistryError::PersistenceFailed)
    }

    pub fn restore(
        bytes: &[u8],
        maximum_assets: usize,
        maximum_observations: usize,
    ) -> Result<Self, RegistryError> {
        let snapshot: RegistrySnapshot =
            serde_json::from_slice(bytes).map_err(|_| RegistryError::PersistenceFailed)?;
        if snapshot.schema_version != AGENT_REGISTRY_SCHEMA_VERSION
            || snapshot.assets.len() > maximum_assets
            || snapshot.observations.len() > maximum_observations
        {
            return Err(RegistryError::PersistenceFailed);
        }
        let assets = snapshot
            .assets
            .into_iter()
            .map(|asset| ((asset.tenant_id.clone(), asset.agent_id.clone()), asset))
            .collect();
        let observations = snapshot
            .observations
            .into_iter()
            .map(|observation| {
                (
                    (
                        observation.tenant_id.clone(),
                        observation.observation_id.clone(),
                    ),
                    observation,
                )
            })
            .collect();
        Ok(Self {
            maximum_assets,
            maximum_observations,
            assets: RwLock::new(assets),
            observations: RwLock::new(observations),
        })
    }
}

pub trait LifecyclePropagationPort: Send + Sync {
    fn revoke_identities(
        &self,
        tenant: &TenantId,
        agent_id: &str,
        identity_refs: &BTreeSet<String>,
        idempotency_key: &str,
    ) -> Result<String, RegistryError>;
    fn revoke_authorizations(
        &self,
        tenant: &TenantId,
        agent_id: &str,
        idempotency_key: &str,
    ) -> Result<String, RegistryError>;
    fn deactivate_packs(
        &self,
        tenant: &TenantId,
        agent_id: &str,
        pack_refs: &BTreeSet<String>,
        idempotency_key: &str,
    ) -> Result<String, RegistryError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleConvergenceReceipt {
    pub propagation: LifecyclePropagationReceipt,
    pub external_evidence_refs: BTreeSet<String>,
    pub converged: bool,
}

pub struct LifecycleCoordinator<'a, P: LifecyclePropagationPort> {
    registry: &'a AgentRegistry,
    port: P,
}

impl<'a, P: LifecyclePropagationPort> LifecycleCoordinator<'a, P> {
    pub fn new(registry: &'a AgentRegistry, port: P) -> Self {
        Self { registry, port }
    }

    pub fn transition(
        &self,
        tenant: &TenantId,
        agent_id: &str,
        to: LifecycleState,
        command_id: &str,
    ) -> Result<LifecycleConvergenceReceipt, RegistryError> {
        if command_id.is_empty() {
            return Err(RegistryError::LifecycleDenied);
        }
        let asset = self.registry.get(tenant, agent_id)?;
        if !lifecycle_allowed(asset.lifecycle, to) {
            return Err(RegistryError::LifecycleDenied);
        }
        let revoke = matches!(
            to,
            LifecycleState::Suspended | LifecycleState::Retired | LifecycleState::Revoked
        );
        let deactivate = matches!(to, LifecycleState::Retired | LifecycleState::Revoked);
        let mut evidence = BTreeSet::new();
        if revoke {
            evidence.insert(self.port.revoke_identities(
                tenant,
                agent_id,
                &asset.identity_refs,
                &format!("{command_id}:identity"),
            )?);
            evidence.insert(self.port.revoke_authorizations(
                tenant,
                agent_id,
                &format!("{command_id}:authorization"),
            )?);
        }
        if deactivate {
            evidence.insert(self.port.deactivate_packs(
                tenant,
                agent_id,
                &asset.pack_refs,
                &format!("{command_id}:pack"),
            )?);
        }
        if (revoke || deactivate) && evidence.iter().any(String::is_empty) {
            return Err(RegistryError::PropagationFailed);
        }
        let propagation = self.registry.transition_lifecycle(tenant, agent_id, to)?;
        Ok(LifecycleConvergenceReceipt {
            propagation,
            external_evidence_refs: evidence,
            converged: true,
        })
    }
}

pub struct PostureEngine;

impl PostureEngine {
    pub fn evaluate(
        registry: &AgentRegistry,
        tenant: &TenantId,
        now: DateTime<Utc>,
    ) -> Vec<PostureFinding> {
        let assets = registry.assets.read();
        let observations = registry.observations.read();
        let mut findings = Vec::new();
        for ((observation_tenant, _), observation) in observations
            .iter()
            .filter(|((tenant_id, _), _)| tenant_id == tenant)
        {
            let registered = observation
                .claimed_agent_id
                .as_ref()
                .is_some_and(|agent_id| {
                    assets.contains_key(&(observation_tenant.clone(), agent_id.clone()))
                });
            if !registered {
                findings.push(posture_finding(
                    tenant,
                    None,
                    Some(observation.observation_id.clone()),
                    PostureKind::Shadow,
                    RiskLevel::High,
                    "DISCOVERY_NOT_REGISTRATION",
                    &observation.payload_digest,
                ));
            }
        }
        for ((asset_tenant, _), asset) in assets
            .iter()
            .filter(|((tenant_id, _), _)| tenant_id == tenant)
        {
            if asset.ownership.owner_subject.is_empty()
                || asset.ownership.sponsor_subject.is_empty()
                || now >= asset.ownership.review_due_at
            {
                findings.push(posture_finding(
                    asset_tenant,
                    Some(asset.agent_id.clone()),
                    None,
                    PostureKind::Orphan,
                    RiskLevel::High,
                    "OWNERSHIP_MISSING_OR_EXPIRED",
                    &asset.bom.bom_digest,
                ));
            }
            if now.signed_duration_since(asset.last_activity_at) > Duration::days(30)
                && asset.lifecycle == LifecycleState::Active
            {
                findings.push(posture_finding(
                    asset_tenant,
                    Some(asset.agent_id.clone()),
                    None,
                    PostureKind::Dormant,
                    RiskLevel::Medium,
                    "DORMANT_ACTIVE_AGENT",
                    &asset.bom.bom_digest,
                ));
            }
            if !asset
                .requested_permissions
                .is_subset(&asset.approved_permissions)
            {
                findings.push(posture_finding(
                    asset_tenant,
                    Some(asset.agent_id.clone()),
                    None,
                    PostureKind::Overprivileged,
                    RiskLevel::Critical,
                    "PERMISSION_SCOPE_DRIFT",
                    &asset.bom.bom_digest,
                ));
            }
            if asset.bom.compute_digest() != asset.bom.bom_digest {
                findings.push(posture_finding(
                    asset_tenant,
                    Some(asset.agent_id.clone()),
                    None,
                    PostureKind::Drifted,
                    RiskLevel::High,
                    "BOM_DIGEST_DRIFT",
                    &asset.bom.bom_digest,
                ));
            }
            if asset.lifecycle == LifecycleState::Revoked
                && now.signed_duration_since(asset.last_activity_at) < Duration::minutes(10)
            {
                findings.push(posture_finding(
                    asset_tenant,
                    Some(asset.agent_id.clone()),
                    None,
                    PostureKind::RevokedButActive,
                    RiskLevel::Critical,
                    "REVOKED_AGENT_ACTIVITY",
                    &asset.bom.bom_digest,
                ));
            }
        }
        findings
    }
}

fn validate_asset(asset: &AgentAsset) -> Result<(), RegistryError> {
    if asset.schema_version != AGENT_REGISTRY_SCHEMA_VERSION
        || asset.agent_id.is_empty()
        || asset.display_name.is_empty()
        || asset.ownership.owner_subject.is_empty()
        || asset.ownership.sponsor_subject.is_empty()
        || asset.ownership.review_due_at <= asset.ownership.confirmed_at
        || asset.environment.is_empty()
        || asset.agent_type.is_empty()
        || asset.endpoints.is_empty()
        || asset.identity_refs.is_empty()
        || asset.bom.schema_version != AGENT_REGISTRY_SCHEMA_VERSION
        || asset.bom.agent_id != asset.agent_id
        || asset.bom.components.is_empty()
        || asset.bom.compute_digest() != asset.bom.bom_digest
    {
        Err(RegistryError::AssetInvalid)
    } else {
        Ok(())
    }
}

fn validate_observation(observation: &DiscoveryObservation) -> Result<(), RegistryError> {
    if observation.schema_version != AGENT_REGISTRY_SCHEMA_VERSION
        || observation.observation_id.is_empty()
        || observation.collector_id.is_empty()
        || observation.endpoint.is_empty()
        || observation.protocol.is_empty()
        || observation.payload_digest.len() != 64
    {
        Err(RegistryError::ObservationInvalid)
    } else {
        Ok(())
    }
}

fn lifecycle_allowed(from: LifecycleState, to: LifecycleState) -> bool {
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

fn posture_finding(
    tenant: &TenantId,
    agent_id: Option<String>,
    observation_id: Option<String>,
    kind: PostureKind,
    severity: RiskLevel,
    reason: &str,
    digest_source: &str,
) -> PostureFinding {
    PostureFinding {
        schema_version: AGENT_REGISTRY_SCHEMA_VERSION.into(),
        finding_id: Uuid::new_v4().to_string(),
        tenant_id: tenant.clone(),
        agent_id,
        observation_id,
        kind,
        severity,
        reason_code: reason.into(),
        evidence_digest: hex(Sha256::digest(digest_source.as_bytes())),
        detected_at: Utc::now(),
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RegistryError {
    #[error("AGENT_REGISTRY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("AGENT_REGISTRY_ASSET_INVALID")]
    AssetInvalid,
    #[error("AGENT_REGISTRY_REGISTRATION_CONFLICT")]
    RegistrationConflict,
    #[error("AGENT_REGISTRY_OBSERVATION_INVALID")]
    ObservationInvalid,
    #[error("AGENT_REGISTRY_OBSERVATION_CONFLICT")]
    ObservationConflict,
    #[error("AGENT_REGISTRY_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[error("AGENT_REGISTRY_NOT_FOUND")]
    NotFound,
    #[error("AGENT_REGISTRY_QUERY_DENIED")]
    QueryDenied,
    #[error("AGENT_REGISTRY_LIFECYCLE_DENIED")]
    LifecycleDenied,
    #[error("AGENT_REGISTRY_PERSISTENCE_FAILED")]
    PersistenceFailed,
    #[error("AGENT_REGISTRY_OWNERSHIP_INVALID")]
    OwnershipInvalid,
    #[error("AGENT_REGISTRY_OWNERSHIP_AMBIGUOUS")]
    OwnershipAmbiguous,
    #[error("AGENT_REGISTRY_RELATIONSHIP_INVALID")]
    RelationshipInvalid,
    #[error("AGENT_REGISTRY_PROPAGATION_FAILED")]
    PropagationFailed,
    #[error("AGENT_REGISTRY_STORE_FAILURE")]
    StoreFailure,
    #[error("AGENT_REGISTRY_PRODUCTION_TRUST_NOT_CONFIGURED")]
    ProductionTrustNotConfigured,
    #[error("AGENT_REGISTRY_TENANT_MISMATCH")]
    TenantMismatch,
    #[error("AGENT_REGISTRY_IDEMPOTENCY_INVALID")]
    IdempotencyInvalid,
    #[error("AGENT_REGISTRY_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("AGENT_REGISTRY_CURSOR_INVALID")]
    CursorInvalid,
    #[error("AGENT_REGISTRY_MANAGEMENT_FORBIDDEN")]
    ManagementForbidden,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::AgentInstanceId;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct LifecyclePort {
        calls: AtomicU32,
    }

    impl LifecyclePropagationPort for LifecyclePort {
        fn revoke_identities(
            &self,
            _: &TenantId,
            _: &str,
            _: &BTreeSet<String>,
            key: &str,
        ) -> Result<String, RegistryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("evidence:{key}"))
        }

        fn revoke_authorizations(
            &self,
            _: &TenantId,
            _: &str,
            key: &str,
        ) -> Result<String, RegistryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("evidence:{key}"))
        }

        fn deactivate_packs(
            &self,
            _: &TenantId,
            _: &str,
            _: &BTreeSet<String>,
            key: &str,
        ) -> Result<String, RegistryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("evidence:{key}"))
        }
    }

    fn asset(tenant: &TenantId) -> AgentAsset {
        let components = BTreeMap::from([
            ("model".into(), "a".repeat(64)),
            ("pack".into(), "b".repeat(64)),
        ]);
        let mut bom = AgentBom {
            schema_version: AGENT_REGISTRY_SCHEMA_VERSION.into(),
            agent_id: "coding-agent".into(),
            components,
            bom_digest: String::new(),
            generated_at: Utc::now(),
        };
        bom.bom_digest = bom.compute_digest();
        AgentAsset {
            schema_version: AGENT_REGISTRY_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            agent_id: "coding-agent".into(),
            display_name: "Coding Agent".into(),
            ownership: Ownership {
                owner_subject: "owner:1".into(),
                sponsor_subject: "sponsor:1".into(),
                confirmed_at: Utc::now(),
                review_due_at: Utc::now() + Duration::days(30),
            },
            environment: "staging".into(),
            lifecycle: LifecycleState::Active,
            agent_type: "CODING".into(),
            endpoints: BTreeSet::from(["a2a://coding".into()]),
            identity_refs: BTreeSet::from([AgentInstanceId::new().0]),
            tool_refs: BTreeSet::from(["coding.repo_read@1.0.0".into()]),
            pack_refs: BTreeSet::from(["coding@1.0.0".into()]),
            requested_permissions: BTreeSet::from(["repo:read".into()]),
            approved_permissions: BTreeSet::from(["repo:read".into()]),
            bom,
            last_activity_at: Utc::now(),
            registered_at: Utc::now(),
        }
    }

    #[test]
    fn discovery_never_elevates_trust_and_cross_tenant_is_hidden() {
        let registry =
            AgentRegistry::new(10, 10).unwrap_or_else(|error| panic!("registry: {error}"));
        let tenant = TenantId::new();
        let observation = DiscoveryObservation {
            schema_version: AGENT_REGISTRY_SCHEMA_VERSION.into(),
            observation_id: "o1".into(),
            tenant_id: tenant.clone(),
            source: ObservationSource::ProtocolDiscovery,
            collector_id: "collector:1".into(),
            endpoint: "mcp://unknown".into(),
            claimed_agent_id: Some("unknown".into()),
            protocol: "MCP".into(),
            observed_component_digests: BTreeMap::new(),
            observed_at: Utc::now(),
            payload_digest: "c".repeat(64),
        };
        registry
            .ingest_observation(observation)
            .unwrap_or_else(|error| panic!("observe: {error}"));
        let findings = PostureEngine::evaluate(&registry, &tenant, Utc::now());
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == PostureKind::Shadow)
        );
        assert!(
            registry
                .search(&TenantId::new(), 0, 10)
                .unwrap_or_else(|error| panic!("search: {error}"))
                .is_empty()
        );
    }

    #[test]
    fn bom_and_permission_drift_trigger_posture() {
        let registry =
            AgentRegistry::new(10, 10).unwrap_or_else(|error| panic!("registry: {error}"));
        let tenant = TenantId::new();
        let mut value = asset(&tenant);
        value.requested_permissions.insert("repo:write".into());
        registry
            .register(value)
            .unwrap_or_else(|error| panic!("register: {error}"));
        let findings = PostureEngine::evaluate(&registry, &tenant, Utc::now());
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == PostureKind::Overprivileged)
        );
    }

    #[test]
    fn retirement_requires_identity_policy_and_pack_convergence() {
        let registry =
            AgentRegistry::new(10, 10).unwrap_or_else(|error| panic!("registry: {error}"));
        let tenant = TenantId::new();
        registry
            .register(asset(&tenant))
            .unwrap_or_else(|error| panic!("register: {error}"));
        let receipt = registry
            .transition_lifecycle(&tenant, "coding-agent", LifecycleState::Retired)
            .unwrap_or_else(|error| panic!("retire: {error}"));
        assert!(receipt.identity_revocation_required);
        assert!(receipt.authorization_revocation_required);
        assert!(receipt.pack_deactivation_required);
        let bytes = registry
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let restored = AgentRegistry::restore(&bytes, 10, 10)
            .unwrap_or_else(|error| panic!("restore: {error}"));
        assert_eq!(
            restored
                .get(&tenant, "coding-agent")
                .unwrap_or_else(|error| panic!("get: {error}"))
                .lifecycle,
            LifecycleState::Retired
        );
    }

    #[test]
    fn coordinated_retirement_invokes_all_revocation_ports_before_state_change() {
        let registry =
            AgentRegistry::new(10, 10).unwrap_or_else(|error| panic!("registry: {error}"));
        let tenant = TenantId::new();
        registry
            .register(asset(&tenant))
            .unwrap_or_else(|error| panic!("register: {error}"));
        let port = LifecyclePort {
            calls: AtomicU32::new(0),
        };
        let coordinator = LifecycleCoordinator::new(&registry, port);
        let receipt = coordinator
            .transition(
                &tenant,
                "coding-agent",
                LifecycleState::Retired,
                "command:1",
            )
            .unwrap_or_else(|error| panic!("retire: {error}"));
        assert!(receipt.converged);
        assert_eq!(receipt.external_evidence_refs.len(), 3);
        assert_eq!(coordinator.port.calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            registry
                .get(&tenant, "coding-agent")
                .unwrap_or_else(|error| panic!("get: {error}"))
                .lifecycle,
            LifecycleState::Retired
        );
    }

    #[test]
    fn relationship_graph_and_discovery_are_tenant_scoped() {
        let tenant = TenantId::new();
        let other = TenantId::new();
        let collector =
            DiscoveryCollector::new("collector:1", BTreeSet::from(["MCP".into(), "A2A".into()]))
                .unwrap_or_else(|error| panic!("collector: {error}"));
        let observation = collector
            .collect(DiscoverySignal {
                tenant_id: tenant.clone(),
                endpoint: "mcp://server".into(),
                claimed_agent_id: Some("coding-agent".into()),
                protocol: "MCP".into(),
                component_digests: BTreeMap::from([("server".into(), "a".repeat(64))]),
                canonical_payload: "mcp://server|coding-agent".into(),
                observed_at: Utc::now(),
            })
            .unwrap_or_else(|error| panic!("collect: {error}"));
        assert_eq!(observation.payload_digest.len(), 64);
        let network = collector
            .collect_as(
                ObservationSource::NetworkObservation,
                DiscoverySignal {
                    tenant_id: tenant.clone(),
                    endpoint: "https://network-observed.invalid".into(),
                    claimed_agent_id: None,
                    protocol: "A2A".into(),
                    component_digests: BTreeMap::new(),
                    canonical_payload: "network-observation".into(),
                    observed_at: Utc::now(),
                },
            )
            .unwrap_or_else(|error| panic!("network observation: {error}"));
        assert_eq!(network.source, ObservationSource::NetworkObservation);

        let graph = RelationshipGraph::new(10).unwrap_or_else(|error| panic!("graph: {error}"));
        graph
            .add(RelationshipEdge {
                schema_version: AGENT_REGISTRY_SCHEMA_VERSION.into(),
                tenant_id: tenant.clone(),
                edge_id: "edge:1".into(),
                from: "agent:coding".into(),
                to: "tool:repo-read".into(),
                kind: RelationshipKind::UsesTool,
                evidence_digest: "b".repeat(64),
            })
            .unwrap_or_else(|error| panic!("edge: {error}"));
        assert_eq!(
            graph
                .query(&tenant, "agent:coding", 2, 10)
                .unwrap_or_else(|error| panic!("query: {error}"))
                .len(),
            1
        );
        assert!(
            graph
                .query(&other, "agent:coding", 2, 10)
                .unwrap_or_else(|error| panic!("query: {error}"))
                .is_empty()
        );
    }

    #[test]
    fn ownership_requires_unique_high_confidence_and_human_confirmation() {
        let now = Utc::now();
        let ownership = OwnershipResolver::resolve(
            &[OwnershipCandidate {
                subject: "owner:1".into(),
                provenance: "iam:directory".into(),
                confidence_millionths: 900_000,
            }],
            "sponsor:1",
            "admin:1",
            now,
            Duration::days(30),
        )
        .unwrap_or_else(|error| panic!("ownership: {error}"));
        assert_eq!(ownership.owner_subject, "owner:1");
        assert_eq!(
            OwnershipResolver::resolve(
                &[
                    OwnershipCandidate {
                        subject: "owner:1".into(),
                        provenance: "iam".into(),
                        confidence_millionths: 900_000,
                    },
                    OwnershipCandidate {
                        subject: "owner:2".into(),
                        provenance: "scm".into(),
                        confidence_millionths: 900_000,
                    },
                ],
                "sponsor:1",
                "admin:1",
                now,
                Duration::days(30),
            ),
            Err(RegistryError::OwnershipAmbiguous)
        );
    }
}
