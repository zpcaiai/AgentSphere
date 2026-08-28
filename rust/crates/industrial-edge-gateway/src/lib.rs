//! Protocol-independent industrial edge safety gateway with simulator adapters.

use agent_trust_contracts::{ActionHash, ApprovalId, RiskLevel, SchemaVersion, TenantId};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};
use thiserror::Error;
use uuid::Uuid;

pub const INDUSTRIAL_SCHEMA_VERSION: &str = "agenttrust.industrial-edge.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndustrialProtocol {
    OpcUa,
    Mqtt,
    Modbus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityCode {
    Good,
    Uncertain,
    Bad,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IndustrialResourceRef {
    pub tenant_id: TenantId,
    pub site: String,
    pub area: String,
    pub line: String,
    pub asset: String,
    pub channel: String,
    pub protocol: IndustrialProtocol,
    pub protocol_address: String,
}

impl IndustrialResourceRef {
    pub fn key(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            self.site, self.area, self.line, self.asset, self.channel
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AssetChannel {
    pub resource: IndustrialResourceRef,
    pub engineering_unit: String,
    pub minimum: f64,
    pub maximum: f64,
    pub maximum_delta_per_write: f64,
    pub writable: bool,
    pub criticality: RiskLevel,
    pub freshness_ms: u64,
    pub byte_order: Option<String>,
    pub allowed_modbus_function_codes: BTreeSet<u8>,
}

#[derive(Default)]
pub struct AssetRegistry {
    channels: RwLock<BTreeMap<(TenantId, String), AssetChannel>>,
}
impl AssetRegistry {
    pub fn register(&self, channel: AssetChannel) -> Result<(), IndustrialError> {
        validate_channel(&channel)?;
        let key = (channel.resource.tenant_id.clone(), channel.resource.key());
        if self.channels.read().contains_key(&key) {
            return Err(IndustrialError::AssetConflict);
        }
        self.channels.write().insert(key, channel);
        Ok(())
    }
    pub fn resolve(&self, tenant: &TenantId, key: &str) -> Result<AssetChannel, IndustrialError> {
        self.channels
            .read()
            .get(&(tenant.clone(), key.into()))
            .cloned()
            .ok_or(IndustrialError::AssetNotFound)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySample {
    pub resource_key: String,
    pub value: Value,
    pub engineering_unit: String,
    pub quality: QualityCode,
    pub resource_version: String,
    pub sampled_at: DateTime<Utc>,
    pub sequence: u64,
}

pub struct TelemetryBuffer {
    capacity: usize,
    samples: Mutex<VecDeque<TelemetrySample>>,
    dropped: Mutex<u64>,
}
impl TelemetryBuffer {
    pub fn new(capacity: usize) -> Result<Self, IndustrialError> {
        if capacity == 0 {
            Err(IndustrialError::ConfigurationInvalid)
        } else {
            Ok(Self {
                capacity,
                samples: Mutex::new(VecDeque::new()),
                dropped: Mutex::new(0),
            })
        }
    }
    pub fn append(&self, sample: TelemetrySample) {
        let mut samples = self.samples.lock();
        if samples.len() == self.capacity {
            samples.pop_front();
            *self.dropped.lock() += 1;
        }
        samples.push_back(sample);
    }
    pub fn flush(&self, maximum: usize) -> Vec<TelemetrySample> {
        let mut samples = self.samples.lock();
        (0..maximum.min(samples.len()))
            .filter_map(|_| samples.pop_front())
            .collect()
    }
    pub fn dropped(&self) -> u64 {
        *self.dropped.lock()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CentralSafetyEnvelope {
    pub schema_version: String,
    pub policy_version: String,
    pub allowed_protocols: BTreeSet<IndustrialProtocol>,
    pub maximum_risk: RiskLevel,
    pub write_enabled: bool,
    pub absolute_minimum: f64,
    pub absolute_maximum: f64,
    pub maximum_delta: f64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalSafetyPolicy {
    pub schema_version: String,
    pub policy_version: String,
    pub allowed_protocols: BTreeSet<IndustrialProtocol>,
    pub maximum_risk: RiskLevel,
    pub write_enabled: bool,
    pub absolute_minimum: f64,
    pub absolute_maximum: f64,
    pub maximum_delta: f64,
}

impl LocalSafetyPolicy {
    pub fn verify_not_looser(
        &self,
        central: &CentralSafetyEnvelope,
        now: DateTime<Utc>,
    ) -> Result<(), IndustrialError> {
        if self.schema_version != INDUSTRIAL_SCHEMA_VERSION
            || central.schema_version != INDUSTRIAL_SCHEMA_VERSION
            || self.policy_version.is_empty()
            || central.policy_version.is_empty()
            || now >= central.expires_at
            || !self.absolute_minimum.is_finite()
            || !self.absolute_maximum.is_finite()
            || !self.maximum_delta.is_finite()
            || !central.absolute_minimum.is_finite()
            || !central.absolute_maximum.is_finite()
            || !central.maximum_delta.is_finite()
            || self.absolute_minimum >= self.absolute_maximum
            || central.absolute_minimum >= central.absolute_maximum
            || self.maximum_delta <= 0.0
            || central.maximum_delta <= 0.0
            || !self.allowed_protocols.is_subset(&central.allowed_protocols)
            || self.maximum_risk > central.maximum_risk
            || (self.write_enabled && !central.write_enabled)
            || self.absolute_minimum < central.absolute_minimum
            || self.absolute_maximum > central.absolute_maximum
            || self.maximum_delta > central.maximum_delta
        {
            return Err(IndustrialError::LocalPolicyTooPermissive);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdgeAuthorization {
    pub schema_version: SchemaVersion,
    pub authorization_id: String,
    pub tenant_id: TenantId,
    pub action_hash: ActionHash,
    pub arguments_digest: String,
    pub resource_key: String,
    pub purpose: String,
    pub expected_resource_version: String,
    pub approval_ids: Vec<ApprovalId>,
    pub central_policy_version: String,
    pub maximum_risk: RiskLevel,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub key_usage: String,
    pub signature: String,
}
impl EdgeAuthorization {
    fn signing_bytes(&self) -> Result<Vec<u8>, IndustrialError> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| IndustrialError::AuthorizationInvalid)
    }
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), IndustrialError> {
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }
}

pub struct EdgeAuthorizationVerifier {
    keys: RwLock<BTreeMap<String, (String, VerifyingKey)>>,
    used: Mutex<BTreeSet<String>>,
    durable_replay: Option<Arc<dyn IndustrialAuthorizationStore>>,
}

pub trait IndustrialAuthorizationStore: Send + Sync {
    /// Atomically inserts the authorization id and binding. Returns false on replay/conflict.
    fn consume_once(&self, authorization: &EdgeAuthorization) -> Result<bool, IndustrialError>;
}
impl Default for EdgeAuthorizationVerifier {
    fn default() -> Self {
        Self {
            keys: RwLock::new(BTreeMap::new()),
            used: Mutex::new(BTreeSet::new()),
            durable_replay: None,
        }
    }
}
impl EdgeAuthorizationVerifier {
    pub fn production(durable_replay: Arc<dyn IndustrialAuthorizationStore>) -> Self {
        Self {
            keys: RwLock::new(BTreeMap::new()),
            used: Mutex::new(BTreeSet::new()),
            durable_replay: Some(durable_replay),
        }
    }
    fn is_production(&self) -> bool {
        self.durable_replay.is_some()
    }
    pub fn add_key(&self, key_id: String, issuer: String, key: VerifyingKey) {
        self.keys.write().insert(key_id, (issuer, key));
    }
    /// Verifies the signed, time-bounded authorization without consuming its single-use id.
    /// Preparation uses this check before reading an asset or writing a PREPARED journal entry;
    /// commit verifies again and atomically consumes the id immediately before dispatch.
    pub fn verify(
        &self,
        auth: &EdgeAuthorization,
        now: DateTime<Utc>,
    ) -> Result<(), IndustrialError> {
        let (issuer, key) = self
            .keys
            .read()
            .get(&auth.key_id)
            .cloned()
            .ok_or(IndustrialError::AuthorizationInvalid)?;
        if issuer != auth.issuer
            || auth.schema_version.0 != INDUSTRIAL_SCHEMA_VERSION
            || auth.authorization_id.is_empty()
            || Uuid::parse_str(&auth.authorization_id).is_err()
            || auth.resource_key.is_empty()
            || auth.resource_key.len() > 1280
            || !matches!(auth.purpose.as_str(), "WRITE" | "SAFE_STOP")
            || !valid_digest(&auth.arguments_digest)
            || auth.expected_resource_version.is_empty()
            || auth.expected_resource_version.len() > 256
            || auth.central_policy_version.is_empty()
            || auth.central_policy_version.len() > 256
            || auth.key_usage != "INDUSTRIAL_EDGE_AUTHORIZATION"
            || !valid_digest(&auth.action_hash.0)
            || auth.approval_ids.is_empty()
            || auth.approval_ids.len() > 128
            || auth.approval_ids.iter().collect::<BTreeSet<_>>().len() != auth.approval_ids.len()
            || now < auth.issued_at
            || now >= auth.expires_at
            || auth.expires_at > auth.issued_at + chrono::Duration::minutes(15)
        {
            return Err(IndustrialError::AuthorizationInvalid);
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&auth.signature)
                .map_err(|_| IndustrialError::AuthorizationInvalid)?,
        )
        .map_err(|_| IndustrialError::AuthorizationInvalid)?;
        key.verify(&auth.signing_bytes()?, &signature)
            .map_err(|_| IndustrialError::AuthorizationInvalid)?;
        Ok(())
    }
    pub fn verify_and_consume(
        &self,
        auth: &EdgeAuthorization,
        now: DateTime<Utc>,
    ) -> Result<(), IndustrialError> {
        self.verify(auth, now)?;
        if let Some(store) = &self.durable_replay
            && !store.consume_once(auth)?
        {
            return Err(IndustrialError::AuthorizationReplayed);
        }
        if !self.used.lock().insert(auth.authorization_id.clone()) {
            return Err(IndustrialError::AuthorizationReplayed);
        }
        Ok(())
    }
}

#[async_trait]
pub trait IndustrialAdapter: Send + Sync {
    async fn read(&self, channel: &AssetChannel) -> Result<TelemetrySample, IndustrialError>;
    async fn compare_and_set(
        &self,
        channel: &AssetChannel,
        expected_version: &str,
        expected_value: &Value,
        new_value: &Value,
    ) -> Result<TelemetrySample, IndustrialError>;
    async fn safe_stop(&self, channel: &AssetChannel) -> Result<(), IndustrialError>;
    /// Production adapters wait for fresh protocol samples. The default is intentionally a single
    /// read and therefore cannot satisfy a production convergence policy requiring two samples.
    async fn observe_after_write(
        &self,
        channel: &AssetChannel,
        maximum_samples: usize,
    ) -> Result<Vec<TelemetrySample>, IndustrialError> {
        if maximum_samples == 0 {
            return Err(IndustrialError::ConfigurationInvalid);
        }
        Ok(vec![self.read(channel).await?])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdgeClockHealth {
    pub synchronized: bool,
    pub absolute_offset_ms: u64,
    pub measured_at: DateTime<Utc>,
    pub source_digest: String,
}

pub trait EdgeClockHealthPort: Send + Sync {
    fn health(&self) -> Result<EdgeClockHealth, IndustrialError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IndustrialConvergencePolicy {
    pub tolerance: f64,
    pub minimum_good_samples: u16,
    pub maximum_samples: u16,
    pub maximum_overshoot: f64,
    pub maximum_oscillations: u16,
    pub maximum_clock_offset_ms: u64,
    pub clock_health_ttl_ms: u64,
}

impl IndustrialConvergencePolicy {
    fn validate(&self, production: bool) -> Result<(), IndustrialError> {
        if !self.tolerance.is_finite()
            || self.tolerance < 0.0
            || self.minimum_good_samples == 0
            || (production && self.minimum_good_samples < 2)
            || self.maximum_samples < self.minimum_good_samples
            || self.maximum_samples > 1024
            || !self.maximum_overshoot.is_finite()
            || self.maximum_overshoot < self.tolerance
            || self.maximum_clock_offset_ms == 0
            || self.maximum_clock_offset_ms > 60_000
            || self.clock_health_ttl_ms == 0
            || self.clock_health_ttl_ms > 86_400_000
        {
            return Err(IndustrialError::ConfigurationInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IndustrialConvergenceEvidence {
    pub target_value: f64,
    pub sample_count: u16,
    pub stable_sample_count: u16,
    pub maximum_observed_error: f64,
    pub oscillations: u16,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub converged: bool,
}

pub trait IndustrialJournal: Send + Sync {
    /// Reloads only a PREPARED action that has no DISPATCHING or terminal journal entry. This is
    /// the crash-recovery authority; implementations must lock the tenant/preparation row while
    /// deciding whether it is still dispatchable.
    fn load_prepared(
        &self,
        tenant_id: &TenantId,
        preparation_id: &str,
    ) -> Result<Option<PreparedIndustrialAction>, IndustrialError>;
    fn record_prepared(
        &self,
        prepared: &PreparedIndustrialAction,
    ) -> Result<String, IndustrialError>;
    fn record_dispatching(
        &self,
        prepared: &PreparedIndustrialAction,
        authorization: &EdgeAuthorization,
    ) -> Result<String, IndustrialError>;
    fn record_commit(&self, receipt: &IndustrialCommitReceipt) -> Result<String, IndustrialError>;
    fn record_unknown(
        &self,
        prepared: &PreparedIndustrialAction,
        stable_error: &str,
    ) -> Result<(), IndustrialError>;
    /// Records a proven pre-write rejection (for example compare-and-set version mismatch).
    /// This is distinct from UNKNOWN because the adapter proves no write was dispatched.
    fn record_noop(
        &self,
        prepared: &PreparedIndustrialAction,
        stable_error: &str,
    ) -> Result<(), IndustrialError>;
    fn record_safe_stop_intent(&self, record: &SafeStopRecord) -> Result<String, IndustrialError>;
    fn record_safe_stop_completed(
        &self,
        record: &SafeStopRecord,
    ) -> Result<String, IndustrialError>;
    fn record_safe_stop_unknown(
        &self,
        record: &SafeStopRecord,
        stable_error: &str,
    ) -> Result<(), IndustrialError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PreparedIndustrialAction {
    pub schema_version: String,
    pub preparation_id: String,
    pub tenant_id: TenantId,
    pub action_hash: ActionHash,
    pub resource_key: String,
    pub before: TelemetrySample,
    pub target_value: Value,
    pub engineering_unit: String,
    pub authorization_id: String,
    pub central_policy_version: String,
    pub local_policy_version: String,
    pub prepared_at: DateTime<Utc>,
    pub clock_health_digest: String,
    pub journal_digest: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IndustrialCommitReceipt {
    pub schema_version: String,
    pub preparation_id: String,
    pub tenant_id: TenantId,
    pub action_hash: ActionHash,
    pub authorization_id: String,
    pub central_policy_version: String,
    pub local_policy_version: String,
    pub before: TelemetrySample,
    pub after: TelemetrySample,
    pub convergence: IndustrialConvergenceEvidence,
    pub verified: bool,
    pub dispatch_journal_digest: String,
    pub journal_digest: String,
    pub committed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SafeStopRecord {
    pub schema_version: String,
    pub record_id: String,
    pub tenant_id: TenantId,
    pub authorization_id: String,
    pub action_hash: ActionHash,
    pub resource_key: String,
    pub reason_code: String,
    pub requested_by: String,
    pub requested_at: DateTime<Utc>,
    pub local_journal_hash: String,
    pub intent_journal_digest: String,
    pub completion_journal_digest: String,
}

pub struct IndustrialGateway<A: IndustrialAdapter> {
    assets: Arc<AssetRegistry>,
    adapter: Arc<A>,
    verifier: Arc<EdgeAuthorizationVerifier>,
    local_policy: LocalSafetyPolicy,
    central_policy: RwLock<CentralSafetyEnvelope>,
    connected: RwLock<bool>,
    prepared: Mutex<BTreeMap<String, PreparedIndustrialAction>>,
    safe_stop_records: Mutex<Vec<SafeStopRecord>>,
    journal: Option<Arc<dyn IndustrialJournal>>,
    clock: Option<Arc<dyn EdgeClockHealthPort>>,
    convergence_policy: IndustrialConvergencePolicy,
}

impl<A: IndustrialAdapter> IndustrialGateway<A> {
    pub fn new(
        assets: Arc<AssetRegistry>,
        adapter: Arc<A>,
        verifier: Arc<EdgeAuthorizationVerifier>,
        local_policy: LocalSafetyPolicy,
        central_policy: CentralSafetyEnvelope,
    ) -> Result<Self, IndustrialError> {
        local_policy.verify_not_looser(&central_policy, Utc::now())?;
        Ok(Self {
            assets,
            adapter,
            verifier,
            local_policy,
            central_policy: RwLock::new(central_policy),
            connected: RwLock::new(true),
            prepared: Mutex::new(BTreeMap::new()),
            safe_stop_records: Mutex::new(vec![]),
            journal: None,
            clock: None,
            convergence_policy: IndustrialConvergencePolicy {
                tolerance: 0.0,
                minimum_good_samples: 1,
                maximum_samples: 1,
                maximum_overshoot: 0.0,
                maximum_oscillations: 0,
                maximum_clock_offset_ms: 1_000,
                clock_health_ttl_ms: 60_000,
            },
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new_production(
        assets: Arc<AssetRegistry>,
        adapter: Arc<A>,
        verifier: Arc<EdgeAuthorizationVerifier>,
        local_policy: LocalSafetyPolicy,
        central_policy: CentralSafetyEnvelope,
        journal: Arc<dyn IndustrialJournal>,
        clock: Arc<dyn EdgeClockHealthPort>,
        convergence_policy: IndustrialConvergencePolicy,
    ) -> Result<Self, IndustrialError> {
        if !verifier.is_production() {
            return Err(IndustrialError::ConfigurationInvalid);
        }
        convergence_policy.validate(true)?;
        let mut gateway = Self::new(assets, adapter, verifier, local_policy, central_policy)?;
        gateway.journal = Some(journal);
        gateway.clock = Some(clock);
        gateway.convergence_policy = convergence_policy;
        gateway.validate_clock(Utc::now())?;
        Ok(gateway)
    }
    pub fn set_connected(&self, connected: bool) {
        *self.connected.write() = connected;
    }
    pub fn update_central_policy(
        &self,
        next: CentralSafetyEnvelope,
        now: DateTime<Utc>,
    ) -> Result<(), IndustrialError> {
        self.local_policy.verify_not_looser(&next, now)?;
        let current = self.central_policy.read().clone();
        let current_digest = hex(Sha256::digest(
            serde_jcs::to_vec(&current).map_err(|_| IndustrialError::ConfigurationInvalid)?,
        ));
        let next_digest = hex(Sha256::digest(
            serde_jcs::to_vec(&next).map_err(|_| IndustrialError::ConfigurationInvalid)?,
        ));
        if next.policy_version == current.policy_version && next_digest != current_digest {
            return Err(IndustrialError::ConfigurationInvalid);
        }
        *self.central_policy.write() = next;
        Ok(())
    }
    pub async fn read(
        &self,
        tenant: &TenantId,
        resource_key: &str,
    ) -> Result<TelemetrySample, IndustrialError> {
        let channel = self.assets.resolve(tenant, resource_key)?;
        self.adapter.read(&channel).await
    }
    pub async fn prepare_write(
        &self,
        auth: &EdgeAuthorization,
        target_value: Value,
        engineering_unit: &str,
    ) -> Result<PreparedIndustrialAction, IndustrialError> {
        let now = Utc::now();
        self.verifier.verify(auth, now)?;
        self.local_policy
            .verify_not_looser(&self.central_policy.read(), now)?;
        let clock_health_digest = self.validate_clock(now)?;
        let central_policy = self.central_policy.read().clone();
        if !*self.connected.read()
            || !self.local_policy.write_enabled
            || auth.purpose != "WRITE"
            || auth.arguments_digest
                != write_arguments_digest(
                    &auth.resource_key,
                    &auth.expected_resource_version,
                    &target_value,
                    engineering_unit,
                )?
            || auth.approval_ids.is_empty()
            || auth.schema_version.0 != INDUSTRIAL_SCHEMA_VERSION
            || auth.central_policy_version != central_policy.policy_version
        {
            return Err(IndustrialError::WriteDenied);
        }
        let channel = self.assets.resolve(&auth.tenant_id, &auth.resource_key)?;
        if !channel.writable
            || channel.criticality > auth.maximum_risk
            || engineering_unit != channel.engineering_unit
            || !self
                .local_policy
                .allowed_protocols
                .contains(&channel.resource.protocol)
        {
            return Err(IndustrialError::WriteDenied);
        }
        let before = self.adapter.read(&channel).await?;
        validate_fresh_good(&before, channel.freshness_ms, Utc::now())?;
        if before.resource_key != auth.resource_key
            || before.engineering_unit != channel.engineering_unit
        {
            return Err(IndustrialError::TelemetryUnavailable);
        }
        if before.resource_version != auth.expected_resource_version {
            return Err(IndustrialError::ResourceVersionChanged);
        }
        let current = before.value.as_f64().ok_or(IndustrialError::ValueInvalid)?;
        let target = target_value.as_f64().ok_or(IndustrialError::ValueInvalid)?;
        let minimum = channel.minimum.max(self.local_policy.absolute_minimum);
        let maximum = channel.maximum.min(self.local_policy.absolute_maximum);
        let maximum_delta = channel
            .maximum_delta_per_write
            .min(self.local_policy.maximum_delta);
        if !(minimum..=maximum).contains(&target) || (target - current).abs() > maximum_delta {
            return Err(IndustrialError::ValueInvalid);
        }
        let prepared = PreparedIndustrialAction {
            schema_version: INDUSTRIAL_SCHEMA_VERSION.into(),
            preparation_id: Uuid::new_v4().to_string(),
            tenant_id: auth.tenant_id.clone(),
            action_hash: auth.action_hash.clone(),
            resource_key: auth.resource_key.clone(),
            before,
            target_value,
            engineering_unit: engineering_unit.into(),
            authorization_id: auth.authorization_id.clone(),
            central_policy_version: central_policy.policy_version,
            local_policy_version: self.local_policy.policy_version.clone(),
            prepared_at: now,
            clock_health_digest,
            journal_digest: String::new(),
            expires_at: auth.expires_at,
        };
        let mut prepared = prepared;
        if let Some(journal) = &self.journal {
            prepared.journal_digest = journal.record_prepared(&prepared)?;
            if !valid_digest(&prepared.journal_digest) {
                return Err(IndustrialError::JournalFailed);
            }
        }
        self.prepared
            .lock()
            .insert(prepared.preparation_id.clone(), prepared.clone());
        Ok(prepared)
    }
    pub async fn commit(
        &self,
        auth: &EdgeAuthorization,
        preparation_id: &str,
    ) -> Result<IndustrialCommitReceipt, IndustrialError> {
        if !*self.connected.read() {
            return Err(IndustrialError::DisconnectedFailClosed);
        }
        self.local_policy
            .verify_not_looser(&self.central_policy.read(), Utc::now())?;
        self.validate_clock(Utc::now())?;
        let prepared = if let Some(prepared) = self.prepared.lock().get(preparation_id).cloned() {
            prepared
        } else if let Some(journal) = &self.journal {
            journal
                .load_prepared(&auth.tenant_id, preparation_id)?
                .ok_or(IndustrialError::PreparationNotFound)?
        } else {
            return Err(IndustrialError::PreparationNotFound);
        };
        if prepared.authorization_id != auth.authorization_id
            || prepared.action_hash != auth.action_hash
            || prepared.tenant_id != auth.tenant_id
            || prepared.central_policy_version != auth.central_policy_version
            || prepared.central_policy_version.as_str()
                != self.central_policy.read().policy_version.as_str()
            || prepared.local_policy_version != self.local_policy.policy_version
            || Utc::now() >= prepared.expires_at
        {
            return Err(IndustrialError::AuthorizationInvalid);
        }
        self.verifier.verify_and_consume(auth, Utc::now())?;
        let channel = self
            .assets
            .resolve(&auth.tenant_id, &prepared.resource_key)?;
        let dispatch_journal_digest = if let Some(journal) = &self.journal {
            let digest = journal.record_dispatching(&prepared, auth)?;
            if !valid_digest(&digest) {
                return Err(IndustrialError::JournalFailed);
            }
            digest
        } else {
            String::new()
        };
        self.prepared.lock().remove(preparation_id);
        let after_result = self
            .adapter
            .compare_and_set(
                &channel,
                &prepared.before.resource_version,
                &prepared.before.value,
                &prepared.target_value,
            )
            .await;
        let after = match after_result {
            Ok(value) => value,
            Err(IndustrialError::ResourceVersionChanged) => {
                if let Some(journal) = &self.journal {
                    journal.record_noop(&prepared, "INDUSTRIAL_RESOURCE_VERSION_CHANGED")?;
                }
                return Err(IndustrialError::ResourceVersionChanged);
            }
            Err(error) => {
                if let Some(journal) = &self.journal {
                    journal.record_unknown(&prepared, &error.to_string())?;
                }
                return Err(IndustrialError::OutcomeUnknown);
            }
        };
        if validate_fresh_good(&after, channel.freshness_ms, Utc::now()).is_err() {
            if let Some(journal) = &self.journal {
                journal.record_unknown(&prepared, "INDUSTRIAL_POST_WRITE_TELEMETRY_INVALID")?;
            }
            return Err(IndustrialError::OutcomeUnknown);
        }
        let mut observations = vec![after.clone()];
        if self.convergence_policy.minimum_good_samples > 1 {
            match self
                .adapter
                .observe_after_write(
                    &channel,
                    usize::from(self.convergence_policy.maximum_samples - 1),
                )
                .await
            {
                Ok(samples) => observations.extend(samples),
                Err(_) => {
                    if let Some(journal) = &self.journal {
                        journal.record_unknown(
                            &prepared,
                            "INDUSTRIAL_CONVERGENCE_OBSERVATION_UNAVAILABLE",
                        )?;
                    }
                    return Err(IndustrialError::OutcomeUnknown);
                }
            }
        }
        let convergence = match verify_convergence(
            &observations,
            prepared
                .target_value
                .as_f64()
                .ok_or(IndustrialError::ValueInvalid)?,
            &prepared.engineering_unit,
            &prepared.resource_key,
            &self.convergence_policy,
            channel.freshness_ms,
            Utc::now(),
        ) {
            Ok(value) => value,
            Err(_) => {
                if let Some(journal) = &self.journal {
                    journal.record_unknown(&prepared, "INDUSTRIAL_CONVERGENCE_NOT_PROVEN")?;
                }
                return Err(IndustrialError::OutcomeUnknown);
            }
        };
        let verified =
            convergence.converged && after.resource_version != prepared.before.resource_version;
        if !verified {
            if let Some(journal) = &self.journal {
                journal.record_unknown(&prepared, "INDUSTRIAL_WRITE_VERIFICATION_NOT_PROVEN")?;
            }
            return Err(IndustrialError::OutcomeUnknown);
        }
        let mut receipt = IndustrialCommitReceipt {
            schema_version: INDUSTRIAL_SCHEMA_VERSION.into(),
            preparation_id: prepared.preparation_id,
            tenant_id: prepared.tenant_id,
            action_hash: prepared.action_hash,
            authorization_id: prepared.authorization_id,
            central_policy_version: prepared.central_policy_version,
            local_policy_version: prepared.local_policy_version,
            before: prepared.before,
            after,
            convergence,
            verified,
            dispatch_journal_digest,
            journal_digest: String::new(),
            committed_at: Utc::now(),
        };
        if let Some(journal) = &self.journal {
            receipt.journal_digest = journal.record_commit(&receipt)?;
            if !valid_digest(&receipt.journal_digest) {
                return Err(IndustrialError::JournalFailed);
            }
        }
        Ok(receipt)
    }
    pub async fn request_safe_stop(
        &self,
        auth: &EdgeAuthorization,
        requested_by: String,
        reason_code: String,
    ) -> Result<SafeStopRecord, IndustrialError> {
        if requested_by.is_empty()
            || requested_by.len() > 256
            || reason_code.is_empty()
            || reason_code.len() > 128
            || reason_code
                .bytes()
                .any(|byte| !(byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'))
        {
            return Err(IndustrialError::RequestInvalid);
        }
        if auth.purpose != "SAFE_STOP"
            || auth.arguments_digest
                != safe_stop_arguments_digest(&auth.resource_key, &auth.expected_resource_version)?
            || auth.central_policy_version != self.central_policy.read().policy_version
        {
            return Err(IndustrialError::AuthorizationInvalid);
        }
        self.verifier.verify_and_consume(auth, Utc::now())?;
        let tenant = &auth.tenant_id;
        let resource_key = &auth.resource_key;
        let channel = self.assets.resolve(tenant, resource_key)?;
        let prior = self
            .safe_stop_records
            .lock()
            .iter()
            .rev()
            .find(|record| &record.tenant_id == tenant)
            .map_or_else(
                || "0".repeat(64),
                |record| record.local_journal_hash.clone(),
            );
        let requested_at = Utc::now();
        let local_journal_hash = hex(Sha256::digest(
            serde_jcs::to_vec(&(
                tenant,
                resource_key,
                &requested_by,
                &reason_code,
                requested_at,
                prior,
            ))
            .map_err(|_| IndustrialError::JournalFailed)?,
        ));
        let mut record = SafeStopRecord {
            schema_version: INDUSTRIAL_SCHEMA_VERSION.into(),
            record_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.clone(),
            authorization_id: auth.authorization_id.clone(),
            action_hash: auth.action_hash.clone(),
            resource_key: resource_key.into(),
            reason_code,
            requested_by,
            requested_at,
            local_journal_hash,
            intent_journal_digest: String::new(),
            completion_journal_digest: String::new(),
        };
        if let Some(journal) = &self.journal {
            record.intent_journal_digest = journal.record_safe_stop_intent(&record)?;
            if !valid_digest(&record.intent_journal_digest) {
                return Err(IndustrialError::JournalFailed);
            }
        }
        if let Err(error) = self.adapter.safe_stop(&channel).await {
            if let Some(journal) = &self.journal {
                journal.record_safe_stop_unknown(&record, &error.to_string())?;
            }
            return Err(IndustrialError::OutcomeUnknown);
        }
        if let Some(journal) = &self.journal {
            match journal.record_safe_stop_completed(&record) {
                Ok(digest) if valid_digest(&digest) => {
                    record.completion_journal_digest = digest;
                }
                Ok(_) | Err(_) => {
                    journal.record_safe_stop_unknown(
                        &record,
                        "INDUSTRIAL_SAFE_STOP_COMPLETION_EVIDENCE_UNKNOWN",
                    )?;
                    return Err(IndustrialError::OutcomeUnknown);
                }
            }
            if !valid_digest(&record.completion_journal_digest) {
                return Err(IndustrialError::OutcomeUnknown);
            }
        }
        self.safe_stop_records.lock().push(record.clone());
        Ok(record)
    }

    fn validate_clock(&self, now: DateTime<Utc>) -> Result<String, IndustrialError> {
        let Some(clock) = &self.clock else {
            return Ok("development-clock-unverified".into());
        };
        let health = clock.health()?;
        if !health.synchronized
            || health.absolute_offset_ms > self.convergence_policy.maximum_clock_offset_ms
            || health.measured_at > now
            || health.measured_at
                + chrono::Duration::milliseconds(self.convergence_policy.clock_health_ttl_ms as i64)
                < now
            || !valid_digest(&health.source_digest)
        {
            return Err(IndustrialError::ClockUnhealthy);
        }
        Ok(hex(Sha256::digest(
            serde_jcs::to_vec(&health).map_err(|_| IndustrialError::ClockUnhealthy)?,
        )))
    }
}

/// Canonical binding shared by the central authorizer and edge prepare path. The digest prevents a
/// caller from reusing an authorization for a different setpoint or engineering unit.
pub fn write_arguments_digest(
    resource_key: &str,
    expected_resource_version: &str,
    target_value: &Value,
    engineering_unit: &str,
) -> Result<String, IndustrialError> {
    if resource_key.is_empty()
        || expected_resource_version.is_empty()
        || engineering_unit.is_empty()
        || !target_value.as_f64().is_some_and(f64::is_finite)
    {
        return Err(IndustrialError::ValueInvalid);
    }
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(&(
            "WRITE",
            resource_key,
            expected_resource_version,
            target_value,
            engineering_unit,
        ))
        .map_err(|_| IndustrialError::ValueInvalid)?,
    )))
}

/// Canonical binding for the side-effecting safe-stop command. Operator reason metadata remains
/// journaled, while the signed grant is scoped to one exact asset/version pair.
pub fn safe_stop_arguments_digest(
    resource_key: &str,
    expected_resource_version: &str,
) -> Result<String, IndustrialError> {
    if resource_key.is_empty() || expected_resource_version.is_empty() {
        return Err(IndustrialError::AuthorizationInvalid);
    }
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(&("SAFE_STOP", resource_key, expected_resource_version))
            .map_err(|_| IndustrialError::AuthorizationInvalid)?,
    )))
}

/// Opaque production protocol session owned by the edge process. Implementations wrap an actual
/// OPC UA, MQTT, or Modbus/TLS client and retain device credentials locally; the control plane
/// never receives them. This port is deliberately not considered real-protocol evidence by itself.
#[async_trait]
pub trait IndustrialProtocolSession: Send + Sync {
    fn protocol(&self) -> IndustrialProtocol;
    fn peer_identity_digest(&self) -> &str;
    fn secure_channel_verified(&self) -> bool;
    async fn read_channel(
        &self,
        channel: &AssetChannel,
    ) -> Result<TelemetrySample, IndustrialError>;
    async fn compare_and_set_channel(
        &self,
        channel: &AssetChannel,
        expected_version: &str,
        expected_value: &Value,
        new_value: &Value,
    ) -> Result<TelemetrySample, IndustrialError>;
    async fn safe_stop_channel(&self, channel: &AssetChannel) -> Result<(), IndustrialError>;
    async fn observe_channel(
        &self,
        channel: &AssetChannel,
        maximum_samples: usize,
    ) -> Result<Vec<TelemetrySample>, IndustrialError>;
}

pub struct ProtocolBackedIndustrialAdapter<S: IndustrialProtocolSession> {
    session: Arc<S>,
    expected_peer_identity_digest: String,
}

impl<S: IndustrialProtocolSession> ProtocolBackedIndustrialAdapter<S> {
    pub fn new(
        session: Arc<S>,
        expected_peer_identity_digest: String,
    ) -> Result<Self, IndustrialError> {
        if !valid_digest(&expected_peer_identity_digest)
            || session.peer_identity_digest() != expected_peer_identity_digest
            || !session.secure_channel_verified()
        {
            return Err(IndustrialError::ProtocolSecurityDenied);
        }
        Ok(Self {
            session,
            expected_peer_identity_digest,
        })
    }
    fn verify_channel(&self, channel: &AssetChannel) -> Result<(), IndustrialError> {
        if self.session.protocol() != channel.resource.protocol
            || self.session.peer_identity_digest() != self.expected_peer_identity_digest
            || !self.session.secure_channel_verified()
        {
            return Err(IndustrialError::ProtocolSecurityDenied);
        }
        match channel.resource.protocol {
            IndustrialProtocol::OpcUa => {
                if channel.resource.protocol_address.is_empty() {
                    return Err(IndustrialError::ProtocolMappingInvalid);
                }
            }
            IndustrialProtocol::Mqtt => {
                MqttAdapter::verify_topic_acl(&channel.resource.protocol_address, "", 1)?;
            }
            IndustrialProtocol::Modbus => {
                let function_code = if channel.writable { 16 } else { 3 };
                if channel.writable {
                    ModbusAdapter::validate_mapping(channel, function_code, 1)?;
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<S: IndustrialProtocolSession> IndustrialAdapter for ProtocolBackedIndustrialAdapter<S> {
    async fn read(&self, channel: &AssetChannel) -> Result<TelemetrySample, IndustrialError> {
        self.verify_channel(channel)?;
        let sample = self.session.read_channel(channel).await?;
        if sample.resource_key != channel.resource.key()
            || sample.engineering_unit != channel.engineering_unit
        {
            return Err(IndustrialError::ProtocolMappingInvalid);
        }
        Ok(sample)
    }
    async fn compare_and_set(
        &self,
        channel: &AssetChannel,
        expected_version: &str,
        expected_value: &Value,
        new_value: &Value,
    ) -> Result<TelemetrySample, IndustrialError> {
        self.verify_channel(channel)?;
        if !channel.writable {
            return Err(IndustrialError::WriteDenied);
        }
        self.session
            .compare_and_set_channel(channel, expected_version, expected_value, new_value)
            .await
    }
    async fn safe_stop(&self, channel: &AssetChannel) -> Result<(), IndustrialError> {
        self.verify_channel(channel)?;
        self.session.safe_stop_channel(channel).await
    }
    async fn observe_after_write(
        &self,
        channel: &AssetChannel,
        maximum_samples: usize,
    ) -> Result<Vec<TelemetrySample>, IndustrialError> {
        self.verify_channel(channel)?;
        self.session.observe_channel(channel, maximum_samples).await
    }
}

#[derive(Default)]
pub struct IndustrialSimulator {
    states: RwLock<BTreeMap<String, TelemetrySample>>,
    safe_stops: Mutex<u32>,
}
impl IndustrialSimulator {
    pub fn set(&self, sample: TelemetrySample) {
        self.states
            .write()
            .insert(sample.resource_key.clone(), sample);
    }
    pub fn safe_stops(&self) -> u32 {
        *self.safe_stops.lock()
    }
}
#[async_trait]
impl IndustrialAdapter for IndustrialSimulator {
    async fn read(&self, channel: &AssetChannel) -> Result<TelemetrySample, IndustrialError> {
        self.states
            .read()
            .get(&channel.resource.key())
            .cloned()
            .ok_or(IndustrialError::TelemetryUnavailable)
    }
    async fn compare_and_set(
        &self,
        channel: &AssetChannel,
        expected_version: &str,
        expected_value: &Value,
        new_value: &Value,
    ) -> Result<TelemetrySample, IndustrialError> {
        let mut states = self.states.write();
        let state = states
            .get_mut(&channel.resource.key())
            .ok_or(IndustrialError::TelemetryUnavailable)?;
        if state.resource_version != expected_version || &state.value != expected_value {
            return Err(IndustrialError::ResourceVersionChanged);
        }
        state.value = new_value.clone();
        state.resource_version = Uuid::new_v4().to_string();
        state.sampled_at = Utc::now();
        state.sequence += 1;
        state.quality = QualityCode::Good;
        Ok(state.clone())
    }
    async fn safe_stop(&self, _channel: &AssetChannel) -> Result<(), IndustrialError> {
        *self.safe_stops.lock() += 1;
        Ok(())
    }
}

pub struct ModbusAdapter;
impl ModbusAdapter {
    pub fn validate_mapping(
        channel: &AssetChannel,
        function_code: u8,
        register_count: u16,
    ) -> Result<(), IndustrialError> {
        if channel.resource.protocol != IndustrialProtocol::Modbus
            || !channel
                .allowed_modbus_function_codes
                .contains(&function_code)
            || register_count == 0
            || register_count > 123
            || !matches!(
                channel.byte_order.as_deref(),
                Some("ABCD" | "BADC" | "CDAB" | "DCBA")
            )
        {
            Err(IndustrialError::ProtocolMappingInvalid)
        } else {
            Ok(())
        }
    }
}
pub struct OpcUaAdapter;
impl OpcUaAdapter {
    pub fn verify_security_mode(
        mode: &str,
        certificate_valid: bool,
    ) -> Result<(), IndustrialError> {
        if certificate_valid && matches!(mode, "Sign" | "SignAndEncrypt") {
            Ok(())
        } else {
            Err(IndustrialError::ProtocolSecurityDenied)
        }
    }
}
pub struct MqttAdapter;
impl MqttAdapter {
    pub fn verify_topic_acl(
        topic: &str,
        allowed_prefix: &str,
        qos: u8,
    ) -> Result<(), IndustrialError> {
        if !topic.is_empty()
            && topic.starts_with(allowed_prefix)
            && qos <= 2
            && !topic.contains(['+', '#'])
        {
            Ok(())
        } else {
            Err(IndustrialError::ProtocolSecurityDenied)
        }
    }
}

fn validate_channel(channel: &AssetChannel) -> Result<(), IndustrialError> {
    let resource_fields = [
        channel.resource.site.as_str(),
        channel.resource.area.as_str(),
        channel.resource.line.as_str(),
        channel.resource.asset.as_str(),
        channel.resource.channel.as_str(),
        channel.resource.protocol_address.as_str(),
    ];
    if channel.resource.key().contains("..")
        || resource_fields.iter().any(|value| {
            value.is_empty()
                || value.len() > 1024
                || value.bytes().any(|byte| byte.is_ascii_control())
        })
        || channel.engineering_unit.is_empty()
        || channel.engineering_unit.len() > 64
        || !channel.minimum.is_finite()
        || !channel.maximum.is_finite()
        || channel.minimum >= channel.maximum
        || channel.maximum_delta_per_write <= 0.0
        || channel.freshness_ms == 0
        || channel.freshness_ms > 86_400_000
        || match channel.resource.protocol {
            IndustrialProtocol::Modbus => {
                !matches!(
                    channel.byte_order.as_deref(),
                    Some("ABCD" | "BADC" | "CDAB" | "DCBA")
                ) || channel
                    .allowed_modbus_function_codes
                    .iter()
                    .any(|code| !matches!(*code, 6 | 16))
            }
            IndustrialProtocol::OpcUa | IndustrialProtocol::Mqtt => {
                channel.byte_order.is_some() || !channel.allowed_modbus_function_codes.is_empty()
            }
        }
    {
        Err(IndustrialError::AssetInvalid)
    } else {
        Ok(())
    }
}
fn validate_fresh_good(
    sample: &TelemetrySample,
    freshness_ms: u64,
    now: DateTime<Utc>,
) -> Result<(), IndustrialError> {
    if sample.quality != QualityCode::Good
        || sample.sampled_at > now
        || sample.sampled_at + chrono::Duration::milliseconds(freshness_ms as i64) < now
    {
        Err(IndustrialError::TelemetryStaleOrBad)
    } else {
        Ok(())
    }
}
fn verify_convergence(
    samples: &[TelemetrySample],
    target: f64,
    engineering_unit: &str,
    resource_key: &str,
    policy: &IndustrialConvergencePolicy,
    freshness_ms: u64,
    now: DateTime<Utc>,
) -> Result<IndustrialConvergenceEvidence, IndustrialError> {
    policy.validate(false)?;
    if samples.len() < usize::from(policy.minimum_good_samples)
        || samples.len() > usize::from(policy.maximum_samples)
        || !target.is_finite()
    {
        return Err(IndustrialError::ConvergenceFailed);
    }
    let mut maximum_error = 0.0_f64;
    let mut stable = 0_u16;
    let mut oscillations = 0_u16;
    let mut prior_sign = 0_i8;
    let mut prior_sequence = None;
    let mut prior_time = None;
    for sample in samples {
        validate_fresh_good(sample, freshness_ms, now)?;
        if sample.engineering_unit != engineering_unit || sample.resource_key != resource_key {
            return Err(IndustrialError::ConvergenceFailed);
        }
        if prior_sequence.is_some_and(|sequence| sample.sequence <= sequence)
            || prior_time.is_some_and(|time| sample.sampled_at <= time)
        {
            return Err(IndustrialError::ConvergenceFailed);
        }
        prior_sequence = Some(sample.sequence);
        prior_time = Some(sample.sampled_at);
        let value = sample
            .value
            .as_f64()
            .filter(|value| value.is_finite())
            .ok_or(IndustrialError::ConvergenceFailed)?;
        let delta = value - target;
        let error = delta.abs();
        maximum_error = maximum_error.max(error);
        if error > policy.maximum_overshoot {
            return Err(IndustrialError::ConvergenceFailed);
        }
        if error <= policy.tolerance {
            stable = stable.saturating_add(1);
        } else {
            stable = 0;
            let sign = if delta.is_sign_positive() { 1 } else { -1 };
            if prior_sign != 0 && prior_sign != sign {
                oscillations = oscillations.saturating_add(1);
            }
            prior_sign = sign;
        }
    }
    let converged =
        stable >= policy.minimum_good_samples && oscillations <= policy.maximum_oscillations;
    if !converged {
        return Err(IndustrialError::ConvergenceFailed);
    }
    Ok(IndustrialConvergenceEvidence {
        target_value: target,
        sample_count: u16::try_from(samples.len())
            .map_err(|_| IndustrialError::ConvergenceFailed)?,
        stable_sample_count: stable,
        maximum_observed_error: maximum_error,
        oscillations,
        first_sequence: samples
            .first()
            .map(|sample| sample.sequence)
            .ok_or(IndustrialError::ConvergenceFailed)?,
        last_sequence: samples
            .last()
            .map(|sample| sample.sequence)
            .ok_or(IndustrialError::ConvergenceFailed)?,
        converged,
    })
}
fn valid_digest(value: &str) -> bool {
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

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IndustrialError {
    #[error("INDUSTRIAL_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("INDUSTRIAL_REQUEST_INVALID")]
    RequestInvalid,
    #[error("INDUSTRIAL_ASSET_INVALID")]
    AssetInvalid,
    #[error("INDUSTRIAL_ASSET_CONFLICT")]
    AssetConflict,
    #[error("INDUSTRIAL_ASSET_NOT_FOUND")]
    AssetNotFound,
    #[error("INDUSTRIAL_LOCAL_POLICY_TOO_PERMISSIVE")]
    LocalPolicyTooPermissive,
    #[error("INDUSTRIAL_AUTHORIZATION_INVALID")]
    AuthorizationInvalid,
    #[error("INDUSTRIAL_AUTHORIZATION_REPLAYED")]
    AuthorizationReplayed,
    #[error("INDUSTRIAL_WRITE_DENIED")]
    WriteDenied,
    #[error("INDUSTRIAL_DISCONNECTED_FAIL_CLOSED")]
    DisconnectedFailClosed,
    #[error("INDUSTRIAL_TELEMETRY_UNAVAILABLE")]
    TelemetryUnavailable,
    #[error("INDUSTRIAL_TELEMETRY_STALE_OR_BAD")]
    TelemetryStaleOrBad,
    #[error("INDUSTRIAL_RESOURCE_VERSION_CHANGED")]
    ResourceVersionChanged,
    #[error("INDUSTRIAL_VALUE_INVALID")]
    ValueInvalid,
    #[error("INDUSTRIAL_PREPARATION_NOT_FOUND")]
    PreparationNotFound,
    #[error("INDUSTRIAL_VERIFICATION_FAILED")]
    VerificationFailed,
    #[error("INDUSTRIAL_PROTOCOL_MAPPING_INVALID")]
    ProtocolMappingInvalid,
    #[error("INDUSTRIAL_PROTOCOL_SECURITY_DENIED")]
    ProtocolSecurityDenied,
    #[error("INDUSTRIAL_JOURNAL_FAILED")]
    JournalFailed,
    #[error("INDUSTRIAL_CLOCK_UNHEALTHY")]
    ClockUnhealthy,
    #[error("INDUSTRIAL_CONVERGENCE_FAILED")]
    ConvergenceFailed,
    #[error("INDUSTRIAL_OUTCOME_UNKNOWN")]
    OutcomeUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(tenant: TenantId) -> AssetChannel {
        AssetChannel {
            resource: IndustrialResourceRef {
                tenant_id: tenant,
                site: "site".into(),
                area: "area".into(),
                line: "line".into(),
                asset: "asset".into(),
                channel: "setpoint".into(),
                protocol: IndustrialProtocol::Modbus,
                protocol_address: "holding:100".into(),
            },
            engineering_unit: "C".into(),
            minimum: 0.0,
            maximum: 100.0,
            maximum_delta_per_write: 10.0,
            writable: true,
            criticality: RiskLevel::High,
            freshness_ms: 1000,
            byte_order: Some("ABCD".into()),
            allowed_modbus_function_codes: BTreeSet::from([6, 16]),
        }
    }
    fn policies() -> (LocalSafetyPolicy, CentralSafetyEnvelope) {
        let local = LocalSafetyPolicy {
            schema_version: INDUSTRIAL_SCHEMA_VERSION.into(),
            policy_version: "local-1".into(),
            allowed_protocols: BTreeSet::from([IndustrialProtocol::Modbus]),
            maximum_risk: RiskLevel::High,
            write_enabled: true,
            absolute_minimum: 0.0,
            absolute_maximum: 100.0,
            maximum_delta: 10.0,
        };
        let central = CentralSafetyEnvelope {
            schema_version: INDUSTRIAL_SCHEMA_VERSION.into(),
            policy_version: "central-1".into(),
            allowed_protocols: BTreeSet::from([IndustrialProtocol::Modbus]),
            maximum_risk: RiskLevel::High,
            write_enabled: true,
            absolute_minimum: 0.0,
            absolute_maximum: 100.0,
            maximum_delta: 10.0,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        (local, central)
    }

    #[test]
    fn unknown_assets_and_protocol_downgrade_are_rejected() {
        assert_eq!(
            AssetRegistry::default()
                .resolve(&TenantId::new(), "unknown")
                .err(),
            Some(IndustrialError::AssetNotFound)
        );
        assert_eq!(
            OpcUaAdapter::verify_security_mode("None", true),
            Err(IndustrialError::ProtocolSecurityDenied)
        );
        let value = channel(TenantId::new());
        assert_eq!(
            ModbusAdapter::validate_mapping(&value, 5, 1),
            Err(IndustrialError::ProtocolMappingInvalid)
        );
    }

    #[test]
    fn edge_policy_cannot_be_looser_than_central() {
        let (mut local, central) = policies();
        local.maximum_delta = 20.0;
        assert_eq!(
            local.verify_not_looser(&central, Utc::now()),
            Err(IndustrialError::LocalPolicyTooPermissive)
        );
    }

    #[tokio::test]
    async fn disconnect_and_state_change_fail_closed() {
        let tenant = TenantId::new();
        let channel = channel(tenant.clone());
        let key = channel.resource.key();
        let assets = Arc::new(AssetRegistry::default());
        assets
            .register(channel.clone())
            .unwrap_or_else(|_| panic!("asset"));
        let simulator = Arc::new(IndustrialSimulator::default());
        simulator.set(TelemetrySample {
            resource_key: key.clone(),
            value: Value::from(50),
            engineering_unit: "C".into(),
            quality: QualityCode::Good,
            resource_version: "v1".into(),
            sampled_at: Utc::now(),
            sequence: 1,
        });
        let signing = SigningKey::from_bytes(&[61u8; 32]);
        let verifier = Arc::new(EdgeAuthorizationVerifier::default());
        verifier.add_key("key".into(), "central".into(), signing.verifying_key());
        let (local, central) = policies();
        let gateway = IndustrialGateway::new(assets, simulator.clone(), verifier, local, central)
            .unwrap_or_else(|_| panic!("gateway"));
        let now = Utc::now();
        let mut auth = EdgeAuthorization {
            schema_version: SchemaVersion(INDUSTRIAL_SCHEMA_VERSION.into()),
            authorization_id: Uuid::new_v4().to_string(),
            tenant_id: tenant,
            action_hash: ActionHash("a".repeat(64)),
            arguments_digest: write_arguments_digest(&key, "v1", &Value::from(55), "C")
                .unwrap_or_else(|_| panic!("arguments digest")),
            resource_key: key.clone(),
            purpose: "WRITE".into(),
            expected_resource_version: "v1".into(),
            approval_ids: vec![ApprovalId::new()],
            central_policy_version: "central-1".into(),
            maximum_risk: RiskLevel::High,
            issued_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::minutes(1),
            issuer: "central".into(),
            key_id: "key".into(),
            key_usage: "INDUSTRIAL_EDGE_AUTHORIZATION".into(),
            signature: String::new(),
        };
        auth.sign(&signing).unwrap_or_else(|_| panic!("sign"));
        let mut tampered = auth.clone();
        tampered.resource_key.push_str("-tampered");
        assert_eq!(
            gateway
                .prepare_write(&tampered, Value::from(55), "C")
                .await
                .err(),
            Some(IndustrialError::AuthorizationInvalid)
        );
        let prepared = gateway
            .prepare_write(&auth, Value::from(55), "C")
            .await
            .unwrap_or_else(|_| panic!("prepare"));
        gateway.set_connected(false);
        assert_eq!(
            gateway.commit(&auth, &prepared.preparation_id).await.err(),
            Some(IndustrialError::DisconnectedFailClosed)
        );
        gateway.set_connected(true);
        simulator
            .compare_and_set(&channel, "v1", &Value::from(50), &Value::from(52))
            .await
            .unwrap_or_else(|_| panic!("external change"));
        assert_eq!(
            gateway.commit(&auth, &prepared.preparation_id).await.err(),
            Some(IndustrialError::ResourceVersionChanged)
        );
    }

    #[test]
    fn telemetry_buffer_is_bounded() {
        let buffer = TelemetryBuffer::new(1).unwrap_or_else(|_| panic!("buffer"));
        let sample = TelemetrySample {
            resource_key: "r".into(),
            value: Value::from(1),
            engineering_unit: "C".into(),
            quality: QualityCode::Good,
            resource_version: "v".into(),
            sampled_at: Utc::now(),
            sequence: 1,
        };
        buffer.append(sample.clone());
        buffer.append(sample);
        assert_eq!(buffer.dropped(), 1);
    }

    #[test]
    fn convergence_requires_fresh_ordered_same_resource_samples() {
        let now = Utc::now();
        let policy = IndustrialConvergencePolicy {
            tolerance: 0.1,
            minimum_good_samples: 2,
            maximum_samples: 3,
            maximum_overshoot: 2.0,
            maximum_oscillations: 1,
            maximum_clock_offset_ms: 100,
            clock_health_ttl_ms: 1_000,
        };
        let samples = [
            TelemetrySample {
                resource_key: "site/area/line/asset/setpoint".into(),
                value: Value::from(9.95),
                engineering_unit: "C".into(),
                quality: QualityCode::Good,
                resource_version: "v2".into(),
                sampled_at: now - chrono::Duration::milliseconds(2),
                sequence: 2,
            },
            TelemetrySample {
                resource_key: "site/area/line/asset/setpoint".into(),
                value: Value::from(10.02),
                engineering_unit: "C".into(),
                quality: QualityCode::Good,
                resource_version: "v3".into(),
                sampled_at: now - chrono::Duration::milliseconds(1),
                sequence: 3,
            },
        ];
        let evidence = verify_convergence(
            &samples,
            10.0,
            "C",
            "site/area/line/asset/setpoint",
            &policy,
            1_000,
            now,
        )
        .unwrap_or_else(|_| panic!("convergence"));
        assert!(evidence.converged);
        let mut future = samples;
        future[1].sampled_at = now + chrono::Duration::seconds(1);
        assert_eq!(
            verify_convergence(
                &future,
                10.0,
                "C",
                "site/area/line/asset/setpoint",
                &policy,
                1_000,
                now,
            ),
            Err(IndustrialError::TelemetryStaleOrBad)
        );
    }

    #[test]
    fn same_policy_version_cannot_change_content() {
        let tenant = TenantId::new();
        let assets = Arc::new(AssetRegistry::default());
        assets
            .register(channel(tenant))
            .unwrap_or_else(|_| panic!("asset"));
        let verifier = Arc::new(EdgeAuthorizationVerifier::default());
        let (local, central) = policies();
        let gateway = IndustrialGateway::new(
            assets,
            Arc::new(IndustrialSimulator::default()),
            verifier,
            local,
            central.clone(),
        )
        .unwrap_or_else(|_| panic!("gateway"));
        let mut drifted = central;
        drifted.maximum_delta = 11.0;
        assert_eq!(
            gateway.update_central_policy(drifted, Utc::now()),
            Err(IndustrialError::ConfigurationInvalid)
        );
    }
}
