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
            || now >= central.expires_at
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
    pub resource_key: String,
    pub expected_resource_version: String,
    pub approval_ids: Vec<ApprovalId>,
    pub central_policy_version: String,
    pub maximum_risk: RiskLevel,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
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
}
impl Default for EdgeAuthorizationVerifier {
    fn default() -> Self {
        Self {
            keys: RwLock::new(BTreeMap::new()),
            used: Mutex::new(BTreeSet::new()),
        }
    }
}
impl EdgeAuthorizationVerifier {
    pub fn add_key(&self, key_id: String, issuer: String, key: VerifyingKey) {
        self.keys.write().insert(key_id, (issuer, key));
    }
    pub fn verify_and_consume(
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
        if issuer != auth.issuer || now < auth.issued_at || now >= auth.expires_at {
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndustrialCommitReceipt {
    pub schema_version: String,
    pub preparation_id: String,
    pub before: TelemetrySample,
    pub after: TelemetrySample,
    pub verified: bool,
    pub committed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafeStopRecord {
    pub schema_version: String,
    pub record_id: String,
    pub resource_key: String,
    pub reason_code: String,
    pub requested_by: String,
    pub requested_at: DateTime<Utc>,
    pub local_journal_hash: String,
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
        })
    }
    pub fn set_connected(&self, connected: bool) {
        *self.connected.write() = connected;
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
        self.local_policy
            .verify_not_looser(&self.central_policy.read(), Utc::now())?;
        if !*self.connected.read()
            || !self.local_policy.write_enabled
            || auth.approval_ids.is_empty()
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
            expires_at: auth.expires_at,
        };
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
        self.verifier.verify_and_consume(auth, Utc::now())?;
        let prepared = self
            .prepared
            .lock()
            .remove(preparation_id)
            .ok_or(IndustrialError::PreparationNotFound)?;
        if prepared.authorization_id != auth.authorization_id
            || prepared.action_hash != auth.action_hash
            || Utc::now() >= prepared.expires_at
        {
            return Err(IndustrialError::AuthorizationInvalid);
        }
        let channel = self
            .assets
            .resolve(&auth.tenant_id, &prepared.resource_key)?;
        let after = self
            .adapter
            .compare_and_set(
                &channel,
                &prepared.before.resource_version,
                &prepared.before.value,
                &prepared.target_value,
            )
            .await?;
        validate_fresh_good(&after, channel.freshness_ms, Utc::now())?;
        let verified = after.value == prepared.target_value
            && after.resource_version != prepared.before.resource_version;
        if !verified {
            return Err(IndustrialError::VerificationFailed);
        }
        Ok(IndustrialCommitReceipt {
            schema_version: INDUSTRIAL_SCHEMA_VERSION.into(),
            preparation_id: prepared.preparation_id,
            before: prepared.before,
            after,
            verified,
            committed_at: Utc::now(),
        })
    }
    pub async fn request_safe_stop(
        &self,
        tenant: &TenantId,
        resource_key: &str,
        requested_by: String,
        reason_code: String,
    ) -> Result<SafeStopRecord, IndustrialError> {
        let channel = self.assets.resolve(tenant, resource_key)?;
        self.adapter.safe_stop(&channel).await?;
        let prior = self.safe_stop_records.lock().last().map_or_else(
            || "0".repeat(64),
            |record| record.local_journal_hash.clone(),
        );
        let requested_at = Utc::now();
        let local_journal_hash = hex(Sha256::digest(
            serde_jcs::to_vec(&(
                resource_key,
                &requested_by,
                &reason_code,
                requested_at,
                prior,
            ))
            .map_err(|_| IndustrialError::JournalFailed)?,
        ));
        let record = SafeStopRecord {
            schema_version: INDUSTRIAL_SCHEMA_VERSION.into(),
            record_id: Uuid::new_v4().to_string(),
            resource_key: resource_key.into(),
            reason_code,
            requested_by,
            requested_at,
            local_journal_hash,
        };
        self.safe_stop_records.lock().push(record.clone());
        Ok(record)
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
        if topic.starts_with(allowed_prefix) && qos <= 2 && !topic.contains(['+', '#']) {
            Ok(())
        } else {
            Err(IndustrialError::ProtocolSecurityDenied)
        }
    }
}

fn validate_channel(channel: &AssetChannel) -> Result<(), IndustrialError> {
    if channel.resource.key().contains("..")
        || channel.engineering_unit.is_empty()
        || !channel.minimum.is_finite()
        || !channel.maximum.is_finite()
        || channel.minimum >= channel.maximum
        || channel.maximum_delta_per_write <= 0.0
        || channel.freshness_ms == 0
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
        || sample.sampled_at + chrono::Duration::milliseconds(freshness_ms as i64) < now
    {
        Err(IndustrialError::TelemetryStaleOrBad)
    } else {
        Ok(())
    }
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
            resource_key: key.clone(),
            expected_resource_version: "v1".into(),
            approval_ids: vec![ApprovalId::new()],
            central_policy_version: "central-1".into(),
            maximum_risk: RiskLevel::High,
            issued_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::minutes(1),
            issuer: "central".into(),
            key_id: "key".into(),
            signature: String::new(),
        };
        auth.sign(&signing).unwrap_or_else(|_| panic!("sign"));
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
}
