//! Strict parsing, normalization, canonicalization, signing, and policy input.

use agent_trust_contracts::{
    ActionHash, ActionId, AgentIdentity, DataContext, ExecutionEnvironment, ExpectedOutcome,
    Intent, ResourceSelector, RiskLevel, SchemaVersion, StepId, StrictJsonObject, TaskId, ToolRef,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Timelike, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{
    Deserialize, Serialize,
    de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use url::Url;

pub const ACTION_SCHEMA_VERSION: &str = "agenttrust.action.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub profile: String,
    pub resource_prefix: String,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TypedPayload {
    pub type_id: String,
    pub schema_version: String,
    pub data: StrictJsonObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionDraft {
    pub schema_version: SchemaVersion,
    pub action_id: ActionId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub agent: AgentIdentity,
    pub intent: Intent,
    pub tool: ToolRef,
    pub payload: TypedPayload,
    pub resource: ResourceSelector,
    pub environment: ExecutionEnvironment,
    pub current_state_version: Option<String>,
    pub risk: agent_trust_contracts::RiskContext,
    pub data: DataContext,
    pub expected_outcome: ExpectedOutcome,
    pub credential_refs: Vec<CredentialRef>,
    pub requested_at: DateTime<Utc>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAction {
    pub schema_version: SchemaVersion,
    pub action_id: ActionId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub agent: AgentIdentity,
    pub intent: Intent,
    pub tool: ToolRef,
    pub payload: TypedPayload,
    pub resource: ResourceSelector,
    pub environment: ExecutionEnvironment,
    pub current_state_version: Option<String>,
    pub risk: agent_trust_contracts::RiskContext,
    pub data: DataContext,
    pub expected_outcome: ExpectedOutcome,
    pub credential_refs: Vec<CredentialRef>,
    pub requested_at: DateTime<Utc>,
    pub extensions: BTreeMap<String, Value>,
}

impl CanonicalAction {
    pub fn arguments(&self) -> &StrictJsonObject {
        &self.payload.data
    }
}

#[derive(Debug, Clone)]
pub struct ParseLimits {
    pub max_body_bytes: usize,
    pub max_depth: usize,
    pub max_array_items: usize,
    pub max_string_bytes: usize,
    pub max_object_keys: usize,
    pub max_number_chars: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1_048_576,
            max_depth: 32,
            max_array_items: 1_024,
            max_string_bytes: 65_536,
            max_object_keys: 256,
            max_number_chars: 128,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NormalizationContext {
    pub allowed_resource_schemes: BTreeSet<String>,
    pub payload_types: PayloadTypeRegistry,
}

impl Default for NormalizationContext {
    fn default() -> Self {
        Self {
            allowed_resource_schemes: ["repo", "file", "database", "opcua", "mqtt", "http"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            payload_types: PayloadTypeRegistry::with_defaults(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PayloadTypeRegistry {
    versions: BTreeMap<String, BTreeSet<String>>,
}

impl PayloadTypeRegistry {
    pub fn with_defaults() -> Self {
        let mut registry = Self::default();
        registry.register("coding.patch.v1", "1");
        registry.register("coding.command.v1", "1");
        registry.register("industrial.read.v1", "1");
        registry.register("industrial.setpoint.v1", "1");
        registry
    }
    pub fn register(&mut self, type_id: impl Into<String>, version: impl Into<String>) {
        self.versions
            .entry(type_id.into())
            .or_default()
            .insert(version.into());
    }
    pub fn contains(&self, type_id: &str, version: &str) -> bool {
        self.versions
            .get(type_id)
            .is_some_and(|versions| versions.contains(version))
    }
}

#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub require_current_state_for_writes: bool,
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self {
            require_current_state_for_writes: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationFinding {
    pub field_path: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationReport {
    pub valid: bool,
    pub findings: Vec<ValidationFinding>,
}

pub trait ActionValidator: Send + Sync {
    fn validate(&self, action: &CanonicalAction, ctx: &ValidationContext)
    -> Vec<ValidationFinding>;
}

pub struct CoreActionValidator;

impl ActionValidator for CoreActionValidator {
    fn validate(
        &self,
        action: &CanonicalAction,
        ctx: &ValidationContext,
    ) -> Vec<ValidationFinding> {
        let mut findings = Vec::new();
        if action.agent.tenant_id != action.environment.tenant_id
            || action.resource.tenant_id != action.environment.tenant_id
        {
            findings.push(finding("$.environment.tenant_id", "TENANT_MISMATCH"));
        }
        if action
            .environment
            .deployment
            .eq_ignore_ascii_case("production")
            && action.environment.simulation
        {
            findings.push(finding(
                "$.environment.simulation",
                "PRODUCTION_SIMULATION_CONFLICT",
            ));
        }
        if action.expected_outcome.metric.trim().is_empty()
            || action.expected_outcome.target.is_null()
        {
            findings.push(finding(
                "$.expected_outcome",
                "EXPECTED_OUTCOME_NOT_MACHINE_EVALUABLE",
            ));
        }
        if action.risk.declared_risk == RiskLevel::Critical && action.risk.automation_allowed {
            findings.push(finding(
                "$.risk.automation_allowed",
                "CRITICAL_AUTO_EXECUTION_DENIED",
            ));
        }
        let operation = action.intent.operation.to_ascii_lowercase();
        let is_write = !["read", "get", "list", "search", "inspect"].contains(&operation.as_str());
        if is_write
            && ctx.require_current_state_for_writes
            && action
                .current_state_version
                .as_deref()
                .unwrap_or_default()
                .is_empty()
        {
            findings.push(finding(
                "$.current_state_version",
                "RESOURCE_VERSION_REQUIRED",
            ));
        }
        for (index, credential) in action.credential_refs.iter().enumerate() {
            if !action
                .resource
                .locator
                .starts_with(&credential.resource_prefix)
            {
                findings.push(finding(
                    &format!("$.credential_refs[{index}]"),
                    "CREDENTIAL_SCOPE_EXCEEDED",
                ));
            }
        }
        findings
    }
}

fn finding(path: &str, reason: &str) -> ValidationFinding {
    ValidationFinding {
        field_path: path.into(),
        reason_code: reason.into(),
    }
}

pub fn parse_draft(bytes: &[u8], limits: &ParseLimits) -> Result<ActionDraft, ActionIrError> {
    let value = parse_strict_json(bytes, limits)?;
    let draft: ActionDraft = serde_json::from_value(value).map_err(|error| {
        let message = error.to_string();
        if message.contains("unknown variant") {
            ActionIrError::UnknownEnum {
                field_path: "$".into(),
            }
        } else {
            ActionIrError::parse("$", "schema_invalid")
        }
    })?;
    if draft.schema_version.0 != ACTION_SCHEMA_VERSION {
        return Err(ActionIrError::UnknownVersion);
    }
    Ok(draft)
}

pub fn parse_strict_json(bytes: &[u8], limits: &ParseLimits) -> Result<Value, ActionIrError> {
    if bytes.len() > limits.max_body_bytes {
        return Err(ActionIrError::size("$", "body"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ActionIrError::parse("$", "invalid_utf8"))?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictValueSeed { limits, depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(map_parse_error)?;
    deserializer.end().map_err(map_parse_error)?;
    Ok(value)
}

pub fn normalize(
    mut draft: ActionDraft,
    ctx: &NormalizationContext,
) -> Result<CanonicalAction, ActionIrError> {
    draft
        .tool
        .validate_exact()
        .map_err(|_| ActionIrError::SemanticInvalid {
            field_path: "$.tool.tool_version".into(),
            reason_code: "VERSION_REQUIRED".into(),
        })?;
    draft.resource.scheme = draft.resource.scheme.trim().to_ascii_lowercase();
    if !ctx
        .allowed_resource_schemes
        .contains(&draft.resource.scheme)
    {
        return Err(ActionIrError::SemanticInvalid {
            field_path: "$.resource.scheme".into(),
            reason_code: "UNKNOWN_RESOURCE_SCHEME".into(),
        });
    }
    if !ctx
        .payload_types
        .contains(&draft.payload.type_id, &draft.payload.schema_version)
    {
        return Err(ActionIrError::SemanticInvalid {
            field_path: "$.payload".into(),
            reason_code: "UNKNOWN_PAYLOAD_TYPE".into(),
        });
    }
    draft.intent.operation = draft.intent.operation.trim().to_ascii_lowercase();
    draft.intent.justification_code = draft.intent.justification_code.trim().to_ascii_uppercase();
    draft.payload.type_id = draft.payload.type_id.trim().to_ascii_lowercase();
    draft.requested_at = draft
        .requested_at
        .with_nanosecond((draft.requested_at.nanosecond() / 1_000_000) * 1_000_000)
        .ok_or(ActionIrError::NormalizationFailed)?;
    draft.resource.locator = normalize_locator(&draft.resource.scheme, &draft.resource.locator)?;
    reject_sensitive_keys(&Value::Object(draft.payload.data.clone()), "$.payload.data")?;
    for key in draft.extensions.keys() {
        if !key.starts_with("x-") {
            return Err(ActionIrError::SemanticInvalid {
                field_path: "$.extensions".into(),
                reason_code: "EXTENSION_NAMESPACE_REQUIRED".into(),
            });
        }
    }
    let action = CanonicalAction {
        schema_version: draft.schema_version,
        action_id: draft.action_id,
        task_id: draft.task_id,
        step_id: draft.step_id,
        agent: draft.agent,
        intent: draft.intent,
        tool: draft.tool,
        payload: draft.payload,
        resource: draft.resource,
        environment: draft.environment,
        current_state_version: draft.current_state_version,
        risk: draft.risk,
        data: draft.data,
        expected_outcome: draft.expected_outcome,
        credential_refs: draft.credential_refs,
        requested_at: draft.requested_at,
        extensions: draft.extensions,
    };
    let report = validate(&action, &ValidationContext::default())?;
    if !report.valid {
        let first = report
            .findings
            .into_iter()
            .next()
            .ok_or(ActionIrError::NormalizationFailed)?;
        return Err(ActionIrError::SemanticInvalid {
            field_path: first.field_path,
            reason_code: first.reason_code,
        });
    }
    Ok(action)
}

fn normalize_locator(scheme: &str, locator: &str) -> Result<String, ActionIrError> {
    let nfc = locator.nfc().collect::<String>();
    if nfc.as_bytes().contains(&0) {
        return Err(ActionIrError::SemanticInvalid {
            field_path: "$.resource.locator".into(),
            reason_code: "NUL_BYTE".into(),
        });
    }
    if scheme == "http" {
        let url = Url::parse(&nfc).map_err(|_| ActionIrError::SemanticInvalid {
            field_path: "$.resource.locator".into(),
            reason_code: "URL_INVALID".into(),
        })?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ActionIrError::SemanticInvalid {
                field_path: "$.resource.locator".into(),
                reason_code: "URL_CREDENTIALS_DENIED".into(),
            });
        }
        return Ok(url.to_string());
    }
    let mut segments = Vec::new();
    for segment in nfc.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                return Err(ActionIrError::SemanticInvalid {
                    field_path: "$.resource.locator".into(),
                    reason_code: "PATH_TRAVERSAL".into(),
                });
            }
            other => segments.push(other),
        }
    }
    Ok(segments.join("/"))
}

fn reject_sensitive_keys(value: &Value, path: &str) -> Result<(), ActionIrError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if ["password", "token", "secret", "private_key", "api_key"]
                    .contains(&lower.as_str())
                {
                    return Err(ActionIrError::SecretInline {
                        field_path: format!("{path}.{key}"),
                    });
                }
                reject_sensitive_keys(child, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                reject_sensitive_keys(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate(
    action: &CanonicalAction,
    ctx: &ValidationContext,
) -> Result<ValidationReport, ActionIrError> {
    let findings = CoreActionValidator.validate(action, ctx);
    Ok(ValidationReport {
        valid: findings.is_empty(),
        findings,
    })
}

#[derive(Serialize)]
struct ActionHashMaterial<'a> {
    schema_version: &'a SchemaVersion,
    task_id: &'a TaskId,
    step_id: &'a StepId,
    agent: &'a AgentIdentity,
    intent: &'a Intent,
    tool: &'a ToolRef,
    payload: &'a TypedPayload,
    resource: &'a ResourceSelector,
    environment: &'a ExecutionEnvironment,
    current_state_version: &'a Option<String>,
    risk: &'a agent_trust_contracts::RiskContext,
    data: &'a DataContext,
    expected_outcome: &'a ExpectedOutcome,
    credential_refs: &'a [CredentialRef],
    extensions: &'a BTreeMap<String, Value>,
}

pub fn canonical_bytes(action: &CanonicalAction) -> Result<Vec<u8>, ActionIrError> {
    let material = ActionHashMaterial {
        schema_version: &action.schema_version,
        task_id: &action.task_id,
        step_id: &action.step_id,
        agent: &action.agent,
        intent: &action.intent,
        tool: &action.tool,
        payload: &action.payload,
        resource: &action.resource,
        environment: &action.environment,
        current_state_version: &action.current_state_version,
        risk: &action.risk,
        data: &action.data,
        expected_outcome: &action.expected_outcome,
        credential_refs: &action.credential_refs,
        extensions: &action.extensions,
    };
    serde_jcs::to_vec(&material).map_err(|_| ActionIrError::CanonicalizationFailed)
}

pub fn hash(action: &CanonicalAction) -> Result<ActionHash, ActionIrError> {
    Ok(ActionHash(hex::encode(Sha256::digest(canonical_bytes(
        action,
    )?))))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActionEnvelope {
    pub canonical_action: CanonicalAction,
    pub action_hash: ActionHash,
    pub signer_id: String,
    pub signature_algorithm: String,
    pub key_id: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct EnvelopeSignatureMaterial<'a> {
    action_hash: &'a ActionHash,
    signer_id: &'a str,
    signature_algorithm: &'a str,
    key_id: &'a str,
    signed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

fn envelope_signing_bytes(envelope: &SignedActionEnvelope) -> Result<Vec<u8>, ActionIrError> {
    serde_jcs::to_vec(&EnvelopeSignatureMaterial {
        action_hash: &envelope.action_hash,
        signer_id: &envelope.signer_id,
        signature_algorithm: &envelope.signature_algorithm,
        key_id: &envelope.key_id,
        signed_at: envelope.signed_at,
        expires_at: envelope.expires_at,
    })
    .map_err(|_| ActionIrError::CanonicalizationFailed)
}

pub fn sign_envelope(
    action: CanonicalAction,
    signer_id: String,
    key_id: String,
    key: &SigningKey,
    ttl: chrono::Duration,
) -> Result<SignedActionEnvelope, ActionIrError> {
    let signed_at = Utc::now();
    let mut envelope = SignedActionEnvelope {
        action_hash: hash(&action)?,
        canonical_action: action,
        signer_id,
        signature_algorithm: "Ed25519".into(),
        key_id,
        signature: String::new(),
        signed_at,
        expires_at: signed_at + ttl,
    };
    envelope.signature =
        URL_SAFE_NO_PAD.encode(key.sign(&envelope_signing_bytes(&envelope)?).to_bytes());
    Ok(envelope)
}

pub trait KeyProvider: Send + Sync {
    fn verifying_key(&self, key_id: &str, signer_id: &str) -> Result<VerifyingKey, ActionIrError>;
    fn is_revoked(&self, key_id: &str) -> bool;
    fn signer_is_bound(&self, signer_id: &str, agent: &AgentIdentity) -> bool;
}

#[derive(Debug, Clone)]
pub struct VerifiedAction(CanonicalAction);

impl VerifiedAction {
    pub fn action(&self) -> &CanonicalAction {
        &self.0
    }
}

pub fn verify_envelope(
    envelope: &SignedActionEnvelope,
    keys: &dyn KeyProvider,
    now: DateTime<Utc>,
) -> Result<VerifiedAction, ActionIrError> {
    if envelope.canonical_action.schema_version.0 != ACTION_SCHEMA_VERSION {
        return Err(ActionIrError::UnknownVersion);
    }
    if hash(&envelope.canonical_action)? != envelope.action_hash {
        return Err(ActionIrError::HashMismatch);
    }
    if envelope.signature_algorithm != "Ed25519" {
        return Err(ActionIrError::SignatureInvalid);
    }
    if keys.is_revoked(&envelope.key_id) {
        return Err(ActionIrError::SignerUntrusted);
    }
    if now < envelope.signed_at || now >= envelope.expires_at {
        return Err(ActionIrError::Expired);
    }
    if !keys.signer_is_bound(&envelope.signer_id, &envelope.canonical_action.agent) {
        return Err(ActionIrError::SignerUntrusted);
    }
    let key = keys.verifying_key(&envelope.key_id, &envelope.signer_id)?;
    let raw = URL_SAFE_NO_PAD
        .decode(&envelope.signature)
        .map_err(|_| ActionIrError::SignatureInvalid)?;
    let signature = Signature::from_slice(&raw).map_err(|_| ActionIrError::SignatureInvalid)?;
    key.verify(&envelope_signing_bytes(envelope)?, &signature)
        .map_err(|_| ActionIrError::SignatureInvalid)?;
    Ok(VerifiedAction(envelope.canonical_action.clone()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPolicySnapshot {
    pub snapshot_hash: String,
    pub tool_id: String,
    pub tool_version: String,
    pub risk: RiskLevel,
    pub effect: agent_trust_contracts::EffectClass,
    pub implementation_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeContext {
    pub identity_subject: String,
    pub prior_approvals: Vec<String>,
    pub budget_remaining_microunits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryRiskSnapshot {
    pub version: String,
    pub accumulated_resources: Vec<String>,
    pub anomaly_score_millionths: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub subject: Value,
    pub intent: Intent,
    pub tool: RegistryPolicySnapshot,
    pub arguments: StrictJsonObject,
    pub resource: ResourceSelector,
    pub environment: ExecutionEnvironment,
    pub current_state_version: Option<String>,
    pub data_classification: agent_trust_contracts::DataClassification,
    pub trajectory_risk: TrajectoryRiskSnapshot,
    pub registry_snapshot_hash: String,
    pub runtime: RuntimeContext,
}

pub fn to_policy_input(
    action: &CanonicalAction,
    registry: &RegistryPolicySnapshot,
    runtime: &RuntimeContext,
    trajectory: &TrajectoryRiskSnapshot,
) -> Result<PolicyInput, ActionIrError> {
    if action.tool.tool_id.0 != registry.tool_id
        || action.tool.tool_version.0 != registry.tool_version
    {
        return Err(ActionIrError::PolicyInputFailed);
    }
    Ok(PolicyInput {
        subject: serde_json::to_value(&action.agent)
            .map_err(|_| ActionIrError::PolicyInputFailed)?,
        intent: action.intent.clone(),
        tool: registry.clone(),
        arguments: action.payload.data.clone(),
        resource: action.resource.clone(),
        environment: action.environment.clone(),
        current_state_version: action.current_state_version.clone(),
        data_classification: action.data.classification,
        trajectory_risk: trajectory.clone(),
        registry_snapshot_hash: registry.snapshot_hash.clone(),
        runtime: runtime.clone(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionMigrationRecord {
    pub source_version: String,
    pub target_version: String,
    pub migration_id: String,
    pub before_hash: String,
    pub after_hash: String,
}

pub fn migrate_v0_to_v1(mut input: Value) -> Result<(Value, ActionMigrationRecord), ActionIrError> {
    let before = hex::encode(Sha256::digest(
        serde_jcs::to_vec(&input).map_err(|_| ActionIrError::MigrationLossy)?,
    ));
    let object = input.as_object_mut().ok_or(ActionIrError::MigrationLossy)?;
    let version = object
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or(ActionIrError::MigrationLossy)?;
    if version != "agenttrust.action.v0" {
        return Err(ActionIrError::UnknownVersion);
    }
    if object.contains_key("arguments") && object.contains_key("payload") {
        return Err(ActionIrError::MigrationLossy);
    }
    let arguments = object
        .remove("arguments")
        .ok_or(ActionIrError::MigrationLossy)?;
    let data = arguments
        .as_object()
        .ok_or(ActionIrError::MigrationLossy)?
        .clone();
    object.insert(
        "payload".into(),
        serde_json::json!({"type_id":"coding.command.v1","schema_version":"1","data":data}),
    );
    object.insert(
        "schema_version".into(),
        Value::String(ACTION_SCHEMA_VERSION.into()),
    );
    let after = hex::encode(Sha256::digest(
        serde_jcs::to_vec(&input).map_err(|_| ActionIrError::MigrationLossy)?,
    ));
    Ok((
        input,
        ActionMigrationRecord {
            source_version: "agenttrust.action.v0".into(),
            target_version: ACTION_SCHEMA_VERSION.into(),
            migration_id: "action-v0-to-v1-001".into(),
            before_hash: before,
            after_hash: after,
        },
    ))
}

struct StrictValueSeed<'a> {
    limits: &'a ParseLimits,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > self.limits.max_depth {
            return Err(D::Error::custom("ACTION_IR_SIZE_LIMIT_EXCEEDED:depth"));
        }
        deserializer.deserialize_any(StrictValueVisitor {
            limits: self.limits,
            depth: self.depth,
        })
    }
}

struct StrictValueVisitor<'a> {
    limits: &'a ParseLimits,
    depth: usize,
}

impl<'de> Visitor<'de> for StrictValueVisitor<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON value")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        if !value.is_finite() {
            return Err(E::custom("ACTION_IR_PARSE_FAILED:non_finite"));
        }
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("ACTION_IR_PARSE_FAILED:number"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        self.visit_string(value.to_string())
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() > self.limits.max_string_bytes {
            return Err(E::custom("ACTION_IR_SIZE_LIMIT_EXCEEDED:string"));
        }
        Ok(Value::String(value))
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        StrictValueSeed {
            limits: self.limits,
            depth: self.depth + 1,
        }
        .deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(StrictValueSeed {
            limits: self.limits,
            depth: self.depth + 1,
        })? {
            if values.len() >= self.limits.max_array_items {
                return Err(A::Error::custom("ACTION_IR_SIZE_LIMIT_EXCEEDED:array"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > self.limits.max_string_bytes {
                return Err(A::Error::custom("ACTION_IR_SIZE_LIMIT_EXCEEDED:key"));
            }
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("ACTION_IR_DUPLICATE_KEY:{key}")));
            }
            if values.len() >= self.limits.max_object_keys {
                return Err(A::Error::custom("ACTION_IR_SIZE_LIMIT_EXCEEDED:object"));
            }
            let value = map.next_value_seed(StrictValueSeed {
                limits: self.limits,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn map_parse_error(error: serde_json::Error) -> ActionIrError {
    let message = error.to_string();
    if message.contains("ACTION_IR_DUPLICATE_KEY") {
        ActionIrError::DuplicateKey {
            field_path: "$".into(),
        }
    } else if message.contains("ACTION_IR_SIZE_LIMIT_EXCEEDED") {
        ActionIrError::size("$", "json_limit")
    } else {
        ActionIrError::parse("$", "malformed_json")
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ActionIrError {
    #[error("ACTION_IR_PARSE_FAILED")]
    ParseFailed {
        field_path: String,
        reason_code: String,
    },
    #[error("ACTION_IR_DUPLICATE_KEY")]
    DuplicateKey { field_path: String },
    #[error("ACTION_IR_UNKNOWN_VERSION")]
    UnknownVersion,
    #[error("ACTION_IR_UNKNOWN_ENUM")]
    UnknownEnum { field_path: String },
    #[error("ACTION_IR_SIZE_LIMIT_EXCEEDED")]
    SizeLimitExceeded {
        field_path: String,
        reason_code: String,
    },
    #[error("ACTION_IR_NORMALIZATION_FAILED")]
    NormalizationFailed,
    #[error("ACTION_IR_SEMANTIC_INVALID")]
    SemanticInvalid {
        field_path: String,
        reason_code: String,
    },
    #[error("ACTION_IR_SECRET_INLINE")]
    SecretInline { field_path: String },
    #[error("ACTION_IR_CANONICALIZATION_FAILED")]
    CanonicalizationFailed,
    #[error("ACTION_IR_HASH_MISMATCH")]
    HashMismatch,
    #[error("ACTION_IR_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("ACTION_IR_SIGNER_UNTRUSTED")]
    SignerUntrusted,
    #[error("ACTION_IR_EXPIRED")]
    Expired,
    #[error("ACTION_IR_MIGRATION_LOSSY")]
    MigrationLossy,
    #[error("ACTION_IR_POLICY_INPUT_FAILED")]
    PolicyInputFailed,
}

impl ActionIrError {
    fn parse(path: &str, reason: &str) -> Self {
        Self::ParseFailed {
            field_path: path.into(),
            reason_code: reason.into(),
        }
    }
    fn size(path: &str, reason: &str) -> Self {
        Self::SizeLimitExceeded {
            field_path: path.into(),
            reason_code: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_contracts::{
        AgentInstanceId, DataClassification, RiskContext, TenantId, ToolId, ToolVersion,
    };

    fn draft() -> ActionDraft {
        let tenant = TenantId::new();
        ActionDraft {
            schema_version: SchemaVersion(ACTION_SCHEMA_VERSION.into()),
            action_id: ActionId::new(),
            task_id: TaskId::new(),
            step_id: StepId::new(),
            agent: AgentIdentity {
                schema_version: SchemaVersion(
                    agent_trust_contracts::CONTRACT_SCHEMA_VERSION.into(),
                ),
                agent_type: "coding".into(),
                agent_instance_id: AgentInstanceId::new(),
                organization_id: "org".into(),
                tenant_id: tenant.clone(),
                owner_subject: "user:1".into(),
                model_provider: "test".into(),
                model_id: "model".into(),
                agent_version: "1".into(),
                deployment_environment: "dev".into(),
                trust_level: "verified".into(),
                auth_context_ref: "auth:1".into(),
                issued_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
            intent: Intent {
                goal_hash: "g".into(),
                operation: "read".into(),
                justification_code: "USER_REQUEST".into(),
                safe_summary: None,
            },
            tool: ToolRef {
                tool_id: ToolId("coding.repo-read".into()),
                tool_version: ToolVersion("1.0.0".into()),
            },
            payload: TypedPayload {
                type_id: "coding.command.v1".into(),
                schema_version: "1".into(),
                data: Map::from_iter([("path".into(), Value::String("src".into()))]),
            },
            resource: ResourceSelector {
                scheme: "repo".into(),
                tenant_id: tenant.clone(),
                locator: "org/repo".into(),
                version: None,
            },
            environment: ExecutionEnvironment {
                tenant_id: tenant,
                deployment: "dev".into(),
                region: "local".into(),
                zone: None,
                simulation: false,
            },
            current_state_version: None,
            risk: RiskContext {
                declared_risk: RiskLevel::Low,
                trajectory_risk_ref: None,
                scope_delta: 0,
                automation_allowed: true,
            },
            data: DataContext {
                classification: DataClassification::Internal,
                jurisdiction: "CN".into(),
                export_constraints: vec![],
            },
            expected_outcome: ExpectedOutcome {
                metric: "files".into(),
                operator: "gte".into(),
                target: Value::from(0),
            },
            credential_refs: vec![],
            requested_at: Utc::now(),
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn rejects_duplicate_keys_before_serde() {
        let bytes =
            br#"{"schema_version":"agenttrust.action.v1","schema_version":"agenttrust.action.v1"}"#;
        assert!(matches!(
            parse_draft(bytes, &ParseLimits::default()),
            Err(ActionIrError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn canonical_hash_ignores_json_key_order() {
        let mut first_draft = draft();
        first_draft.payload.data = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap_or_default();
        let mut second_draft = first_draft.clone();
        second_draft.payload.data = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap_or_default();
        let first_with_args = normalize(first_draft, &NormalizationContext::default())
            .unwrap_or_else(|_| panic!("normalization"));
        let second = normalize(second_draft, &NormalizationContext::default())
            .unwrap_or_else(|_| panic!("normalization"));
        assert_eq!(hash(&first_with_args), hash(&second));
    }

    #[test]
    fn rejects_inline_secret_and_traversal() {
        let mut secret = draft();
        secret
            .payload
            .data
            .insert("token".into(), Value::String("s".into()));
        assert!(matches!(
            normalize(secret, &NormalizationContext::default()),
            Err(ActionIrError::SecretInline { .. })
        ));
        let mut traversal = draft();
        traversal.resource.locator = "../etc/passwd".into();
        assert!(matches!(
            normalize(traversal, &NormalizationContext::default()),
            Err(ActionIrError::SemanticInvalid { .. })
        ));
    }

    struct Keys {
        key: VerifyingKey,
        agent: AgentInstanceId,
    }
    impl KeyProvider for Keys {
        fn verifying_key(&self, key_id: &str, _: &str) -> Result<VerifyingKey, ActionIrError> {
            if key_id == "k" {
                Ok(self.key)
            } else {
                Err(ActionIrError::SignerUntrusted)
            }
        }
        fn is_revoked(&self, _: &str) -> bool {
            false
        }
        fn signer_is_bound(&self, _: &str, agent: &AgentIdentity) -> bool {
            agent.agent_instance_id == self.agent
        }
    }

    #[test]
    fn signature_tampering_fails_closed() {
        let action = normalize(draft(), &NormalizationContext::default())
            .unwrap_or_else(|_| panic!("normalization"));
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let keys = Keys {
            key: signing.verifying_key(),
            agent: action.agent.agent_instance_id.clone(),
        };
        let mut envelope = sign_envelope(
            action,
            "adapter".into(),
            "k".into(),
            &signing,
            chrono::Duration::minutes(1),
        )
        .unwrap_or_else(|_| panic!("sign"));
        assert!(verify_envelope(&envelope, &keys, Utc::now()).is_ok());
        envelope.canonical_action.intent.operation = "write".into();
        assert!(matches!(
            verify_envelope(&envelope, &keys, Utc::now()),
            Err(ActionIrError::HashMismatch)
        ));
    }
}
