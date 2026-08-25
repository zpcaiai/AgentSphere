//! Fail-closed mTLS delivery of durable Approval decision evidence outbox rows.

use crate::ApprovalError;
use crate::review_evidence::ApprovalReviewEvidenceKeyring;
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{AuthorityEvidenceEventRequest, SignedAuthorityEvidenceReceipt};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Certificate, Identity, redirect::Policy};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use url::Url;

const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_TOKEN_BYTES: u64 = 8_194;
const MAX_PEM_BYTES: u64 = 4_194_304;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_ITEMS: usize = 4_096;
pub(crate) const EVIDENCE_REQUEST_TIMEOUT_SECONDS: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ApprovalEvidenceDeliveryError {
    #[error("APPROVAL_EVIDENCE_DELIVERY_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("APPROVAL_EVIDENCE_DELIVERY_DEPENDENCY_UNAVAILABLE")]
    DependencyUnavailable,
    #[error("APPROVAL_EVIDENCE_DELIVERY_RECEIPT_INVALID")]
    ReceiptInvalid,
}

impl ApprovalEvidenceDeliveryError {
    pub fn retry_code(self) -> &'static str {
        match self {
            Self::ConfigurationInvalid => "CONFIGURATION_INVALID",
            Self::DependencyUnavailable => "OUTCOME_UNKNOWN",
            Self::ReceiptInvalid => "RECEIPT_INVALID",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceReadiness {
    schema_version: String,
    ready: bool,
    database_ready: bool,
    worm_ready: bool,
}

/// A production-only Evidence Authority client. Construction loads and pins the
/// CA and mTLS identity; the scope token is re-read for every request so normal
/// secret rotation does not require a process restart.
#[derive(Clone)]
pub struct ApprovalEvidencePublisher {
    client: reqwest::Client,
    delivery_url: Url,
    readiness_url: Url,
    readiness_schema: String,
    token_file: PathBuf,
    keyring: ApprovalReviewEvidenceKeyring,
}

impl ApprovalEvidencePublisher {
    pub fn new(
        origin: Url,
        token_file: PathBuf,
        ca_file: &Path,
        certificate_file: &Path,
        private_key_file: &Path,
        readiness_schema: String,
        keyring: ApprovalReviewEvidenceKeyring,
    ) -> Result<Self, ApprovalEvidenceDeliveryError> {
        validate_https_origin(&origin)?;
        if readiness_schema != "agenttrust.evidence-readiness.v1" {
            return Err(ApprovalEvidenceDeliveryError::ConfigurationInvalid);
        }
        validate_file(&token_file, true, MAX_TOKEN_BYTES)?;
        validate_file(ca_file, false, MAX_PEM_BYTES)?;
        validate_file(certificate_file, false, MAX_PEM_BYTES)?;
        validate_file(private_key_file, true, MAX_PEM_BYTES)?;

        let ca = std::fs::read(ca_file)
            .map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
        let ca = Certificate::from_pem(&ca)
            .map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
        let mut identity_pem = std::fs::read(certificate_file)
            .map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
        let mut private_key = std::fs::read(private_key_file)
            .map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&private_key);
        private_key.fill(0);
        let identity_result = Identity::from_pem(&identity_pem);
        identity_pem.fill(0);
        let identity =
            identity_result.map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(identity)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(EVIDENCE_REQUEST_TIMEOUT_SECONDS))
            .pool_max_idle_per_host(8)
            .build()
            .map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
        let delivery_url = origin
            .join("v1/evidence/authority-events")
            .map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
        let readiness_url = origin
            .join("ready")
            .map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
        if delivery_url.path() != "/v1/evidence/authority-events"
            || readiness_url.path() != "/ready"
        {
            return Err(ApprovalEvidenceDeliveryError::ConfigurationInvalid);
        }
        read_token(&token_file)?;
        Ok(Self {
            client,
            delivery_url,
            readiness_url,
            readiness_schema,
            token_file,
            keyring,
        })
    }

    pub async fn ready(&self) -> bool {
        let Ok(token) = read_token(&self.token_file) else {
            return false;
        };
        let Ok(response) = self
            .client
            .get(self.readiness_url.clone())
            .bearer_auth(token)
            .send()
            .await
        else {
            return false;
        };
        if !response.status().is_success()
            || !exact_content_type(response.headers(), "application/json")
        {
            return false;
        }
        let Ok(body) = read_bounded_body(response, 4_096).await else {
            return false;
        };
        let Ok(readiness) = strict_json::<EvidenceReadiness>(&body) else {
            return false;
        };
        readiness.schema_version == self.readiness_schema
            && readiness.ready
            && readiness.database_ready
            && readiness.worm_ready
    }

    pub async fn publish(
        &self,
        request: &AuthorityEvidenceEventRequest,
    ) -> Result<SignedAuthorityEvidenceReceipt, ApprovalEvidenceDeliveryError> {
        let request_digest = request
            .request_digest()
            .map_err(|_| ApprovalEvidenceDeliveryError::ReceiptInvalid)?;
        let token = read_token(&self.token_file)?;
        let response = self
            .client
            .post(self.delivery_url.clone())
            .bearer_auth(token)
            .header("x-agenttrust-tenant-id", &request.tenant_id.0)
            .header("idempotency-key", &request.idempotency_key.0)
            .header(
                "x-agenttrust-authority-event-id",
                &request.authority_event_id,
            )
            .header("x-agenttrust-payload-digest", &request.event.payload_hash)
            .json(request)
            .send()
            .await
            .map_err(|_| ApprovalEvidenceDeliveryError::DependencyUnavailable)?;
        classify_delivery_status(response.status())?;
        if !exact_content_type(response.headers(), "application/json") {
            return Err(ApprovalEvidenceDeliveryError::ReceiptInvalid);
        }
        let body = read_bounded_body(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| ApprovalEvidenceDeliveryError::DependencyUnavailable)?;
        let receipt: SignedAuthorityEvidenceReceipt =
            strict_json(&body).map_err(|_| ApprovalEvidenceDeliveryError::ReceiptInvalid)?;
        if !canonical_ed25519_signature(&receipt.signature) {
            return Err(ApprovalEvidenceDeliveryError::ReceiptInvalid);
        }
        self.keyring
            .verify_authority_delivery(request, &receipt, chrono::Utc::now())
            .map_err(|_| ApprovalEvidenceDeliveryError::ReceiptInvalid)?;
        if receipt.request_digest != request_digest {
            return Err(ApprovalEvidenceDeliveryError::ReceiptInvalid);
        }
        Ok(receipt)
    }
}

fn validate_https_origin(origin: &Url) -> Result<(), ApprovalEvidenceDeliveryError> {
    if origin.scheme() != "https"
        || origin.cannot_be_a_base()
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(ApprovalEvidenceDeliveryError::ConfigurationInvalid);
    }
    Ok(())
}

fn read_token(path: &Path) -> Result<String, ApprovalEvidenceDeliveryError> {
    validate_file(path, true, MAX_TOKEN_BYTES)?;
    let value = std::fs::read_to_string(path)
        .map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
    let token = value.trim_end_matches(['\r', '\n']);
    if !(16..=8_192).contains(&token.len())
        || token.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(token.len()) > 2
    {
        return Err(ApprovalEvidenceDeliveryError::ConfigurationInvalid);
    }
    Ok(token.to_string())
}

fn validate_file(
    path: &Path,
    private: bool,
    maximum_size: u64,
) -> Result<(), ApprovalEvidenceDeliveryError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ApprovalEvidenceDeliveryError::ConfigurationInvalid)?;
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_size
    {
        return Err(ApprovalEvidenceDeliveryError::ConfigurationInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        let effective_uid = nix::unistd::Uid::effective().as_raw();
        let effective_gid = nix::unistd::Gid::effective().as_raw();
        let allowed = 0o400
            | if metadata.gid() == effective_gid {
                0o040
            } else {
                0
            };
        let readable_by_process = (metadata.uid() == effective_uid && mode & 0o400 != 0)
            || (metadata.gid() == effective_gid && mode & 0o040 != 0);
        if metadata.nlink() != 1
            || (private && (!readable_by_process || mode & !allowed != 0))
            || (!private && mode & 0o022 != 0)
        {
            return Err(ApprovalEvidenceDeliveryError::ConfigurationInvalid);
        }
    }
    Ok(())
}

fn exact_content_type(headers: &reqwest::header::HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(reqwest::header::CONTENT_TYPE).iter();
    values.next().and_then(|value| value.to_str().ok()) == Some(expected) && values.next().is_none()
}

fn classify_delivery_status(
    status: reqwest::StatusCode,
) -> Result<(), ApprovalEvidenceDeliveryError> {
    if status.is_success() {
        return Ok(());
    }
    if matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) || status.is_redirection()
    {
        return Err(ApprovalEvidenceDeliveryError::ConfigurationInvalid);
    }
    if status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_EARLY
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        return Err(ApprovalEvidenceDeliveryError::DependencyUnavailable);
    }
    Err(ApprovalEvidenceDeliveryError::ReceiptInvalid)
}

fn canonical_ed25519_signature(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .filter(|raw| raw.len() == 64)
        .is_some_and(|raw| URL_SAFE_NO_PAD.encode(raw) == value)
}

fn strict_json<T: DeserializeOwned>(raw: &[u8]) -> Result<T, ApprovalError> {
    if raw.is_empty() || raw.len() > MAX_RESPONSE_BYTES {
        return Err(ApprovalError::GrantInvalid);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value =
        StrictJsonValue::deserialize(&mut deserializer).map_err(|_| ApprovalError::GrantInvalid)?;
    deserializer
        .end()
        .map_err(|_| ApprovalError::GrantInvalid)?;
    serde_json::from_value(value.0).map_err(|_| ApprovalError::GrantInvalid)
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor { depth: 0 })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl StrictJsonVisitor {
    fn nested<E: de::Error>(&self) -> Result<Self, E> {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| E::custom("JSON depth"))?;
        if depth > MAX_JSON_DEPTH {
            return Err(E::custom("JSON depth"));
        }
        Ok(Self { depth })
    }
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON without duplicate object members")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_string(value.to_string())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        if value.len() > MAX_RESPONSE_BYTES {
            return Err(E::custom("JSON string too long"));
        }
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        let nested = self.nested::<A::Error>()?;
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            depth: nested.depth,
        })? {
            if values.len() >= MAX_JSON_ITEMS {
                return Err(de::Error::custom("too many JSON array items"));
            }
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = Map::new();
        let mut keys = BTreeSet::new();
        let nested = self.nested::<A::Error>()?;
        while let Some(key) = map.next_key::<String>()? {
            if keys.len() >= MAX_JSON_ITEMS || !keys.insert(key.clone()) {
                return Err(de::Error::custom("duplicate or excessive JSON object key"));
            }
            let value = map.next_value_seed(StrictJsonSeed {
                depth: nested.depth,
            })?;
            values.insert(key, value.0);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

struct StrictJsonSeed {
    depth: usize,
}

impl<'de> de::DeserializeSeed<'de> for StrictJsonSeed {
    type Value = StrictJsonValue;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_requires_an_exact_https_origin() {
        for invalid in [
            "http://evidence.internal/",
            "https://user@evidence.internal/",
            "https://evidence.internal/base/",
            "https://evidence.internal/?redirect=true",
        ] {
            let parsed = Url::parse(invalid).unwrap_or_else(|_| panic!("test URL"));
            assert_eq!(
                validate_https_origin(&parsed),
                Err(ApprovalEvidenceDeliveryError::ConfigurationInvalid)
            );
        }
        let valid =
            Url::parse("https://evidence.internal/").unwrap_or_else(|_| panic!("valid test URL"));
        assert_eq!(validate_https_origin(&valid), Ok(()));
    }

    #[test]
    fn strict_json_rejects_duplicate_members_and_trailing_data() {
        assert!(strict_json::<Value>(br#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json::<Value>(br#"{"a":1} false"#).is_err());
        assert_eq!(
            strict_json::<Value>(br#"{"a":1}"#).unwrap_or_else(|_| panic!("strict JSON")),
            serde_json::json!({"a": 1})
        );
    }

    #[test]
    fn evidence_readiness_requires_the_exact_complete_authority_shape() {
        let ready = strict_json::<EvidenceReadiness>(
            br#"{"schema_version":"agenttrust.evidence-readiness.v1","ready":true,"database_ready":true,"worm_ready":true}"#,
        )
        .unwrap_or_else(|_| panic!("complete readiness"));
        assert!(ready.ready && ready.database_ready && ready.worm_ready);
        assert!(
            strict_json::<EvidenceReadiness>(
                br#"{"schema_version":"agenttrust.evidence-readiness.v1","ready":true}"#
            )
            .is_err()
        );
        assert!(strict_json::<EvidenceReadiness>(
            br#"{"schema_version":"agenttrust.evidence-readiness.v1","ready":true,"database_ready":true,"worm_ready":true,"development":true}"#
        )
        .is_err());
    }

    #[test]
    fn authority_receipt_signature_encoding_is_canonical_base64url() {
        let raw = [0_u8; 64];
        let canonical = URL_SAFE_NO_PAD.encode(raw);
        assert!(canonical_ed25519_signature(&canonical));
        for replacement in b'A'..=b'z' {
            let mut alias = canonical.as_bytes().to_vec();
            let last = alias.len().saturating_sub(1);
            alias[last] = replacement;
            let Ok(alias) = String::from_utf8(alias) else {
                continue;
            };
            if alias != canonical
                && URL_SAFE_NO_PAD
                    .decode(&alias)
                    .is_ok_and(|decoded| decoded == raw)
            {
                assert!(!canonical_ed25519_signature(&alias));
            }
        }
        assert!(!canonical_ed25519_signature(&(canonical + "=")));
    }

    #[test]
    fn delivery_http_statuses_preserve_known_failure_vs_uncertain_outcome() {
        assert_eq!(classify_delivery_status(reqwest::StatusCode::OK), Ok(()));
        for status in [
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::CONFLICT,
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert_eq!(
                classify_delivery_status(status),
                Err(ApprovalEvidenceDeliveryError::ReceiptInvalid)
            );
        }
        for status in [
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::FORBIDDEN,
            reqwest::StatusCode::TEMPORARY_REDIRECT,
        ] {
            assert_eq!(
                classify_delivery_status(status),
                Err(ApprovalEvidenceDeliveryError::ConfigurationInvalid)
            );
        }
        for status in [
            reqwest::StatusCode::REQUEST_TIMEOUT,
            reqwest::StatusCode::TOO_EARLY,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert_eq!(
                classify_delivery_status(status),
                Err(ApprovalEvidenceDeliveryError::DependencyUnavailable)
            );
        }
    }
}
