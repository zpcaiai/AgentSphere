//! Content-addressed production adapter for an HTTPS WORM/object-lock gateway.

use crate::{EvidenceError, StoredArtifact};
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{ArtifactRef, IdempotencyKey, TaskId, TenantId};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderValue, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

pub const ARTIFACT_UPLOAD_SCHEMA_VERSION: &str = "agenttrust.evidence-artifact-upload.v1";
pub const WORM_RECEIPT_SCHEMA_VERSION: &str = "agenttrust.worm-object-receipt.v1";
pub const WORM_READINESS_SCHEMA_VERSION: &str = "agenttrust.worm-readiness.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUploadRequest {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub idempotency_key: IdempotencyKey,
    pub media_type: String,
    pub classification: String,
    pub retention_until: DateTime<Utc>,
    pub access_policy: String,
    pub content_base64url: String,
    pub requested_at: DateTime<Utc>,
}

impl ArtifactUploadRequest {
    pub fn validate_and_decode(&self, maximum_bytes: usize) -> Result<Vec<u8>, EvidenceError> {
        if self.schema_version != ARTIFACT_UPLOAD_SCHEMA_VERSION
            || canonical_uuid(&self.tenant_id.0).is_none()
            || canonical_uuid(&self.task_id.0).is_none()
            || self.idempotency_key.0.is_empty()
            || self.idempotency_key.0.len() > 128
            || self.media_type.is_empty()
            || self.media_type.len() > 256
            || self.classification.is_empty()
            || self.classification.len() > 64
            || self.access_policy.is_empty()
            || self.access_policy.len() > 512
            || self.retention_until <= self.requested_at
            || self.retention_until > self.requested_at + chrono::Duration::days(365 * 25)
            || self.content_base64url.contains('=')
        {
            return Err(EvidenceError::ArtifactDenied);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.content_base64url)
            .map_err(|_| EvidenceError::ArtifactDenied)?;
        if bytes.is_empty() || bytes.len() > maximum_bytes || contains_secret(&bytes) {
            return Err(EvidenceError::ArtifactDenied);
        }
        Ok(bytes)
    }

    pub fn request_digest(&self) -> Result<String, EvidenceError> {
        Ok(hex(Sha256::digest(
            serde_jcs::to_vec(self).map_err(|_| EvidenceError::Canonicalization)?,
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WormObjectReceipt {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub artifact_ref: ArtifactRef,
    pub sha256: String,
    pub object_ref: String,
    pub version_id: String,
    pub retention_until: DateTime<Utc>,
    pub stored_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl WormObjectReceipt {
    pub fn expected_digest(&self) -> Result<String, EvidenceError> {
        let mut copy = self.clone();
        copy.receipt_digest.clear();
        Ok(hex(Sha256::digest(
            serde_jcs::to_vec(&copy).map_err(|_| EvidenceError::Canonicalization)?,
        )))
    }

    pub fn verify(
        &self,
        tenant: &TenantId,
        digest: &str,
        retention_until: DateTime<Utc>,
    ) -> Result<(), EvidenceError> {
        if self.schema_version != WORM_RECEIPT_SCHEMA_VERSION
            || &self.tenant_id != tenant
            || self.sha256 != digest
            || self.artifact_ref.0 != format!("artifact:sha256:{digest}")
            || !self.object_ref.starts_with("object-lock://")
            || self.object_ref.len() > 2_048
            || self.version_id.is_empty()
            || self.version_id.len() > 512
            || self.retention_until != retention_until
            || self.stored_at > Utc::now()
            || self.receipt_digest != self.expected_digest()?
        {
            return Err(EvidenceError::IntegrityInvalid);
        }
        Ok(())
    }

    pub fn stored_artifact(
        &self,
        request: &ArtifactUploadRequest,
        bytes: usize,
    ) -> Result<StoredArtifact, EvidenceError> {
        let retention_seconds = (request.retention_until - request.requested_at)
            .num_seconds()
            .try_into()
            .map_err(|_| EvidenceError::ArtifactDenied)?;
        Ok(StoredArtifact {
            artifact_ref: self.artifact_ref.clone(),
            sha256: self.sha256.clone(),
            media_type: request.media_type.clone(),
            classification: request.classification.clone(),
            retention_seconds,
            access_policy: request.access_policy.clone(),
            bytes: u64::try_from(bytes).map_err(|_| EvidenceError::ArtifactDenied)?,
            created_at: self.stored_at,
        })
    }
}

#[async_trait]
pub trait WormArtifactPort: Send + Sync {
    async fn put_immutable(
        &self,
        request: &ArtifactUploadRequest,
        bytes: Vec<u8>,
    ) -> Result<WormObjectReceipt, EvidenceError>;
    async fn ready(&self) -> bool;
}

/// Real HTTPS adapter for a storage gateway that enforces provider-side object lock. The gateway
/// must return a versioned receipt; code existence is not evidence that a particular bucket has
/// Object Lock enabled.
#[derive(Clone)]
pub struct HttpWormArtifactStore {
    client: reqwest::Client,
    endpoint: Url,
    bearer: Arc<str>,
    maximum_bytes: usize,
}

impl HttpWormArtifactStore {
    pub fn new(
        endpoint: &str,
        bearer: String,
        ca_file: &Path,
        certificate_file: &Path,
        private_key_file: &Path,
        maximum_bytes: usize,
    ) -> Result<Self, EvidenceError> {
        let endpoint = Url::parse(endpoint).map_err(|_| EvidenceError::ConfigurationInvalid)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || bearer.is_empty()
            || bearer.len() > 8_192
            || bearer.contains(char::is_whitespace)
            || maximum_bytes == 0
            || maximum_bytes > 64 * 1024 * 1024
        {
            return Err(EvidenceError::ConfigurationInvalid);
        }
        let ca = std::fs::read(ca_file).map_err(|_| EvidenceError::ConfigurationInvalid)?;
        let mut identity =
            std::fs::read(certificate_file).map_err(|_| EvidenceError::ConfigurationInvalid)?;
        identity.extend(
            std::fs::read(private_key_file).map_err(|_| EvidenceError::ConfigurationInvalid)?,
        );
        let client = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(30))
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca)
                    .map_err(|_| EvidenceError::ConfigurationInvalid)?,
            )
            .identity(
                reqwest::Identity::from_pem(&identity)
                    .map_err(|_| EvidenceError::ConfigurationInvalid)?,
            )
            .build()
            .map_err(|_| EvidenceError::ConfigurationInvalid)?;
        Ok(Self {
            client,
            endpoint,
            bearer: bearer.into(),
            maximum_bytes,
        })
    }
}

#[async_trait]
impl WormArtifactPort for HttpWormArtifactStore {
    async fn put_immutable(
        &self,
        request: &ArtifactUploadRequest,
        bytes: Vec<u8>,
    ) -> Result<WormObjectReceipt, EvidenceError> {
        if bytes.len() > self.maximum_bytes {
            return Err(EvidenceError::ArtifactDenied);
        }
        let digest = hex(Sha256::digest(&bytes));
        let url = self
            .endpoint
            .join(&format!(
                "v1/immutable-objects/{}/{}",
                request.tenant_id.0, digest
            ))
            .map_err(|_| EvidenceError::ConfigurationInvalid)?;
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(&request.idempotency_key.0)
                .map_err(|_| EvidenceError::RequestInvalid)?,
        );
        headers.insert(
            "x-agenttrust-retention-until",
            HeaderValue::from_str(&request.retention_until.to_rfc3339())
                .map_err(|_| EvidenceError::RequestInvalid)?,
        );
        headers.insert(
            "x-agenttrust-classification",
            HeaderValue::from_str(&request.classification)
                .map_err(|_| EvidenceError::RequestInvalid)?,
        );
        headers.insert(
            "x-agenttrust-content-sha256",
            HeaderValue::from_str(&digest).map_err(|_| EvidenceError::RequestInvalid)?,
        );
        let response = self
            .client
            .put(url)
            .bearer_auth(self.bearer.as_ref())
            .headers(headers)
            .body(bytes)
            .send()
            .await
            .map_err(|_| EvidenceError::DependencyUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 65_536)
        {
            return Err(EvidenceError::DependencyUnavailable);
        }
        let body = read_bounded_body(response, 65_536)
            .await
            .map_err(|_| EvidenceError::DependencyUnavailable)?;
        let receipt: WormObjectReceipt =
            serde_json::from_slice(&body).map_err(|_| EvidenceError::DependencyUnavailable)?;
        receipt.verify(&request.tenant_id, &digest, request.retention_until)?;
        Ok(receipt)
    }

    async fn ready(&self) -> bool {
        let url = match self.endpoint.join("ready") {
            Ok(value) => value,
            Err(_) => return false,
        };
        let response = match self
            .client
            .get(url)
            .bearer_auth(self.bearer.as_ref())
            .send()
            .await
        {
            Ok(value) => value,
            Err(_) => return false,
        };
        if !response.status().is_success() || response.content_length().unwrap_or(4_097) > 4_096 {
            return false;
        }
        read_bounded_body(response, 4_096)
            .await
            .ok()
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .is_some_and(|value| {
                value.get("schema_version").and_then(|value| value.as_str())
                    == Some(WORM_READINESS_SCHEMA_VERSION)
                    && value.get("ready").and_then(|value| value.as_bool()) == Some(true)
                    && value.get("object_lock").and_then(|value| value.as_bool()) == Some(true)
            })
    }
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.to_string() == value)
}

fn contains_secret(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    [
        "authorization: bearer",
        "password=",
        "api_key=",
        "-----begin private key-----",
    ]
    .iter()
    .any(|marker| text.contains(marker))
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
    fn artifact_upload_rejects_embedded_secret_material() {
        let request = ArtifactUploadRequest {
            schema_version: ARTIFACT_UPLOAD_SCHEMA_VERSION.into(),
            tenant_id: TenantId::new(),
            task_id: TaskId::new(),
            idempotency_key: IdempotencyKey("artifact-1".into()),
            media_type: "text/plain".into(),
            classification: "INTERNAL".into(),
            retention_until: Utc::now() + chrono::Duration::days(1),
            access_policy: "owner-only".into(),
            content_base64url: URL_SAFE_NO_PAD.encode(b"authorization: bearer secret"),
            requested_at: Utc::now(),
        };
        assert_eq!(
            request.validate_and_decode(1024),
            Err(EvidenceError::ArtifactDenied)
        );
    }
}
