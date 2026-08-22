use crate::config::{ConfigurationError, EndpointConfig, TlsClientConfig, validate_relative_path};
use reqwest::{Certificate, Identity, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use std::{fs, io::Read, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("PRODUCTION_TRANSPORT_CONFIGURATION_INVALID")]
    Configuration,
    #[error("PRODUCTION_TRANSPORT_CREDENTIAL_UNAVAILABLE")]
    CredentialUnavailable,
    #[error("PRODUCTION_TRANSPORT_REQUEST_FAILED")]
    RequestFailed,
    #[error("PRODUCTION_TRANSPORT_RESPONSE_INVALID")]
    ResponseInvalid,
    #[error("PRODUCTION_TRANSPORT_REMOTE_REJECTED_{0}")]
    RemoteRejected(u16),
}

impl From<ConfigurationError> for TransportError {
    fn from(_: ConfigurationError) -> Self {
        Self::Configuration
    }
}

#[derive(Clone)]
pub struct SecureHttpTransport {
    base_url: Arc<str>,
    token_file: Option<std::path::PathBuf>,
    async_client: reqwest::Client,
    blocking_client: reqwest::blocking::Client,
}

impl SecureHttpTransport {
    pub fn new(config: &EndpointConfig) -> Result<Self, TransportError> {
        config.validate()?;
        let ca = fs::read(&config.tls.ca_bundle).map_err(|_| TransportError::Configuration)?;
        let certificate = Certificate::from_pem(&ca).map_err(|_| TransportError::Configuration)?;
        let mut async_builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.tls.timeout())
            .add_root_certificate(certificate.clone());
        let mut blocking_builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.tls.timeout())
            .add_root_certificate(certificate);
        if let Some(path) = &config.tls.client_identity_pem {
            let pem = fs::read(path).map_err(|_| TransportError::Configuration)?;
            async_builder = async_builder
                .identity(Identity::from_pem(&pem).map_err(|_| TransportError::Configuration)?);
            blocking_builder = blocking_builder
                .identity(Identity::from_pem(&pem).map_err(|_| TransportError::Configuration)?);
        }
        Ok(Self {
            base_url: config.base_url.trim_end_matches('/').into(),
            token_file: config.tls.bearer_token_file.clone(),
            async_client: async_builder
                .build()
                .map_err(|_| TransportError::Configuration)?,
            blocking_client: blocking_builder
                .build()
                .map_err(|_| TransportError::Configuration)?,
        })
    }

    pub fn for_jwks(url: &str, tls: &TlsClientConfig) -> Result<Self, TransportError> {
        let parsed = url::Url::parse(url).map_err(|_| TransportError::Configuration)?;
        let path = parsed.path().to_string();
        let mut origin = parsed;
        origin.set_path("");
        origin.set_query(None);
        origin.set_fragment(None);
        let endpoint = EndpointConfig {
            base_url: origin.to_string(),
            tls: tls.clone(),
            health_path: Some(path.clone()),
        };
        let transport = Self::new(&endpoint)?;
        validate_relative_path(&path).map_err(|_| TransportError::Configuration)?;
        Ok(transport)
    }

    fn url(&self, path: &str) -> Result<String, TransportError> {
        validate_relative_path(path).map_err(|_| TransportError::Configuration)?;
        Ok(format!("{}{}", self.base_url, path))
    }

    fn token(&self) -> Result<Option<String>, TransportError> {
        let Some(path) = &self.token_file else {
            return Ok(None);
        };
        let metadata = fs::metadata(path).map_err(|_| TransportError::CredentialUnavailable)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 16_384 {
            return Err(TransportError::CredentialUnavailable);
        }
        let token = fs::read_to_string(path).map_err(|_| TransportError::CredentialUnavailable)?;
        let token = token.trim();
        if token.is_empty() || token.chars().any(char::is_whitespace) {
            return Err(TransportError::CredentialUnavailable);
        }
        Ok(Some(token.to_owned()))
    }

    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>, TransportError> {
        let mut request = self.async_client.get(self.url(path)?);
        if let Some(token) = self.token()? {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|_| TransportError::RequestFailed)?;
        ensure_success(response.status())?;
        bounded_async_body(response, 4 * 1024 * 1024).await
    }

    pub fn get_bytes_blocking(&self, path: &str) -> Result<Vec<u8>, TransportError> {
        let mut request = self.blocking_client.get(self.url(path)?);
        if let Some(token) = self.token()? {
            request = request.bearer_auth(token);
        }
        let response = request.send().map_err(|_| TransportError::RequestFailed)?;
        ensure_success(response.status())?;
        bounded_blocking_body(response, 4 * 1024 * 1024)
    }

    pub async fn post_json<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, TransportError> {
        let mut request = self.async_client.post(self.url(path)?).json(body);
        if let Some(token) = self.token()? {
            request = request.bearer_auth(token);
        }
        if let Some(key) = idempotency_key {
            request = request.header("idempotency-key", key);
        }
        let response = request
            .send()
            .await
            .map_err(|_| TransportError::RequestFailed)?;
        ensure_success(response.status())?;
        let bytes = bounded_async_body(response, 8 * 1024 * 1024).await?;
        serde_json::from_slice(&bytes).map_err(|_| TransportError::ResponseInvalid)
    }

    pub async fn post_json_tenant<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        tenant_id: &str,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, TransportError> {
        if tenant_id.is_empty()
            || tenant_id.len() > 64
            || !tenant_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err(TransportError::Configuration);
        }
        let mut request = self
            .async_client
            .post(self.url(path)?)
            .header("x-agenttrust-tenant-id", tenant_id)
            .json(body);
        if let Some(token) = self.token()? {
            request = request.bearer_auth(token);
        }
        if let Some(key) = idempotency_key {
            request = request.header("idempotency-key", key);
        }
        let response = request
            .send()
            .await
            .map_err(|_| TransportError::RequestFailed)?;
        ensure_success(response.status())?;
        let bytes = bounded_async_body(response, 8 * 1024 * 1024).await?;
        serde_json::from_slice(&bytes).map_err(|_| TransportError::ResponseInvalid)
    }

    pub async fn post_json_bytes<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
        maximum_bytes: usize,
        accept: &str,
    ) -> Result<Vec<u8>, TransportError> {
        if maximum_bytes == 0 || maximum_bytes > 32 * 1024 * 1024 {
            return Err(TransportError::Configuration);
        }
        let mut request = self
            .async_client
            .post(self.url(path)?)
            .json(body)
            .header("accept", accept);
        if let Some(token) = self.token()? {
            request = request.bearer_auth(token);
        }
        if let Some(key) = idempotency_key {
            request = request.header("idempotency-key", key);
        }
        let response = request
            .send()
            .await
            .map_err(|_| TransportError::RequestFailed)?;
        ensure_success(response.status())?;
        bounded_async_body(response, maximum_bytes).await
    }

    pub fn post_json_blocking<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, TransportError> {
        let mut request = self.blocking_client.post(self.url(path)?).json(body);
        if let Some(token) = self.token()? {
            request = request.bearer_auth(token);
        }
        if let Some(key) = idempotency_key {
            request = request.header("idempotency-key", key);
        }
        let response = request.send().map_err(|_| TransportError::RequestFailed)?;
        ensure_success(response.status())?;
        let bytes = bounded_blocking_body(response, 8 * 1024 * 1024)?;
        serde_json::from_slice(&bytes).map_err(|_| TransportError::ResponseInvalid)
    }

    pub async fn delete_json<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, TransportError> {
        let mut request = self.async_client.delete(self.url(path)?).json(body);
        if let Some(token) = self.token()? {
            request = request.bearer_auth(token);
        }
        if let Some(key) = idempotency_key {
            request = request.header("idempotency-key", key);
        }
        let response = request
            .send()
            .await
            .map_err(|_| TransportError::RequestFailed)?;
        ensure_success(response.status())?;
        let bytes = bounded_async_body(response, 8 * 1024 * 1024).await?;
        serde_json::from_slice(&bytes).map_err(|_| TransportError::ResponseInvalid)
    }
}

fn ensure_success(status: StatusCode) -> Result<(), TransportError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(TransportError::RemoteRejected(status.as_u16()))
    }
}

async fn bounded_async_body(
    mut response: reqwest::Response,
    maximum: usize,
) -> Result<Vec<u8>, TransportError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(TransportError::ResponseInvalid);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| TransportError::ResponseInvalid)?
    {
        let next = body
            .len()
            .checked_add(chunk.len())
            .ok_or(TransportError::ResponseInvalid)?;
        if next > maximum {
            return Err(TransportError::ResponseInvalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn bounded_blocking_body(
    response: reqwest::blocking::Response,
    maximum: usize,
) -> Result<Vec<u8>, TransportError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(TransportError::ResponseInvalid);
    }
    let mut body = Vec::new();
    response
        .take(maximum as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| TransportError::ResponseInvalid)?;
    if body.len() > maximum {
        Err(TransportError::ResponseInvalid)
    } else {
        Ok(body)
    }
}
