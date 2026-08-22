//! Tenant-scoped enterprise Control API and authoritative-service BFF.

pub mod authority;
pub mod principal;
pub mod server;

use agent_trust_contracts::{TaskId, TaskStatus, TenantId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

pub const ENTERPRISE_SCHEMA_VERSION: &str = "agenttrust.enterprise-control.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tenant {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub display_name: String,
    pub owner_subject: String,
    pub data_region: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Organization {
    pub organization_id: String,
    pub tenant_id: TenantId,
    pub display_name: String,
    pub sponsor_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Project {
    pub project_id: String,
    pub tenant_id: TenantId,
    pub organization_id: String,
    pub environment_ids: BTreeSet<String>,
    pub owner_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminPrincipal {
    pub subject: String,
    pub tenant_id: TenantId,
    pub roles: BTreeSet<String>,
    pub project_ids: BTreeSet<String>,
    pub csrf_verified: bool,
    pub authentication_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminAction {
    pub schema_version: String,
    pub action_id: String,
    pub tenant_id: TenantId,
    pub project_id: Option<String>,
    pub operation: String,
    pub resource: String,
    pub requested_by: String,
    pub approval_ids: BTreeSet<String>,
    pub action_digest: String,
    pub requested_at: DateTime<Utc>,
}

pub struct AdminAuthorizer;

impl AdminAuthorizer {
    pub fn authorize(
        principal: &AdminPrincipal,
        action: &AdminAction,
        expected_action_digest: &str,
        required_roles: &BTreeSet<String>,
        separation_required: bool,
    ) -> Result<(), EnterpriseError> {
        if principal.subject.is_empty()
            || action.schema_version != ENTERPRISE_SCHEMA_VERSION
            || action.action_id.is_empty()
            || principal.tenant_id != action.tenant_id
            || principal.subject != action.requested_by
            || action.operation.is_empty()
            || action.resource.is_empty()
            || action.approval_ids.iter().any(String::is_empty)
            || !principal.csrf_verified
            || !required_roles.is_subset(&principal.roles)
            || action
                .project_id
                .as_ref()
                .is_some_and(|project| !principal.project_ids.contains(project))
            || !is_sha256(&action.action_digest)
            || !is_sha256(expected_action_digest)
            || !constant_time_equal(
                action.action_digest.as_bytes(),
                expected_action_digest.as_bytes(),
            )
            || separation_required && action.approval_ids.is_empty()
        {
            return Err(EnterpriseError::AdminDenied);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Quota {
    pub maximum_active_tasks: usize,
    pub maximum_export_records: usize,
    pub maximum_webhooks: usize,
    pub maximum_api_requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuotaUsage {
    pub tenant_id: TenantId,
    pub quota_key: String,
    pub window_started_at: DateTime<Utc>,
    pub used: u64,
    pub limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CostUsage {
    pub tenant_id: TenantId,
    pub project_id: String,
    pub meter: String,
    pub quantity: u64,
    pub unit_cost_micros: u64,
    pub total_cost_micros: u64,
    pub source_digest: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct CostService {
    entries: RwLock<Vec<CostUsage>>,
}

impl CostService {
    pub fn record(&self, usage: CostUsage) -> Result<(), EnterpriseError> {
        if usage.project_id.is_empty()
            || usage.meter.is_empty()
            || usage.quantity == 0
            || !is_sha256(&usage.source_digest)
            || usage.total_cost_micros
                != usage
                    .quantity
                    .checked_mul(usage.unit_cost_micros)
                    .ok_or(EnterpriseError::CostInvalid)?
        {
            return Err(EnterpriseError::CostInvalid);
        }
        let mut entries = self.entries.write();
        if entries.len() >= 100_000 {
            return Err(EnterpriseError::CapacityExceeded);
        }
        entries.push(usage);
        Ok(())
    }

    pub fn total_for_project(
        &self,
        tenant: &TenantId,
        project_id: &str,
    ) -> Result<u64, EnterpriseError> {
        self.entries
            .read()
            .iter()
            .filter(|entry| &entry.tenant_id == tenant && entry.project_id == project_id)
            .try_fold(0_u64, |total, entry| {
                total
                    .checked_add(entry.total_cost_micros)
                    .ok_or(EnterpriseError::CostInvalid)
            })
    }
}

#[derive(Default)]
pub struct QuotaService {
    usage: RwLock<BTreeMap<QuotaWindowKey, QuotaUsage>>,
}

type QuotaWindowKey = (TenantId, String, DateTime<Utc>);

impl QuotaService {
    pub fn consume(
        &self,
        tenant: &TenantId,
        quota_key: &str,
        window_started_at: DateTime<Utc>,
        amount: u64,
        limit: u64,
    ) -> Result<QuotaUsage, EnterpriseError> {
        if quota_key.is_empty() || amount == 0 || limit == 0 || amount > limit {
            return Err(EnterpriseError::QuotaInvalid);
        }
        let key = (tenant.clone(), quota_key.into(), window_started_at);
        let mut values = self.usage.write();
        let usage = values.entry(key).or_insert_with(|| QuotaUsage {
            tenant_id: tenant.clone(),
            quota_key: quota_key.into(),
            window_started_at,
            used: 0,
            limit,
        });
        if usage.limit != limit || usage.used.saturating_add(amount) > usage.limit {
            return Err(EnterpriseError::QuotaExceeded);
        }
        usage.used += amount;
        Ok(usage.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyRecord {
    pub api_key_id: String,
    pub tenant_id: TenantId,
    pub project_id: Option<String>,
    pub key_hash: String,
    pub scopes: BTreeSet<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedApiKey {
    pub record: ApiKeyRecord,
    pub one_time_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnterpriseLicense {
    pub schema_version: String,
    pub license_id: String,
    pub tenant_id: TenantId,
    pub plan_code: String,
    pub entitlements: BTreeSet<String>,
    pub starts_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub key_id: String,
    pub signature: String,
}

impl EnterpriseLicense {
    fn signing_bytes(&self) -> Result<Vec<u8>, EnterpriseError> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| EnterpriseError::SerializationFailed)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), EnterpriseError> {
        self.validate_fields()?;
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), EnterpriseError> {
        self.validate_fields()?;
        if now < self.starts_at || now >= self.expires_at {
            return Err(EnterpriseError::LicenseDenied);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| EnterpriseError::LicenseDenied)?;
        let signature =
            Signature::from_slice(&decoded).map_err(|_| EnterpriseError::LicenseDenied)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| EnterpriseError::LicenseDenied)
    }

    pub fn digest(&self) -> Result<String, EnterpriseError> {
        Ok(hex(Sha256::digest(
            serde_jcs::to_vec(self).map_err(|_| EnterpriseError::SerializationFailed)?,
        )))
    }

    fn validate_fields(&self) -> Result<(), EnterpriseError> {
        if self.schema_version != ENTERPRISE_SCHEMA_VERSION
            || self.license_id.is_empty()
            || self.plan_code.is_empty()
            || self.entitlements.is_empty()
            || self.entitlements.len() > 256
            || self.entitlements.iter().any(String::is_empty)
            || self.starts_at >= self.expires_at
            || self.key_id.is_empty()
        {
            return Err(EnterpriseError::LicenseInvalid);
        }
        Ok(())
    }
}

pub struct LicenseService {
    verification_keys: BTreeMap<String, VerifyingKey>,
    licenses: RwLock<BTreeMap<(TenantId, String), EnterpriseLicense>>,
    revoked: RwLock<BTreeSet<(TenantId, String)>>,
}

impl LicenseService {
    pub fn new(verification_keys: BTreeMap<String, VerifyingKey>) -> Result<Self, EnterpriseError> {
        if verification_keys.is_empty() || verification_keys.keys().any(String::is_empty) {
            return Err(EnterpriseError::ConfigurationInvalid);
        }
        Ok(Self {
            verification_keys,
            licenses: RwLock::new(BTreeMap::new()),
            revoked: RwLock::new(BTreeSet::new()),
        })
    }

    pub fn install(
        &self,
        license: EnterpriseLicense,
        now: DateTime<Utc>,
    ) -> Result<String, EnterpriseError> {
        let key = self
            .verification_keys
            .get(&license.key_id)
            .ok_or(EnterpriseError::LicenseDenied)?;
        license.verify(key, now)?;
        let digest = license.digest()?;
        self.licenses.write().insert(
            (license.tenant_id.clone(), license.license_id.clone()),
            license,
        );
        Ok(digest)
    }

    pub fn authorize(
        &self,
        tenant: &TenantId,
        license_id: &str,
        entitlement: &str,
        now: DateTime<Utc>,
    ) -> Result<(), EnterpriseError> {
        let identity = (tenant.clone(), license_id.to_owned());
        if self.revoked.read().contains(&identity) {
            return Err(EnterpriseError::LicenseDenied);
        }
        let license = self
            .licenses
            .read()
            .get(&identity)
            .cloned()
            .ok_or(EnterpriseError::LicenseDenied)?;
        let key = self
            .verification_keys
            .get(&license.key_id)
            .ok_or(EnterpriseError::LicenseDenied)?;
        license.verify(key, now)?;
        if !license.entitlements.contains(entitlement) {
            return Err(EnterpriseError::LicenseDenied);
        }
        Ok(())
    }

    pub fn revoke(&self, tenant: &TenantId, license_id: &str) -> Result<(), EnterpriseError> {
        let identity = (tenant.clone(), license_id.to_owned());
        if !self.licenses.read().contains_key(&identity) {
            return Err(EnterpriseError::LicenseDenied);
        }
        self.revoked.write().insert(identity);
        Ok(())
    }
}

pub struct ApiKeyService {
    pepper: String,
    keys: RwLock<BTreeMap<(TenantId, String), ApiKeyRecord>>,
}

impl ApiKeyService {
    pub fn new(pepper: impl Into<String>) -> Result<Self, EnterpriseError> {
        let pepper = pepper.into();
        if pepper.len() < 32 {
            return Err(EnterpriseError::ConfigurationInvalid);
        }
        Ok(Self {
            pepper,
            keys: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn issue(
        &self,
        tenant: TenantId,
        project_id: Option<String>,
        scopes: BTreeSet<String>,
        created_by: String,
        expires_at: DateTime<Utc>,
    ) -> Result<IssuedApiKey, EnterpriseError> {
        if scopes.is_empty()
            || scopes.len() > 64
            || scopes.iter().any(String::is_empty)
            || created_by.is_empty()
            || expires_at <= Utc::now()
            || expires_at > Utc::now() + chrono::Duration::days(365)
        {
            return Err(EnterpriseError::ApiKeyInvalid);
        }
        let api_key_id = Uuid::new_v4().to_string();
        let one_time_secret = format!(
            "atk_{}_{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let record = ApiKeyRecord {
            api_key_id: api_key_id.clone(),
            tenant_id: tenant.clone(),
            project_id,
            key_hash: secret_hash(&self.pepper, &one_time_secret),
            scopes,
            created_by,
            created_at: Utc::now(),
            expires_at,
            revoked_at: None,
            revocation_reason: None,
        };
        self.keys
            .write()
            .insert((tenant, api_key_id), record.clone());
        Ok(IssuedApiKey {
            record,
            one_time_secret,
        })
    }

    pub fn authenticate(
        &self,
        tenant: &TenantId,
        api_key_id: &str,
        secret: &str,
        required_scope: &str,
        now: DateTime<Utc>,
    ) -> Result<ApiKeyRecord, EnterpriseError> {
        let record = self
            .keys
            .read()
            .get(&(tenant.clone(), api_key_id.into()))
            .cloned()
            .ok_or(EnterpriseError::ApiKeyDenied)?;
        if record.revoked_at.is_some()
            || now >= record.expires_at
            || !record.scopes.contains(required_scope)
            || !constant_time_equal(
                record.key_hash.as_bytes(),
                secret_hash(&self.pepper, secret).as_bytes(),
            )
        {
            return Err(EnterpriseError::ApiKeyDenied);
        }
        Ok(record)
    }

    pub fn revoke(
        &self,
        tenant: &TenantId,
        api_key_id: &str,
        reason: &str,
    ) -> Result<(), EnterpriseError> {
        if reason.is_empty() {
            return Err(EnterpriseError::ApiKeyInvalid);
        }
        let mut keys = self.keys.write();
        let record = keys
            .get_mut(&(tenant.clone(), api_key_id.into()))
            .ok_or(EnterpriseError::ApiKeyDenied)?;
        record.revoked_at = Some(Utc::now());
        record.revocation_reason = Some(reason.into());
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrationKind {
    Iam,
    Notification,
    Ticketing,
    Siem,
    Webhook,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationConfig {
    pub integration_id: String,
    pub tenant_id: TenantId,
    pub kind: IntegrationKind,
    pub endpoint: String,
    pub secret_ref: String,
    pub configuration_digest: String,
    pub active: bool,
}

pub trait IntegrationPort: Send + Sync {
    fn deliver(
        &self,
        config: &IntegrationConfig,
        envelope: &WebhookEnvelope,
        idempotency_key: &str,
    ) -> Result<String, EnterpriseError>;
}

pub struct IntegrationService<P: IntegrationPort> {
    port: P,
    key_id: String,
    signing_key: SigningKey,
}

impl<P: IntegrationPort> IntegrationService<P> {
    pub fn new(port: P, key_id: String, signing_key: SigningKey) -> Result<Self, EnterpriseError> {
        if key_id.is_empty() {
            return Err(EnterpriseError::ConfigurationInvalid);
        }
        Ok(Self {
            port,
            key_id,
            signing_key,
        })
    }

    pub fn send(
        &self,
        config: &IntegrationConfig,
        event_id: &str,
        event_type: &str,
        payload: Value,
    ) -> Result<String, EnterpriseError> {
        let endpoint =
            Url::parse(&config.endpoint).map_err(|_| EnterpriseError::IntegrationInvalid)?;
        if config.integration_id.is_empty()
            || !config.active
            || endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || config.secret_ref.is_empty()
            || !is_sha256(&config.configuration_digest)
            || event_id.is_empty()
            || event_id.len() > 200
            || event_type.is_empty()
            || event_type.len() > 100
        {
            return Err(EnterpriseError::IntegrationInvalid);
        }
        let payload_digest = hex(Sha256::digest(
            serde_jcs::to_vec(&payload).map_err(|_| EnterpriseError::SerializationFailed)?,
        ));
        let mut envelope = WebhookEnvelope {
            schema_version: ENTERPRISE_SCHEMA_VERSION.into(),
            webhook_id: config.integration_id.clone(),
            tenant_id: config.tenant_id.clone(),
            event_id: event_id.into(),
            event_type: event_type.into(),
            payload,
            payload_digest,
            issued_at: Utc::now(),
            key_id: self.key_id.clone(),
            signature: String::new(),
        };
        envelope.sign(&self.signing_key)?;
        let evidence_ref = self.port.deliver(
            config,
            &envelope,
            &format!("integration:{}:{event_id}", config.integration_id),
        )?;
        if evidence_ref.is_empty() {
            return Err(EnterpriseError::IntegrationFailed);
        }
        Ok(evidence_ref)
    }
}

#[derive(Default)]
pub struct TenantService {
    tenants: RwLock<BTreeMap<TenantId, Tenant>>,
    organizations: RwLock<BTreeMap<(TenantId, String), Organization>>,
    projects: RwLock<BTreeMap<(TenantId, String), Project>>,
    quotas: RwLock<BTreeMap<TenantId, Quota>>,
}

impl TenantService {
    pub fn create_tenant(&self, tenant: Tenant, quota: Quota) -> Result<(), EnterpriseError> {
        if tenant.schema_version != ENTERPRISE_SCHEMA_VERSION
            || tenant.display_name.is_empty()
            || tenant.owner_subject.is_empty()
            || tenant.data_region.is_empty()
            || quota.maximum_active_tasks == 0
            || quota.maximum_export_records == 0
            || quota.maximum_webhooks == 0
            || quota.maximum_api_requests_per_minute == 0
        {
            return Err(EnterpriseError::TenantInvalid);
        }
        self.quotas.write().insert(tenant.tenant_id.clone(), quota);
        self.tenants
            .write()
            .insert(tenant.tenant_id.clone(), tenant);
        Ok(())
    }

    pub fn create_project(&self, project: Project) -> Result<(), EnterpriseError> {
        if project.project_id.is_empty()
            || project.organization_id.is_empty()
            || project.environment_ids.is_empty()
            || project.owner_subject.is_empty()
            || !self.tenants.read().contains_key(&project.tenant_id)
        {
            return Err(EnterpriseError::ProjectInvalid);
        }
        self.projects.write().insert(
            (project.tenant_id.clone(), project.project_id.clone()),
            project,
        );
        Ok(())
    }

    pub fn create_organization(&self, organization: Organization) -> Result<(), EnterpriseError> {
        if organization.organization_id.is_empty()
            || organization.display_name.is_empty()
            || organization.sponsor_subject.is_empty()
            || !self.tenants.read().contains_key(&organization.tenant_id)
        {
            return Err(EnterpriseError::OrganizationInvalid);
        }
        let key = (
            organization.tenant_id.clone(),
            organization.organization_id.clone(),
        );
        self.organizations.write().insert(key, organization);
        Ok(())
    }

    pub fn project(&self, tenant: &TenantId, project_id: &str) -> Result<Project, EnterpriseError> {
        self.projects
            .read()
            .get(&(tenant.clone(), project_id.into()))
            .cloned()
            .ok_or(EnterpriseError::NotFound)
    }

    pub fn quota(&self, tenant: &TenantId) -> Result<Quota, EnterpriseError> {
        self.quotas
            .read()
            .get(tenant)
            .cloned()
            .ok_or(EnterpriseError::NotFound)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityView {
    pub service: String,
    pub available: bool,
    pub authoritative: bool,
    pub data: Value,
    pub data_digest: String,
    pub safe_error_code: Option<String>,
    pub fetched_at: DateTime<Utc>,
}

pub trait AuthoritativeServicePort: Send + Sync {
    fn fetch(
        &self,
        tenant: &TenantId,
        resource: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<AuthorityView, EnterpriseError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DashboardView {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub sections: BTreeMap<String, AuthorityView>,
    pub complete: bool,
    pub unavailable_sections: BTreeSet<String>,
    pub generated_at: DateTime<Utc>,
}

pub struct AdminBff<P: AuthoritativeServicePort> {
    ports: BTreeMap<String, P>,
}

impl<P: AuthoritativeServicePort> AdminBff<P> {
    pub fn new(ports: BTreeMap<String, P>) -> Result<Self, EnterpriseError> {
        if ports.is_empty() {
            return Err(EnterpriseError::ConfigurationInvalid);
        }
        Ok(Self { ports })
    }

    pub fn dashboard(
        &self,
        tenant: &TenantId,
        resource: &str,
        limit: usize,
    ) -> Result<DashboardView, EnterpriseError> {
        if limit == 0 || limit > 100 {
            return Err(EnterpriseError::QueryDenied);
        }
        let mut sections = BTreeMap::new();
        let mut unavailable = BTreeSet::new();
        for (name, port) in &self.ports {
            match port.fetch(tenant, resource, None, limit) {
                Ok(view)
                    if view.available && view.authoritative && is_sha256(&view.data_digest) =>
                {
                    sections.insert(name.clone(), view);
                }
                Ok(mut view) => {
                    view.available = false;
                    view.data = Value::Null;
                    view.safe_error_code = Some("AUTHORITATIVE_SOURCE_UNAVAILABLE".into());
                    unavailable.insert(name.clone());
                    sections.insert(name.clone(), view);
                }
                Err(_) => {
                    unavailable.insert(name.clone());
                    sections.insert(
                        name.clone(),
                        AuthorityView {
                            service: name.clone(),
                            available: false,
                            authoritative: true,
                            data: Value::Null,
                            data_digest: "0".repeat(64),
                            safe_error_code: Some("AUTHORITATIVE_SOURCE_UNAVAILABLE".into()),
                            fetched_at: Utc::now(),
                        },
                    );
                }
            }
        }
        Ok(DashboardView {
            schema_version: ENTERPRISE_SCHEMA_VERSION.into(),
            tenant_id: tenant.clone(),
            complete: unavailable.is_empty(),
            unavailable_sections: unavailable,
            sections,
            generated_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritativeTaskStatus {
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub runtime_status: TaskStatus,
    pub ledger_terminal: bool,
    pub evaluation_passed: bool,
    pub evidence_verified: bool,
    pub status_digest: String,
}

impl AuthoritativeTaskStatus {
    pub fn ui_completion_label(&self) -> &'static str {
        if self.runtime_status == TaskStatus::Completed
            && self.ledger_terminal
            && self.evaluation_passed
            && self.evidence_verified
        {
            "COMPLETED"
        } else if matches!(
            self.runtime_status,
            TaskStatus::Completed | TaskStatus::Verifying
        ) {
            "VERIFYING"
        } else {
            "IN_PROGRESS"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookEnvelope {
    pub schema_version: String,
    pub webhook_id: String,
    pub tenant_id: TenantId,
    pub event_id: String,
    pub event_type: String,
    pub payload: Value,
    pub payload_digest: String,
    pub issued_at: DateTime<Utc>,
    pub key_id: String,
    pub signature: String,
}

impl WebhookEnvelope {
    fn signing_bytes(&self) -> Result<Vec<u8>, EnterpriseError> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| EnterpriseError::SerializationFailed)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), EnterpriseError> {
        let digest = hex(Sha256::digest(
            serde_jcs::to_vec(&self.payload).map_err(|_| EnterpriseError::SerializationFailed)?,
        ));
        if digest != self.payload_digest {
            return Err(EnterpriseError::WebhookInvalid);
        }
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), EnterpriseError> {
        let digest = hex(Sha256::digest(
            serde_jcs::to_vec(&self.payload).map_err(|_| EnterpriseError::SerializationFailed)?,
        ));
        if digest != self.payload_digest {
            return Err(EnterpriseError::WebhookInvalid);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| EnterpriseError::WebhookInvalid)?;
        let signature =
            Signature::from_slice(&decoded).map_err(|_| EnterpriseError::WebhookInvalid)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| EnterpriseError::WebhookInvalid)
    }
}

#[derive(Default)]
pub struct WebhookService {
    delivered: RwLock<BTreeSet<(TenantId, String)>>,
}

impl WebhookService {
    pub fn accept(
        &self,
        envelope: &WebhookEnvelope,
        key: &VerifyingKey,
    ) -> Result<bool, EnterpriseError> {
        envelope.verify(key)?;
        Ok(self
            .delivered
            .write()
            .insert((envelope.tenant_id.clone(), envelope.event_id.clone())))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EnterpriseError {
    #[error("ENTERPRISE_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("ENTERPRISE_ADMIN_DENIED")]
    AdminDenied,
    #[error("ENTERPRISE_TENANT_INVALID")]
    TenantInvalid,
    #[error("ENTERPRISE_PROJECT_INVALID")]
    ProjectInvalid,
    #[error("ENTERPRISE_ORGANIZATION_INVALID")]
    OrganizationInvalid,
    #[error("ENTERPRISE_QUERY_DENIED")]
    QueryDenied,
    #[error("ENTERPRISE_WEBHOOK_INVALID")]
    WebhookInvalid,
    #[error("ENTERPRISE_SERIALIZATION_FAILED")]
    SerializationFailed,
    #[error("ENTERPRISE_AUTHORITY_UNAVAILABLE")]
    AuthorityUnavailable,
    #[error("ENTERPRISE_NOT_FOUND")]
    NotFound,
    #[error("ENTERPRISE_QUOTA_INVALID")]
    QuotaInvalid,
    #[error("ENTERPRISE_QUOTA_EXCEEDED")]
    QuotaExceeded,
    #[error("ENTERPRISE_API_KEY_INVALID")]
    ApiKeyInvalid,
    #[error("ENTERPRISE_API_KEY_DENIED")]
    ApiKeyDenied,
    #[error("ENTERPRISE_INTEGRATION_INVALID")]
    IntegrationInvalid,
    #[error("ENTERPRISE_INTEGRATION_FAILED")]
    IntegrationFailed,
    #[error("ENTERPRISE_LICENSE_INVALID")]
    LicenseInvalid,
    #[error("ENTERPRISE_LICENSE_DENIED")]
    LicenseDenied,
    #[error("ENTERPRISE_COST_INVALID")]
    CostInvalid,
    #[error("ENTERPRISE_CAPACITY_EXCEEDED")]
    CapacityExceeded,
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn secret_hash(pepper: &str, secret: &str) -> String {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(pepper.as_bytes()) else {
        return String::new();
    };
    mac.update(secret.as_bytes());
    hex(mac.finalize().into_bytes())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestPort {
        available: bool,
    }

    impl AuthoritativeServicePort for TestPort {
        fn fetch(
            &self,
            _: &TenantId,
            _: &str,
            _: Option<&str>,
            _: usize,
        ) -> Result<AuthorityView, EnterpriseError> {
            if !self.available {
                return Err(EnterpriseError::AuthorityUnavailable);
            }
            Ok(AuthorityView {
                service: "test".into(),
                available: true,
                authoritative: true,
                data: Value::String("safe".into()),
                data_digest: "d".repeat(64),
                safe_error_code: None,
                fetched_at: Utc::now(),
            })
        }
    }

    struct TestIntegrationPort {
        verifying_key: VerifyingKey,
    }

    impl IntegrationPort for TestIntegrationPort {
        fn deliver(
            &self,
            _: &IntegrationConfig,
            envelope: &WebhookEnvelope,
            idempotency_key: &str,
        ) -> Result<String, EnterpriseError> {
            envelope.verify(&self.verifying_key)?;
            if !idempotency_key.starts_with("integration:") {
                return Err(EnterpriseError::IntegrationFailed);
            }
            Ok(format!("evidence://{idempotency_key}"))
        }
    }

    #[test]
    fn cross_tenant_and_missing_separation_are_denied() {
        let principal = AdminPrincipal {
            subject: "admin:1".into(),
            tenant_id: TenantId::new(),
            roles: BTreeSet::from(["policy-admin".into()]),
            project_ids: BTreeSet::from(["project:1".into()]),
            csrf_verified: true,
            authentication_time: Utc::now(),
        };
        let action = AdminAction {
            schema_version: ENTERPRISE_SCHEMA_VERSION.into(),
            action_id: Uuid::new_v4().to_string(),
            tenant_id: TenantId::new(),
            project_id: Some("project:1".into()),
            operation: "PROMOTE_POLICY".into(),
            resource: "policy://bundle".into(),
            requested_by: "admin:1".into(),
            approval_ids: BTreeSet::new(),
            action_digest: "a".repeat(64),
            requested_at: Utc::now(),
        };
        assert_eq!(
            AdminAuthorizer::authorize(
                &principal,
                &action,
                &"a".repeat(64),
                &BTreeSet::from(["policy-admin".into()]),
                true
            ),
            Err(EnterpriseError::AdminDenied)
        );
    }

    #[test]
    fn admin_authorization_is_bound_to_canonical_action_digest() {
        let tenant_id = TenantId::new();
        let principal = AdminPrincipal {
            subject: "admin:1".into(),
            tenant_id: tenant_id.clone(),
            roles: BTreeSet::from(["policy-admin".into()]),
            project_ids: BTreeSet::from(["project:1".into()]),
            csrf_verified: true,
            authentication_time: Utc::now(),
        };
        let action = AdminAction {
            schema_version: ENTERPRISE_SCHEMA_VERSION.into(),
            action_id: Uuid::new_v4().to_string(),
            tenant_id,
            project_id: Some("project:1".into()),
            operation: "PROMOTE_POLICY".into(),
            resource: "policy://bundle".into(),
            requested_by: "admin:1".into(),
            approval_ids: BTreeSet::from(["approval:1".into()]),
            action_digest: "a".repeat(64),
            requested_at: Utc::now(),
        };
        let roles = BTreeSet::from(["policy-admin".into()]);
        assert_eq!(
            AdminAuthorizer::authorize(&principal, &action, &"a".repeat(64), &roles, true),
            Ok(())
        );
        assert_eq!(
            AdminAuthorizer::authorize(&principal, &action, &"b".repeat(64), &roles, true),
            Err(EnterpriseError::AdminDenied)
        );
    }

    #[test]
    fn unavailable_authority_is_visible_not_fake_success() {
        let bff = AdminBff::new(BTreeMap::from([
            ("tasks".into(), TestPort { available: true }),
            ("evidence".into(), TestPort { available: false }),
        ]))
        .unwrap_or_else(|error| panic!("bff: {error}"));
        let view = bff
            .dashboard(&TenantId::new(), "dashboard", 10)
            .unwrap_or_else(|error| panic!("dashboard: {error}"));
        assert!(!view.complete);
        assert!(view.unavailable_sections.contains("evidence"));
        assert_eq!(
            view.sections
                .get("evidence")
                .and_then(|section| section.safe_error_code.as_deref()),
            Some("AUTHORITATIVE_SOURCE_UNAVAILABLE")
        );
    }

    #[test]
    fn browser_cannot_claim_completion_without_ledger_evaluation_and_evidence() {
        let status = AuthoritativeTaskStatus {
            tenant_id: TenantId::new(),
            task_id: TaskId::new(),
            runtime_status: TaskStatus::Completed,
            ledger_terminal: true,
            evaluation_passed: true,
            evidence_verified: false,
            status_digest: "s".repeat(64),
        };
        assert_eq!(status.ui_completion_label(), "VERIFYING");
    }

    #[test]
    fn webhook_tamper_and_replay_are_detected() {
        let key = SigningKey::from_bytes(&[61_u8; 32]);
        let payload = Value::String("safe".into());
        let mut envelope = WebhookEnvelope {
            schema_version: ENTERPRISE_SCHEMA_VERSION.into(),
            webhook_id: "webhook:1".into(),
            tenant_id: TenantId::new(),
            event_id: "event:1".into(),
            event_type: "INCIDENT_CREATED".into(),
            payload_digest: hex(Sha256::digest(
                serde_jcs::to_vec(&payload).unwrap_or_else(|_| panic!("payload")),
            )),
            payload,
            issued_at: Utc::now(),
            key_id: "webhook-key".into(),
            signature: String::new(),
        };
        envelope
            .sign(&key)
            .unwrap_or_else(|error| panic!("sign: {error}"));
        let service = WebhookService::default();
        assert_eq!(service.accept(&envelope, &key.verifying_key()), Ok(true));
        assert_eq!(service.accept(&envelope, &key.verifying_key()), Ok(false));
        envelope.payload = Value::String("tampered".into());
        assert_eq!(
            service.accept(&envelope, &key.verifying_key()),
            Err(EnterpriseError::WebhookInvalid)
        );
    }

    #[test]
    fn quota_and_cost_are_tenant_scoped_and_bounded() {
        let tenant = TenantId::new();
        let quota = QuotaService::default();
        let window = Utc::now();
        assert_eq!(
            quota
                .consume(&tenant, "api_requests", window, 7, 10)
                .map(|usage| usage.used),
            Ok(7)
        );
        assert_eq!(
            quota.consume(&tenant, "api_requests", window, 4, 10),
            Err(EnterpriseError::QuotaExceeded)
        );

        let costs = CostService::default();
        assert_eq!(
            costs.record(CostUsage {
                tenant_id: tenant.clone(),
                project_id: "project:1".into(),
                meter: "model_tokens".into(),
                quantity: 10,
                unit_cost_micros: 3,
                total_cost_micros: 30,
                source_digest: "c".repeat(64),
                recorded_at: Utc::now(),
            }),
            Ok(())
        );
        assert_eq!(costs.total_for_project(&tenant, "project:1"), Ok(30));
        assert_eq!(
            costs.total_for_project(&TenantId::new(), "project:1"),
            Ok(0)
        );
    }

    #[test]
    fn api_keys_are_one_time_scoped_expiring_and_revocable() {
        let tenant = TenantId::new();
        let service = ApiKeyService::new("p".repeat(32))
            .unwrap_or_else(|error| panic!("api key service: {error}"));
        let issued = service
            .issue(
                tenant.clone(),
                Some("project:1".into()),
                BTreeSet::from(["tasks:read".into()]),
                "admin:1".into(),
                Utc::now() + chrono::Duration::days(1),
            )
            .unwrap_or_else(|error| panic!("issue key: {error}"));
        assert!(
            service
                .authenticate(
                    &tenant,
                    &issued.record.api_key_id,
                    &issued.one_time_secret,
                    "tasks:read",
                    Utc::now(),
                )
                .is_ok()
        );
        assert_eq!(
            service.authenticate(
                &tenant,
                &issued.record.api_key_id,
                "wrong",
                "tasks:read",
                Utc::now(),
            ),
            Err(EnterpriseError::ApiKeyDenied)
        );
        assert_eq!(
            service.revoke(&tenant, &issued.record.api_key_id, "rotation"),
            Ok(())
        );
        assert_eq!(
            service.authenticate(
                &tenant,
                &issued.record.api_key_id,
                &issued.one_time_secret,
                "tasks:read",
                Utc::now(),
            ),
            Err(EnterpriseError::ApiKeyDenied)
        );
    }

    #[test]
    fn signed_license_fails_closed_after_revocation() {
        let tenant = TenantId::new();
        let signing_key = SigningKey::from_bytes(&[71_u8; 32]);
        let now = Utc::now();
        let mut license = EnterpriseLicense {
            schema_version: ENTERPRISE_SCHEMA_VERSION.into(),
            license_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.clone(),
            plan_code: "enterprise".into(),
            entitlements: BTreeSet::from(["policy:promote".into()]),
            starts_at: now - chrono::Duration::minutes(1),
            expires_at: now + chrono::Duration::days(30),
            key_id: "license-key:1".into(),
            signature: String::new(),
        };
        license
            .sign(&signing_key)
            .unwrap_or_else(|error| panic!("sign license: {error}"));
        let license_id = license.license_id.clone();
        let service = LicenseService::new(BTreeMap::from([(
            "license-key:1".into(),
            signing_key.verifying_key(),
        )]))
        .unwrap_or_else(|error| panic!("license service: {error}"));
        assert!(service.install(license, now).is_ok());
        assert_eq!(
            service.authorize(&tenant, &license_id, "policy:promote", now),
            Ok(())
        );
        assert_eq!(service.revoke(&tenant, &license_id), Ok(()));
        assert_eq!(
            service.authorize(&tenant, &license_id, "policy:promote", now),
            Err(EnterpriseError::LicenseDenied)
        );
    }

    #[test]
    fn integration_requires_https_and_signs_delivery() {
        let signing_key = SigningKey::from_bytes(&[72_u8; 32]);
        let service = IntegrationService::new(
            TestIntegrationPort {
                verifying_key: signing_key.verifying_key(),
            },
            "integration-key:1".into(),
            signing_key,
        )
        .unwrap_or_else(|error| panic!("integration service: {error}"));
        let mut config = IntegrationConfig {
            integration_id: "integration:1".into(),
            tenant_id: TenantId::new(),
            kind: IntegrationKind::Siem,
            endpoint: "https://siem.example.invalid/events".into(),
            secret_ref: "vault://integrations/siem".into(),
            configuration_digest: "f".repeat(64),
            active: true,
        };
        assert!(
            service
                .send(
                    &config,
                    "event:1",
                    "INCIDENT_CREATED",
                    serde_json::json!({"incident_id": "incident:1"}),
                )
                .is_ok()
        );
        config.endpoint = "http://insecure.invalid/events".into();
        assert_eq!(
            service.send(&config, "event:2", "INCIDENT_CREATED", Value::Null),
            Err(EnterpriseError::IntegrationInvalid)
        );
    }
}
