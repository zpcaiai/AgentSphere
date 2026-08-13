//! Tenant-isolated Domain Pack marketplace and activation lifecycle.

use agent_trust_contracts::TenantId;
use agent_trust_pack_supply_chain::{DomainPackManifest, PermissionDiff};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const MARKETPLACE_SCHEMA_VERSION: &str = "agenttrust.pack-marketplace.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublisherTrust {
    Untrusted,
    Verified,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublisherRecord {
    pub publisher_id: String,
    pub tenant_id: Option<TenantId>,
    pub trust: PublisherTrust,
    pub identity_digest: String,
    pub responsibility_contact: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct PublisherTrustService {
    publishers: RwLock<BTreeMap<String, PublisherRecord>>,
}

impl PublisherTrustService {
    pub fn upsert(
        &self,
        record: PublisherRecord,
        independent_reviewer: &str,
    ) -> Result<(), MarketplaceError> {
        if record.publisher_id.is_empty()
            || record.identity_digest.len() != 64
            || record.responsibility_contact.is_empty()
            || independent_reviewer.is_empty()
            || record.publisher_id == independent_reviewer
        {
            return Err(MarketplaceError::PublisherDenied);
        }
        self.publishers
            .write()
            .insert(record.publisher_id.clone(), record);
        Ok(())
    }

    pub fn require_verified(
        &self,
        publisher: &str,
        tenant: &TenantId,
    ) -> Result<(), MarketplaceError> {
        let record = self
            .publishers
            .read()
            .get(publisher)
            .cloned()
            .ok_or(MarketplaceError::PublisherDenied)?;
        if record.trust != PublisherTrust::Verified
            || record
                .tenant_id
                .as_ref()
                .is_some_and(|publisher_tenant| publisher_tenant != tenant)
        {
            return Err(MarketplaceError::PublisherDenied);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketplaceListing {
    pub schema_version: String,
    pub listing_id: String,
    pub owner_tenant_id: TenantId,
    pub pack_id: String,
    pub version: String,
    pub pack_digest: String,
    pub publisher_id: String,
    pub private: bool,
    pub permission_summary: BTreeSet<String>,
    pub risk_summary: BTreeSet<String>,
    pub compatibility: BTreeSet<String>,
    pub certificate_digest: String,
    pub published_at: DateTime<Utc>,
    pub revoked: bool,
}

pub struct MarketplaceService<'a> {
    publisher_trust: &'a PublisherTrustService,
    listings: RwLock<BTreeMap<(String, String), MarketplaceListing>>,
}

impl<'a> MarketplaceService<'a> {
    pub fn new(publisher_trust: &'a PublisherTrustService) -> Self {
        Self {
            publisher_trust,
            listings: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn publish(
        &self,
        tenant: TenantId,
        manifest: &DomainPackManifest,
        private: bool,
        certificate_digest: String,
    ) -> Result<MarketplaceListing, MarketplaceError> {
        self.publisher_trust
            .require_verified(&manifest.publisher_identity, &tenant)?;
        if manifest.digest.len() != 64 || certificate_digest.len() != 64 {
            return Err(MarketplaceError::ListingDenied);
        }
        let key = (manifest.pack_id.clone(), manifest.version.clone());
        let mut listings = self.listings.write();
        if let Some(existing) = listings.get(&key) {
            if existing.pack_digest == manifest.digest && existing.owner_tenant_id == tenant {
                return Ok(existing.clone());
            }
            return Err(MarketplaceError::NameConflict);
        }
        let listing = MarketplaceListing {
            schema_version: MARKETPLACE_SCHEMA_VERSION.into(),
            listing_id: Uuid::new_v4().to_string(),
            owner_tenant_id: tenant,
            pack_id: manifest.pack_id.clone(),
            version: manifest.version.clone(),
            pack_digest: manifest.digest.clone(),
            publisher_id: manifest.publisher_identity.clone(),
            private,
            permission_summary: manifest.permissions.tools.clone(),
            risk_summary: manifest.threat_scenario_refs.clone(),
            compatibility: manifest.compatibility.clone(),
            certificate_digest,
            published_at: Utc::now(),
            revoked: false,
        };
        listings.insert(key, listing.clone());
        Ok(listing)
    }

    pub fn search(
        &self,
        requester_tenant: &TenantId,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MarketplaceListing>, MarketplaceError> {
        if limit == 0 || limit > 100 {
            return Err(MarketplaceError::QueryDenied);
        }
        Ok(self
            .listings
            .read()
            .values()
            .filter(|listing| {
                !listing.revoked
                    && (!listing.private || &listing.owner_tenant_id == requester_tenant)
                    && (query.is_empty() || listing.pack_id.contains(query))
            })
            .take(limit)
            .cloned()
            .collect())
    }

    pub fn revoke(
        &self,
        pack_id: &str,
        version: &str,
        publisher: &str,
    ) -> Result<MarketplaceListing, MarketplaceError> {
        let mut listings = self.listings.write();
        let listing = listings
            .get_mut(&(pack_id.into(), version.into()))
            .ok_or(MarketplaceError::NotFound)?;
        if listing.publisher_id != publisher {
            return Err(MarketplaceError::PublisherDenied);
        }
        listing.revoked = true;
        Ok(listing.clone())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationState {
    PendingApproval,
    Approved,
    Installed,
    Active,
    RolledBack,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Installation {
    pub schema_version: String,
    pub installation_id: String,
    pub tenant_id: TenantId,
    pub environment: String,
    pub pack_id: String,
    pub version: String,
    pub pack_digest: String,
    pub permissions_digest: String,
    pub state: InstallationState,
    pub approved_by: Option<String>,
    pub production_certificate_digest: Option<String>,
    pub previous_installation_id: Option<String>,
    pub running_task_response: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct InstallationService {
    installations: RwLock<BTreeMap<String, Installation>>,
    active: RwLock<BTreeMap<(TenantId, String, String), String>>,
}

impl InstallationService {
    pub fn request(
        &self,
        tenant: TenantId,
        environment: String,
        listing: &MarketplaceListing,
        permissions_digest: String,
    ) -> Result<Installation, MarketplaceError> {
        if listing.revoked || environment.is_empty() || permissions_digest.len() != 64 {
            return Err(MarketplaceError::InstallationDenied);
        }
        let installation = Installation {
            schema_version: MARKETPLACE_SCHEMA_VERSION.into(),
            installation_id: Uuid::new_v4().to_string(),
            tenant_id: tenant,
            environment,
            pack_id: listing.pack_id.clone(),
            version: listing.version.clone(),
            pack_digest: listing.pack_digest.clone(),
            permissions_digest,
            state: InstallationState::PendingApproval,
            approved_by: None,
            production_certificate_digest: None,
            previous_installation_id: None,
            running_task_response: None,
            updated_at: Utc::now(),
        };
        self.installations
            .write()
            .insert(installation.installation_id.clone(), installation.clone());
        Ok(installation)
    }

    pub fn approve(
        &self,
        installation_id: &str,
        reviewer: &str,
        permission_diff: &PermissionDiff,
    ) -> Result<Installation, MarketplaceError> {
        let mut installations = self.installations.write();
        let installation = installations
            .get_mut(installation_id)
            .ok_or(MarketplaceError::NotFound)?;
        if installation.state != InstallationState::PendingApproval || reviewer.is_empty() {
            return Err(MarketplaceError::InstallationDenied);
        }
        if permission_diff.expands_privilege() && reviewer == installation.pack_id {
            return Err(MarketplaceError::PermissionReviewRequired);
        }
        installation.state = InstallationState::Approved;
        installation.approved_by = Some(reviewer.into());
        installation.updated_at = Utc::now();
        Ok(installation.clone())
    }

    pub fn install(&self, installation_id: &str) -> Result<Installation, MarketplaceError> {
        self.transition(
            installation_id,
            InstallationState::Approved,
            InstallationState::Installed,
        )
    }

    pub fn activate(
        &self,
        installation_id: &str,
        production_certificate_digest: Option<String>,
    ) -> Result<Installation, MarketplaceError> {
        let mut installations = self.installations.write();
        let installation = installations
            .get_mut(installation_id)
            .ok_or(MarketplaceError::NotFound)?;
        if installation.state != InstallationState::Installed
            || installation.environment == "production"
                && production_certificate_digest
                    .as_deref()
                    .is_none_or(|digest| digest.len() != 64)
        {
            return Err(MarketplaceError::ActivationDenied);
        }
        installation.production_certificate_digest = production_certificate_digest;
        installation.state = InstallationState::Active;
        installation.updated_at = Utc::now();
        let key = (
            installation.tenant_id.clone(),
            installation.environment.clone(),
            installation.pack_id.clone(),
        );
        let previous = self
            .active
            .write()
            .insert(key, installation.installation_id.clone());
        installation.previous_installation_id = previous;
        Ok(installation.clone())
    }

    pub fn rollback(&self, installation_id: &str) -> Result<Installation, MarketplaceError> {
        let mut installations = self.installations.write();
        let current = installations
            .get(installation_id)
            .cloned()
            .ok_or(MarketplaceError::NotFound)?;
        if current.state != InstallationState::Active {
            return Err(MarketplaceError::RollbackDenied);
        }
        let previous_id = current
            .previous_installation_id
            .clone()
            .ok_or(MarketplaceError::RollbackDenied)?;
        let previous = installations
            .get_mut(&previous_id)
            .ok_or(MarketplaceError::RollbackDenied)?;
        previous.state = InstallationState::Active;
        previous.updated_at = Utc::now();
        let key = (
            current.tenant_id.clone(),
            current.environment.clone(),
            current.pack_id.clone(),
        );
        self.active.write().insert(key, previous_id);
        let current_mut = installations
            .get_mut(installation_id)
            .ok_or(MarketplaceError::NotFound)?;
        current_mut.state = InstallationState::RolledBack;
        current_mut.updated_at = Utc::now();
        Ok(current_mut.clone())
    }

    pub fn revoke(
        &self,
        installation_id: &str,
        running_task_response: &str,
    ) -> Result<Installation, MarketplaceError> {
        if !matches!(running_task_response, "PAUSE" | "KILL" | "ALLOW_TO_FINISH") {
            return Err(MarketplaceError::RevocationDenied);
        }
        let mut installations = self.installations.write();
        let installation = installations
            .get_mut(installation_id)
            .ok_or(MarketplaceError::NotFound)?;
        installation.state = InstallationState::Revoked;
        installation.running_task_response = Some(running_task_response.into());
        installation.updated_at = Utc::now();
        let key = (
            installation.tenant_id.clone(),
            installation.environment.clone(),
            installation.pack_id.clone(),
        );
        self.active.write().remove(&key);
        Ok(installation.clone())
    }

    pub fn active(
        &self,
        tenant: &TenantId,
        environment: &str,
        pack_id: &str,
    ) -> Result<Installation, MarketplaceError> {
        let id = self
            .active
            .read()
            .get(&(tenant.clone(), environment.into(), pack_id.into()))
            .cloned()
            .ok_or(MarketplaceError::NotFound)?;
        self.installations
            .read()
            .get(&id)
            .cloned()
            .ok_or(MarketplaceError::NotFound)
    }

    fn transition(
        &self,
        installation_id: &str,
        from: InstallationState,
        to: InstallationState,
    ) -> Result<Installation, MarketplaceError> {
        let mut installations = self.installations.write();
        let installation = installations
            .get_mut(installation_id)
            .ok_or(MarketplaceError::NotFound)?;
        if installation.state != from {
            return Err(MarketplaceError::InstallationDenied);
        }
        installation.state = to;
        installation.updated_at = Utc::now();
        Ok(installation.clone())
    }
}

pub fn permission_digest(manifest: &DomainPackManifest) -> Result<String, MarketplaceError> {
    Ok(hex(Sha256::digest(
        serde_json::to_vec(&manifest.permissions)
            .map_err(|_| MarketplaceError::SerializationFailed)?,
    )))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MarketplaceError {
    #[error("MARKETPLACE_PUBLISHER_DENIED")]
    PublisherDenied,
    #[error("MARKETPLACE_LISTING_DENIED")]
    ListingDenied,
    #[error("MARKETPLACE_NAME_CONFLICT")]
    NameConflict,
    #[error("MARKETPLACE_QUERY_DENIED")]
    QueryDenied,
    #[error("MARKETPLACE_INSTALLATION_DENIED")]
    InstallationDenied,
    #[error("MARKETPLACE_PERMISSION_REVIEW_REQUIRED")]
    PermissionReviewRequired,
    #[error("MARKETPLACE_ACTIVATION_DENIED")]
    ActivationDenied,
    #[error("MARKETPLACE_ROLLBACK_DENIED")]
    RollbackDenied,
    #[error("MARKETPLACE_REVOCATION_DENIED")]
    RevocationDenied,
    #[error("MARKETPLACE_SERIALIZATION_FAILED")]
    SerializationFailed,
    #[error("MARKETPLACE_NOT_FOUND")]
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_trust_pack_supply_chain::{
        PACK_SCHEMA_VERSION, PackPermissionDeclaration, SignatureEnvelope,
    };

    fn manifest() -> DomainPackManifest {
        DomainPackManifest {
            schema_version: PACK_SCHEMA_VERSION.into(),
            pack_id: "coding".into(),
            version: "1.0.0".into(),
            digest: "a".repeat(64),
            publisher_identity: "publisher:trusted".into(),
            description: "coding".into(),
            permissions: PackPermissionDeclaration {
                tools: BTreeSet::from(["coding.repo_read".into()]),
                ..PackPermissionDeclaration::default()
            },
            tools: vec![],
            policy_bundle_ref: "policy".into(),
            evaluator_ref: "evaluator".into(),
            compensation_refs: BTreeSet::new(),
            threat_scenario_refs: BTreeSet::from(["threat".into()]),
            artifact_refs: BTreeSet::from(["artifact".into()]),
            compatibility: BTreeSet::from(["v1".into()]),
            signature: SignatureEnvelope {
                key_id: "key".into(),
                publisher_identity: "publisher:trusted".into(),
                subject_digest: "a".repeat(64),
                signature: "signature".into(),
                signed_at: Utc::now(),
            },
        }
    }

    fn listing(tenant: &TenantId) -> MarketplaceListing {
        let trust = PublisherTrustService::default();
        trust
            .upsert(
                PublisherRecord {
                    publisher_id: "publisher:trusted".into(),
                    tenant_id: Some(tenant.clone()),
                    trust: PublisherTrust::Verified,
                    identity_digest: "p".repeat(64),
                    responsibility_contact: "security@example.test".into(),
                    updated_at: Utc::now(),
                },
                "reviewer:1",
            )
            .unwrap_or_else(|error| panic!("trust: {error}"));
        MarketplaceService::new(&trust)
            .publish(tenant.clone(), &manifest(), true, "c".repeat(64))
            .unwrap_or_else(|error| panic!("publish: {error}"))
    }

    #[test]
    fn private_listing_is_tenant_isolated() {
        let tenant = TenantId::new();
        let trust = PublisherTrustService::default();
        trust
            .upsert(
                PublisherRecord {
                    publisher_id: "publisher:trusted".into(),
                    tenant_id: Some(tenant.clone()),
                    trust: PublisherTrust::Verified,
                    identity_digest: "p".repeat(64),
                    responsibility_contact: "security@example.test".into(),
                    updated_at: Utc::now(),
                },
                "reviewer:1",
            )
            .unwrap_or_else(|error| panic!("trust: {error}"));
        let service = MarketplaceService::new(&trust);
        service
            .publish(tenant.clone(), &manifest(), true, "c".repeat(64))
            .unwrap_or_else(|error| panic!("publish: {error}"));
        assert_eq!(
            service
                .search(&tenant, "coding", 10)
                .unwrap_or_else(|error| panic!("search: {error}"))
                .len(),
            1
        );
        assert!(
            service
                .search(&TenantId::new(), "coding", 10)
                .unwrap_or_else(|error| panic!("search other: {error}"))
                .is_empty()
        );
    }

    #[test]
    fn production_needs_certificate_and_revocation_blocks_resolution() {
        let tenant = TenantId::new();
        let listing = listing(&tenant);
        let service = InstallationService::default();
        let requested = service
            .request(
                tenant.clone(),
                "production".into(),
                &listing,
                "d".repeat(64),
            )
            .unwrap_or_else(|error| panic!("request: {error}"));
        service
            .approve(
                &requested.installation_id,
                "reviewer:2",
                &PermissionDiff::default(),
            )
            .unwrap_or_else(|error| panic!("approve: {error}"));
        service
            .install(&requested.installation_id)
            .unwrap_or_else(|error| panic!("install: {error}"));
        assert_eq!(
            service.activate(&requested.installation_id, None),
            Err(MarketplaceError::ActivationDenied)
        );
        service
            .activate(&requested.installation_id, Some("e".repeat(64)))
            .unwrap_or_else(|error| panic!("activate: {error}"));
        service
            .revoke(&requested.installation_id, "PAUSE")
            .unwrap_or_else(|error| panic!("revoke: {error}"));
        assert_eq!(
            service.active(&tenant, "production", "coding"),
            Err(MarketplaceError::NotFound)
        );
    }
}
