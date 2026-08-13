//! Tenant-isolated audit retention, control catalog, legal hold, and offline export.

pub mod postgres;

use agent_trust_contracts::{DataClassification, SchemaVersion, TaskId, TenantId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const AUDIT_SCHEMA_VERSION: &str = "agenttrust.audit-retention.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditRecordDraft {
    pub schema_version: SchemaVersion,
    pub request_id: String,
    pub tenant_id: TenantId,
    pub task_id: TaskId,
    pub event_type: String,
    pub actor_subject: String,
    pub resource: String,
    pub classification: DataClassification,
    pub payload_hash: String,
    pub safe_summary: String,
    pub artifact_hashes: Vec<String>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub schema_version: String,
    pub record_id: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub record_hash: String,
    pub key_id: String,
    pub signature: String,
    pub draft: AuditRecordDraft,
}

impl AuditRecord {
    fn unsigned_bytes(&self) -> Result<Vec<u8>, AuditError> {
        let mut copy = self.clone();
        copy.record_hash.clear();
        copy.signature.clear();
        serde_jcs::to_vec(&copy).map_err(|_| AuditError::Canonicalization)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AuditSnapshot {
    schema_version: String,
    records: BTreeMap<TenantId, Vec<AuditRecord>>,
    request_ids: BTreeMap<String, AuditRecord>,
    deleted_payloads: BTreeSet<String>,
}

pub struct AuditIngest {
    key_id: String,
    signing_key: SigningKey,
    maximum_records_per_tenant: usize,
    records: Mutex<BTreeMap<TenantId, Vec<AuditRecord>>>,
    request_ids: Mutex<BTreeMap<String, AuditRecord>>,
    deleted_payloads: Mutex<BTreeSet<String>>,
}

impl AuditIngest {
    pub fn new(
        key_id: String,
        signing_key: SigningKey,
        maximum_records_per_tenant: usize,
    ) -> Result<Self, AuditError> {
        if key_id.is_empty() || maximum_records_per_tenant == 0 {
            return Err(AuditError::ConfigurationInvalid);
        }
        Ok(Self {
            key_id,
            signing_key,
            maximum_records_per_tenant,
            records: Mutex::new(BTreeMap::new()),
            request_ids: Mutex::new(BTreeMap::new()),
            deleted_payloads: Mutex::new(BTreeSet::new()),
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn append_batch(
        &self,
        drafts: Vec<AuditRecordDraft>,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        if drafts.is_empty() {
            return Err(AuditError::RecordInvalid);
        }
        for draft in &drafts {
            validate_draft(draft)?;
        }
        let first_tenant = drafts[0].tenant_id.clone();
        if drafts.iter().any(|draft| draft.tenant_id != first_tenant) {
            return Err(AuditError::TenantDenied);
        }
        let request_ids = self.request_ids.lock();
        let existing: Vec<AuditRecord> = drafts
            .iter()
            .filter_map(|draft| request_ids.get(&draft.request_id).cloned())
            .collect();
        if !existing.is_empty() {
            if existing.len() == drafts.len() {
                return Ok(existing);
            }
            return Err(AuditError::IdempotencyConflict);
        }
        drop(request_ids);

        let mut chains = self.records.lock();
        let chain = chains.entry(first_tenant).or_default();
        if chain.len().saturating_add(drafts.len()) > self.maximum_records_per_tenant {
            return Err(AuditError::CapacityExceeded);
        }
        let mut appended = Vec::with_capacity(drafts.len());
        for draft in drafts {
            let mut record = AuditRecord {
                schema_version: AUDIT_SCHEMA_VERSION.into(),
                record_id: Uuid::new_v4().to_string(),
                sequence: chain.len() as u64 + 1,
                previous_hash: chain
                    .last()
                    .map_or_else(|| "0".repeat(64), |entry| entry.record_hash.clone()),
                record_hash: String::new(),
                key_id: self.key_id.clone(),
                signature: String::new(),
                draft,
            };
            record.record_hash = hex(Sha256::digest(record.unsigned_bytes()?));
            record.signature = URL_SAFE_NO_PAD.encode(
                self.signing_key
                    .sign(record.record_hash.as_bytes())
                    .to_bytes(),
            );
            chain.push(record.clone());
            appended.push(record);
        }
        let mut request_ids = self.request_ids.lock();
        for record in &appended {
            request_ids.insert(record.draft.request_id.clone(), record.clone());
        }
        Ok(appended)
    }

    pub fn tenant_records(&self, tenant: &TenantId) -> Vec<AuditRecord> {
        self.records.lock().get(tenant).cloned().unwrap_or_default()
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, AuditError> {
        serde_json::to_vec(&AuditSnapshot {
            schema_version: AUDIT_SCHEMA_VERSION.into(),
            records: self.records.lock().clone(),
            request_ids: self.request_ids.lock().clone(),
            deleted_payloads: self.deleted_payloads.lock().clone(),
        })
        .map_err(|_| AuditError::PersistenceFailed)
    }

    pub fn restore(
        bytes: &[u8],
        key_id: String,
        signing_key: SigningKey,
        maximum_records_per_tenant: usize,
    ) -> Result<Self, AuditError> {
        let snapshot: AuditSnapshot =
            serde_json::from_slice(bytes).map_err(|_| AuditError::PersistenceFailed)?;
        if snapshot.schema_version != AUDIT_SCHEMA_VERSION
            || snapshot
                .records
                .values()
                .any(|records| records.len() > maximum_records_per_tenant)
        {
            return Err(AuditError::PersistenceFailed);
        }
        let service = Self::new(key_id, signing_key, maximum_records_per_tenant)?;
        *service.records.lock() = snapshot.records;
        *service.request_ids.lock() = snapshot.request_ids;
        *service.deleted_payloads.lock() = snapshot.deleted_payloads;
        Ok(service)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditQuery {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub actor_subject: String,
    pub audit_task_id: TaskId,
    pub resource_prefix: String,
    pub maximum_classification: DataClassification,
    pub limit: usize,
}

pub struct AuditQueryService<'a> {
    ingest: &'a AuditIngest,
    maximum_query_records: usize,
}

impl<'a> AuditQueryService<'a> {
    pub fn new(ingest: &'a AuditIngest, maximum_query_records: usize) -> Result<Self, AuditError> {
        if maximum_query_records == 0 {
            return Err(AuditError::ConfigurationInvalid);
        }
        Ok(Self {
            ingest,
            maximum_query_records,
        })
    }

    pub fn search(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, AuditError> {
        if query.schema_version != AUDIT_SCHEMA_VERSION
            || query.actor_subject.is_empty()
            || query.limit == 0
            || query.limit > self.maximum_query_records
        {
            return Err(AuditError::QueryDenied);
        }
        let records: Vec<AuditRecord> = self
            .ingest
            .tenant_records(&query.tenant_id)
            .into_iter()
            .filter(|record| {
                record.draft.resource.starts_with(&query.resource_prefix)
                    && record.draft.classification <= query.maximum_classification
            })
            .take(query.limit)
            .collect();
        let query_hash = hex(Sha256::digest(
            serde_jcs::to_vec(query).map_err(|_| AuditError::Canonicalization)?,
        ));
        self.ingest.append_batch(vec![AuditRecordDraft {
            schema_version: SchemaVersion(AUDIT_SCHEMA_VERSION.into()),
            request_id: format!("query:{query_hash}"),
            tenant_id: query.tenant_id.clone(),
            task_id: query.audit_task_id.clone(),
            event_type: "AUDIT_QUERY".into(),
            actor_subject: query.actor_subject.clone(),
            resource: "audit://query".into(),
            classification: DataClassification::Internal,
            payload_hash: query_hash,
            safe_summary: format!("audit query returned {} records", records.len()),
            artifact_hashes: vec![],
            occurred_at: Utc::now(),
        }])?;
        Ok(records)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub tenant_id: TenantId,
    pub event_type: String,
    pub classification: DataClassification,
    pub compliance_profile: String,
    pub retain_seconds: u64,
    pub anonymize_after_seconds: Option<u64>,
    pub policy_digest: String,
}

#[derive(Default)]
pub struct RetentionEngine {
    policies: RwLock<BTreeMap<(TenantId, String, DataClassification, String), RetentionPolicy>>,
}

impl RetentionEngine {
    pub fn register(&self, policy: RetentionPolicy) -> Result<(), AuditError> {
        if policy.schema_version != AUDIT_SCHEMA_VERSION
            || policy.policy_id.is_empty()
            || policy.event_type.is_empty()
            || policy.compliance_profile.is_empty()
            || policy.retain_seconds == 0
            || policy.policy_digest.len() != 64
        {
            return Err(AuditError::RetentionPolicyInvalid);
        }
        let key = (
            policy.tenant_id.clone(),
            policy.event_type.clone(),
            policy.classification,
            policy.compliance_profile.clone(),
        );
        self.policies.write().insert(key, policy);
        Ok(())
    }

    pub fn resolve(
        &self,
        tenant: &TenantId,
        event_type: &str,
        classification: DataClassification,
        profile: &str,
    ) -> Result<RetentionPolicy, AuditError> {
        self.policies
            .read()
            .get(&(
                tenant.clone(),
                event_type.into(),
                classification,
                profile.into(),
            ))
            .cloned()
            .ok_or(AuditError::RetentionPolicyMissing)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegalHold {
    pub schema_version: String,
    pub hold_id: String,
    pub tenant_id: TenantId,
    pub task_id: Option<TaskId>,
    pub actor_subject: Option<String>,
    pub resource_prefix: Option<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: Option<DateTime<Utc>>,
    pub placed_by: String,
    pub reason_code: String,
    pub released_at: Option<DateTime<Utc>>,
    pub released_by: Option<String>,
}

#[derive(Default)]
pub struct LegalHoldService {
    holds: RwLock<BTreeMap<String, LegalHold>>,
}

impl LegalHoldService {
    pub fn place(&self, hold: LegalHold) -> Result<(), AuditError> {
        if hold.schema_version != AUDIT_SCHEMA_VERSION
            || hold.hold_id.is_empty()
            || hold.placed_by.is_empty()
            || hold.reason_code.is_empty()
            || hold.released_at.is_some()
            || hold.released_by.is_some()
        {
            return Err(AuditError::LegalHoldInvalid);
        }
        if self.holds.read().contains_key(&hold.hold_id) {
            return Err(AuditError::LegalHoldConflict);
        }
        self.holds.write().insert(hold.hold_id.clone(), hold);
        Ok(())
    }

    pub fn release(
        &self,
        hold_id: &str,
        actor: &str,
        roles: &BTreeSet<String>,
        now: DateTime<Utc>,
    ) -> Result<LegalHold, AuditError> {
        let mut holds = self.holds.write();
        let hold = holds.get_mut(hold_id).ok_or(AuditError::NotFound)?;
        if actor == hold.placed_by
            || !roles.contains("legal_hold_release")
            || hold.released_at.is_some()
        {
            return Err(AuditError::LegalHoldReleaseDenied);
        }
        hold.released_at = Some(now);
        hold.released_by = Some(actor.into());
        Ok(hold.clone())
    }

    pub fn protects(&self, record: &AuditRecord) -> bool {
        self.holds.read().values().any(|hold| {
            hold.released_at.is_none()
                && hold.tenant_id == record.draft.tenant_id
                && hold.starts_at <= record.draft.occurred_at
                && hold
                    .ends_at
                    .is_none_or(|end| record.draft.occurred_at <= end)
                && hold
                    .task_id
                    .as_ref()
                    .is_none_or(|task| task == &record.draft.task_id)
                && hold
                    .actor_subject
                    .as_ref()
                    .is_none_or(|actor| actor == &record.draft.actor_subject)
                && hold
                    .resource_prefix
                    .as_ref()
                    .is_none_or(|prefix| record.draft.resource.starts_with(prefix))
        })
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, AuditError> {
        serde_json::to_vec(&*self.holds.read()).map_err(|_| AuditError::PersistenceFailed)
    }

    pub fn restore(bytes: &[u8]) -> Result<Self, AuditError> {
        let holds = serde_json::from_slice(bytes).map_err(|_| AuditError::PersistenceFailed)?;
        Ok(Self {
            holds: RwLock::new(holds),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeletionProof {
    pub schema_version: String,
    pub deletion_id: String,
    pub tenant_id: TenantId,
    pub policy_id: String,
    pub deleted_payload_hashes: Vec<String>,
    pub protected_record_ids: Vec<String>,
    pub executed_at: DateTime<Utc>,
}

pub struct DeletionService<'a> {
    ingest: &'a AuditIngest,
    holds: &'a LegalHoldService,
}

impl<'a> DeletionService<'a> {
    pub fn new(ingest: &'a AuditIngest, holds: &'a LegalHoldService) -> Self {
        Self { ingest, holds }
    }

    pub fn delete_with_proof(
        &self,
        tenant: &TenantId,
        policy_id: String,
        before: DateTime<Utc>,
    ) -> Result<DeletionProof, AuditError> {
        if policy_id.is_empty() {
            return Err(AuditError::RetentionPolicyInvalid);
        }
        let mut deleted = self.ingest.deleted_payloads.lock();
        let mut deleted_payload_hashes = Vec::new();
        let mut protected_record_ids = Vec::new();
        for record in self.ingest.tenant_records(tenant) {
            if record.draft.occurred_at >= before {
                continue;
            }
            if self.holds.protects(&record) {
                protected_record_ids.push(record.record_id);
            } else if deleted.insert(record.draft.payload_hash.clone()) {
                deleted_payload_hashes.push(record.draft.payload_hash);
            }
        }
        Ok(DeletionProof {
            schema_version: AUDIT_SCHEMA_VERSION.into(),
            deletion_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.clone(),
            policy_id,
            deleted_payload_hashes,
            protected_record_ids,
            executed_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditExportManifest {
    pub schema_version: String,
    pub export_id: String,
    pub tenant_id: TenantId,
    pub record_hashes: Vec<String>,
    pub chain_head: String,
    pub transformed: bool,
    pub transformation_hash: Option<String>,
    pub key_id: String,
    pub manifest_hash: String,
    pub signature: String,
    pub exported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditExportPackage {
    pub manifest: AuditExportManifest,
    pub records: Vec<AuditRecord>,
}

pub struct AuditExportService<'a> {
    ingest: &'a AuditIngest,
    key_id: String,
    signing_key: SigningKey,
}

impl<'a> AuditExportService<'a> {
    pub fn new(
        ingest: &'a AuditIngest,
        key_id: String,
        signing_key: SigningKey,
    ) -> Result<Self, AuditError> {
        if key_id.is_empty() {
            return Err(AuditError::ConfigurationInvalid);
        }
        Ok(Self {
            ingest,
            key_id,
            signing_key,
        })
    }

    pub fn export(
        &self,
        tenant: &TenantId,
        maximum_classification: DataClassification,
        transformed: bool,
    ) -> Result<AuditExportPackage, AuditError> {
        let records: Vec<AuditRecord> = self
            .ingest
            .tenant_records(tenant)
            .into_iter()
            .filter(|record| record.draft.classification <= maximum_classification)
            .collect();
        if records.is_empty() {
            return Err(AuditError::NotFound);
        }
        let record_hashes: Vec<String> = records
            .iter()
            .map(|record| record.record_hash.clone())
            .collect();
        let transformation_hash =
            transformed.then(|| hex(Sha256::digest(record_hashes.join(":redacted:").as_bytes())));
        let mut manifest = AuditExportManifest {
            schema_version: AUDIT_SCHEMA_VERSION.into(),
            export_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.clone(),
            chain_head: record_hashes.last().cloned().unwrap_or_default(),
            record_hashes,
            transformed,
            transformation_hash,
            key_id: self.key_id.clone(),
            manifest_hash: String::new(),
            signature: String::new(),
            exported_at: Utc::now(),
        };
        manifest.manifest_hash = manifest_hash(&manifest)?;
        manifest.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(manifest.manifest_hash.as_bytes())
                .to_bytes(),
        );
        Ok(AuditExportPackage { manifest, records })
    }
}

pub struct IntegrityVerifier {
    keys: BTreeMap<String, VerifyingKey>,
}

impl IntegrityVerifier {
    pub fn new(keys: BTreeMap<String, VerifyingKey>) -> Self {
        Self { keys }
    }

    pub fn verify(&self, package: &AuditExportPackage) -> Result<(), AuditError> {
        let key = self
            .keys
            .get(&package.manifest.key_id)
            .ok_or(AuditError::SignatureInvalid)?;
        verify_signature(
            key,
            &package.manifest.manifest_hash,
            &package.manifest.signature,
        )?;
        if manifest_hash(&package.manifest)? != package.manifest.manifest_hash
            || package.records.is_empty()
            || package.manifest.tenant_id != package.records[0].draft.tenant_id
            || package.manifest.record_hashes
                != package
                    .records
                    .iter()
                    .map(|record| record.record_hash.clone())
                    .collect::<Vec<_>>()
        {
            return Err(AuditError::IntegrityFailed);
        }
        let mut previous = "0".repeat(64);
        for (index, record) in package.records.iter().enumerate() {
            if record.sequence != index as u64 + 1
                || record.previous_hash != previous
                || record.record_hash != hex(Sha256::digest(record.unsigned_bytes()?))
            {
                return Err(AuditError::IntegrityFailed);
            }
            let record_key = self
                .keys
                .get(&record.key_id)
                .ok_or(AuditError::SignatureInvalid)?;
            verify_signature(record_key, &record.record_hash, &record.signature)?;
            previous = record.record_hash.clone();
        }
        if previous != package.manifest.chain_head {
            return Err(AuditError::IntegrityFailed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlDefinition {
    pub schema_version: String,
    pub control_id: String,
    pub requirement_ids: BTreeSet<String>,
    pub owner: String,
    pub policy_refs: BTreeSet<String>,
    pub test_refs: BTreeSet<String>,
    pub external_mappings: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlStatus {
    pub schema_version: String,
    pub control_id: String,
    pub effective: bool,
    pub missing_evidence_refs: BTreeSet<String>,
}

#[derive(Default)]
pub struct ControlCatalog {
    controls: RwLock<BTreeMap<String, ControlDefinition>>,
}

impl ControlCatalog {
    pub fn register(&self, control: ControlDefinition) -> Result<(), AuditError> {
        if control.schema_version != AUDIT_SCHEMA_VERSION
            || control.control_id.is_empty()
            || control.owner.is_empty()
            || control.requirement_ids.is_empty()
            || control.policy_refs.is_empty()
            || control.test_refs.is_empty()
        {
            return Err(AuditError::ControlInvalid);
        }
        self.controls
            .write()
            .insert(control.control_id.clone(), control);
        Ok(())
    }

    pub fn status(
        &self,
        control_id: &str,
        evidence_refs: &BTreeSet<String>,
    ) -> Result<ControlStatus, AuditError> {
        let control = self
            .controls
            .read()
            .get(control_id)
            .cloned()
            .ok_or(AuditError::NotFound)?;
        let missing_evidence_refs = control
            .test_refs
            .difference(evidence_refs)
            .cloned()
            .collect::<BTreeSet<_>>();
        Ok(ControlStatus {
            schema_version: AUDIT_SCHEMA_VERSION.into(),
            control_id: control_id.into(),
            effective: missing_evidence_refs.is_empty(),
            missing_evidence_refs,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceNode {
    pub schema_version: String,
    pub node_id: String,
    pub tenant_id: TenantId,
    pub node_type: String,
    pub digest: String,
    pub classification: DataClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceEdge {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub from_node: String,
    pub relation: String,
    pub to_node: String,
}

#[derive(Default)]
pub struct EvidenceGraph {
    nodes: RwLock<BTreeMap<(TenantId, String), EvidenceNode>>,
    edges: RwLock<Vec<EvidenceEdge>>,
}

impl EvidenceGraph {
    pub fn add_node(&self, node: EvidenceNode) -> Result<(), AuditError> {
        if node.schema_version != AUDIT_SCHEMA_VERSION
            || node.node_id.is_empty()
            || node.digest.len() != 64
        {
            return Err(AuditError::GraphInvalid);
        }
        self.nodes
            .write()
            .insert((node.tenant_id.clone(), node.node_id.clone()), node);
        Ok(())
    }

    pub fn add_edge(&self, edge: EvidenceEdge) -> Result<(), AuditError> {
        if edge.schema_version != AUDIT_SCHEMA_VERSION || edge.relation.is_empty() {
            return Err(AuditError::GraphInvalid);
        }
        let nodes = self.nodes.read();
        if !nodes.contains_key(&(edge.tenant_id.clone(), edge.from_node.clone()))
            || !nodes.contains_key(&(edge.tenant_id.clone(), edge.to_node.clone()))
        {
            return Err(AuditError::GraphInvalid);
        }
        drop(nodes);
        self.edges.write().push(edge);
        Ok(())
    }

    pub fn neighbors(&self, tenant: &TenantId, node: &str) -> Vec<EvidenceNode> {
        let target_ids: BTreeSet<String> = self
            .edges
            .read()
            .iter()
            .filter(|edge| &edge.tenant_id == tenant && edge.from_node == node)
            .map(|edge| edge.to_node.clone())
            .collect();
        self.nodes
            .read()
            .iter()
            .filter(|((node_tenant, node_id), _)| {
                node_tenant == tenant && target_ids.contains(node_id)
            })
            .map(|(_, value)| value.clone())
            .collect()
    }
}

fn validate_draft(draft: &AuditRecordDraft) -> Result<(), AuditError> {
    let summary = draft.safe_summary.to_ascii_lowercase();
    if draft.schema_version.0 != AUDIT_SCHEMA_VERSION
        || draft.request_id.is_empty()
        || draft.event_type.is_empty()
        || draft.actor_subject.is_empty()
        || draft.resource.is_empty()
        || draft.payload_hash.len() != 64
        || draft.safe_summary.is_empty()
        || draft.artifact_hashes.iter().any(|hash| hash.len() != 64)
        || ["password=", "api_key=", "bearer ", "private key"]
            .iter()
            .any(|needle| summary.contains(needle))
    {
        Err(AuditError::RecordInvalid)
    } else {
        Ok(())
    }
}

fn manifest_hash(manifest: &AuditExportManifest) -> Result<String, AuditError> {
    let mut copy = manifest.clone();
    copy.manifest_hash.clear();
    copy.signature.clear();
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(&copy).map_err(|_| AuditError::Canonicalization)?,
    )))
}

fn verify_signature(key: &VerifyingKey, message: &str, encoded: &str) -> Result<(), AuditError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AuditError::SignatureInvalid)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| AuditError::SignatureInvalid)?;
    key.verify(message.as_bytes(), &signature)
        .map_err(|_| AuditError::SignatureInvalid)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuditError {
    #[error("AUDIT_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("AUDIT_RECORD_INVALID")]
    RecordInvalid,
    #[error("AUDIT_TENANT_DENIED")]
    TenantDenied,
    #[error("AUDIT_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("AUDIT_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[error("AUDIT_QUERY_DENIED")]
    QueryDenied,
    #[error("AUDIT_RETENTION_POLICY_INVALID")]
    RetentionPolicyInvalid,
    #[error("AUDIT_RETENTION_POLICY_MISSING")]
    RetentionPolicyMissing,
    #[error("AUDIT_LEGAL_HOLD_INVALID")]
    LegalHoldInvalid,
    #[error("AUDIT_LEGAL_HOLD_CONFLICT")]
    LegalHoldConflict,
    #[error("AUDIT_LEGAL_HOLD_RELEASE_DENIED")]
    LegalHoldReleaseDenied,
    #[error("AUDIT_NOT_FOUND")]
    NotFound,
    #[error("AUDIT_CANONICALIZATION_FAILED")]
    Canonicalization,
    #[error("AUDIT_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("AUDIT_INTEGRITY_FAILED")]
    IntegrityFailed,
    #[error("AUDIT_PERSISTENCE_FAILED")]
    PersistenceFailed,
    #[error("AUDIT_CONTROL_INVALID")]
    ControlInvalid,
    #[error("AUDIT_GRAPH_INVALID")]
    GraphInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn tenant() -> TenantId {
        TenantId::new()
    }

    fn draft(
        tenant: &TenantId,
        task: &TaskId,
        request: &str,
        at: DateTime<Utc>,
    ) -> AuditRecordDraft {
        AuditRecordDraft {
            schema_version: SchemaVersion(AUDIT_SCHEMA_VERSION.into()),
            request_id: request.into(),
            tenant_id: tenant.clone(),
            task_id: task.clone(),
            event_type: "TOOL_EXECUTED".into(),
            actor_subject: "agent:test".into(),
            resource: "repo://demo/src/lib.rs".into(),
            classification: DataClassification::Internal,
            payload_hash: "a".repeat(64),
            safe_summary: "tool execution recorded".into(),
            artifact_hashes: vec!["b".repeat(64)],
            occurred_at: at,
        }
    }

    #[test]
    fn batch_is_idempotent_and_snapshot_recovers() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let ingest = AuditIngest::new("audit-key".into(), key.clone(), 20)
            .unwrap_or_else(|error| panic!("create ingest: {error}"));
        let tenant = tenant();
        let task = TaskId::new();
        let input = vec![draft(&tenant, &task, "r1", Utc::now())];
        let first = ingest
            .append_batch(input.clone())
            .unwrap_or_else(|error| panic!("append: {error}"));
        let second = ingest
            .append_batch(input)
            .unwrap_or_else(|error| panic!("retry: {error}"));
        assert_eq!(first, second);
        let bytes = ingest
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let recovered = AuditIngest::restore(&bytes, "audit-key".into(), key, 20)
            .unwrap_or_else(|error| panic!("restore: {error}"));
        assert_eq!(recovered.tenant_records(&tenant).len(), 1);
    }

    #[test]
    fn legal_hold_beats_deletion_and_requires_independent_release() {
        let ingest = AuditIngest::new("audit-key".into(), SigningKey::from_bytes(&[8_u8; 32]), 20)
            .unwrap_or_else(|error| panic!("create ingest: {error}"));
        let tenant = tenant();
        let task = TaskId::new();
        ingest
            .append_batch(vec![draft(
                &tenant,
                &task,
                "old",
                Utc::now() - Duration::days(30),
            )])
            .unwrap_or_else(|error| panic!("append: {error}"));
        let holds = LegalHoldService::default();
        holds
            .place(LegalHold {
                schema_version: AUDIT_SCHEMA_VERSION.into(),
                hold_id: "hold-1".into(),
                tenant_id: tenant.clone(),
                task_id: Some(task),
                actor_subject: None,
                resource_prefix: None,
                starts_at: Utc::now() - Duration::days(40),
                ends_at: None,
                placed_by: "legal-a".into(),
                reason_code: "INVESTIGATION".into(),
                released_at: None,
                released_by: None,
            })
            .unwrap_or_else(|error| panic!("place: {error}"));
        let proof = DeletionService::new(&ingest, &holds)
            .delete_with_proof(&tenant, "p1".into(), Utc::now())
            .unwrap_or_else(|error| panic!("delete: {error}"));
        assert_eq!(proof.deleted_payload_hashes.len(), 0);
        assert_eq!(proof.protected_record_ids.len(), 1);
        let mut roles = BTreeSet::new();
        roles.insert("legal_hold_release".into());
        assert_eq!(
            holds.release("hold-1", "legal-a", &roles, Utc::now()),
            Err(AuditError::LegalHoldReleaseDenied)
        );
        assert!(
            holds
                .release("hold-1", "legal-b", &roles, Utc::now())
                .is_ok()
        );
    }

    #[test]
    fn offline_export_detects_tamper_and_cross_tenant_graph_is_empty() {
        let record_key = SigningKey::from_bytes(&[9_u8; 32]);
        let export_key = SigningKey::from_bytes(&[10_u8; 32]);
        let ingest = AuditIngest::new("record-key".into(), record_key.clone(), 20)
            .unwrap_or_else(|error| panic!("create ingest: {error}"));
        let tenant = tenant();
        ingest
            .append_batch(vec![draft(&tenant, &TaskId::new(), "one", Utc::now())])
            .unwrap_or_else(|error| panic!("append: {error}"));
        let exporter = AuditExportService::new(&ingest, "export-key".into(), export_key.clone())
            .unwrap_or_else(|error| panic!("exporter: {error}"));
        let package = exporter
            .export(&tenant, DataClassification::Internal, false)
            .unwrap_or_else(|error| panic!("export: {error}"));
        let verifier = IntegrityVerifier::new(BTreeMap::from([
            ("record-key".into(), record_key.verifying_key()),
            ("export-key".into(), export_key.verifying_key()),
        ]));
        assert!(verifier.verify(&package).is_ok());
        let mut tampered = package;
        tampered.records[0].draft.safe_summary = "changed".into();
        assert_eq!(verifier.verify(&tampered), Err(AuditError::IntegrityFailed));

        let graph = EvidenceGraph::default();
        graph
            .add_node(EvidenceNode {
                schema_version: AUDIT_SCHEMA_VERSION.into(),
                node_id: "n1".into(),
                tenant_id: tenant,
                node_type: "CONTROL".into(),
                digest: "c".repeat(64),
                classification: DataClassification::Internal,
            })
            .unwrap_or_else(|error| panic!("node: {error}"));
        assert!(graph.neighbors(&TenantId::new(), "n1").is_empty());
    }

    #[test]
    fn query_is_bounded_and_audited() {
        let ingest = AuditIngest::new(
            "record-key".into(),
            SigningKey::from_bytes(&[11_u8; 32]),
            20,
        )
        .unwrap_or_else(|error| panic!("create ingest: {error}"));
        let tenant = tenant();
        ingest
            .append_batch(vec![draft(&tenant, &TaskId::new(), "one", Utc::now())])
            .unwrap_or_else(|error| panic!("append: {error}"));
        let query =
            AuditQueryService::new(&ingest, 5).unwrap_or_else(|error| panic!("query: {error}"));
        let found = query
            .search(&AuditQuery {
                schema_version: AUDIT_SCHEMA_VERSION.into(),
                tenant_id: tenant.clone(),
                actor_subject: "auditor:1".into(),
                audit_task_id: TaskId::new(),
                resource_prefix: "repo://demo".into(),
                maximum_classification: DataClassification::Internal,
                limit: 2,
            })
            .unwrap_or_else(|error| panic!("search: {error}"));
        assert_eq!(found.len(), 1);
        assert_eq!(ingest.tenant_records(&tenant).len(), 2);
    }
}
