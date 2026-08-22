//! Durable, tenant-isolated production approval state and atomic grant consumption.

use super::*;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::sync::Arc;

const MAX_REASON_BYTES: usize = 4_096;
const MAX_TEXT_BYTES: usize = 2_048;
const MAX_APPROVAL_TTL_SECONDS: u64 = 604_800;
const MAX_AUTHORITATIVE_PAGE_SIZE: u16 = 100;
const AUTHORITATIVE_CURSOR_TTL_SECONDS: i64 = 900;

pub const APPROVAL_CASE_VIEW_SCHEMA_VERSION: &str = "agenttrust.approval-case-view.v1";
pub const AUTHORITATIVE_APPROVAL_PAGE_SCHEMA_VERSION: &str =
    "agenttrust.authoritative-approval-page.v1";
const AUTHORITATIVE_APPROVAL_CURSOR_SCHEMA_VERSION: &str =
    "agenttrust.authoritative-approval-cursor.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalCaseDomain {
    Coding,
    Industrial,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalCaseViewStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCaseView {
    pub schema_version: String,
    pub case_id: String,
    pub domain: ApprovalCaseDomain,
    pub safe_summary: String,
    pub action_hash: String,
    pub resource: String,
    pub resource_version: String,
    pub policy_version: String,
    pub risk: RiskLevel,
    pub evidence_refs: Vec<String>,
    pub status: ApprovalCaseViewStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeApprovalPage {
    pub schema_version: String,
    pub authoritative: bool,
    pub tenant_id: String,
    pub resource: String,
    pub items: Vec<ApprovalCaseView>,
    pub next_cursor: Option<String>,
    pub data_digest: String,
}

#[derive(Serialize)]
struct AuthoritativeApprovalPageMaterial<'a> {
    schema_version: &'a str,
    authoritative: bool,
    tenant_id: &'a str,
    resource: &'a str,
    items: &'a [ApprovalCaseView],
    next_cursor: &'a Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthoritativeApprovalCursor {
    schema_version: String,
    tenant_id: String,
    resource: String,
    created_at: DateTime<Utc>,
    case_id: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    issuer: String,
    key_id: String,
    signature: String,
}

impl AuthoritativeApprovalCursor {
    fn signing_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        let mut material = self.clone();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| ApprovalError::RequestInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCaseCreateEnvelope {
    pub schema_version: String,
    pub request: ApprovalRequest,
    pub policy: ApprovalPolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalDecision {
    Approve,
    Reject,
    PostReviewed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionEnvelope {
    pub schema_version: String,
    pub decision: ApprovalDecision,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrantIssueRequest {
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrantRevocationRequest {
    pub schema_version: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrantRevocationReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub tenant_id: String,
    pub grant_id: String,
    pub case_id: String,
    pub reason_digest: String,
    pub revoked_by: String,
    pub principal_assertion_jti: String,
    pub principal_assertion_digest: String,
    pub revoked_at: DateTime<Utc>,
    pub issuer: String,
    pub key_id: String,
    pub signature: String,
}

impl ApprovalGrantRevocationReceipt {
    fn signing_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        let mut material = self.clone();
        material.signature.clear();
        serde_jcs::to_vec(&material).map_err(|_| ApprovalError::GrantInvalid)
    }

    pub fn verify(
        &self,
        issuer: &str,
        key_id: &str,
        key: &VerifyingKey,
    ) -> Result<(), ApprovalError> {
        if self.schema_version != "agenttrust.approval-grant-revocation.v1"
            || self.issuer != issuer
            || self.key_id != key_id
            || !canonical_uuid(&self.receipt_id)
            || !canonical_uuid(&self.tenant_id)
            || !canonical_uuid(&self.grant_id)
            || !canonical_uuid(&self.case_id)
            || !is_digest(&self.reason_digest)
            || !identifier(&self.revoked_by)
            || !canonical_uuid(&self.principal_assertion_jti)
            || !is_digest(&self.principal_assertion_digest)
        {
            return Err(ApprovalError::GrantInvalid);
        }
        let signature = decode_signature(&self.signature)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ApprovalError::GrantInvalid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPrincipal {
    pub(crate) tenant_id: TenantId,
    pub(crate) subject: String,
    pub(crate) roles: BTreeSet<String>,
    pub(crate) owned_resources: BTreeSet<String>,
    pub(crate) strong_auth: bool,
    pub(crate) assertion_issuer: String,
    pub(crate) assertion_jti: String,
    pub(crate) assertion_request_digest: String,
    pub(crate) assertion_digest: String,
    pub(crate) assertion_document: Value,
    pub(crate) assertion_expires_at: DateTime<Utc>,
}

impl ApprovalPrincipal {
    fn identity(&self) -> ApproverIdentity {
        ApproverIdentity {
            tenant_id: self.tenant_id.clone(),
            subject: self.subject.clone(),
            roles: self.roles.clone(),
            owned_resources: self.owned_resources.clone(),
            delegated_until: None,
            strong_auth: self.strong_auth,
            active: true,
        }
    }
}

#[derive(Clone)]
pub struct ApprovalSigner {
    issuer: String,
    key_id: String,
    key: Arc<SigningKey>,
}

impl ApprovalSigner {
    pub fn new(issuer: String, key_id: String, key: SigningKey) -> Result<Self, ApprovalError> {
        if !identifier(&issuer) || !key_identifier(&key_id) {
            return Err(ApprovalError::ConfigurationInvalid);
        }
        Ok(Self {
            issuer,
            key_id,
            key: Arc::new(key),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    fn sign_grant(&self, grant: &mut EnterpriseApprovalGrant) -> Result<(), ApprovalError> {
        grant.signature = URL_SAFE_NO_PAD.encode(self.key.sign(&grant.signing_bytes()?).to_bytes());
        Ok(())
    }

    fn sign_consumption(
        &self,
        receipt: &mut SignedApprovalConsumptionReceipt,
    ) -> Result<(), ApprovalError> {
        receipt.signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(&receipt.signing_bytes()?).to_bytes());
        Ok(())
    }

    fn sign_revocation(
        &self,
        receipt: &mut ApprovalGrantRevocationReceipt,
    ) -> Result<(), ApprovalError> {
        receipt.signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(&receipt.signing_bytes()?).to_bytes());
        Ok(())
    }

    fn sign_authoritative_cursor(
        &self,
        cursor: &mut AuthoritativeApprovalCursor,
    ) -> Result<(), ApprovalError> {
        cursor.signature =
            URL_SAFE_NO_PAD.encode(self.key.sign(&cursor.signing_bytes()?).to_bytes());
        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresApprovalStore {
    pool: PgPool,
    signer: ApprovalSigner,
}

impl PostgresApprovalStore {
    pub fn new(pool: PgPool, signer: ApprovalSigner) -> Self {
        Self { pool, signer }
    }

    pub fn signer(&self) -> &ApprovalSigner {
        &self.signer
    }

    pub async fn ready(&self) -> bool {
        sqlx::query(
            "SELECT NOT pg_is_in_recovery() \
             AND to_regclass('public.approval_cases') IS NOT NULL \
             AND to_regclass('public.approval_decisions') IS NOT NULL \
             AND to_regclass('public.approval_grants') IS NOT NULL \
             AND to_regclass('public.approval_notification_outbox') IS NOT NULL \
             AND to_regclass('public.approval_consumptions') IS NOT NULL \
             AND to_regclass('public.approval_mutation_receipts') IS NOT NULL \
             AND to_regclass('public.approval_principal_assertion_uses') IS NOT NULL \
             AND to_regclass('public.approval_events') IS NOT NULL \
             AND (SELECT count(*) = 8 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                  WHERE n.nspname='public' AND c.relname::text = ANY(ARRAY[\
                    'approval_cases','approval_decisions','approval_grants','approval_notification_outbox',\
                    'approval_consumptions','approval_mutation_receipts','approval_principal_assertion_uses','approval_events'\
                  ]) AND c.relrowsecurity AND c.relforcerowsecurity) \
             AND (SELECT count(*) = 8 FROM pg_policies WHERE schemaname='public' \
                  AND tablename::text = ANY(ARRAY[\
                    'approval_cases','approval_decisions','approval_grants','approval_notification_outbox',\
                    'approval_consumptions','approval_mutation_receipts','approval_principal_assertion_uses','approval_events'\
                  ]) AND policyname='tenant_isolation' AND roles=ARRAY['public']::name[]) AS ready",
        )
        .fetch_one(&self.pool)
        .await
        .ok()
        .and_then(|row| row.try_get::<bool, _>("ready").ok())
        .unwrap_or(false)
    }

    pub async fn create_case(
        &self,
        envelope: &ApprovalCaseCreateEnvelope,
        principal: &ApprovalPrincipal,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<ApprovalCase, ApprovalError> {
        validate_create(envelope)?;
        validate_principal(principal, now)?;
        require_same_tenant(&envelope.request.tenant_id, &principal.tenant_id)?;
        if envelope.request.requester_subject != principal.subject {
            return Err(ApprovalError::ScopeForbidden);
        }
        validate_idempotency_key(idempotency_key)?;
        let request_digest = canonical_digest(envelope)?;
        let scope = "case:create";
        let mut transaction = self.begin_tenant(&principal.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &principal.tenant_id,
            scope,
            idempotency_key,
        )
        .await?;
        register_principal_assertion(&mut transaction, principal, "approvals:request", now).await?;
        if let Some(replay) = replay::<ApprovalCase>(
            &mut transaction,
            &principal.tenant_id,
            scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            if replay.schema_version != APPROVAL_SCHEMA_VERSION
                || replay.request.tenant_id != principal.tenant_id
                || replay.request.requester_subject != principal.subject
            {
                return Err(ApprovalError::DatabaseUnavailable);
            }
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let ttl = i64::try_from(envelope.request.requested_ttl_seconds)
            .map_err(|_| ApprovalError::RequestInvalid)?;
        let case_id = Uuid::new_v4().to_string();
        let status = if envelope.policy.approval_type == ApprovalType::Emergency {
            ApprovalStatus::PostReviewRequired
        } else {
            ApprovalStatus::Pending
        };
        let post_review_due_at = (envelope.policy.approval_type == ApprovalType::Emergency)
            .then_some(now + chrono::Duration::hours(24));
        let case = ApprovalCase {
            schema_version: APPROVAL_SCHEMA_VERSION.into(),
            case_id: case_id.clone(),
            request: envelope.request.clone(),
            policy: envelope.policy.clone(),
            status,
            decisions: Vec::new(),
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl),
            post_review_due_at,
        };
        sqlx::query(
            "INSERT INTO approval_cases \
             (tenant_id,case_id,task_id,step_id,action_hash,plan_hash,parameter_hash,resource,\
              resource_version,policy_version,status,request,policy,created_at,expires_at,\
              post_review_due_at,request_digest,created_by,updated_at) \
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$14)",
        )
        .bind(&principal.tenant_id.0)
        .bind(&case.case_id)
        .bind(&case.request.task_id.0)
        .bind(&case.request.step_id.0)
        .bind(&case.request.action_hash.0)
        .bind(&case.request.plan_hash)
        .bind(&case.request.parameter_hash)
        .bind(&case.request.resource)
        .bind(&case.request.resource_version.0)
        .bind(&case.request.policy_version.0)
        .bind(status_text(case.status))
        .bind(serde_json::to_value(&case.request).map_err(|_| ApprovalError::RequestInvalid)?)
        .bind(serde_json::to_value(&case.policy).map_err(|_| ApprovalError::RequestInvalid)?)
        .bind(case.created_at)
        .bind(case.expires_at)
        .bind(case.post_review_due_at)
        .bind(&request_digest)
        .bind(&principal.subject)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        append_event(
            &mut transaction,
            &principal.tenant_id,
            "CASE_CREATED",
            &case.case_id,
            &principal.subject,
            &request_digest,
            now,
        )
        .await?;
        save_replay(
            &mut transaction,
            &principal.tenant_id,
            scope,
            idempotency_key,
            &request_digest,
            &case,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(case)
    }

    pub async fn get_case(
        &self,
        tenant: &TenantId,
        case_id: &str,
    ) -> Result<ApprovalCase, ApprovalError> {
        require_uuid(case_id)?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let case = load_case(&mut transaction, tenant, case_id, false).await?;
        transaction.commit().await.map_err(database)?;
        Ok(case)
    }

    pub async fn list_authoritative_cases(
        &self,
        tenant: &TenantId,
        resource: &str,
        limit: u16,
        encoded_cursor: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<AuthoritativeApprovalPage, ApprovalError> {
        require_uuid(&tenant.0)?;
        if !dashboard_resource(resource) || limit == 0 || limit > MAX_AUTHORITATIVE_PAGE_SIZE {
            return Err(ApprovalError::RequestInvalid);
        }
        let cursor = encoded_cursor
            .map(|value| decode_authoritative_cursor(value, tenant, resource, &self.signer, now))
            .transpose()?;
        let cursor_created_at = cursor.as_ref().map(|value| value.created_at.to_owned());
        let cursor_case_id = cursor.as_ref().map(|value| value.case_id.as_str());
        let fetch_limit = i64::from(limit) + 1;
        let mut transaction = self.begin_tenant(tenant).await?;
        let rows = sqlx::query(
            "SELECT case_id::text,request,status,created_at,expires_at \
             FROM approval_cases \
             WHERE tenant_id=$1::uuid \
               AND ($2::timestamptz IS NULL OR created_at < $2 \
                    OR (created_at=$2 AND case_id < $3::uuid)) \
             ORDER BY created_at DESC,case_id DESC LIMIT $4",
        )
        .bind(&tenant.0)
        .bind(cursor_created_at)
        .bind(cursor_case_id)
        .bind(fetch_limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(database)?;

        let has_more = rows.len() > usize::from(limit);
        let mut results = Vec::with_capacity(rows.len().min(usize::from(limit)));
        for row in rows.into_iter().take(usize::from(limit)) {
            let case_id = row.try_get::<String, _>("case_id").map_err(database)?;
            let request: ApprovalRequest =
                serde_json::from_value(row.try_get::<Value, _>("request").map_err(database)?)
                    .map_err(|_| ApprovalError::DatabaseUnavailable)?;
            let stored_status =
                parse_status(&row.try_get::<String, _>("status").map_err(database)?)?;
            let created_at = row
                .try_get::<DateTime<Utc>, _>("created_at")
                .map_err(database)?;
            let expires_at = row
                .try_get::<DateTime<Utc>, _>("expires_at")
                .map_err(database)?;
            if request.tenant_id != *tenant || !canonical_uuid(&case_id) {
                return Err(ApprovalError::DatabaseUnavailable);
            }
            let domain = approval_case_domain(&request);
            let status = approval_case_view_status(stored_status, expires_at, now);
            let safe_summary = match domain {
                ApprovalCaseDomain::Coding => "Review governed coding action",
                ApprovalCaseDomain::Industrial => "Review supervised industrial action",
            }
            .to_string();
            let view = ApprovalCaseView {
                schema_version: APPROVAL_CASE_VIEW_SCHEMA_VERSION.into(),
                case_id: case_id.clone(),
                domain,
                safe_summary,
                action_hash: request.action_hash.0,
                resource: request.resource,
                resource_version: request.resource_version.0,
                policy_version: request.policy_version.0,
                risk: request.risk,
                // Evidence references are deliberately empty until a real immutable
                // evidence artifact is linked; the authority never fabricates one.
                evidence_refs: Vec::new(),
                status,
            };
            validate_case_view(&view)?;
            results.push((view, created_at, case_id));
        }
        transaction.commit().await.map_err(database)?;

        let next_cursor = if has_more {
            let (_, created_at, case_id) =
                results.last().ok_or(ApprovalError::DatabaseUnavailable)?;
            Some(encode_authoritative_cursor(
                tenant,
                resource,
                created_at.to_owned(),
                case_id,
                &self.signer,
                now,
            )?)
        } else {
            None
        };
        let items = results
            .into_iter()
            .map(|(view, _, _)| view)
            .collect::<Vec<_>>();
        let material = AuthoritativeApprovalPageMaterial {
            schema_version: AUTHORITATIVE_APPROVAL_PAGE_SCHEMA_VERSION,
            authoritative: true,
            tenant_id: &tenant.0,
            resource,
            items: &items,
            next_cursor: &next_cursor,
        };
        let data_digest = canonical_digest(&material)?;
        Ok(AuthoritativeApprovalPage {
            schema_version: AUTHORITATIVE_APPROVAL_PAGE_SCHEMA_VERSION.into(),
            authoritative: true,
            tenant_id: tenant.0.clone(),
            resource: resource.into(),
            items,
            next_cursor,
            data_digest,
        })
    }

    pub async fn decide(
        &self,
        case_id: &str,
        envelope: &ApprovalDecisionEnvelope,
        principal: &ApprovalPrincipal,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<ApprovalCase, ApprovalError> {
        require_uuid(case_id)?;
        if envelope.schema_version != APPROVAL_DECISION_SCHEMA_VERSION
            || envelope.reason.trim().is_empty()
            || envelope.reason.len() > MAX_REASON_BYTES
        {
            return Err(ApprovalError::RequestInvalid);
        }
        validate_principal(principal, now)?;
        validate_idempotency_key(idempotency_key)?;
        let request_digest = canonical_digest(&(case_id, envelope))?;
        let scope = format!("case:decision:{case_id}:{}", principal.subject);
        let mut transaction = self.begin_tenant(&principal.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
        )
        .await?;
        register_principal_assertion(&mut transaction, principal, "approvals:decide", now).await?;
        if let Some(replay) = replay::<ApprovalCase>(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            if replay.schema_version != APPROVAL_SCHEMA_VERSION
                || replay.case_id != case_id
                || replay.request.tenant_id != principal.tenant_id
            {
                return Err(ApprovalError::DatabaseUnavailable);
            }
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let mut case = load_case(&mut transaction, &principal.tenant_id, case_id, true).await?;
        if now >= case.expires_at {
            update_case_status(
                &mut transaction,
                &principal.tenant_id,
                case_id,
                ApprovalStatus::Expired,
                now,
            )
            .await?;
            transaction.commit().await.map_err(database)?;
            return Err(ApprovalError::Expired);
        }
        if case
            .decisions
            .iter()
            .any(|decision| decision.approver_subject == principal.subject)
        {
            return Err(ApprovalError::DuplicateApprover);
        }
        SoDEngine::validate(&case, &principal.identity(), now)?;
        let decision_text = match envelope.decision {
            ApprovalDecision::Approve => {
                if !matches!(
                    case.status,
                    ApprovalStatus::Pending | ApprovalStatus::PostReviewRequired
                ) {
                    return Err(ApprovalError::LifecycleInvalid);
                }
                "APPROVE"
            }
            ApprovalDecision::Reject => {
                if !matches!(
                    case.status,
                    ApprovalStatus::Pending | ApprovalStatus::PostReviewRequired
                ) {
                    return Err(ApprovalError::LifecycleInvalid);
                }
                "REJECT"
            }
            ApprovalDecision::PostReviewed => {
                if case.policy.approval_type != ApprovalType::Emergency
                    || case.status != ApprovalStatus::PostReviewRequired
                    || case
                        .post_review_due_at
                        .is_none_or(|deadline| now > deadline)
                    || !grant_exists(&mut transaction, &principal.tenant_id, case_id).await?
                {
                    return Err(ApprovalError::LifecycleInvalid);
                }
                "POST_REVIEWED"
            }
        };
        sqlx::query(
            "INSERT INTO approval_decisions \
             (tenant_id,case_id,approver_subject,decision,roles,reason,strong_auth,decided_at,\
              assertion_issuer,assertion_jti,assertion_request_digest,assertion_digest,assertion_expires_at) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10::uuid,$11,$12,$13)",
        )
        .bind(&principal.tenant_id.0)
        .bind(case_id)
        .bind(&principal.subject)
        .bind(decision_text)
        .bind(serde_json::to_value(&principal.roles).map_err(|_| ApprovalError::RequestInvalid)?)
        .bind(&envelope.reason)
        .bind(principal.strong_auth)
        .bind(now)
        .bind(&principal.assertion_issuer)
        .bind(&principal.assertion_jti)
        .bind(&principal.assertion_request_digest)
        .bind(&principal.assertion_digest)
        .bind(principal.assertion_expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_decision_insert)?;
        case.decisions.push(ApprovalDecisionRecord {
            approver_subject: principal.subject.clone(),
            roles: principal.roles.clone(),
            decision: decision_text.into(),
            reason: envelope.reason.clone(),
            decided_at: now,
            strong_auth: principal.strong_auth,
        });
        let next_status = match envelope.decision {
            ApprovalDecision::Reject => ApprovalStatus::Rejected,
            ApprovalDecision::PostReviewed => ApprovalStatus::Approved,
            ApprovalDecision::Approve => {
                let approvals = case
                    .decisions
                    .iter()
                    .filter(|record| record.decision == "APPROVE")
                    .map(|record| &record.approver_subject)
                    .collect::<BTreeSet<_>>()
                    .len() as u32;
                if approvals >= case.policy.minimum_approvers {
                    if case.policy.approval_type == ApprovalType::Emergency {
                        ApprovalStatus::PostReviewRequired
                    } else {
                        ApprovalStatus::Approved
                    }
                } else {
                    case.status
                }
            }
        };
        update_case_status(
            &mut transaction,
            &principal.tenant_id,
            case_id,
            next_status,
            now,
        )
        .await?;
        case.status = next_status;
        append_event(
            &mut transaction,
            &principal.tenant_id,
            decision_text,
            case_id,
            &principal.subject,
            &request_digest,
            now,
        )
        .await?;
        save_replay(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
            &case,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(case)
    }

    pub async fn issue_grant(
        &self,
        case_id: &str,
        request: &ApprovalGrantIssueRequest,
        principal: &ApprovalPrincipal,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<EnterpriseApprovalGrant, ApprovalError> {
        require_uuid(case_id)?;
        if request.schema_version != APPROVAL_SCHEMA_VERSION {
            return Err(ApprovalError::RequestInvalid);
        }
        validate_principal(principal, now)?;
        validate_idempotency_key(idempotency_key)?;
        let request_digest = canonical_digest(&(case_id, request))?;
        let scope = format!("case:grant:{case_id}");
        let mut transaction = self.begin_tenant(&principal.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
        )
        .await?;
        register_principal_assertion(&mut transaction, principal, "approvals:issue", now).await?;
        if let Some(replay) = replay::<EnterpriseApprovalGrant>(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            verify_grant_signature(
                &replay,
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
                now,
            )?;
            if replay.tenant_id != principal.tenant_id || replay.case_id != case_id {
                return Err(ApprovalError::GrantInvalid);
            }
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let case = load_case(&mut transaction, &principal.tenant_id, case_id, true).await?;
        if now >= case.expires_at {
            return Err(ApprovalError::Expired);
        }
        if !matches!(
            case.status,
            ApprovalStatus::Approved | ApprovalStatus::PostReviewRequired
        ) {
            return Err(ApprovalError::GrantNotReady);
        }
        let approvals = case
            .decisions
            .iter()
            .filter(|record| record.decision == "APPROVE")
            .map(|record| &record.approver_subject)
            .collect::<BTreeSet<_>>()
            .len() as u32;
        if approvals < case.policy.minimum_approvers
            || case.request.requested_uses != 1
            || case.policy.maximum_uses != 1
        {
            return Err(ApprovalError::GrantNotReady);
        }
        if let Some((existing, remaining_uses, revoked_at)) =
            load_grant_by_case(&mut transaction, &principal.tenant_id, case_id).await?
        {
            verify_grant_signature(
                &existing,
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
                now,
            )?;
            if existing.tenant_id != principal.tenant_id || existing.case_id != case_id {
                return Err(ApprovalError::GrantInvalid);
            }
            if revoked_at.is_some() {
                return Err(ApprovalError::Revoked);
            }
            if remaining_uses != 1 {
                return Err(ApprovalError::GrantReplayed);
            }
            save_replay(
                &mut transaction,
                &principal.tenant_id,
                &scope,
                idempotency_key,
                &request_digest,
                &existing,
                now,
            )
            .await?;
            transaction.commit().await.map_err(database)?;
            return Ok(existing);
        }
        let mut grant = make_grant(self.signer.issuer(), self.signer.key_id(), &case, now);
        self.signer.sign_grant(&mut grant)?;
        let grant_digest = canonical_digest(&grant)?;
        let lookup_digest = grant_lookup_digest_from_grant(&grant)?;
        sqlx::query(
            "INSERT INTO approval_grants \
             (tenant_id,grant_id,case_id,grant_hash,signed_grant,remaining_uses,revoked_at,expires_at,\
              binding_hash,task_id,step_id,action_hash,plan_hash,parameter_hash,resource,resource_version,\
              policy_version,environment,maximum_risk,issued_at,issued_by,key_id) \
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,1,NULL,$6,$7,$8::uuid,$9::uuid,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
        )
        .bind(&principal.tenant_id.0)
        .bind(&grant.grant_id.0)
        .bind(case_id)
        .bind(&grant_digest)
        .bind(serde_json::to_value(&grant).map_err(|_| ApprovalError::GrantInvalid)?)
        .bind(grant.expires_at)
        .bind(&lookup_digest)
        .bind(&grant.task_id.0)
        .bind(&grant.step_id.0)
        .bind(&grant.action_hash.0)
        .bind(&grant.plan_hash)
        .bind(&grant.parameter_hash)
        .bind(&grant.resource)
        .bind(&grant.resource_version.0)
        .bind(&grant.policy_version.0)
        .bind(&grant.environment)
        .bind(risk_text(grant.maximum_risk))
        .bind(grant.issued_at)
        .bind(&principal.subject)
        .bind(&grant.key_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_grant_insert)?;
        append_event(
            &mut transaction,
            &principal.tenant_id,
            "GRANT_ISSUED",
            &grant.grant_id.0,
            &principal.subject,
            &grant_digest,
            now,
        )
        .await?;
        save_replay(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
            &grant,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(grant)
    }

    pub async fn revoke_grant(
        &self,
        grant_id: &str,
        request: &ApprovalGrantRevocationRequest,
        principal: &ApprovalPrincipal,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<ApprovalGrantRevocationReceipt, ApprovalError> {
        require_uuid(grant_id)?;
        if request.schema_version != APPROVAL_SCHEMA_VERSION
            || request.reason.trim().is_empty()
            || request.reason.len() > MAX_REASON_BYTES
        {
            return Err(ApprovalError::RequestInvalid);
        }
        validate_principal(principal, now)?;
        validate_idempotency_key(idempotency_key)?;
        let request_digest = canonical_digest(&(grant_id, request))?;
        let scope = format!("grant:revoke:{grant_id}");
        let mut transaction = self.begin_tenant(&principal.tenant_id).await?;
        lock_idempotency(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
        )
        .await?;
        register_principal_assertion(&mut transaction, principal, "approvals:revoke", now).await?;
        if let Some(replay) = replay::<ApprovalGrantRevocationReceipt>(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            replay.verify(
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
            )?;
            if replay.tenant_id != principal.tenant_id.0 || replay.grant_id != grant_id {
                return Err(ApprovalError::GrantInvalid);
            }
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let row = sqlx::query(
            "SELECT case_id::text,signed_grant,grant_hash,revocation_receipt FROM approval_grants \
             WHERE tenant_id=$1::uuid AND grant_id=$2::uuid FOR UPDATE",
        )
        .bind(&principal.tenant_id.0)
        .bind(grant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(ApprovalError::GrantInvalid)?;
        let case_id = row.try_get::<String, _>("case_id").map_err(database)?;
        let signed_grant = row.try_get::<Value, _>("signed_grant").map_err(database)?;
        let grant_hash = row.try_get::<String, _>("grant_hash").map_err(database)?;
        let existing = row
            .try_get::<Option<Value>, _>("revocation_receipt")
            .map_err(database)?;
        let (receipt, newly_revoked) = if let Some(value) = existing {
            let receipt: ApprovalGrantRevocationReceipt =
                serde_json::from_value(value).map_err(|_| ApprovalError::DatabaseUnavailable)?;
            receipt.verify(
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
            )?;
            if receipt.tenant_id != principal.tenant_id.0
                || receipt.grant_id != grant_id
                || receipt.case_id != case_id
            {
                return Err(ApprovalError::GrantInvalid);
            }
            (receipt, false)
        } else {
            let grant: EnterpriseApprovalGrant = serde_json::from_value(signed_grant)
                .map_err(|_| ApprovalError::DatabaseUnavailable)?;
            verify_grant_signature(
                &grant,
                self.signer.issuer(),
                self.signer.key_id(),
                &self.signer.verifying_key(),
                now,
            )?;
            if grant.tenant_id != principal.tenant_id
                || grant.grant_id.0 != grant_id
                || grant.case_id != case_id
                || canonical_digest(&grant)? != grant_hash
            {
                return Err(ApprovalError::GrantInvalid);
            }
            let mut receipt = ApprovalGrantRevocationReceipt {
                schema_version: "agenttrust.approval-grant-revocation.v1".into(),
                receipt_id: Uuid::new_v4().to_string(),
                tenant_id: principal.tenant_id.0.clone(),
                grant_id: grant_id.into(),
                case_id: case_id.clone(),
                reason_digest: hex(Sha256::digest(request.reason.as_bytes())),
                revoked_by: principal.subject.clone(),
                principal_assertion_jti: principal.assertion_jti.clone(),
                principal_assertion_digest: principal.assertion_digest.clone(),
                revoked_at: now,
                issuer: self.signer.issuer().into(),
                key_id: self.signer.key_id().into(),
                signature: String::new(),
            };
            self.signer.sign_revocation(&mut receipt)?;
            sqlx::query(
                "UPDATE approval_grants SET remaining_uses=0,revoked_at=$3,revoked_by=$4,\
                 revocation_reason_digest=$5,revocation_receipt=$6 \
                 WHERE tenant_id=$1::uuid AND grant_id=$2::uuid",
            )
            .bind(&principal.tenant_id.0)
            .bind(grant_id)
            .bind(now)
            .bind(&principal.subject)
            .bind(&receipt.reason_digest)
            .bind(serde_json::to_value(&receipt).map_err(|_| ApprovalError::GrantInvalid)?)
            .execute(&mut *transaction)
            .await
            .map_err(database)?;
            update_case_status(
                &mut transaction,
                &principal.tenant_id,
                &case_id,
                ApprovalStatus::Revoked,
                now,
            )
            .await?;
            (receipt, true)
        };
        if newly_revoked {
            append_event(
                &mut transaction,
                &principal.tenant_id,
                "GRANT_REVOKED",
                grant_id,
                &principal.subject,
                &receipt.reason_digest,
                now,
            )
            .await?;
        }
        save_replay(
            &mut transaction,
            &principal.tenant_id,
            &scope,
            idempotency_key,
            &request_digest,
            &receipt,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(receipt)
    }

    pub async fn consume_grant(
        &self,
        request: &ApprovalConsumptionRequest,
        tenant: &TenantId,
        subject: &str,
        client_identity: &str,
        idempotency_key: &str,
        now: DateTime<Utc>,
    ) -> Result<ApprovalGrantReceipt, ApprovalError> {
        validate_consumption(request)?;
        if request.tenant_id != tenant.0
            || !identifier(subject)
            || !service_client_identity(client_identity)
        {
            return Err(ApprovalError::ScopeForbidden);
        }
        validate_idempotency_key(idempotency_key)?;
        let request_digest = canonical_digest(request)?;
        let scope = format!("grant:consume:{client_identity}:{subject}");
        let mut transaction = self.begin_tenant(tenant).await?;
        lock_idempotency(&mut transaction, tenant, &scope, idempotency_key).await?;
        if let Some(replay) = replay::<ApprovalGrantReceipt>(
            &mut transaction,
            tenant,
            &scope,
            idempotency_key,
            &request_digest,
        )
        .await?
        {
            verify_consumption_replay(
                &mut transaction,
                &self.signer,
                tenant,
                request,
                subject,
                client_identity,
                &replay,
            )
            .await?;
            transaction.commit().await.map_err(database)?;
            return Ok(replay);
        }
        let lookup_digest = grant_lookup_digest_from_request(request)?;
        let row = sqlx::query(
            "SELECT grant_id::text,case_id::text,signed_grant,grant_hash,remaining_uses,\
                    revoked_at,expires_at \
             FROM approval_grants WHERE tenant_id=$1::uuid AND binding_hash=$2 FOR UPDATE",
        )
        .bind(&tenant.0)
        .bind(&lookup_digest)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(ApprovalError::GrantNotReady)?;
        let grant: EnterpriseApprovalGrant =
            serde_json::from_value(row.try_get::<Value, _>("signed_grant").map_err(database)?)
                .map_err(|_| ApprovalError::GrantInvalid)?;
        let grant_id = row.try_get::<String, _>("grant_id").map_err(database)?;
        let case_id = row.try_get::<String, _>("case_id").map_err(database)?;
        let remaining = row.try_get::<i32, _>("remaining_uses").map_err(database)?;
        let revoked_at = row
            .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
            .map_err(database)?;
        let expires_at = row
            .try_get::<DateTime<Utc>, _>("expires_at")
            .map_err(database)?;
        let grant_digest = row.try_get::<String, _>("grant_hash").map_err(database)?;
        verify_grant_signature(
            &grant,
            self.signer.issuer(),
            self.signer.key_id(),
            &self.signer.verifying_key(),
            now,
        )?;
        if revoked_at.is_some()
            || expires_at <= now
            || remaining != 1
            || canonical_digest(&grant)? != grant_digest
            || !consumption_matches_grant(request, &grant)
        {
            return Err(ApprovalError::GrantNotReady);
        }
        let case = load_case(&mut transaction, tenant, &case_id, true).await?;
        if matches!(
            case.status,
            ApprovalStatus::Rejected
                | ApprovalStatus::Revoked
                | ApprovalStatus::Expired
                | ApprovalStatus::Consumed
        ) {
            return Err(ApprovalError::GrantNotReady);
        }
        let updated = sqlx::query(
            "UPDATE approval_grants SET remaining_uses=0,last_consumed_at=$3 \
             WHERE tenant_id=$1::uuid AND grant_id=$2::uuid AND remaining_uses=1 AND revoked_at IS NULL",
        )
        .bind(&tenant.0)
        .bind(&grant_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(ApprovalError::ConcurrentMutation);
        }
        let mut signed = SignedApprovalConsumptionReceipt {
            schema_version: APPROVAL_CONSUMPTION_SCHEMA_VERSION.into(),
            receipt_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.0.clone(),
            grant_id: grant_id.clone(),
            case_id: case_id.clone(),
            request: request.clone(),
            grant: grant.clone(),
            request_digest: request_digest.clone(),
            grant_digest,
            idempotency_key_digest: hex(Sha256::digest(idempotency_key.as_bytes())),
            consumed_by: subject.into(),
            client_identity: client_identity.into(),
            consumed_at: now,
            remaining_uses: 0,
            issuer: self.signer.issuer().into(),
            key_id: self.signer.key_id().into(),
            signature: String::new(),
        };
        self.signer.sign_consumption(&mut signed)?;
        let payload_digest = hex(Sha256::digest(signed.signing_bytes()?));
        let consumption_ref = consumption_reference(&signed, &payload_digest)?;
        let wire = ApprovalGrantReceipt {
            schema_version: APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION.into(),
            grant,
            consumed_at: now,
            remaining_uses: 0,
            consumption_ref,
        };
        sqlx::query(
            "INSERT INTO approval_consumptions \
             (tenant_id,receipt_id,grant_id,case_id,idempotency_key,request_digest,\
              consumption_ref,signed_receipt,wire_receipt,consumed_by,client_identity,consumed_at) \
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(&tenant.0)
        .bind(&signed.receipt_id)
        .bind(&grant_id)
        .bind(&case_id)
        .bind(idempotency_key)
        .bind(&request_digest)
        .bind(&wire.consumption_ref)
        .bind(serde_json::to_value(&signed).map_err(|_| ApprovalError::GrantInvalid)?)
        .bind(serde_json::to_value(&wire).map_err(|_| ApprovalError::GrantInvalid)?)
        .bind(subject)
        .bind(client_identity)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(map_consumption_insert)?;
        if !wire.grant.break_glass {
            update_case_status(
                &mut transaction,
                tenant,
                &case_id,
                ApprovalStatus::Consumed,
                now,
            )
            .await?;
        }
        append_event(
            &mut transaction,
            tenant,
            "GRANT_CONSUMED",
            &signed.receipt_id,
            subject,
            &request_digest,
            now,
        )
        .await?;
        save_replay(
            &mut transaction,
            tenant,
            &scope,
            idempotency_key,
            &request_digest,
            &wire,
            now,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        Ok(wire)
    }

    pub async fn get_consumption_by_reference(
        &self,
        tenant: &TenantId,
        consumption_ref: &str,
    ) -> Result<SignedApprovalConsumptionReceipt, ApprovalError> {
        validate_consumption_reference(consumption_ref)?;
        let mut transaction = self.begin_tenant(tenant).await?;
        let value = sqlx::query_scalar::<_, Value>(
            "SELECT signed_receipt FROM approval_consumptions \
             WHERE tenant_id=$1::uuid AND consumption_ref=$2",
        )
        .bind(&tenant.0)
        .bind(consumption_ref)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(ApprovalError::GrantInvalid)?;
        let receipt: SignedApprovalConsumptionReceipt =
            serde_json::from_value(value).map_err(|_| ApprovalError::DatabaseUnavailable)?;
        receipt.verify(
            self.signer.issuer(),
            self.signer.key_id(),
            &self.signer.verifying_key(),
        )?;
        let payload_digest = hex(Sha256::digest(receipt.signing_bytes()?));
        if consumption_reference(&receipt, &payload_digest)? != consumption_ref {
            return Err(ApprovalError::GrantInvalid);
        }
        transaction.commit().await.map_err(database)?;
        Ok(receipt)
    }

    async fn begin_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Transaction<'_, Postgres>, ApprovalError> {
        require_uuid(&tenant.0)?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&tenant.0)
            .fetch_one(&mut *transaction)
            .await
            .map_err(database)?;
        Ok(transaction)
    }
}

async fn load_case(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    case_id: &str,
    lock: bool,
) -> Result<ApprovalCase, ApprovalError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let query = format!(
        "SELECT case_id::text,request,policy,status,created_at,expires_at,post_review_due_at \
         FROM approval_cases WHERE tenant_id=$1::uuid AND case_id=$2::uuid{suffix}"
    );
    let row = sqlx::query(&query)
        .bind(&tenant.0)
        .bind(case_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database)?
        .ok_or(ApprovalError::CaseNotFound)?;
    let decisions = sqlx::query(
        "SELECT approver_subject,roles,decision,reason,decided_at,strong_auth \
         FROM approval_decisions WHERE tenant_id=$1::uuid AND case_id=$2::uuid \
         ORDER BY decided_at,approver_subject",
    )
    .bind(&tenant.0)
    .bind(case_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(database)?
    .into_iter()
    .map(|decision| {
        Ok(ApprovalDecisionRecord {
            approver_subject: decision.try_get("approver_subject").map_err(database)?,
            roles: serde_json::from_value(decision.try_get("roles").map_err(database)?)
                .map_err(|_| ApprovalError::DatabaseUnavailable)?,
            decision: decision.try_get("decision").map_err(database)?,
            reason: decision.try_get("reason").map_err(database)?,
            decided_at: decision.try_get("decided_at").map_err(database)?,
            strong_auth: decision.try_get("strong_auth").map_err(database)?,
        })
    })
    .collect::<Result<Vec<_>, ApprovalError>>()?;
    Ok(ApprovalCase {
        schema_version: APPROVAL_SCHEMA_VERSION.into(),
        case_id: row.try_get("case_id").map_err(database)?,
        request: serde_json::from_value(row.try_get("request").map_err(database)?)
            .map_err(|_| ApprovalError::DatabaseUnavailable)?,
        policy: serde_json::from_value(row.try_get("policy").map_err(database)?)
            .map_err(|_| ApprovalError::DatabaseUnavailable)?,
        status: parse_status(&row.try_get::<String, _>("status").map_err(database)?)?,
        decisions,
        created_at: row.try_get("created_at").map_err(database)?,
        expires_at: row.try_get("expires_at").map_err(database)?,
        post_review_due_at: row.try_get("post_review_due_at").map_err(database)?,
    })
}

async fn load_grant_by_case(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    case_id: &str,
) -> Result<Option<(EnterpriseApprovalGrant, i32, Option<DateTime<Utc>>)>, ApprovalError> {
    let row = sqlx::query(
        "SELECT signed_grant,remaining_uses,revoked_at FROM approval_grants \
         WHERE tenant_id=$1::uuid AND case_id=$2::uuid FOR UPDATE",
    )
    .bind(&tenant.0)
    .bind(case_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database)?;
    row.map(|row| {
        let grant =
            serde_json::from_value(row.try_get::<Value, _>("signed_grant").map_err(database)?)
                .map_err(|_| ApprovalError::DatabaseUnavailable)?;
        Ok((
            grant,
            row.try_get("remaining_uses").map_err(database)?,
            row.try_get("revoked_at").map_err(database)?,
        ))
    })
    .transpose()
}

async fn verify_consumption_replay(
    transaction: &mut Transaction<'_, Postgres>,
    signer: &ApprovalSigner,
    tenant: &TenantId,
    request: &ApprovalConsumptionRequest,
    subject: &str,
    client_identity: &str,
    wire: &ApprovalGrantReceipt,
) -> Result<(), ApprovalError> {
    if wire.schema_version != APPROVAL_GRANT_RECEIPT_SCHEMA_VERSION
        || wire.remaining_uses != 0
        || &wire.grant.tenant_id != tenant
        || !consumption_matches_grant(request, &wire.grant)
    {
        return Err(ApprovalError::GrantInvalid);
    }
    validate_consumption_reference(&wire.consumption_ref)?;
    verify_grant_signature(
        &wire.grant,
        signer.issuer(),
        signer.key_id(),
        &signer.verifying_key(),
        wire.consumed_at,
    )?;
    let value = sqlx::query_scalar::<_, Value>(
        "SELECT signed_receipt FROM approval_consumptions \
         WHERE tenant_id=$1::uuid AND consumption_ref=$2",
    )
    .bind(&tenant.0)
    .bind(&wire.consumption_ref)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database)?
    .ok_or(ApprovalError::GrantInvalid)?;
    let signed: SignedApprovalConsumptionReceipt =
        serde_json::from_value(value).map_err(|_| ApprovalError::DatabaseUnavailable)?;
    signed.verify(signer.issuer(), signer.key_id(), &signer.verifying_key())?;
    let payload_digest = hex(Sha256::digest(signed.signing_bytes()?));
    if &signed.request != request
        || &signed.grant != &wire.grant
        || signed.consumed_by != subject
        || signed.client_identity != client_identity
        || signed.consumed_at != wire.consumed_at
        || consumption_reference(&signed, &payload_digest)? != wire.consumption_ref
    {
        return Err(ApprovalError::GrantInvalid);
    }
    Ok(())
}

async fn grant_exists(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    case_id: &str,
) -> Result<bool, ApprovalError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM approval_grants \
         WHERE tenant_id=$1::uuid AND case_id=$2::uuid AND revoked_at IS NULL)",
    )
    .bind(&tenant.0)
    .bind(case_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database)
}

async fn update_case_status(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    case_id: &str,
    status: ApprovalStatus,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    let result = sqlx::query(
        "UPDATE approval_cases SET status=$3,updated_at=$4 \
         WHERE tenant_id=$1::uuid AND case_id=$2::uuid",
    )
    .bind(&tenant.0)
    .bind(case_id)
    .bind(status_text(status))
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(database)?;
    if result.rows_affected() != 1 {
        return Err(ApprovalError::CaseNotFound);
    }
    Ok(())
}

async fn lock_idempotency(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    scope: &str,
    key: &str,
) -> Result<(), ApprovalError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{}:{scope}:{key}", tenant.0))
        .fetch_one(&mut **transaction)
        .await
        .map_err(database)?;
    Ok(())
}

async fn register_principal_assertion(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &ApprovalPrincipal,
    scope: &str,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    sqlx::query(
        "INSERT INTO approval_principal_assertion_uses \
         (tenant_id,assertion_jti,issuer,subject,scope,request_digest,assertion_digest,signed_assertion,expires_at,first_used_at) \
         VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING",
    )
    .bind(&principal.tenant_id.0)
    .bind(&principal.assertion_jti)
    .bind(&principal.assertion_issuer)
    .bind(&principal.subject)
    .bind(scope)
    .bind(&principal.assertion_request_digest)
    .bind(&principal.assertion_digest)
    .bind(&principal.assertion_document)
    .bind(principal.assertion_expires_at)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(database)?;
    let row = sqlx::query(
        "SELECT issuer,subject,scope,request_digest,assertion_digest,signed_assertion,expires_at \
         FROM approval_principal_assertion_uses \
         WHERE tenant_id=$1::uuid AND assertion_jti=$2::uuid FOR UPDATE",
    )
    .bind(&principal.tenant_id.0)
    .bind(&principal.assertion_jti)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database)?;
    if row.try_get::<String, _>("issuer").map_err(database)? != principal.assertion_issuer
        || row.try_get::<String, _>("subject").map_err(database)? != principal.subject
        || row.try_get::<String, _>("scope").map_err(database)? != scope
        || row
            .try_get::<String, _>("request_digest")
            .map_err(database)?
            != principal.assertion_request_digest
        || row
            .try_get::<String, _>("assertion_digest")
            .map_err(database)?
            != principal.assertion_digest
        || row
            .try_get::<Value, _>("signed_assertion")
            .map_err(database)?
            != principal.assertion_document
        || row
            .try_get::<DateTime<Utc>, _>("expires_at")
            .map_err(database)?
            != principal.assertion_expires_at
    {
        return Err(ApprovalError::AuthenticationRequired);
    }
    Ok(())
}

async fn replay<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    operation: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<Option<T>, ApprovalError> {
    let row = sqlx::query(
        "SELECT request_digest,response_body FROM approval_mutation_receipts \
         WHERE tenant_id=$1::uuid AND operation=$2 AND idempotency_key=$3",
    )
    .bind(&tenant.0)
    .bind(operation)
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row
        .try_get::<String, _>("request_digest")
        .map_err(database)?
        != request_digest
    {
        return Err(ApprovalError::IdempotencyConflict);
    }
    let response = row.try_get::<Value, _>("response_body").map_err(database)?;
    serde_json::from_value(response)
        .map(Some)
        .map_err(|_| ApprovalError::DatabaseUnavailable)
}

async fn save_replay<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    operation: &str,
    idempotency_key: &str,
    request_digest: &str,
    response: &T,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    sqlx::query(
        "INSERT INTO approval_mutation_receipts \
         (tenant_id,operation,idempotency_key,request_digest,response_body,created_at) \
         VALUES ($1::uuid,$2,$3,$4,$5,$6)",
    )
    .bind(&tenant.0)
    .bind(operation)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(serde_json::to_value(response).map_err(|_| ApprovalError::RequestInvalid)?)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_idempotency_insert)?;
    Ok(())
}

async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    event_type: &str,
    aggregate_id: &str,
    actor: &str,
    payload_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    sqlx::query(
        "INSERT INTO approval_events \
         (tenant_id,event_id,event_type,aggregate_id,actor_subject,payload_digest,occurred_at) \
         VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7)",
    )
    .bind(&tenant.0)
    .bind(Uuid::new_v4().to_string())
    .bind(event_type)
    .bind(aggregate_id)
    .bind(actor)
    .bind(payload_digest)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(database)?;
    Ok(())
}

fn validate_create(envelope: &ApprovalCaseCreateEnvelope) -> Result<(), ApprovalError> {
    if envelope.schema_version != APPROVAL_CASE_CREATE_SCHEMA_VERSION {
        return Err(ApprovalError::RequestInvalid);
    }
    validate_policy(&envelope.policy)?;
    validate_request(&envelope.request, &envelope.policy)?;
    require_uuid(&envelope.request.tenant_id.0)?;
    require_uuid(&envelope.request.task_id.0)?;
    require_uuid(&envelope.request.step_id.0)?;
    if envelope.request.requested_uses != 1
        || envelope.policy.maximum_uses != 1
        || envelope.policy.minimum_approvers > 64
        || envelope.policy.maximum_ttl_seconds > MAX_APPROVAL_TTL_SECONDS
        || envelope.policy.policy_id.len() > 256
        || envelope.policy.policy_version.len() > 256
        || envelope.policy.required_roles.len() > 64
        || envelope
            .policy
            .required_roles
            .iter()
            .any(|role| !identifier(role))
        || !is_digest(&envelope.request.action_hash.0)
        || !is_digest(&envelope.request.plan_hash)
        || !is_digest(&envelope.request.parameter_hash)
        || !bounded(&envelope.request.resource)
        || !bounded(&envelope.request.resource_version.0)
        || !bounded(&envelope.request.policy_version.0)
        || !bounded(&envelope.request.environment)
        || !identifier(&envelope.request.requester_subject)
        || !identifier(&envelope.request.agent_owner_subject)
        || envelope.request.justification.len() > MAX_REASON_BYTES
    {
        return Err(ApprovalError::RequestInvalid);
    }
    if envelope.policy.approval_type == ApprovalType::Emergency
        && envelope.request.requested_ttl_seconds > 300
    {
        return Err(ApprovalError::BreakGlassDenied);
    }
    Ok(())
}

fn validate_principal(
    principal: &ApprovalPrincipal,
    now: DateTime<Utc>,
) -> Result<(), ApprovalError> {
    let tenant = Uuid::parse_str(&principal.tenant_id.0)
        .map_err(|_| ApprovalError::AuthenticationRequired)?;
    let jti = Uuid::parse_str(&principal.assertion_jti)
        .map_err(|_| ApprovalError::AuthenticationRequired)?;
    if tenant.to_string() != principal.tenant_id.0
        || jti.to_string() != principal.assertion_jti
        || !identifier(&principal.subject)
        || !principal.strong_auth
        || principal.roles.is_empty()
        || principal.roles.len() > 64
        || principal.roles.iter().any(|role| !identifier(role))
        || principal.owned_resources.len() > 1_024
        || principal
            .owned_resources
            .iter()
            .any(|resource| !bounded(resource))
        || !identifier(&principal.assertion_issuer)
        || !is_digest(&principal.assertion_request_digest)
        || !is_digest(&principal.assertion_digest)
        || canonical_digest(&principal.assertion_document)? != principal.assertion_digest
        || principal.assertion_expires_at <= now
        || principal.assertion_expires_at > now + chrono::Duration::seconds(330)
    {
        return Err(ApprovalError::AuthenticationRequired);
    }
    Ok(())
}

fn validate_consumption(request: &ApprovalConsumptionRequest) -> Result<(), ApprovalError> {
    if request.schema_version != APPROVAL_GRANT_REQUEST_SCHEMA_VERSION
        || require_uuid(&request.tenant_id).is_err()
        || require_uuid(&request.task_id).is_err()
        || require_uuid(&request.step_id).is_err()
        || !is_digest(&request.action_hash)
        || !is_digest(&request.plan_hash)
        || !is_digest(&request.parameter_hash)
        || !bounded(&request.resource)
        || !bounded(&request.resource_version)
        || !bounded(&request.policy_version)
        || !bounded(&request.environment)
    {
        return Err(ApprovalError::RequestInvalid);
    }
    Ok(())
}

fn consumption_matches_grant(
    request: &ApprovalConsumptionRequest,
    grant: &EnterpriseApprovalGrant,
) -> bool {
    request.tenant_id == grant.tenant_id.0
        && request.task_id == grant.task_id.0
        && request.step_id == grant.step_id.0
        && request.action_hash == grant.action_hash.0
        && request.plan_hash == grant.plan_hash
        && request.parameter_hash == grant.parameter_hash
        && request.resource == grant.resource
        && request.resource_version == grant.resource_version.0
        && request.policy_version == grant.policy_version.0
        && request.environment == grant.environment
        && request.maximum_risk <= grant.maximum_risk
        && grant.maximum_uses == 1
}

#[derive(Serialize)]
struct GrantLookupBinding<'a> {
    tenant_id: &'a str,
    task_id: &'a str,
    step_id: &'a str,
    action_hash: &'a str,
    plan_hash: &'a str,
    parameter_hash: &'a str,
    resource: &'a str,
    resource_version: &'a str,
    policy_version: &'a str,
    environment: &'a str,
}

fn grant_lookup_digest_from_grant(
    grant: &EnterpriseApprovalGrant,
) -> Result<String, ApprovalError> {
    canonical_digest(&GrantLookupBinding {
        tenant_id: &grant.tenant_id.0,
        task_id: &grant.task_id.0,
        step_id: &grant.step_id.0,
        action_hash: &grant.action_hash.0,
        plan_hash: &grant.plan_hash,
        parameter_hash: &grant.parameter_hash,
        resource: &grant.resource,
        resource_version: &grant.resource_version.0,
        policy_version: &grant.policy_version.0,
        environment: &grant.environment,
    })
}

fn grant_lookup_digest_from_request(
    request: &ApprovalConsumptionRequest,
) -> Result<String, ApprovalError> {
    canonical_digest(&GrantLookupBinding {
        tenant_id: &request.tenant_id,
        task_id: &request.task_id,
        step_id: &request.step_id,
        action_hash: &request.action_hash,
        plan_hash: &request.plan_hash,
        parameter_hash: &request.parameter_hash,
        resource: &request.resource,
        resource_version: &request.resource_version,
        policy_version: &request.policy_version,
        environment: &request.environment,
    })
}

fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Result<String, ApprovalError> {
    Ok(hex(Sha256::digest(
        serde_jcs::to_vec(value).map_err(|_| ApprovalError::RequestInvalid)?,
    )))
}

fn decode_signature(value: &str) -> Result<Signature, ApprovalError> {
    Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ApprovalError::GrantInvalid)?,
    )
    .map_err(|_| ApprovalError::GrantInvalid)
}

fn consumption_reference(
    receipt: &SignedApprovalConsumptionReceipt,
    payload_digest: &str,
) -> Result<String, ApprovalError> {
    if !is_digest(payload_digest)
        || !key_identifier(&receipt.key_id)
        || decode_signature(&receipt.signature).is_err()
    {
        return Err(ApprovalError::GrantInvalid);
    }
    let value = format!(
        "urn:agenttrust:approval-consumption:{}:sha256:{}:kid:{}:sig:{}",
        receipt.receipt_id, payload_digest, receipt.key_id, receipt.signature
    );
    if value.len() > 2_048 {
        return Err(ApprovalError::GrantInvalid);
    }
    Ok(value)
}

fn validate_consumption_reference(value: &str) -> Result<(), ApprovalError> {
    let body = value
        .strip_prefix("urn:agenttrust:approval-consumption:")
        .ok_or(ApprovalError::GrantInvalid)?;
    let (receipt_id, body) = body
        .split_once(":sha256:")
        .ok_or(ApprovalError::GrantInvalid)?;
    let (payload_digest, body) = body
        .split_once(":kid:")
        .ok_or(ApprovalError::GrantInvalid)?;
    let (key_id, signature) = body
        .split_once(":sig:")
        .ok_or(ApprovalError::GrantInvalid)?;
    let receipt_uuid = Uuid::parse_str(receipt_id).map_err(|_| ApprovalError::GrantInvalid)?;
    if value.len() > 2_048
        || receipt_uuid.to_string() != receipt_id
        || !is_digest(payload_digest)
        || !key_identifier(key_id)
        || decode_signature(signature).is_err()
    {
        return Err(ApprovalError::GrantInvalid);
    }
    Ok(())
}

fn encode_authoritative_cursor(
    tenant: &TenantId,
    resource: &str,
    created_at: DateTime<Utc>,
    case_id: &str,
    signer: &ApprovalSigner,
    now: DateTime<Utc>,
) -> Result<String, ApprovalError> {
    if !canonical_uuid(&tenant.0) || !dashboard_resource(resource) || !canonical_uuid(case_id) {
        return Err(ApprovalError::RequestInvalid);
    }
    let mut cursor = AuthoritativeApprovalCursor {
        schema_version: AUTHORITATIVE_APPROVAL_CURSOR_SCHEMA_VERSION.into(),
        tenant_id: tenant.0.clone(),
        resource: resource.into(),
        created_at,
        case_id: case_id.into(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(AUTHORITATIVE_CURSOR_TTL_SECONDS),
        issuer: signer.issuer().into(),
        key_id: signer.key_id().into(),
        signature: String::new(),
    };
    signer.sign_authoritative_cursor(&mut cursor)?;
    let raw = serde_json::to_vec(&cursor).map_err(|_| ApprovalError::RequestInvalid)?;
    if raw.is_empty() || raw.len() > 4_096 {
        return Err(ApprovalError::RequestInvalid);
    }
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn decode_authoritative_cursor(
    encoded: &str,
    tenant: &TenantId,
    resource: &str,
    signer: &ApprovalSigner,
    now: DateTime<Utc>,
) -> Result<AuthoritativeApprovalCursor, ApprovalError> {
    if encoded.is_empty()
        || encoded.len() > 5_462
        || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ApprovalError::RequestInvalid);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApprovalError::RequestInvalid)?;
    if raw.is_empty() || raw.len() > 4_096 {
        return Err(ApprovalError::RequestInvalid);
    }
    let cursor: AuthoritativeApprovalCursor =
        serde_json::from_slice(&raw).map_err(|_| ApprovalError::RequestInvalid)?;
    if cursor.schema_version != AUTHORITATIVE_APPROVAL_CURSOR_SCHEMA_VERSION
        || cursor.tenant_id != tenant.0
        || cursor.resource != resource
        || cursor.issuer != signer.issuer()
        || cursor.key_id != signer.key_id()
        || !canonical_uuid(&cursor.case_id)
        || cursor.issued_at > now + chrono::Duration::seconds(30)
        || cursor.expires_at <= now
        || cursor.expires_at <= cursor.issued_at
        || cursor.expires_at
            > cursor.issued_at + chrono::Duration::seconds(AUTHORITATIVE_CURSOR_TTL_SECONDS)
    {
        return Err(ApprovalError::RequestInvalid);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(&cursor.signature)
        .map_err(|_| ApprovalError::RequestInvalid)?;
    let signature = Signature::from_slice(&signature).map_err(|_| ApprovalError::RequestInvalid)?;
    signer
        .verifying_key()
        .verify(&cursor.signing_bytes()?, &signature)
        .map_err(|_| ApprovalError::RequestInvalid)?;
    Ok(cursor)
}

fn dashboard_resource(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn approval_case_domain(request: &ApprovalRequest) -> ApprovalCaseDomain {
    let resource = request.resource.to_ascii_lowercase();
    let industrial_resource = [
        "opcua:",
        "opc.tcp:",
        "mqtt:",
        "modbus:",
        "plc:",
        "scada:",
        "plant/",
        "urn:agenttrust:industrial:",
    ]
    .iter()
    .any(|prefix| resource.starts_with(prefix));
    if industrial_resource
        || matches!(
            request.environment.as_str(),
            "industrial" | "physical-production"
        )
    {
        ApprovalCaseDomain::Industrial
    } else {
        ApprovalCaseDomain::Coding
    }
}

fn approval_case_view_status(
    stored: ApprovalStatus,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> ApprovalCaseViewStatus {
    if expires_at <= now && stored == ApprovalStatus::Pending {
        return ApprovalCaseViewStatus::Expired;
    }
    match stored {
        ApprovalStatus::Pending | ApprovalStatus::PostReviewRequired => {
            ApprovalCaseViewStatus::Pending
        }
        ApprovalStatus::Approved | ApprovalStatus::Consumed => ApprovalCaseViewStatus::Approved,
        ApprovalStatus::Rejected => ApprovalCaseViewStatus::Rejected,
        ApprovalStatus::Expired => ApprovalCaseViewStatus::Expired,
        ApprovalStatus::Revoked => ApprovalCaseViewStatus::Revoked,
    }
}

fn validate_case_view(view: &ApprovalCaseView) -> Result<(), ApprovalError> {
    if view.schema_version != APPROVAL_CASE_VIEW_SCHEMA_VERSION
        || !canonical_uuid(&view.case_id)
        || view.safe_summary.is_empty()
        || view.safe_summary.len() > MAX_TEXT_BYTES
        || !is_digest(&view.action_hash)
        || !bounded(&view.resource)
        || !bounded(&view.resource_version)
        || !bounded(&view.policy_version)
        || view.evidence_refs.len() > 100
        || view.evidence_refs.iter().any(|value| !bounded(value))
        || view.evidence_refs.iter().collect::<BTreeSet<_>>().len() != view.evidence_refs.len()
    {
        return Err(ApprovalError::DatabaseUnavailable);
    }
    Ok(())
}

fn require_same_tenant(left: &TenantId, right: &TenantId) -> Result<(), ApprovalError> {
    if left != right {
        Err(ApprovalError::ScopeForbidden)
    } else {
        Ok(())
    }
}

fn validate_idempotency_key(value: &str) -> Result<(), ApprovalError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
    {
        Err(ApprovalError::IdempotencyInvalid)
    } else {
        Ok(())
    }
}

fn require_uuid(value: &str) -> Result<(), ApprovalError> {
    if canonical_uuid(value) {
        Ok(())
    } else {
        Err(ApprovalError::RequestInvalid)
    }
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn service_client_identity(value: &str) -> bool {
    value.len() <= 512
        && (value.starts_with("DNS:") || value.starts_with("URI:"))
        && value.split_once(':').is_some_and(|(_, identity)| {
            !identity.is_empty() && identity.bytes().all(|byte| byte.is_ascii_graphic())
        })
}

fn key_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn bounded(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

fn status_text(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "PENDING",
        ApprovalStatus::Approved => "APPROVED",
        ApprovalStatus::Rejected => "REJECTED",
        ApprovalStatus::Revoked => "REVOKED",
        ApprovalStatus::Expired => "EXPIRED",
        ApprovalStatus::Consumed => "CONSUMED",
        ApprovalStatus::PostReviewRequired => "POST_REVIEW_REQUIRED",
    }
}

fn parse_status(value: &str) -> Result<ApprovalStatus, ApprovalError> {
    match value {
        "PENDING" => Ok(ApprovalStatus::Pending),
        "APPROVED" => Ok(ApprovalStatus::Approved),
        "REJECTED" => Ok(ApprovalStatus::Rejected),
        "REVOKED" => Ok(ApprovalStatus::Revoked),
        "EXPIRED" => Ok(ApprovalStatus::Expired),
        "CONSUMED" => Ok(ApprovalStatus::Consumed),
        "POST_REVIEW_REQUIRED" => Ok(ApprovalStatus::PostReviewRequired),
        _ => Err(ApprovalError::DatabaseUnavailable),
    }
}

fn risk_text(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    }
}

fn database(_: sqlx::Error) -> ApprovalError {
    ApprovalError::DatabaseUnavailable
}

fn map_decision_insert(error: sqlx::Error) -> ApprovalError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        ApprovalError::DuplicateApprover
    } else {
        database(error)
    }
}

fn map_grant_insert(error: sqlx::Error) -> ApprovalError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        ApprovalError::ConcurrentMutation
    } else {
        database(error)
    }
}

fn map_idempotency_insert(error: sqlx::Error) -> ApprovalError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        ApprovalError::IdempotencyConflict
    } else {
        database(error)
    }
}

fn map_consumption_insert(error: sqlx::Error) -> ApprovalError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        ApprovalError::GrantReplayed
    } else {
        database(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_idempotency_keys_are_bounded_and_unambiguous() {
        assert!(validate_idempotency_key("execute:01900000-0000-7000-8000-000000000001").is_ok());
        assert!(validate_idempotency_key("contains a space").is_err());
        assert!(validate_idempotency_key(&"a".repeat(129)).is_err());
    }

    #[test]
    fn lookup_binding_does_not_weaken_any_resource_field() {
        let request = ApprovalConsumptionRequest {
            schema_version: APPROVAL_GRANT_REQUEST_SCHEMA_VERSION.into(),
            tenant_id: Uuid::new_v4().to_string(),
            task_id: Uuid::new_v4().to_string(),
            step_id: Uuid::new_v4().to_string(),
            action_hash: "a".repeat(64),
            plan_hash: "b".repeat(64),
            parameter_hash: "c".repeat(64),
            resource: "urn:resource:one".into(),
            resource_version: "version-1".into(),
            policy_version: "policy-1".into(),
            environment: "production".into(),
            maximum_risk: RiskLevel::High,
        };
        let original =
            grant_lookup_digest_from_request(&request).unwrap_or_else(|_| panic!("lookup digest"));
        let mut changed_resource_version = request.clone();
        changed_resource_version.resource_version = "version-2".into();
        let changed_resource_version = grant_lookup_digest_from_request(&changed_resource_version)
            .unwrap_or_else(|_| panic!("changed lookup digest"));
        let mut changed_plan = request;
        changed_plan.plan_hash = "d".repeat(64);
        let changed_plan = grant_lookup_digest_from_request(&changed_plan)
            .unwrap_or_else(|_| panic!("changed plan lookup digest"));
        assert_ne!(original, changed_resource_version);
        assert_ne!(original, changed_plan);
    }
}
