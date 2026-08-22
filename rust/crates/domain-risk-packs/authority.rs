//! Durable production authority shared by the five Domain Pack plugins.
//!
//! It owns no domain policy. It reserves the exact Canonical Action/PEP/ledger/fence binding,
//! invokes a typed ToolProxy/executor port, verifies its signed receipt, persists evaluator state,
//! and emits Evidence through a durable outbox. Ambiguous effects become `UNKNOWN` and are never
//! replayed automatically.

use crate::production::{
    DomainExecutionEnvelope, DomainKind, DomainProductionError, ProductionDomainPackContract,
    safe_digest, validate_approvals,
};
use agent_trust_contracts::EffectClass;
use agent_trust_pack_supply_chain::{ArtifactVerifier,production::AuthorityEvidenceDelivery};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap,BTreeSet};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const DOMAIN_RECEIPT_SCHEMA:&str="agenttrust.domain-runtime-receipt.v1";
pub const DOMAIN_RESULT_SCHEMA:&str="agenttrust.domain-runtime-result.v1";
pub const DOMAIN_STATE_SCHEMA:&str="agenttrust.domain-runtime-authoritative-state.v1";
pub const DOMAIN_KEYRING_SCHEMA:&str="agenttrust.domain-runtime-receipt-keyring.v1";
pub const DOMAIN_EFFECT_RECEIPT_SCHEMA:&str="agenttrust.domain-effect-receipt.v1";
pub const DOMAIN_EVALUATOR_RESULT_SCHEMA:&str="agenttrust.domain-evaluator-result.v1";

#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum DomainEvaluatorConclusion { Pass, Fail, NeedsHuman, ManualRecovery }

#[derive(Debug,Clone,Deserialize)]
#[serde(deny_unknown_fields)]
struct TypedDomainEffectReceipt {
    schema_version:String,
    tenant_id:Uuid,
    execution_id:Uuid,
    tool_id:String,
    operation:String,
    resource_key:String,
    resource_version:u64,
    before_digest:String,
    target_digest:String,
    executor_identity:String,
    status:String,
    executor_receipt_ref:String,
    executor_receipt_digest:String,
    external_receipt_ref:Option<String>,
    external_receipt_digest:Option<String>,
    compensation_ref:Option<String>,
    started_at:DateTime<Utc>,
    completed_at:DateTime<Utc>,
}

#[derive(Debug,Clone,Deserialize)]
#[serde(deny_unknown_fields)]
struct TypedDomainEvaluatorResult {
    schema_version:String,
    domain:DomainKind,
    operation:String,
    resource_key:String,
    before_digest:String,
    target_digest:String,
    checks:BTreeMap<String,bool>,
    reason_codes:BTreeSet<String>,
    conclusion:DomainEvaluatorConclusion,
    evaluated_at:DateTime<Utc>,
}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DomainRuntimeReceipt {
    pub schema_version:String,
    pub execution_id:Uuid,
    pub domain:DomainKind,
    pub operation:String,
    pub resource_key:String,
    pub resource_version:u64,
    pub action_hash:String,
    pub request_digest:String,
    pub effect_receipt:Value,
    pub effect_receipt_digest:String,
    pub evaluator_result:Value,
    pub evaluator_result_digest:String,
    pub conclusion:DomainEvaluatorConclusion,
    pub external_effect_started:bool,
    pub completed_at:DateTime<Utc>,
    pub key_id:String,
    pub signature:String,
}

impl DomainRuntimeReceipt {
    fn signing_bytes(&self)->Result<Vec<u8>,DomainAuthorityError>{
        let mut value=self.clone();value.signature.clear();
        serde_jcs::to_vec(&value).map_err(|_|DomainAuthorityError::ReceiptInvalid)
    }
}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DomainExecutionResult {
    pub schema_version:String,
    pub execution_id:Uuid,
    pub state:String,
    pub domain:DomainKind,
    pub resource_key:String,
    pub resource_version:u64,
    pub effect_receipt_digest:Option<String>,
    pub evaluator_result_digest:Option<String>,
    pub evaluator_conclusion:Option<DomainEvaluatorConclusion>,
    pub evidence_ref:Option<String>,
    pub evidence_digest:Option<String>,
    pub stable_error:Option<String>,
}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeDomainExecution {
    pub execution_id:Uuid,
    pub command_id:Uuid,
    pub domain:DomainKind,
    pub pack_id:String,
    pub pack_version:String,
    pub pack_manifest_digest:String,
    pub tool_id:String,
    pub operation:String,
    pub resource_key:String,
    pub resource_version:u64,
    pub state:String,
    pub effect_receipt_digest:Option<String>,
    pub evaluator_result_digest:Option<String>,
    pub evaluator_conclusion:Option<String>,
    pub evidence_ref:Option<String>,
    pub evidence_digest:Option<String>,
    pub stable_error:Option<String>,
    pub created_at:DateTime<Utc>,
    pub updated_at:DateTime<Utc>,
}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeDomainExecutionPage {
    pub schema_version:String,
    pub tenant_id:Uuid,
    pub authoritative:bool,
    pub data_digest:String,
    pub items:Vec<AuthoritativeDomainExecution>,
    pub next_cursor:Option<String>,
}

#[derive(Debug,Clone,Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringDocument { schema_version:String,keys:Vec<KeyDocument> }
#[derive(Debug,Clone,Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDocument { key_id:String,usage:String,public_key:String,not_before:DateTime<Utc>,expires_at:DateTime<Utc>,revoked:bool }

#[derive(Clone)]
pub struct DomainReceiptKeyring { keys:Arc<BTreeMap<String,(VerifyingKey,DateTime<Utc>,DateTime<Utc>)>> }

impl DomainReceiptKeyring {
    pub fn from_json(raw:&[u8],now:DateTime<Utc>)->Result<Self,DomainAuthorityError>{
        if raw.is_empty()||raw.len()>1_048_576{return Err(DomainAuthorityError::ConfigurationInvalid);}
        let document:KeyringDocument=serde_json::from_slice(raw).map_err(|_|DomainAuthorityError::ConfigurationInvalid)?;
        if document.schema_version!=DOMAIN_KEYRING_SCHEMA||document.keys.is_empty()||document.keys.len()>256{return Err(DomainAuthorityError::ConfigurationInvalid);}
        let mut keys=BTreeMap::new();
        for entry in document.keys {
            let decoded=URL_SAFE_NO_PAD.decode(entry.public_key).map_err(|_|DomainAuthorityError::ConfigurationInvalid)?;
            let bytes:<[u8;32]>::try_from(decoded).map_err(|_|DomainAuthorityError::ConfigurationInvalid)?;
            let key=VerifyingKey::from_bytes(&bytes).map_err(|_|DomainAuthorityError::ConfigurationInvalid)?;
            if entry.usage!="DOMAIN_RUNTIME_RECEIPT"||entry.revoked||entry.not_before>now||entry.expires_at<=now
                ||!identifier(&entry.key_id,256)||keys.insert(entry.key_id,(key,entry.not_before,entry.expires_at)).is_some(){return Err(DomainAuthorityError::ConfigurationInvalid);}
        }
        Ok(Self{keys:Arc::new(keys)})
    }

    fn verify(&self,receipt:&DomainRuntimeReceipt,envelope:&DomainExecutionEnvelope,request_digest:&str,action_hash:&str,effect:EffectClass,now:DateTime<Utc>)->Result<(),DomainAuthorityError>{
        let (key,not_before,expires_at)=self.keys.get(&receipt.key_id).ok_or(DomainAuthorityError::ReceiptInvalid)?;
        if receipt.schema_version!=DOMAIN_RECEIPT_SCHEMA||receipt.execution_id!=envelope.execution_id||receipt.domain!=envelope.domain
            ||receipt.operation!=envelope.operation||receipt.resource_key!=envelope.resource_key||receipt.resource_version!=envelope.binding.resource_version
            ||receipt.action_hash!=action_hash||receipt.request_digest!=request_digest||receipt.completed_at<envelope.canonical_action.requested_at
            ||receipt.completed_at>now+Duration::minutes(1)||now<*not_before||now>=*expires_at
            ||safe_digest(&receipt.effect_receipt).map_err(DomainAuthorityError::from)!=receipt.effect_receipt_digest
            ||safe_digest(&receipt.evaluator_result).map_err(DomainAuthorityError::from)!=receipt.evaluator_result_digest
            ||receipt.evaluator_result.get("conclusion").and_then(Value::as_str)!=Some(conclusion_name(receipt.conclusion))
            ||(effect==EffectClass::Pure&&receipt.external_effect_started)
            ||(effect!=EffectClass::Pure&&!receipt.external_effect_started){return Err(DomainAuthorityError::ReceiptInvalid);}
        validate_typed_runtime_payloads(receipt,envelope,effect)?;
        let signature=URL_SAFE_NO_PAD.decode(&receipt.signature).ok().and_then(|raw|Signature::from_slice(&raw).ok()).ok_or(DomainAuthorityError::ReceiptInvalid)?;
        key.verify(&receipt.signing_bytes()?,&signature).map_err(|_|DomainAuthorityError::ReceiptInvalid)
    }
}

fn validate_typed_runtime_payloads(receipt:&DomainRuntimeReceipt,envelope:&DomainExecutionEnvelope,effect:EffectClass)->Result<(),DomainAuthorityError>{
    let effect_receipt:TypedDomainEffectReceipt=serde_json::from_value(receipt.effect_receipt.clone()).map_err(|_|DomainAuthorityError::ReceiptInvalid)?;
    let tool=envelope.pack_manifest.tools.iter().find(|tool|tool.tool_id==envelope.operation).ok_or(DomainAuthorityError::ReceiptInvalid)?;
    let external_pair=match (&effect_receipt.external_receipt_ref,&effect_receipt.external_receipt_digest){
        (Some(reference_value),Some(digest_value)) if reference(reference_value,2048)&&digest(digest_value)=>true,
        (None,None)=>false,
        _=>return Err(DomainAuthorityError::ReceiptInvalid),
    };
    if effect_receipt.schema_version!=DOMAIN_EFFECT_RECEIPT_SCHEMA
        ||effect_receipt.tenant_id!=envelope.binding.tenant_id||effect_receipt.execution_id!=envelope.execution_id
        ||effect_receipt.tool_id!=envelope.operation||effect_receipt.operation!=envelope.operation
        ||effect_receipt.resource_key!=envelope.resource_key||effect_receipt.resource_version!=envelope.binding.resource_version
        ||effect_receipt.before_digest!=envelope.before_digest||effect_receipt.target_digest!=envelope.target_digest
        ||!identifier(&effect_receipt.executor_identity,512)||!reference(&effect_receipt.executor_receipt_ref,2048)
        ||!digest(&effect_receipt.executor_receipt_digest)||effect_receipt.compensation_ref.as_deref()!=tool.compensation_ref.as_deref()
        ||effect_receipt.started_at<envelope.canonical_action.requested_at||effect_receipt.completed_at<effect_receipt.started_at
        ||effect_receipt.completed_at>receipt.completed_at
        ||(effect==EffectClass::Pure&&(effect_receipt.status!="OBSERVED"||external_pair))
        ||(effect!=EffectClass::Pure&&(!matches!(effect_receipt.status.as_str(),"APPLIED"|"COMPENSATED")||!external_pair)){
        return Err(DomainAuthorityError::ReceiptInvalid);
    }

    let evaluator:TypedDomainEvaluatorResult=serde_json::from_value(receipt.evaluator_result.clone()).map_err(|_|DomainAuthorityError::ReceiptInvalid)?;
    let expected_checks=required_evaluator_checks(envelope.domain);
    let actual_checks=evaluator.checks.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let reasons_valid=evaluator.reason_codes.len()<=64&&evaluator.reason_codes.iter().all(|reason|identifier(reason,128));
    let all_pass=evaluator.checks.values().all(|passed|*passed);
    if evaluator.schema_version!=DOMAIN_EVALUATOR_RESULT_SCHEMA||evaluator.domain!=envelope.domain
        ||evaluator.operation!=envelope.operation||evaluator.resource_key!=envelope.resource_key
        ||evaluator.before_digest!=envelope.before_digest||evaluator.target_digest!=envelope.target_digest
        ||evaluator.conclusion!=receipt.conclusion||actual_checks!=expected_checks||!reasons_valid
        ||evaluator.evaluated_at<effect_receipt.completed_at||evaluator.evaluated_at>receipt.completed_at
        ||(evaluator.conclusion==DomainEvaluatorConclusion::Pass&&(!all_pass||!evaluator.reason_codes.is_empty()))
        ||(evaluator.conclusion!=DomainEvaluatorConclusion::Pass&&(all_pass||evaluator.reason_codes.is_empty())){
        return Err(DomainAuthorityError::ReceiptInvalid);
    }
    Ok(())
}

fn required_evaluator_checks(domain:DomainKind)->BTreeSet<&'static str>{
    match domain{
        DomainKind::Coding=>BTreeSet::from(["build_test_gate","command_template","dependency_lock","path_scope","secret_scan"]),
        DomainKind::Industrial=>BTreeSet::from(["alarm_clear","interlock_healthy","quality_good","rate_limit","state_fresh"]),
        DomainKind::Energy=>BTreeSet::from(["fallback_ready","forecast_valid","hard_constraints","not_ood","telemetry_fresh"]),
        DomainKind::Medical=>BTreeSet::from(["clinical_evidence","minimum_necessary","patient_match","privacy_boundary","professional_review"]),
        DomainKind::Sensitive=>BTreeSet::from(["citation_integrity","consent","escalation","manipulation_absent","relationship_boundary"]),
    }
}

#[async_trait]
pub trait DomainRuntimePort:Send+Sync {
    async fn execute(&self,envelope:&DomainExecutionEnvelope,request_digest:&str,action_hash:&str)->Result<DomainRuntimeReceipt,DomainAuthorityError>;
    async fn deliver_evidence(&self,tenant_id:Uuid,idempotency_key:&str,payload:&Value,payload_digest:&str)->Result<AuthorityEvidenceDelivery,DomainAuthorityError>;
    async fn ready(&self)->bool;
}

#[derive(Clone)]
pub struct PostgresDomainRuntimeStore { pool:PgPool }

impl PostgresDomainRuntimeStore {
    pub fn new(pool:PgPool)->Self{Self{pool}}
    async fn begin_tenant(&self,tenant:Uuid)->Result<Transaction<'_,Postgres>,DomainAuthorityError>{
        let mut tx=self.pool.begin().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)").bind(tenant.to_string()).execute(&mut *tx).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        Ok(tx)
    }
    pub async fn ready(&self)->bool{sqlx::query_scalar::<_,i32>("SELECT 1 FROM public.domain_pack_executions WHERE false UNION ALL SELECT 1 LIMIT 1").fetch_optional(&self.pool).await.is_ok()}

    async fn verifier(&self,tenant:Uuid,envelope:&DomainExecutionEnvelope)->Result<ArtifactVerifier,DomainAuthorityError>{
        let mut tx=self.begin_tenant(tenant).await?;
        let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.supply_chain_pack_releases r JOIN public.supply_chain_artifact_revisions a ON a.tenant_id=r.tenant_id AND a.artifact_id=r.artifact_id WHERE r.tenant_id=$1 AND r.pack_id=$2 AND r.version=$3 AND r.manifest_digest=$4 AND r.lifecycle_state='ACTIVE' AND a.status='VERIFIED')")
            .bind(tenant).bind(&envelope.pack_manifest.pack_id).bind(&envelope.pack_manifest.version).bind(&envelope.pack_manifest.digest)
            .fetch_one(&mut *tx).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        if !active{return Err(DomainAuthorityError::PackInactive);}
        let row=sqlx::query("SELECT k.public_key_spki,k.algorithm,k.status AS key_status,p.status AS publisher_status,k.valid_from,k.valid_until FROM public.supply_chain_publisher_keys k JOIN public.supply_chain_publishers p ON p.publisher_id=k.publisher_id WHERE k.publisher_id=$1 AND k.key_id=$2")
            .bind(&envelope.pack_manifest.publisher_identity).bind(&envelope.pack_manifest.signature.key_id).fetch_optional(&mut *tx).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?.ok_or(DomainAuthorityError::PackInactive)?;
        let signed_at=envelope.pack_manifest.signature.signed_at;
        if row.get::<String,_>("algorithm")!="ED25519"||row.get::<String,_>("key_status")!="ACTIVE"||row.get::<String,_>("publisher_status")!="ACTIVE"
            ||row.get::<DateTime<Utc>,_>("valid_from")>signed_at||row.get::<DateTime<Utc>,_>("valid_until")<=signed_at{return Err(DomainAuthorityError::PackInactive);}
        let bytes:<[u8;32]>::try_from(row.get::<Vec<u8>,_>("public_key_spki")).map_err(|_|DomainAuthorityError::PackInactive)?;
        let key=VerifyingKey::from_bytes(&bytes).map_err(|_|DomainAuthorityError::PackInactive)?;
        let verifier=ArtifactVerifier::default();
        verifier.authorize_publisher(envelope.pack_manifest.signature.key_id.clone(),envelope.pack_manifest.publisher_identity.clone(),key);
        tx.commit().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        Ok(verifier)
    }

    async fn prepare_and_claim(&self,envelope:&DomainExecutionEnvelope,request_digest:&str,action_hash:&str,effect:EffectClass,instance_id:Uuid,lease_seconds:i64)->Result<Option<DomainExecutionResult>,DomainAuthorityError>{
        let tenant=envelope.binding.tenant_id;let mut tx=self.begin_tenant(tenant).await?;
        let canonical=serde_json::to_value(&envelope.canonical_action).map_err(|_|DomainAuthorityError::RequestInvalid)?;
        let task_id=Uuid::parse_str(&envelope.canonical_action.task_id.0).map_err(|_|DomainAuthorityError::RequestInvalid)?;
        let input_digest=safe_digest(&envelope.safe_command).map_err(DomainAuthorityError::from)?;
        sqlx::query("INSERT INTO public.domain_pack_executions
            (tenant_id,execution_id,command_id,task_id,domain,pack_id,pack_version,pack_manifest_digest,tool_id,effect_class,
             action_id,action_hash,request_digest,idempotency_key,actor_subject,authorization_id,authorization_digest,
             policy_decision_id,policy_decision_digest,authorization_evidence_ref,authorization_evidence_digest,
             ledger_execution_id,ledger_event_id,ledger_event_digest,fence_digest,resource_key,resource_version,
             canonical_action,safe_input,input_digest,state)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$3,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,'PREPARED')
             ON CONFLICT (tenant_id,idempotency_key) DO NOTHING")
            .bind(tenant).bind(envelope.execution_id).bind(envelope.command_id).bind(task_id).bind(domain_name(envelope.domain))
            .bind(&envelope.pack_manifest.pack_id).bind(&envelope.pack_manifest.version).bind(&envelope.pack_manifest.digest)
            .bind(&envelope.canonical_action.tool.tool_id.0).bind(effect_name(effect)).bind(action_hash).bind(request_digest)
            .bind(&envelope.binding.idempotency_key).bind(&envelope.actor_subject).bind(envelope.binding.authorization_id)
            .bind(&envelope.binding.authorization_digest).bind(&envelope.binding.policy_decision_id).bind(&envelope.binding.policy_decision_digest)
            .bind(&envelope.binding.authorization_evidence_ref).bind(&envelope.binding.authorization_evidence_digest)
            .bind(envelope.binding.ledger_execution_id).bind(envelope.binding.ledger_event_id).bind(&envelope.binding.ledger_event_digest)
            .bind(&envelope.binding.fence_digest).bind(&envelope.resource_key)
            .bind(i64::try_from(envelope.binding.resource_version).map_err(|_|DomainAuthorityError::RequestInvalid)?)
            .bind(canonical).bind(&envelope.safe_command).bind(input_digest).execute(&mut *tx).await.map_err(|_|DomainAuthorityError::StateConflict)?;
        let row=sqlx::query("SELECT execution_id,command_id,domain,resource_key,resource_version,state,request_digest,action_hash,
             effect_receipt_digest,evaluator_result,evaluator_result_digest,evidence_ref,evidence_digest,stable_error
             FROM public.domain_pack_executions WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE")
            .bind(tenant).bind(&envelope.binding.idempotency_key).fetch_one(&mut *tx).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        if row.get::<Uuid,_>("execution_id")!=envelope.execution_id||row.get::<String,_>("request_digest")!=request_digest||row.get::<String,_>("action_hash")!=action_hash
            ||row.get::<String,_>("resource_key")!=envelope.resource_key||row.get::<i64,_>("resource_version")!=i64::try_from(envelope.binding.resource_version).map_err(|_|DomainAuthorityError::RequestInvalid)?{return Err(DomainAuthorityError::IdempotencyConflict);}
        if row.get::<String,_>("state")!="PREPARED"{let result=result_from_row(&row)?;tx.commit().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;return Ok(Some(result));}
        let tool=envelope.pack_manifest.tools.iter().find(|tool|tool.tool_id==envelope.canonical_action.tool.tool_id.0).ok_or(DomainAuthorityError::RequestInvalid)?;
        let minimum=if envelope.physical_supervision.is_some(){2usize}else if tool.approval_required{1usize}else{0usize};
        if minimum>0{
            let approval_set=validate_approvals(envelope,Utc::now(),minimum).map_err(|_|DomainAuthorityError::ApprovalInvalid)?;
            if envelope.physical_supervision.as_ref().is_some_and(|grant|grant.approval_set_id!=approval_set){return Err(DomainAuthorityError::ApprovalInvalid);}
            let approval_ids=envelope.expert_approvals.iter().filter(|approval|approval.approval_set_id==approval_set).map(|approval|approval.approval_id).collect::<Vec<_>>();
            let supervisor=envelope.physical_supervision.as_ref().map(|grant|grant.supervisor_subject.as_str());
            let rows=sqlx::query("SELECT approval_id,approval_set_id,domain,operation,resource_key,before_digest,target_digest,
                    resource_version,decision,reviewer_subject,reviewer_role,reviewer_qualification_digest,
                    principal_assertion_digest,evidence_ref,evidence_digest,approved_at,expires_at
                FROM public.domain_expert_approvals WHERE tenant_id=$1 AND approval_id=ANY($2) FOR KEY SHARE")
                .bind(tenant).bind(&approval_ids).fetch_all(&mut *tx).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
            if rows.len()!=approval_ids.len()||rows.len()<minimum{return Err(DomainAuthorityError::ApprovalInvalid);}
            for approval in &envelope.expert_approvals{
                let row=rows.iter().find(|row|row.get::<Uuid,_>("approval_id")==approval.approval_id).ok_or(DomainAuthorityError::ApprovalInvalid)?;
                if row.get::<Uuid,_>("approval_set_id")!=approval_set||row.get::<String,_>("domain")!=domain_name(envelope.domain)
                    ||row.get::<String,_>("operation")!=envelope.operation||row.get::<String,_>("resource_key")!=envelope.resource_key
                    ||row.get::<String,_>("before_digest")!=envelope.before_digest||row.get::<String,_>("target_digest")!=envelope.target_digest
                    ||row.get::<i64,_>("resource_version")!=i64::try_from(envelope.binding.resource_version).map_err(|_|DomainAuthorityError::RequestInvalid)?
                    ||row.get::<String,_>("decision")!="APPROVED"||row.get::<String,_>("reviewer_subject")!=approval.reviewer_subject
                    ||row.get::<String,_>("reviewer_role")!=approval.reviewer_role||row.get::<String,_>("reviewer_qualification_digest")!=approval.qualification_digest
                    ||row.get::<String,_>("principal_assertion_digest")!=approval.principal_assertion_digest||row.get::<String,_>("evidence_ref")!=approval.evidence_ref
                    ||row.get::<String,_>("evidence_digest")!=approval.evidence_digest||row.get::<DateTime<Utc>,_>("approved_at")!=approval.approved_at
                    ||row.get::<DateTime<Utc>,_>("expires_at")!=approval.expires_at||row.get::<DateTime<Utc>,_>("approved_at")>Utc::now()
                    ||row.get::<DateTime<Utc>,_>("expires_at")<=Utc::now()||supervisor==Some(approval.reviewer_subject.as_str()){
                    return Err(DomainAuthorityError::ApprovalInvalid);
                }
            }
        }
        if let Some(grant)=&envelope.physical_supervision{
            let affected=sqlx::query("UPDATE public.domain_physical_supervision SET consumed_by_execution_id=$3,consumed_at=now() WHERE tenant_id=$1 AND supervision_id=$2 AND approval_set_id=$4 AND domain=$5 AND stage='LIMITED_WRITE' AND resource_key=$6 AND before_digest=$7 AND target_digest=$8 AND resource_version=$9 AND supervisor_subject=$10 AND supervisor_assertion_digest=$11 AND evidence_ref=$12 AND evidence_digest=$13 AND issued_at=$14 AND expires_at=$15 AND issued_at<=now() AND expires_at>now() AND consumed_by_execution_id IS NULL AND consumed_at IS NULL")
                .bind(tenant).bind(grant.supervision_id).bind(envelope.execution_id).bind(grant.approval_set_id).bind(domain_name(envelope.domain))
                .bind(&envelope.resource_key).bind(&envelope.before_digest).bind(&envelope.target_digest)
                .bind(i64::try_from(envelope.binding.resource_version).map_err(|_|DomainAuthorityError::RequestInvalid)?).bind(&grant.supervisor_subject)
                .bind(&grant.supervisor_assertion_digest).bind(&grant.evidence_ref).bind(&grant.evidence_digest).bind(grant.issued_at).bind(grant.expires_at)
                .execute(&mut *tx).await.map_err(|_|DomainAuthorityError::SupervisionInvalid)?.rows_affected();
            if affected!=1{return Err(DomainAuthorityError::SupervisionInvalid);}
        }
        let affected=sqlx::query("UPDATE public.domain_pack_executions SET state='EXECUTING',owner_instance_id=$3,lease_expires_at=now()+make_interval(secs=>$4),updated_at=now() WHERE tenant_id=$1 AND execution_id=$2 AND state='PREPARED'")
            .bind(tenant).bind(envelope.execution_id).bind(instance_id).bind(lease_seconds).execute(&mut *tx).await.map_err(|_|DomainAuthorityError::StateConflict)?.rows_affected();
        if affected!=1{return Err(DomainAuthorityError::StateConflict);}tx.commit().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;Ok(None)
    }

    async fn commit_receipt(&self,envelope:&DomainExecutionEnvelope,receipt:&DomainRuntimeReceipt)->Result<DomainExecutionResult,DomainAuthorityError>{
        let tenant=envelope.binding.tenant_id;let mut tx=self.begin_tenant(tenant).await?;
        let state:String=sqlx::query_scalar("SELECT state FROM public.domain_pack_executions WHERE tenant_id=$1 AND execution_id=$2 AND lease_expires_at>now() FOR UPDATE")
            .bind(tenant).bind(envelope.execution_id).fetch_optional(&mut *tx).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?.ok_or(DomainAuthorityError::OutcomeUnknown)?;
        if state!="EXECUTING"{return Err(DomainAuthorityError::OutcomeUnknown);}
        let receipt_value=serde_json::to_value(&receipt.effect_receipt).map_err(|_|DomainAuthorityError::ReceiptInvalid)?;
        let evaluator_value=serde_json::to_value(&receipt.evaluator_result).map_err(|_|DomainAuthorityError::ReceiptInvalid)?;
        let verifying=sqlx::query("UPDATE public.domain_pack_executions SET state='VERIFYING',effect_receipt=$3,effect_receipt_digest=$4,evaluator_result=$5,evaluator_result_digest=$6,updated_at=now() WHERE tenant_id=$1 AND execution_id=$2 AND state='EXECUTING'")
            .bind(tenant).bind(envelope.execution_id).bind(receipt_value).bind(&receipt.effect_receipt_digest).bind(evaluator_value).bind(&receipt.evaluator_result_digest)
            .execute(&mut *tx).await.map_err(|_|DomainAuthorityError::OutcomeUnknown)?.rows_affected();
        if verifying!=1{return Err(DomainAuthorityError::OutcomeUnknown);}
        let evidence_event_id=Uuid::new_v4();
        // Persist the Evidence wire timestamps in the outbox. Reconstructing them with `now()`
        // would change the request digest on retry and violate durable idempotency.
        let evidence_requested_at=Utc::now();
        let payload=json!({"schema_version":"agenttrust.domain-runtime-evidence.v1","event_id":evidence_event_id,"tenant_id":tenant,
            "evidence_occurred_at":evidence_requested_at,"evidence_requested_at":evidence_requested_at,
            "task_id":envelope.canonical_action.task_id.0,"actor_subject":envelope.actor_subject,"trace_id":envelope.binding.trace_id,"execution_id":envelope.execution_id,
            "command_id":envelope.command_id,"domain":envelope.domain,"pack_manifest_digest":envelope.pack_manifest.digest,
            "action_hash":receipt.action_hash,"request_digest":receipt.request_digest,"operation":envelope.operation,
            "resource_key":envelope.resource_key,"resource_version":envelope.binding.resource_version,
            "policy_decision_id":envelope.binding.policy_decision_id,"policy_decision_digest":envelope.binding.policy_decision_digest,
            "authorization_evidence_ref":envelope.binding.authorization_evidence_ref,"authorization_evidence_digest":envelope.binding.authorization_evidence_digest,
            "ledger_execution_id":envelope.binding.ledger_execution_id,"ledger_event_id":envelope.binding.ledger_event_id,
            "ledger_event_digest":envelope.binding.ledger_event_digest,"fence_digest":envelope.binding.fence_digest,"runtime_receipt":receipt});
        let payload_digest=safe_digest(&payload).map_err(DomainAuthorityError::from)?;
        let evidence_ref=format!("evidence://domain-runtime/{}",envelope.execution_id);
        sqlx::query("INSERT INTO public.domain_pack_evidence_outbox(tenant_id,outbox_id,execution_id,domain,idempotency_key,payload,payload_digest,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now())")
            .bind(tenant).bind(evidence_event_id).bind(envelope.execution_id).bind(domain_name(envelope.domain))
            .bind(format!("domain-evidence:{}",envelope.execution_id)).bind(payload).bind(&payload_digest)
            .execute(&mut *tx).await.map_err(|_|DomainAuthorityError::StateConflict)?;
        let (terminal,stable)=match receipt.conclusion{DomainEvaluatorConclusion::Pass|DomainEvaluatorConclusion::Fail=>("SUCCEEDED",None),DomainEvaluatorConclusion::NeedsHuman=>("NEEDS_HUMAN",Some("DOMAIN_EVALUATOR_NEEDS_HUMAN")),DomainEvaluatorConclusion::ManualRecovery=>("MANUAL_RECOVERY",Some("DOMAIN_EVALUATOR_MANUAL_RECOVERY"))};
        let affected=sqlx::query("UPDATE public.domain_pack_executions SET state=$3,stable_error=$4,evidence_ref=$5,evidence_digest=$6,updated_at=now() WHERE tenant_id=$1 AND execution_id=$2 AND state='VERIFYING'")
            .bind(tenant).bind(envelope.execution_id).bind(terminal).bind(stable).bind(&evidence_ref).bind(&payload_digest)
            .execute(&mut *tx).await.map_err(|_|DomainAuthorityError::OutcomeUnknown)?.rows_affected();
        if affected!=1{return Err(DomainAuthorityError::OutcomeUnknown);}tx.commit().await.map_err(|_|DomainAuthorityError::OutcomeUnknown)?;
        Ok(DomainExecutionResult{schema_version:DOMAIN_RESULT_SCHEMA.into(),execution_id:envelope.execution_id,state:terminal.into(),domain:envelope.domain,
            resource_key:envelope.resource_key.clone(),resource_version:envelope.binding.resource_version,effect_receipt_digest:Some(receipt.effect_receipt_digest.clone()),
            evaluator_result_digest:Some(receipt.evaluator_result_digest.clone()),evaluator_conclusion:Some(receipt.conclusion),evidence_ref:Some(evidence_ref),evidence_digest:Some(payload_digest),stable_error:stable.map(str::to_string)})
    }

    async fn finish_uncertain(&self,envelope:&DomainExecutionEnvelope,state:&str,error:&str)->Result<(),DomainAuthorityError>{
        if !matches!(state,"FAILED"|"UNKNOWN")||!identifier(error,128){return Err(DomainAuthorityError::RequestInvalid);}
        let mut tx=self.begin_tenant(envelope.binding.tenant_id).await?;
        let affected=sqlx::query("UPDATE public.domain_pack_executions SET state=$3,stable_error=$4,updated_at=now() WHERE tenant_id=$1 AND execution_id=$2 AND state='EXECUTING'")
            .bind(envelope.binding.tenant_id).bind(envelope.execution_id).bind(state).bind(error).execute(&mut *tx).await.map_err(|_|DomainAuthorityError::OutcomeUnknown)?.rows_affected();
        if affected!=1{return Err(DomainAuthorityError::OutcomeUnknown);}
        tx.commit().await.map_err(|_|DomainAuthorityError::OutcomeUnknown)
    }

    pub async fn recover_expired(&self,tenant:Uuid,limit:i64)->Result<u64,DomainAuthorityError>{
        if !(1..=1000).contains(&limit){return Err(DomainAuthorityError::RequestInvalid);}let mut tx=self.begin_tenant(tenant).await?;
        let rows=sqlx::query("SELECT execution_id FROM public.domain_pack_executions WHERE tenant_id=$1 AND state IN ('EXECUTING','VERIFYING') AND lease_expires_at<now() ORDER BY lease_expires_at LIMIT $2 FOR UPDATE SKIP LOCKED")
            .bind(tenant).bind(limit).fetch_all(&mut *tx).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        for row in &rows{sqlx::query("UPDATE public.domain_pack_executions SET state='UNKNOWN',stable_error='DOMAIN_RUNTIME_LEASE_EXPIRED',updated_at=now() WHERE tenant_id=$1 AND execution_id=$2 AND state IN ('EXECUTING','VERIFYING')")
            .bind(tenant).bind(row.get::<Uuid,_>("execution_id")).execute(&mut *tx).await.map_err(|_|DomainAuthorityError::OutcomeUnknown)?;}
        tx.commit().await.map_err(|_|DomainAuthorityError::OutcomeUnknown)?;u64::try_from(rows.len()).map_err(|_|DomainAuthorityError::DependencyUnavailable)
    }

    pub async fn authoritative_state(&self,tenant:Uuid,limit:i64,cursor:Option<&str>)->Result<AuthoritativeDomainExecutionPage,DomainAuthorityError>{
        if !(1..=200).contains(&limit){return Err(DomainAuthorityError::RequestInvalid);}let decoded=cursor.map(decode_cursor).transpose()?;
        let after_time=decoded.as_ref().map(|value|value.0);let after_id=decoded.as_ref().map(|value|value.1);
        let mut tx=self.begin_tenant(tenant).await?;
        let rows=sqlx::query("SELECT execution_id,command_id,domain,pack_id,pack_version,pack_manifest_digest,tool_id,
            canonical_action->'intent'->>'operation' AS operation,resource_key,resource_version,state,effect_receipt_digest,
            evaluator_result_digest,evaluator_result->>'conclusion' AS evaluator_conclusion,
            COALESCE((SELECT o.delivery_evidence_ref FROM public.domain_pack_evidence_outbox o WHERE o.tenant_id=domain_pack_executions.tenant_id AND o.execution_id=domain_pack_executions.execution_id AND o.delivered_at IS NOT NULL ORDER BY o.created_at DESC,o.outbox_id DESC LIMIT 1),evidence_ref) AS evidence_ref,
            COALESCE((SELECT o.delivery_receipt_digest FROM public.domain_pack_evidence_outbox o WHERE o.tenant_id=domain_pack_executions.tenant_id AND o.execution_id=domain_pack_executions.execution_id AND o.delivered_at IS NOT NULL ORDER BY o.created_at DESC,o.outbox_id DESC LIMIT 1),evidence_digest) AS evidence_digest,
            stable_error,created_at,updated_at
            FROM public.domain_pack_executions WHERE tenant_id=$1 AND ($2::timestamptz IS NULL OR (created_at,execution_id)>($2,$3))
            ORDER BY created_at,execution_id LIMIT $4")
            .bind(tenant).bind(after_time).bind(after_id).bind(limit+1).fetch_all(&mut *tx).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        tx.commit().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;let has_more=i64::try_from(rows.len()).is_ok_and(|count|count>limit);
        let items=rows.into_iter().take(usize::try_from(limit).map_err(|_|DomainAuthorityError::RequestInvalid)?).map(authoritative_from_row).collect::<Result<Vec<_>,_>>()?;
        let next_cursor=if has_more{items.last().map(|item|encode_cursor(item.created_at,item.execution_id)).transpose()?}else{None};
        // The digest covers the exact response object with only `data_digest` removed. Keep
        // this shape explicit so a BFF can verify it without authority-specific assumptions.
        let data_digest=safe_digest(&json!({
            "schema_version":DOMAIN_STATE_SCHEMA,
            "tenant_id":tenant,
            "authoritative":true,
            "items":&items,
            "next_cursor":&next_cursor,
        })).map_err(DomainAuthorityError::from)?;
        Ok(AuthoritativeDomainExecutionPage{schema_version:DOMAIN_STATE_SCHEMA.into(),tenant_id:tenant,authoritative:true,data_digest,items,next_cursor})
    }
}

#[derive(Clone)]
pub struct DomainRuntimeAuthority { store:PostgresDomainRuntimeStore,runtime:Arc<dyn DomainRuntimePort>,keyring:DomainReceiptKeyring,instance_id:Uuid,lease_seconds:i64 }

impl DomainRuntimeAuthority {
    pub fn new(store:PostgresDomainRuntimeStore,runtime:Arc<dyn DomainRuntimePort>,keyring:DomainReceiptKeyring,instance_id:Uuid,lease_seconds:i64)->Result<Self,DomainAuthorityError>{
        if instance_id.is_nil()||!(15..=300).contains(&lease_seconds){return Err(DomainAuthorityError::ConfigurationInvalid);}Ok(Self{store,runtime,keyring,instance_id,lease_seconds})
    }
    pub async fn ready(&self)->bool{self.store.ready().await&&self.runtime.ready().await}
    pub async fn execute(&self,envelope:DomainExecutionEnvelope)->Result<DomainExecutionResult,DomainAuthorityError>{
        let verifier=self.store.verifier(envelope.binding.tenant_id,&envelope).await?;
        let action_hash=ProductionDomainPackContract::authorize(&envelope,&verifier,Utc::now()).map_err(DomainAuthorityError::from)?;
        let request_digest=safe_digest(&envelope).map_err(DomainAuthorityError::from)?;
        let effect=envelope.pack_manifest.tools.iter().find(|tool|tool.tool_id==envelope.canonical_action.tool.tool_id.0).map(|tool|tool.effect_class).ok_or(DomainAuthorityError::RequestInvalid)?;
        if let Some(result)=self.store.prepare_and_claim(&envelope,&request_digest,&action_hash,effect,self.instance_id,self.lease_seconds).await?{return Ok(result);}
        let receipt=match self.runtime.execute(&envelope,&request_digest,&action_hash).await{Ok(value)=>value,Err(error)=>{let unknown=effect!=EffectClass::Pure;self.store.finish_uncertain(&envelope,if unknown{"UNKNOWN"}else{"FAILED"},if unknown{"DOMAIN_RUNTIME_EXTERNAL_OUTCOME_UNKNOWN"}else{error.code()}).await?;return Err(if unknown{DomainAuthorityError::OutcomeUnknown}else{error});}};
        if let Err(error)=self.keyring.verify(&receipt,&envelope,&request_digest,&action_hash,effect,Utc::now()){self.store.finish_uncertain(&envelope,"UNKNOWN","DOMAIN_RUNTIME_RECEIPT_INVALID").await?;return Err(error);}
        let result=match self.store.commit_receipt(&envelope,&receipt).await{
            Ok(result)=>result,
            Err(_)=>{
                // A signed executor receipt means the effect may have occurred. If the local
                // receipt/evaluator transaction cannot be proven committed, force reconciliation
                // instead of surfacing a retryable policy or persistence error.
                let _=self.store.finish_uncertain(&envelope,"UNKNOWN","DOMAIN_RUNTIME_COMMIT_OUTCOME_UNKNOWN").await;
                return Err(DomainAuthorityError::OutcomeUnknown);
            }
        };let _=self.flush_evidence(envelope.binding.tenant_id,32).await;Ok(result)
    }
    pub async fn authoritative_state(&self,tenant:Uuid,limit:i64,cursor:Option<&str>)->Result<AuthoritativeDomainExecutionPage,DomainAuthorityError>{self.store.authoritative_state(tenant,limit,cursor).await}
    pub async fn recover_expired(&self,tenant:Uuid,limit:i64)->Result<u64,DomainAuthorityError>{self.store.recover_expired(tenant,limit).await}
    pub async fn flush_evidence(&self,tenant:Uuid,limit:i64)->Result<u64,DomainAuthorityError>{
        if !(1..=100).contains(&limit){return Err(DomainAuthorityError::RequestInvalid);}let mut tx=self.store.begin_tenant(tenant).await?;
        let rows=sqlx::query("SELECT outbox_id,idempotency_key,payload,payload_digest FROM public.domain_pack_evidence_outbox WHERE tenant_id=$1 AND delivered_at IS NULL ORDER BY created_at LIMIT $2")
            .bind(tenant).bind(limit).fetch_all(&mut *tx).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;tx.commit().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;let mut delivered=0u64;
        for row in rows{let outbox_id:Uuid=row.get("outbox_id");let idempotency:String=row.get("idempotency_key");let payload:Value=row.get("payload");let digest_value:String=row.get("payload_digest");
            let receipt=self.runtime.deliver_evidence(tenant,&idempotency,&payload,&digest_value).await?;
            if !digest(&digest_value)||!digest(&receipt.evidence_digest)||!reference(&receipt.evidence_ref,2048){return Err(DomainAuthorityError::ReceiptInvalid);}
            let mut delivery=self.store.begin_tenant(tenant).await?;
            let affected=sqlx::query("UPDATE public.domain_pack_evidence_outbox SET delivered_at=now(),delivery_receipt_digest=$4,delivery_evidence_ref=$5 WHERE tenant_id=$1 AND outbox_id=$2 AND payload_digest=$3 AND delivered_at IS NULL")
                .bind(tenant).bind(outbox_id).bind(&digest_value).bind(&receipt.evidence_digest).bind(&receipt.evidence_ref).execute(&mut *delivery).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?.rows_affected();
            if affected!=1{return Err(DomainAuthorityError::StateConflict);}delivery.commit().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;delivered=delivered.saturating_add(1);}
        Ok(delivered)
    }
}

fn result_from_row(row:&sqlx::postgres::PgRow)->Result<DomainExecutionResult,DomainAuthorityError>{
    let evaluator=row.get::<Option<Value>,_>("evaluator_result");let conclusion=evaluator.as_ref().and_then(|value|value.get("conclusion")).and_then(Value::as_str).and_then(parse_conclusion);
    Ok(DomainExecutionResult{schema_version:DOMAIN_RESULT_SCHEMA.into(),execution_id:row.get("execution_id"),state:row.get("state"),domain:parse_domain(&row.get::<String,_>("domain"))?,resource_key:row.get("resource_key"),resource_version:u64::try_from(row.get::<i64,_>("resource_version")).map_err(|_|DomainAuthorityError::StateConflict)?,effect_receipt_digest:row.get("effect_receipt_digest"),evaluator_result_digest:row.get("evaluator_result_digest"),evaluator_conclusion:conclusion,evidence_ref:row.get("evidence_ref"),evidence_digest:row.get("evidence_digest"),stable_error:row.get("stable_error")})
}
fn authoritative_from_row(row:sqlx::postgres::PgRow)->Result<AuthoritativeDomainExecution,DomainAuthorityError>{Ok(AuthoritativeDomainExecution{execution_id:row.get("execution_id"),command_id:row.get("command_id"),domain:parse_domain(&row.get::<String,_>("domain"))?,pack_id:row.get("pack_id"),pack_version:row.get("pack_version"),pack_manifest_digest:row.get("pack_manifest_digest"),tool_id:row.get("tool_id"),operation:row.get("operation"),resource_key:row.get("resource_key"),resource_version:u64::try_from(row.get::<i64,_>("resource_version")).map_err(|_|DomainAuthorityError::StateConflict)?,state:row.get("state"),effect_receipt_digest:row.get("effect_receipt_digest"),evaluator_result_digest:row.get("evaluator_result_digest"),evaluator_conclusion:row.get("evaluator_conclusion"),evidence_ref:row.get("evidence_ref"),evidence_digest:row.get("evidence_digest"),stable_error:row.get("stable_error"),created_at:row.get("created_at"),updated_at:row.get("updated_at")})}
fn domain_name(value:DomainKind)->&'static str{match value{DomainKind::Coding=>"CODING",DomainKind::Industrial=>"INDUSTRIAL",DomainKind::Energy=>"ENERGY",DomainKind::Medical=>"MEDICAL",DomainKind::Sensitive=>"SENSITIVE"}}
fn parse_domain(value:&str)->Result<DomainKind,DomainAuthorityError>{match value{"CODING"=>Ok(DomainKind::Coding),"INDUSTRIAL"=>Ok(DomainKind::Industrial),"ENERGY"=>Ok(DomainKind::Energy),"MEDICAL"=>Ok(DomainKind::Medical),"SENSITIVE"=>Ok(DomainKind::Sensitive),_=>Err(DomainAuthorityError::StateConflict)}}
fn effect_name(value:EffectClass)->&'static str{match value{EffectClass::Pure=>"PURE",EffectClass::Idempotent=>"IDEMPOTENT",EffectClass::Compensatable=>"COMPENSATABLE",EffectClass::Irreversible=>"IRREVERSIBLE"}}
fn parse_conclusion(value:&str)->Option<DomainEvaluatorConclusion>{match value{"PASS"=>Some(DomainEvaluatorConclusion::Pass),"FAIL"=>Some(DomainEvaluatorConclusion::Fail),"NEEDS_HUMAN"=>Some(DomainEvaluatorConclusion::NeedsHuman),"MANUAL_RECOVERY"=>Some(DomainEvaluatorConclusion::ManualRecovery),_=>None}}
fn conclusion_name(value:DomainEvaluatorConclusion)->&'static str{match value{DomainEvaluatorConclusion::Pass=>"PASS",DomainEvaluatorConclusion::Fail=>"FAIL",DomainEvaluatorConclusion::NeedsHuman=>"NEEDS_HUMAN",DomainEvaluatorConclusion::ManualRecovery=>"MANUAL_RECOVERY"}}
fn identifier(value:&str,maximum:usize)->bool{!value.is_empty()&&value.len()<=maximum&&!value.chars().any(char::is_control)}
fn digest(value:&str)->bool{value.len()==64&&value.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte))}
fn reference(value:&str,maximum:usize)->bool{identifier(value,maximum)&&!value.contains("..")}
fn decode_cursor(value:&str)->Result<(DateTime<Utc>,Uuid),DomainAuthorityError>{if value.is_empty()||value.len()>512{return Err(DomainAuthorityError::RequestInvalid);}let raw=URL_SAFE_NO_PAD.decode(value).map_err(|_|DomainAuthorityError::RequestInvalid)?;let fields:Vec<String>=serde_json::from_slice(&raw).map_err(|_|DomainAuthorityError::RequestInvalid)?;if fields.len()!=2{return Err(DomainAuthorityError::RequestInvalid);}let at=DateTime::parse_from_rfc3339(&fields[0]).map(|value|value.with_timezone(&Utc)).map_err(|_|DomainAuthorityError::RequestInvalid)?;let id=Uuid::parse_str(&fields[1]).map_err(|_|DomainAuthorityError::RequestInvalid)?;Ok((at,id))}
fn encode_cursor(at:DateTime<Utc>,id:Uuid)->Result<String,DomainAuthorityError>{serde_jcs::to_vec(&[at.to_rfc3339_opts(SecondsFormat::Micros,true),id.to_string()]).map(|raw|URL_SAFE_NO_PAD.encode(raw)).map_err(|_|DomainAuthorityError::RequestInvalid)}

impl From<DomainProductionError> for DomainAuthorityError { fn from(value:DomainProductionError)->Self{Self::Contract(value.to_string())} }

#[derive(Debug,Error,Clone,PartialEq,Eq)]
pub enum DomainAuthorityError {
    #[error("DOMAIN_RUNTIME_CONTRACT_DENIED:{0}")]Contract(String),
    #[error("DOMAIN_RUNTIME_REQUEST_INVALID")]RequestInvalid,
    #[error("DOMAIN_RUNTIME_PACK_INACTIVE")]PackInactive,
    #[error("DOMAIN_RUNTIME_APPROVAL_INVALID")]ApprovalInvalid,
    #[error("DOMAIN_RUNTIME_SUPERVISION_INVALID")]SupervisionInvalid,
    #[error("DOMAIN_RUNTIME_IDEMPOTENCY_CONFLICT")]IdempotencyConflict,
    #[error("DOMAIN_RUNTIME_STATE_CONFLICT")]StateConflict,
    #[error("DOMAIN_RUNTIME_RECEIPT_INVALID")]ReceiptInvalid,
    #[error("DOMAIN_RUNTIME_OUTCOME_UNKNOWN")]OutcomeUnknown,
    #[error("DOMAIN_RUNTIME_DEPENDENCY_UNAVAILABLE")]DependencyUnavailable,
    #[error("DOMAIN_RUNTIME_PRINCIPAL_DENIED")]PrincipalDenied,
    #[error("DOMAIN_RUNTIME_CONFIGURATION_INVALID")]ConfigurationInvalid,
}
impl DomainAuthorityError { pub fn code(&self)->&str{match self{Self::Contract(_)=>"DOMAIN_RUNTIME_CONTRACT_DENIED",Self::RequestInvalid=>"DOMAIN_RUNTIME_REQUEST_INVALID",Self::PackInactive=>"DOMAIN_RUNTIME_PACK_INACTIVE",Self::ApprovalInvalid=>"DOMAIN_RUNTIME_APPROVAL_INVALID",Self::SupervisionInvalid=>"DOMAIN_RUNTIME_SUPERVISION_INVALID",Self::IdempotencyConflict=>"DOMAIN_RUNTIME_IDEMPOTENCY_CONFLICT",Self::StateConflict=>"DOMAIN_RUNTIME_STATE_CONFLICT",Self::ReceiptInvalid=>"DOMAIN_RUNTIME_RECEIPT_INVALID",Self::OutcomeUnknown=>"DOMAIN_RUNTIME_OUTCOME_UNKNOWN",Self::DependencyUnavailable=>"DOMAIN_RUNTIME_DEPENDENCY_UNAVAILABLE",Self::PrincipalDenied=>"DOMAIN_RUNTIME_PRINCIPAL_DENIED",Self::ConfigurationInvalid=>"DOMAIN_RUNTIME_CONFIGURATION_INVALID"}}}
