//! Authoritative Domain Runtime HTTP surface. The router is composed with a concrete
//! `DomainRuntimePort`; domain plugins never receive bearer credentials or raw protocol secrets.

use crate::authority::{
    AuthoritativeDomainExecutionPage, DomainAuthorityError, DomainExecutionResult,
    DomainRuntimeAuthority,DomainRuntimePort,DomainRuntimeReceipt,
};
use crate::production::DomainExecutionEnvelope;
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_contracts::{
    APPROVAL_REVIEW_EVIDENCE_SCHEMA_VERSION, ActionHash, ApprovalReviewEvidence,
    ApprovalReviewEvidenceIssueRequest, AuthorityEvidenceControlBinding,
    AuthorityEvidenceEventRequest, AuthorityEvidenceSourceKind, EVIDENCE_EVENT_SCHEMA_VERSION as EVIDENCE_SCHEMA_VERSION,
    EvidenceEventDraft, EvidenceEventType, ExecutionId, IdempotencyKey,
    SignedAuthorityEvidenceReceipt, TaskId, TenantId,
    AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION,
};
use agent_trust_pack_supply_chain::server::{EvidenceEventKeyring,ExactPeerIdentity,ExactPeerIdentityAcceptor,SupplyDependency};
use agent_trust_pack_supply_chain::production::AuthorityEvidenceDelivery;
use async_trait::async_trait;
use axum::extract::{DefaultBodyLimit,Path as AxumPath,Query,State};
use axum::http::{HeaderMap,StatusCode};
use axum::response::{IntoResponse,Response};
use axum::routing::{get,post};
use axum::{Extension,Json,Router};
use ring::hmac;
use serde::Deserialize;
use sha2::{Digest,Sha256};
use std::collections::{BTreeSet};
use std::net::SocketAddr;
use std::path::{Path,PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

pub const DOMAIN_READINESS_SCHEMA:&str="agenttrust.domain-runtime-readiness.v1";
pub const DOMAIN_EXECUTE_SCOPE:&str="domain-runtime:execute";
pub const DOMAIN_READ_SCOPE:&str="domain-runtime:read";
pub const DOMAIN_RECOVER_SCOPE:&str="domain-runtime:recover";
pub const DOMAIN_APPROVAL_REVIEW_EVIDENCE_SCOPE:&str="domain-runtime:approval-review-evidence";

#[derive(Debug,Clone)]
pub struct DomainServerConfig{
    pub data_address:SocketAddr,pub management_address:SocketAddr,
    pub tls_ca_file:PathBuf,pub tls_certificate_file:PathBuf,pub tls_private_key_file:PathBuf,
    pub allowed_client_identities:BTreeSet<String>,
}

#[derive(Clone)]struct ApiState{authority:DomainRuntimeAuthority,tokens:Arc<DomainTokenAuthorizer>,review_producer:Arc<HttpDomainRuntimePort>}
#[derive(Clone)]struct ReadyState{authority:DomainRuntimeAuthority}

#[derive(Debug,Deserialize)]#[serde(deny_unknown_fields)]
struct TokenDocument{schema_version:String,bindings:Vec<TokenBinding>}
#[derive(Debug,Deserialize)]#[serde(deny_unknown_fields)]
struct TokenBinding{client_identity:String,tenant_id:String,subject:String,scope:String,token_sha256:String}
#[derive(Debug,Clone,PartialEq,Eq,PartialOrd,Ord)]
struct TokenAuthorization{client_identity:String,tenant_id:String,subject:String,scope:String,token_sha256:String}

pub struct DomainTokenAuthorizer{bindings:BTreeSet<TokenAuthorization>}
impl DomainTokenAuthorizer{
    pub fn from_file(path:&Path,allowed:&BTreeSet<String>)->Result<Self,DomainAuthorityError>{
        let raw=read_private(path,1,1_048_576)?;let document:TokenDocument=serde_json::from_slice(&raw).map_err(|_|DomainAuthorityError::ConfigurationInvalid)?;
        if document.schema_version!="agenttrust.domain-runtime-token-bindings.v1"||document.bindings.is_empty()||document.bindings.len()>10_000{return Err(DomainAuthorityError::ConfigurationInvalid);}
        let mut bindings=BTreeSet::new();let mut physical=BTreeSet::new();
        for binding in document.bindings{
            if !allowed.contains(&binding.client_identity)||!matches!(binding.scope.as_str(),DOMAIN_EXECUTE_SCOPE|DOMAIN_READ_SCOPE|DOMAIN_RECOVER_SCOPE|DOMAIN_APPROVAL_REVIEW_EVIDENCE_SCOPE)
                ||!canonical_uuid(&binding.tenant_id)||!identifier(&binding.subject,512)||!digest(&binding.token_sha256)
                ||!physical.insert(binding.token_sha256.clone())||!bindings.insert(TokenAuthorization{client_identity:binding.client_identity,tenant_id:binding.tenant_id,subject:binding.subject,scope:binding.scope,token_sha256:binding.token_sha256}){return Err(DomainAuthorityError::ConfigurationInvalid);}
        }
        if allowed.is_empty()||allowed.iter().any(|identity|!bindings.iter().any(|binding|&binding.client_identity==identity)){return Err(DomainAuthorityError::ConfigurationInvalid);}Ok(Self{bindings})
    }
    fn authorize(&self,peer:&str,tenant:Uuid,scope:&str,headers:&HeaderMap)->Result<String,DomainAuthorityError>{
        let token=single_header(headers,"authorization").and_then(|value|value.strip_prefix("Bearer ")).filter(|value|(16..=8192).contains(&value.len())&&value.bytes().all(|byte|byte.is_ascii_graphic())).ok_or(DomainAuthorityError::PrincipalDenied)?;
        let supplied=hex::encode(Sha256::digest(token.as_bytes()));let matches=self.bindings.iter().filter(|binding|binding.client_identity==peer&&binding.tenant_id==tenant.to_string()&&binding.scope==scope&&constant_time_equal(&supplied,&binding.token_sha256)).collect::<Vec<_>>();
        if matches.len()!=1{return Err(DomainAuthorityError::PrincipalDenied);}Ok(matches[0].subject.clone())
    }
}

#[derive(Clone)]
pub struct HttpDomainRuntimePort{
    client:reqwest::Client,coordinator:SupplyDependency,evidence:SupplyDependency,
    evidence_keyring:EvidenceEventKeyring,evidence_client_identity:String,
}
impl HttpDomainRuntimePort{
    pub fn new(client:reqwest::Client,coordinator:SupplyDependency,evidence:SupplyDependency,evidence_keyring:EvidenceEventKeyring,evidence_client_identity:String)->Result<Self,DomainAuthorityError>{
        if coordinator.name!="executor"||evidence.name!="evidence"||coordinator.endpoint==evidence.endpoint
            ||!valid_https_root(&coordinator.endpoint)||!valid_https_root(&evidence.endpoint)
            ||coordinator.token_file==evidence.token_file||read_token(&coordinator.token_file)?==read_token(&evidence.token_file)?
            ||!identifier(&coordinator.readiness_schema,128)||!identifier(&evidence.readiness_schema,128)
            ||!evidence_client_identity.strip_prefix("DNS:").or_else(||evidence_client_identity.strip_prefix("URI:")).is_some_and(|identity|!identity.is_empty())
            ||!identifier(&evidence_client_identity,256){return Err(DomainAuthorityError::ConfigurationInvalid);}
        Ok(Self{client,coordinator,evidence,evidence_keyring,evidence_client_identity})
    }

    pub async fn issue_approval_review_evidence(
        &self,
        issue: &ApprovalReviewEvidenceIssueRequest,
    )->Result<ApprovalReviewEvidence,DomainAuthorityError>{
        let request=issue.to_authority_event(&self.evidence_client_identity,chrono::Utc::now())
            .map_err(|_|DomainAuthorityError::RequestInvalid)?;
        let payload_digest=request.event.payload_hash.clone();
        let response=self.client.post(self.evidence.endpoint.join("v1/evidence/authority-events").map_err(|_|DomainAuthorityError::ConfigurationInvalid)?)
            .bearer_auth(read_token(&self.evidence.token_file)?)
            .header("X-AgentTrust-Tenant-Id",&issue.material.tenant_id)
            .header("Idempotency-Key",&issue.idempotency_key)
            .header("X-AgentTrust-Authority-Event-Id",&issue.request_id)
            .header("X-AgentTrust-Payload-Digest",&payload_digest)
            .json(&request).send().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        if response.status()==StatusCode::CONFLICT{return Err(DomainAuthorityError::IdempotencyConflict);}
        if !response.status().is_success()||response.content_length().is_some_and(|length|length>262_144){return Err(DomainAuthorityError::DependencyUnavailable);}
        let bytes=read_bounded_body(response,262_144).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty(){return Err(DomainAuthorityError::DependencyUnavailable);}
        let receipt:SignedAuthorityEvidenceReceipt=serde_json::from_slice(&bytes).map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        self.evidence_keyring.verify_for_source_kind(
            &receipt,&request,&payload_digest,&self.evidence_client_identity,
            AuthorityEvidenceSourceKind::AuthenticatedEvent,
        ).map_err(|_|DomainAuthorityError::ReceiptInvalid)?;
        Ok(ApprovalReviewEvidence{
            schema_version:APPROVAL_REVIEW_EVIDENCE_SCHEMA_VERSION.into(),
            material:issue.material.clone(),authority_request:request,receipt,
        })
    }
}
#[derive(Debug,Deserialize)]#[serde(deny_unknown_fields)]struct DependencyReadiness{schema_version:String,ready:bool}

#[async_trait]
impl DomainRuntimePort for HttpDomainRuntimePort{
    async fn execute(&self,envelope:&DomainExecutionEnvelope,request_digest:&str,action_hash:&str)->Result<DomainRuntimeReceipt,DomainAuthorityError>{
        let response=self.client.post(self.coordinator.endpoint.join("v1/domain-runtime/effects").map_err(|_|DomainAuthorityError::ConfigurationInvalid)?)
            .bearer_auth(read_token(&self.coordinator.token_file)?).header("X-AgentTrust-Tenant-Id",envelope.binding.tenant_id.to_string())
            .header("Idempotency-Key",&envelope.binding.idempotency_key).header("X-AgentTrust-Execution-Id",envelope.execution_id.to_string()).header("X-AgentTrust-Action-Hash",action_hash)
            .header("X-AgentTrust-Authorization-Id",envelope.binding.authorization_id.to_string()).header("X-AgentTrust-Authorization-Digest",&envelope.binding.authorization_digest)
            .header("X-AgentTrust-Policy-Decision-Digest",&envelope.binding.policy_decision_digest).header("X-AgentTrust-Authorization-Evidence-Ref",&envelope.binding.authorization_evidence_ref)
            .header("X-AgentTrust-Authorization-Evidence-Digest",&envelope.binding.authorization_evidence_digest).header("X-AgentTrust-Ledger-Execution-Id",envelope.binding.ledger_execution_id.to_string())
            .header("X-AgentTrust-Ledger-Entry-Id",envelope.binding.ledger_event_id.to_string()).header("X-AgentTrust-Ledger-Entry-Digest",&envelope.binding.ledger_event_digest)
            .header("X-AgentTrust-Fence-Digest",&envelope.binding.fence_digest).header("X-AgentTrust-Request-Digest",request_digest)
            .json(envelope).send().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        if !response.status().is_success()||response.content_length().is_some_and(|length|length>1_048_576){return Err(DomainAuthorityError::DependencyUnavailable);}
        let bytes=read_bounded_body(response,1_048_576).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;if bytes.is_empty(){return Err(DomainAuthorityError::DependencyUnavailable);}
        serde_json::from_slice(&bytes).map_err(|_|DomainAuthorityError::DependencyUnavailable)
    }
    async fn deliver_evidence(&self,tenant_id:Uuid,idempotency_key:&str,payload:&serde_json::Value,payload_digest:&str)->Result<AuthorityEvidenceDelivery,DomainAuthorityError>{
        let tenant_string=tenant_id.to_string();
        if payload.get("tenant_id").and_then(serde_json::Value::as_str)!=Some(tenant_string.as_str())||!digest(payload_digest){return Err(DomainAuthorityError::ReceiptInvalid);}
        let task_id=Uuid::parse_str(payload_string(payload,"task_id",36)?).map_err(|_|DomainAuthorityError::ReceiptInvalid)?;
        let event_id=Uuid::parse_str(payload_string(payload,"event_id",36)?).map_err(|_|DomainAuthorityError::ReceiptInvalid)?;
        let ledger_execution_id=Uuid::parse_str(payload_string(payload,"ledger_execution_id",36)?).map_err(|_|DomainAuthorityError::ReceiptInvalid)?;
        let ledger_event_id=Uuid::parse_str(payload_string(payload,"ledger_event_id",36)?).map_err(|_|DomainAuthorityError::ReceiptInvalid)?;
        let action_hash=payload_string(payload,"action_hash",64)?;let ledger_event_digest=payload_string(payload,"ledger_event_digest",64)?;let fence_digest=payload_string(payload,"fence_digest",64)?;
        let policy_decision_id=payload_string(payload,"policy_decision_id",256)?;let policy_decision_digest=payload_string(payload,"policy_decision_digest",64)?;
        let authorization_evidence_ref=payload_string(payload,"authorization_evidence_ref",2048)?;let authorization_evidence_digest=payload_string(payload,"authorization_evidence_digest",64)?;
        if [action_hash,ledger_event_digest,fence_digest,policy_decision_digest,authorization_evidence_digest].into_iter().any(|value|!digest(value)){return Err(DomainAuthorityError::ReceiptInvalid);}
        let occurred_at=parse_evidence_time(payload,"evidence_occurred_at")?;let requested_at=parse_evidence_time(payload,"evidence_requested_at")?;
        if occurred_at>requested_at+chrono::Duration::minutes(1)||requested_at>chrono::Utc::now()+chrono::Duration::minutes(1){return Err(DomainAuthorityError::ReceiptInvalid);}
        let actor=payload_string(payload,"actor_subject",512)?;let trace=payload_string(payload,"trace_id",256)?;let span=payload_string(payload,"command_id",256)?;
        let request=AuthorityEvidenceEventRequest{schema_version:AUTHORITY_EVIDENCE_EVENT_REQUEST_SCHEMA_VERSION.into(),tenant_id:TenantId(tenant_id.to_string()),task_id:TaskId(task_id.to_string()),authority_event_id:event_id.to_string(),idempotency_key:IdempotencyKey(idempotency_key.into()),source_kind:AuthorityEvidenceSourceKind::GovernedAction,
            control_binding:Some(AuthorityEvidenceControlBinding{action_hash:ActionHash(action_hash.into()),ledger_execution_id:ExecutionId(ledger_execution_id.to_string()),ledger_event_id:ledger_event_id.to_string(),ledger_event_digest:ledger_event_digest.into(),fence_digest:fence_digest.into(),policy_decision_id:policy_decision_id.into(),policy_decision_digest:policy_decision_digest.into(),authorization_evidence_ref:authorization_evidence_ref.into(),authorization_evidence_digest:authorization_evidence_digest.into()}),
            event:EvidenceEventDraft{schema_version:EVIDENCE_SCHEMA_VERSION.into(),tenant_id:TenantId(tenant_id.to_string()),task_id:TaskId(task_id.to_string()),event_type:EvidenceEventType::StateTransition,actor_subject:actor.into(),source_service:self.evidence_client_identity.clone(),trace_id:trace.into(),span_id:span.into(),payload_hash:payload_digest.into(),safe_summary:"Domain Runtime authority outcome persisted".into(),artifact_refs:Vec::new(),occurred_at},requested_at};
        let response=self.client.post(self.evidence.endpoint.join("v1/evidence/authority-events").map_err(|_|DomainAuthorityError::ConfigurationInvalid)?)
            .bearer_auth(read_token(&self.evidence.token_file)?).header("X-AgentTrust-Tenant-Id",tenant_id.to_string()).header("Idempotency-Key",idempotency_key)
            .header("X-AgentTrust-Authority-Event-Id",event_id.to_string()).header("X-AgentTrust-Payload-Digest",payload_digest).json(&request).send().await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        if !response.status().is_success()||response.content_length().is_some_and(|length|length>262_144){return Err(DomainAuthorityError::DependencyUnavailable);}let bytes=read_bounded_body(response,262_144).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        if bytes.is_empty()||bytes.len()>262_144{return Err(DomainAuthorityError::DependencyUnavailable);}let receipt:SignedAuthorityEvidenceReceipt=serde_json::from_slice(&bytes).map_err(|_|DomainAuthorityError::DependencyUnavailable)?;
        self.evidence_keyring.verify(&receipt,&request,payload_digest,&self.evidence_client_identity).map_err(|_|DomainAuthorityError::ReceiptInvalid)
    }
    async fn ready(&self)->bool{dependency_ready(&self.client,&self.coordinator).await&&dependency_ready(&self.client,&self.evidence).await}
}

async fn dependency_ready(client:&reqwest::Client,dependency:&SupplyDependency)->bool{let Ok(token)=read_token(&dependency.token_file)else{return false;};let Ok(url)=dependency.endpoint.join("ready")else{return false;};let Ok(response)=client.get(url).bearer_auth(token).send().await else{return false;};if !response.status().is_success()||response.content_length().is_some_and(|value|value>4096){return false;}let Ok(bytes)=read_bounded_body(response,4_096).await else{return false;};!bytes.is_empty()&&serde_json::from_slice::<DependencyReadiness>(&bytes).is_ok_and(|value|value.ready&&value.schema_version==dependency.readiness_schema)}

pub fn router(authority:DomainRuntimeAuthority,tokens:Arc<DomainTokenAuthorizer>,review_producer:Arc<HttpDomainRuntimePort>)->Router{
    Router::new().route("/ready",get(data_ready))
        .route("/v1/domain-runtime/executions",post(execute))
        .route("/v1/domain-runtime/approval-review-evidence",post(issue_approval_review_evidence))
        .route("/v1/authoritative/domain-runtime/executions",get(authoritative_state))
        .route("/v1/domain-runtime/recoveries/{tenant_id}",post(recover))
        .layer(DefaultBodyLimit::max(1_048_576)).layer(TimeoutLayer::new(Duration::from_secs(60))).with_state(ApiState{authority,tokens,review_producer})
}
async fn data_ready(State(state):State<ApiState>)->Result<Json<serde_json::Value>,ApiError>{ready(&state.authority).await}
async fn execute(State(state):State<ApiState>,Extension(ExactPeerIdentity(peer)):Extension<ExactPeerIdentity>,headers:HeaderMap,Json(body):Json<DomainExecutionEnvelope>)->Result<Json<DomainExecutionResult>,ApiError>{
    exact_headers(&headers,&body)?;let subject=state.tokens.authorize(&peer,body.binding.tenant_id,DOMAIN_EXECUTE_SCOPE,&headers)?;
    if subject!=body.actor_subject{return Err(DomainAuthorityError::PrincipalDenied.into());}Ok(Json(state.authority.execute(body).await?))
}
async fn issue_approval_review_evidence(State(state):State<ApiState>,Extension(ExactPeerIdentity(peer)):Extension<ExactPeerIdentity>,headers:HeaderMap,Json(body):Json<ApprovalReviewEvidenceIssueRequest>)->Result<Json<ApprovalReviewEvidence>,ApiError>{
    body.material.validate().map_err(|_|DomainAuthorityError::RequestInvalid)?;
    let tenant=Uuid::parse_str(&body.material.tenant_id).map_err(|_|DomainAuthorityError::RequestInvalid)?;
    let payload_digest=body.material.payload_digest().map_err(|_|DomainAuthorityError::RequestInvalid)?;
    if tenant.to_string()!=body.material.tenant_id
        ||single_header(&headers,"x-agenttrust-tenant-id")!=Some(body.material.tenant_id.as_str())
        ||single_header(&headers,"idempotency-key")!=Some(body.idempotency_key.as_str())
        ||single_header(&headers,"x-agenttrust-authority-event-id")!=Some(body.request_id.as_str())
        ||single_header(&headers,"x-agenttrust-payload-digest")!=Some(payload_digest.as_str()){
        return Err(DomainAuthorityError::RequestInvalid.into());
    }
    let subject=state.tokens.authorize(&peer,tenant,DOMAIN_APPROVAL_REVIEW_EVIDENCE_SCOPE,&headers)?;
    if subject!=body.actor_subject{return Err(DomainAuthorityError::PrincipalDenied.into());}
    Ok(Json(state.review_producer.issue_approval_review_evidence(&body).await?))
}
#[derive(Debug,Deserialize)]#[serde(deny_unknown_fields)]struct StateQuery{tenant_id:Uuid,limit:Option<u16>,cursor:Option<String>}
async fn authoritative_state(State(state):State<ApiState>,Extension(ExactPeerIdentity(peer)):Extension<ExactPeerIdentity>,headers:HeaderMap,Query(query):Query<StateQuery>)->Result<Json<AuthoritativeDomainExecutionPage>,ApiError>{
    if required_header(&headers,"x-agenttrust-tenant-id")?!=query.tenant_id.to_string(){return Err(DomainAuthorityError::PrincipalDenied.into());}
    state.tokens.authorize(&peer,query.tenant_id,DOMAIN_READ_SCOPE,&headers)?;Ok(Json(state.authority.authoritative_state(query.tenant_id,i64::from(query.limit.unwrap_or(50)),query.cursor.as_deref()).await?))
}
async fn recover(State(state):State<ApiState>,Extension(ExactPeerIdentity(peer)):Extension<ExactPeerIdentity>,AxumPath(tenant):AxumPath<Uuid>,headers:HeaderMap)->Result<Json<serde_json::Value>,ApiError>{
    if required_header(&headers,"x-agenttrust-tenant-id")?!=tenant.to_string(){return Err(DomainAuthorityError::PrincipalDenied.into());}
    state.tokens.authorize(&peer,tenant,DOMAIN_RECOVER_SCOPE,&headers)?;let marked=state.authority.recover_expired(tenant,100).await?;Ok(Json(serde_json::json!({"schema_version":"agenttrust.domain-runtime-recovery.v1","marked_unknown":marked})))
}
fn exact_headers(headers:&HeaderMap,body:&DomainExecutionEnvelope)->Result<(),DomainAuthorityError>{
    let expected=[("x-agenttrust-tenant-id",body.binding.tenant_id.to_string()),("idempotency-key",body.binding.idempotency_key.clone()),("x-agenttrust-execution-id",body.execution_id.to_string()),("x-agenttrust-action-id",body.command_id.to_string()),("x-agenttrust-authorization-id",body.binding.authorization_id.to_string()),("x-agenttrust-authorization-digest",body.binding.authorization_digest.clone()),("x-agenttrust-policy-decision-id",body.binding.policy_decision_id.clone()),("x-agenttrust-policy-decision-digest",body.binding.policy_decision_digest.clone()),("x-agenttrust-authorization-evidence-ref",body.binding.authorization_evidence_ref.clone()),("x-agenttrust-authorization-evidence-digest",body.binding.authorization_evidence_digest.clone()),("x-agenttrust-ledger-execution-id",body.binding.ledger_execution_id.to_string()),("x-agenttrust-ledger-entry-id",body.binding.ledger_event_id.to_string()),("x-agenttrust-ledger-entry-digest",body.binding.ledger_event_digest.clone()),("x-agenttrust-fence-digest",body.binding.fence_digest.clone()),("x-agenttrust-resource-version",body.binding.resource_version.to_string()),("x-agenttrust-trace-id",body.binding.trace_id.clone())];
    if expected.into_iter().any(|(name,value)|single_header(headers,name)!=Some(value.as_str())){return Err(DomainAuthorityError::RequestInvalid);}Ok(())
}
pub async fn serve(config:DomainServerConfig,application:Router,authority:DomainRuntimeAuthority)->Result<(),DomainAuthorityError>{
    if !(config.management_address.ip().is_loopback()||config.management_address.ip().is_unspecified())||config.data_address==config.management_address{return Err(DomainAuthorityError::ConfigurationInvalid);}
    let acceptor=ExactPeerIdentityAcceptor::new(&config.tls_ca_file,&config.tls_certificate_file,&config.tls_private_key_file,config.allowed_client_identities).map_err(|_|DomainAuthorityError::ConfigurationInvalid)?;
    let listener=tokio::net::TcpListener::bind(config.management_address).await.map_err(|_|DomainAuthorityError::ConfigurationInvalid)?;
    let management=Router::new().route("/live",get(management_live)).route("/ready",get(management_ready)).with_state(ReadyState{authority:authority.clone()});
    let data=async move{axum_server::bind(config.data_address).acceptor(acceptor).serve(application.into_make_service()).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)};
    let management=async move{axum::serve(listener,management).await.map_err(|_|DomainAuthorityError::DependencyUnavailable)};tokio::try_join!(data,management)?;Ok(())
}
async fn management_live()->Json<serde_json::Value>{Json(serde_json::json!({"schema_version":DOMAIN_READINESS_SCHEMA,"live":true}))}
async fn management_ready(State(state):State<ReadyState>)->Result<Json<serde_json::Value>,ApiError>{ready(&state.authority).await}
async fn ready(authority:&DomainRuntimeAuthority)->Result<Json<serde_json::Value>,ApiError>{if !authority.ready().await{return Err(DomainAuthorityError::DependencyUnavailable.into());}Ok(Json(serde_json::json!({"schema_version":DOMAIN_READINESS_SCHEMA,"ready":true,"database_ready":true,"executor_ready":true,"evidence_ready":true})))}
struct ApiError(DomainAuthorityError);impl From<DomainAuthorityError> for ApiError{fn from(value:DomainAuthorityError)->Self{Self(value)}}
impl IntoResponse for ApiError{fn into_response(self)->Response{let status=match self.0{DomainAuthorityError::PrincipalDenied=>StatusCode::UNAUTHORIZED,DomainAuthorityError::RequestInvalid|DomainAuthorityError::Contract(_)|DomainAuthorityError::ReceiptInvalid=>StatusCode::BAD_REQUEST,DomainAuthorityError::PackInactive|DomainAuthorityError::ApprovalInvalid|DomainAuthorityError::SupervisionInvalid|DomainAuthorityError::IdempotencyConflict|DomainAuthorityError::StateConflict=>StatusCode::CONFLICT,DomainAuthorityError::OutcomeUnknown|DomainAuthorityError::DependencyUnavailable|DomainAuthorityError::ConfigurationInvalid=>StatusCode::SERVICE_UNAVAILABLE};(status,Json(serde_json::json!({"schema_version":"agenttrust.domain-runtime-error.v1","error":self.0.code()}))).into_response()}}
fn required_header<'a>(headers:&'a HeaderMap,name:&'static str)->Result<&'a str,DomainAuthorityError>{single_header(headers,name).ok_or(DomainAuthorityError::RequestInvalid)}
fn single_header<'a>(headers:&'a HeaderMap,name:&'static str)->Option<&'a str>{let mut values=headers.get_all(name).iter();let value=values.next()?.to_str().ok()?;if values.next().is_some(){return None;}Some(value)}
fn read_private(path:&Path,minimum:u64,maximum:u64)->Result<Vec<u8>,DomainAuthorityError>{let metadata=std::fs::symlink_metadata(path).map_err(|_|DomainAuthorityError::ConfigurationInvalid)?;if !path.is_absolute()||!metadata.file_type().is_file()||metadata.file_type().is_symlink()||metadata.len()<minimum||metadata.len()>maximum{return Err(DomainAuthorityError::ConfigurationInvalid);}#[cfg(unix)]{use std::os::unix::fs::MetadataExt;let mode=metadata.mode()&0o777;let uid=nix::unistd::Uid::effective().as_raw();let gid=nix::unistd::Gid::effective().as_raw();let allowed=0o400|if metadata.gid()==gid{0o040}else{0};let readable=(metadata.uid()==uid&&mode&0o400!=0)||(metadata.gid()==gid&&mode&0o040!=0);if metadata.nlink()!=1||!readable||mode&!allowed!=0{return Err(DomainAuthorityError::ConfigurationInvalid);}}std::fs::read(path).map_err(|_|DomainAuthorityError::ConfigurationInvalid)}
fn constant_time_equal(first:&str,second:&str)->bool{let key=hmac::Key::new(hmac::HMAC_SHA256,b"agenttrust-domain-token-compare-v1");let tag=hmac::sign(&key,second.as_bytes());hmac::verify(&key,first.as_bytes(),tag.as_ref()).is_ok()}
fn canonical_uuid(value:&str)->bool{Uuid::parse_str(value).is_ok_and(|parsed|parsed.to_string()==value)}
fn identifier(value:&str,maximum:usize)->bool{!value.is_empty()&&value.len()<=maximum&&!value.chars().any(char::is_control)}
fn digest(value:&str)->bool{value.len()==64&&value.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte))}
fn payload_string<'a>(payload:&'a serde_json::Value,key:&str,maximum:usize)->Result<&'a str,DomainAuthorityError>{payload.get(key).and_then(serde_json::Value::as_str).filter(|value|identifier(value,maximum)).ok_or(DomainAuthorityError::ReceiptInvalid)}
fn parse_evidence_time(payload:&serde_json::Value,key:&str)->Result<chrono::DateTime<chrono::Utc>,DomainAuthorityError>{let value=payload_string(payload,key,64)?;chrono::DateTime::parse_from_rfc3339(value).map(|parsed|parsed.with_timezone(&chrono::Utc)).map_err(|_|DomainAuthorityError::ReceiptInvalid)}
fn read_token(path:&Path)->Result<String,DomainAuthorityError>{let raw=read_private(path,16,8194)?;let value=std::str::from_utf8(&raw).map_err(|_|DomainAuthorityError::ConfigurationInvalid)?;let token=value.trim_end_matches(['\r','\n']);if !(16..=8192).contains(&token.len())||token.bytes().any(|byte|!byte.is_ascii_graphic())||value.len().saturating_sub(token.len())>2{return Err(DomainAuthorityError::ConfigurationInvalid);}Ok(token.to_string())}
fn valid_https_root(value:&url::Url)->bool{value.scheme()=="https"&&value.host_str().is_some()&&value.username().is_empty()&&value.password().is_none()&&value.path()=="/"&&value.query().is_none()&&value.fragment().is_none()}
