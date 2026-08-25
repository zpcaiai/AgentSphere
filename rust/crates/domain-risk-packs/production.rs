//! Shared production plugin contract for Batch 23-27.
//!
//! Domain code supplies typed validation and evaluation only. It cannot weaken identity, PEP,
//! Sandbox, ToolProxy, ledger, fence, kill-switch or Evidence controls. The common production
//! executor validates this envelope before dispatching any domain tool.

use crate::{coding, energy, industrial, medical, sensitive};
use agent_trust_action_ir::{CanonicalAction, hash as action_hash};
use agent_trust_contracts::EffectClass;
use agent_trust_pack_supply_chain::{ArtifactVerifier, DomainPackManifest, PackSdk};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const DOMAIN_EXECUTION_SCHEMA: &str = "agenttrust.domain-execution.v1";
pub const DOMAIN_BINDING_SCHEMA: &str = "agenttrust.domain-control-binding.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DomainKind { Coding, Industrial, Energy, Medical, Sensitive }

impl DomainKind {
    pub fn pack_id(self) -> &'static str {
        match self { Self::Coding=>"coding",Self::Industrial=>"industrial",Self::Energy=>"energy",Self::Medical=>"medical",Self::Sensitive=>"sensitive-interaction" }
    }
    fn expected_manifest(self)->DomainPackManifest {
        match self { Self::Coding=>coding::manifest(),Self::Industrial=>industrial::manifest(),Self::Energy=>energy::manifest(),Self::Medical=>medical::manifest(),Self::Sensitive=>sensitive::manifest() }
    }
}

#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,PartialOrd,Ord)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum DeploymentStage { Simulator, DigitalTwin, ReadOnly, Shadow, LimitedWrite }

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct DomainControlBinding {
    pub schema_version:String,
    pub tenant_id:Uuid,
    pub authorization_id:Uuid,
    pub authorization_digest:String,
    pub policy_decision_id:String,
    pub policy_decision_digest:String,
    pub authorization_evidence_ref:String,
    pub authorization_evidence_digest:String,
    pub ledger_execution_id:Uuid,
    pub ledger_event_id:Uuid,
    pub ledger_event_digest:String,
    pub fence_digest:String,
    pub resource_version:u64,
    pub idempotency_key:String,
    pub trace_id:String,
}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpertApproval {
    pub approval_id:Uuid,
    pub approval_set_id:Uuid,
    pub domain:DomainKind,
    pub operation:String,
    pub resource_key:String,
    pub before_digest:String,
    pub target_digest:String,
    pub resource_version:u64,
    pub reviewer_subject:String,
    pub reviewer_role:String,
    pub qualification_digest:String,
    pub principal_assertion_digest:String,
    pub evidence_ref:String,
    pub evidence_digest:String,
    pub approved_at:DateTime<Utc>,
    pub expires_at:DateTime<Utc>,
}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct PhysicalSupervisionGrant {
    pub supervision_id:Uuid,
    pub approval_set_id:Uuid,
    pub domain:DomainKind,
    pub stage:DeploymentStage,
    pub resource_key:String,
    pub before_digest:String,
    pub target_digest:String,
    pub resource_version:u64,
    pub supervisor_subject:String,
    pub supervisor_assertion_digest:String,
    pub evidence_ref:String,
    pub evidence_digest:String,
    pub issued_at:DateTime<Utc>,
    pub expires_at:DateTime<Utc>,
    pub consumed:bool,
}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DomainExecutionEnvelope {
    pub schema_version:String,
    pub execution_id:Uuid,
    pub command_id:Uuid,
    pub actor_subject:String,
    pub domain:DomainKind,
    pub pack_manifest:DomainPackManifest,
    pub canonical_action:CanonicalAction,
    pub binding:DomainControlBinding,
    pub operation:String,
    pub resource_key:String,
    pub before_digest:String,
    pub target_digest:String,
    pub deployment_stage:Option<DeploymentStage>,
    pub expert_approvals:Vec<ExpertApproval>,
    pub physical_supervision:Option<PhysicalSupervisionGrant>,
    pub safe_command:Value,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct CodingCommand{
    schema_version:String,repository_ref:String,base_commit:String,branch:String,paths:Vec<String>,
    command_template_id:String,requested_network:Vec<String>,dependency_lock_digest:String,
    rollback_ref:String,effect_class:EffectClass,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct IndustrialCommand{
    schema_version:String,asset_id:Uuid,point_id:String,stage:DeploymentStage,expected_version:String,
    target_value:f64,before_digest:String,target_digest:String,prepared_digest:String,
    interlock_digest:String,alarm_digest:String,approval_set_id:Option<Uuid>,supervision_id:Option<Uuid>,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct IndustrialOperationCommand{
    schema_version:String,asset_id:Uuid,stage:DeploymentStage,endpoint_manifest_digest:String,
    observed_resource_version:u64,state_digest:String,outcome_digest:String,maximum_age_ms:u64,
    scenario_digest:Option<String>,safe_stop_profile_digest:Option<String>,reason_code:Option<String>,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct EnergyCommand{
    schema_version:String,asset_id:Uuid,algorithm:String,algorithm_manifest_digest:String,stage:DeploymentStage,
    setpoints_kw:Vec<f64>,confidence:f64,out_of_distribution:bool,requires_shadow_validation:bool,
    constraint_digest:String,forecast_digest:String,fallback_controller_digest:String,fallback_reason:Option<String>,
    approval_set_id:Option<Uuid>,supervision_id:Option<Uuid>,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct EnergyObservationCommand{
    schema_version:String,asset_id:Uuid,stage:DeploymentStage,endpoint_manifest_digest:String,
    observed_resource_version:u64,telemetry_digest:String,output_digest:String,
    model_manifest_digest:Option<String>,forecast_valid_until:Option<DateTime<Utc>>,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct MedicalReviewCommand{
    schema_version:String,tenant_id:Uuid,review_id:Uuid,patient_ref_hash:String,care_relationship_digest:String,
    recommendation_digest:String,clinical_evidence_digest:String,model_manifest_digest:String,risk_level:String,
    reviewer_subject:String,reviewer_role:String,reviewer_qualification_digest:String,principal_assertion_digest:String,
    decision:String,evidence_ref:String,evidence_digest:String,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct MedicalAssistCommand{
    schema_version:String,tenant_id:Uuid,patient_ref_hash:String,care_relationship_digest:String,
    purpose_of_use:String,requested_fields:Vec<String>,data_policy_decision_digest:String,
    residency_decision_digest:String,private_deployment:bool,model_manifest_digest:String,
    clinical_evidence_digest:String,output_digest:String,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct SensitiveHandoffCommand{
    schema_version:String,tenant_id:Uuid,handoff_id:Uuid,conversation_hash:String,region_code:String,risk_level:String,
    destination_type:String,dynamic_region_directory_digest:String,minimum_safe_context_digest:String,
    ordinary_agent_paused:bool,status:String,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct SensitiveInteractionCommand{
    schema_version:String,tenant_id:Uuid,conversation_hash:String,consent_digest:String,
    relationship_boundary_digest:String,source_snapshot_digest:String,minimum_safe_context_digest:String,
    risk_level:String,ordinary_agent_paused:bool,citation_digests:Vec<String>,approval_set_id:Option<Uuid>,
}

pub struct ProductionDomainPackContract;

impl ProductionDomainPackContract {
    pub fn validate_manifest(
        domain:DomainKind,
        manifest:&DomainPackManifest,
        verifier:&ArtifactVerifier,
    )->Result<(),DomainProductionError>{
        PackSdk::validate(manifest).map_err(|_|DomainProductionError::PackInvalid)?;
        verifier.verify_pack(manifest).map_err(|_|DomainProductionError::PackInvalid)?;
        let expected=domain.expected_manifest();
        if manifest.pack_id!=domain.pack_id() || manifest.version!=expected.version
            ||manifest.publisher_identity!=expected.publisher_identity
            || manifest.permissions.secret_scopes.len()>0
            || manifest.permissions.network_destinations!=expected.permissions.network_destinations
            || manifest.permissions.data_classes!=expected.permissions.data_classes
            || manifest.permissions.executors!=expected.permissions.executors
            || manifest.permissions.approval_scopes!=expected.permissions.approval_scopes
            || normalized_tools(&manifest.tools)!=normalized_tools(&expected.tools)
            || manifest.policy_bundle_ref!=expected.policy_bundle_ref
            || manifest.evaluator_ref!=expected.evaluator_ref
            || manifest.artifact_refs!=expected.artifact_refs
            || manifest.compensation_refs!=expected.compensation_refs
            || manifest.threat_scenario_refs!=expected.threat_scenario_refs
            || manifest.compatibility!=expected.compatibility
            || !immutable_reference(&manifest.policy_bundle_ref,"policy")
            || !immutable_reference(&manifest.evaluator_ref,"evaluator")
            || manifest.artifact_refs.iter().any(|value|!immutable_reference(value,"artifact"))
        {return Err(DomainProductionError::PackInvalid);}
        Ok(())
    }

    pub fn authorize(
        envelope:&DomainExecutionEnvelope,
        verifier:&ArtifactVerifier,
        now:DateTime<Utc>,
    )->Result<String,DomainProductionError>{
        let expected_current_state_version=envelope.binding.resource_version.saturating_sub(1).to_string();
        if envelope.schema_version!=DOMAIN_EXECUTION_SCHEMA
            || envelope.binding.schema_version!=DOMAIN_BINDING_SCHEMA
            || envelope.execution_id.is_nil()||envelope.command_id.is_nil()||envelope.binding.tenant_id.is_nil()
            || envelope.binding.authorization_id.is_nil()||envelope.binding.ledger_execution_id.is_nil()||envelope.binding.ledger_event_id.is_nil()
            || envelope.binding.resource_version==0
            || !identifier(&envelope.actor_subject,512)
            || envelope.actor_subject!=envelope.canonical_action.agent.owner_subject
            || envelope.command_id.to_string()!=envelope.canonical_action.action_id.0
            || envelope.binding.tenant_id.to_string()!=envelope.canonical_action.agent.tenant_id.0
            || envelope.binding.tenant_id.to_string()!=envelope.canonical_action.resource.tenant_id.0
            || envelope.binding.tenant_id.to_string()!=envelope.canonical_action.environment.tenant_id.0
            || envelope.canonical_action.environment.deployment!="production"
            || envelope.canonical_action.resource.locator!=envelope.resource_key
            || envelope.canonical_action.intent.operation!=envelope.operation
            // Domain operation and executor profile are a single signed capability. Without
            // this equality an irreversible tool could be paired with a benign operation name
            // and evade the operation-specific policy gate below.
            || envelope.canonical_action.tool.tool_id.0!=envelope.operation
            || envelope.canonical_action.current_state_version.as_deref()!=Some(expected_current_state_version.as_str())
            || envelope.canonical_action.payload.type_id!="domain-pack.command.v1"
            || envelope.canonical_action.payload.schema_version!="1"
            || envelope.canonical_action.tool.tool_version.0!=envelope.pack_manifest.version
            || !Uuid::parse_str(&envelope.canonical_action.task_id.0).is_ok_and(|value|value.to_string()==envelope.canonical_action.task_id.0)
            || envelope.canonical_action.requested_at>now+Duration::minutes(1)
            || envelope.canonical_action.requested_at<now-Duration::minutes(10)
            || !identifier(&envelope.operation,128)||!identifier(&envelope.resource_key,1024)
            || !digest(&envelope.before_digest)||!digest(&envelope.target_digest)
            || !digest(&envelope.binding.authorization_digest)||!digest(&envelope.binding.policy_decision_digest)
            || !digest(&envelope.binding.authorization_evidence_digest)||!digest(&envelope.binding.ledger_event_digest)
            || !digest(&envelope.binding.fence_digest)||!idempotency(&envelope.binding.idempotency_key)
            || !identifier(&envelope.binding.policy_decision_id,256)||!reference(&envelope.binding.authorization_evidence_ref)
            || !identifier(&envelope.binding.trace_id,256)
            || envelope.canonical_action.extensions.get("x-policy-decision-digest")!=Some(&Value::String(envelope.binding.policy_decision_digest.clone()))
            || envelope.canonical_action.extensions.get("x-authorization-evidence-digest")!=Some(&Value::String(envelope.binding.authorization_evidence_digest.clone()))
            || envelope.canonical_action.extensions.get("x-ledger-event-digest")!=Some(&Value::String(envelope.binding.ledger_event_digest.clone()))
            || envelope.canonical_action.extensions.get("x-execution-fence-digest")!=Some(&Value::String(envelope.binding.fence_digest.clone()))
            || envelope.canonical_action.extensions.get("x-domain-command-digest")!=Some(&Value::String(safe_digest(&envelope.safe_command)?))
            || envelope.canonical_action.extensions.get("x-domain-pack-manifest-digest")!=Some(&Value::String(envelope.pack_manifest.digest.clone()))
            || envelope.canonical_action.extensions.get("x-domain-before-digest")!=Some(&Value::String(envelope.before_digest.clone()))
            || envelope.canonical_action.extensions.get("x-domain-target-digest")!=Some(&Value::String(envelope.target_digest.clone()))
            || json_limits(&envelope.safe_command,0).is_err()
        {return Err(DomainProductionError::BindingInvalid);}
        Self::validate_manifest(envelope.domain,&envelope.pack_manifest,verifier)?;
        let tool=envelope.pack_manifest.tools.iter().find(|tool|tool.tool_id==envelope.canonical_action.tool.tool_id.0)
            .ok_or(DomainProductionError::ToolDenied)?;
        validate_typed_command(envelope,tool)?;
        let limited_physical_write=matches!(envelope.domain,DomainKind::Industrial|DomainKind::Energy)
            &&envelope.deployment_stage==Some(DeploymentStage::LimitedWrite)
            &&(envelope.operation.ends_with("commit")||envelope.operation.ends_with("restore")||envelope.operation.ends_with("activate"));
        if envelope.physical_supervision.is_some()!=limited_physical_write
            ||(!tool.approval_required&&!limited_physical_write&&!envelope.expert_approvals.is_empty()){
            return Err(DomainProductionError::SupervisionRequired);
        }
        if tool.approval_required {
            let _=validate_approvals(envelope,now,1)?;
        }
        match envelope.domain {
            DomainKind::Coding=>authorize_coding(envelope,tool.effect_class)?,
            DomainKind::Industrial|DomainKind::Energy=>authorize_physical(envelope,now)?,
            DomainKind::Medical=>authorize_medical(envelope,now)?,
            DomainKind::Sensitive=>authorize_sensitive(envelope,now)?,
        }
        action_hash(&envelope.canonical_action).map_err(|_|DomainProductionError::BindingInvalid)
    }
}

fn validate_typed_command(envelope:&DomainExecutionEnvelope,tool:&agent_trust_pack_supply_chain::PackToolDefinition)->Result<(),DomainProductionError>{
    if envelope.safe_command.get("schema_version")!=Some(&Value::String(DOMAIN_PACKS_SCHEMA_VERSION.into())){
        return Err(DomainProductionError::CommandInvalid);
    }
    match envelope.domain{
        DomainKind::Coding=>{
            let command: CodingCommand=serde_json::from_value(envelope.safe_command.clone()).map_err(|_|DomainProductionError::CommandInvalid)?;
            let mut paths=BTreeSet::new();let mut network=BTreeSet::new();
            if command.schema_version!=DOMAIN_PACKS_SCHEMA_VERSION||envelope.deployment_stage.is_some()||command.repository_ref!=envelope.resource_key
                ||!https_reference(&command.repository_ref)||!hex_length(&command.base_commit,&[40,64])
                ||!command.branch.starts_with("agent/")||command.branch.len()>486||command.paths.is_empty()||command.paths.len()>10_000
                ||command.paths.iter().any(|path|!paths.insert(path.as_str())||unsafe_repository_path(path))
                ||command.command_template_id!=tool.executor_template||command.command_template_id.to_ascii_lowercase().contains("shell")
                ||command.requested_network.iter().any(|value|!network.insert(value.as_str())||!identifier(value,256))||!network.is_empty()
                ||!digest(&command.dependency_lock_digest)||!reference(&command.rollback_ref)||command.effect_class!=tool.effect_class{
                return Err(DomainProductionError::CommandInvalid);
            }
        }
        DomainKind::Industrial if matches!(envelope.operation.as_str(),"industrial.setpoint_prepare"|"industrial.setpoint_commit")=>{
            let command:IndustrialCommand=serde_json::from_value(envelope.safe_command.clone()).map_err(|_|DomainProductionError::CommandInvalid)?;
            let current=envelope.binding.resource_version.saturating_sub(1).to_string();
            let limited_write=command.stage==DeploymentStage::LimitedWrite&&envelope.operation=="industrial.setpoint_commit";
            let approval_matches=command.approval_set_id.is_some_and(|set|envelope.expert_approvals.iter().any(|approval|approval.approval_set_id==set));
            if command.schema_version!=DOMAIN_PACKS_SCHEMA_VERSION||!identifier(&command.point_id,512)
                ||envelope.resource_key!=format!("industrial:{}:{}",command.asset_id,command.point_id)||envelope.deployment_stage!=Some(command.stage)
                ||!matches!(command.stage,DeploymentStage::Simulator|DeploymentStage::DigitalTwin|DeploymentStage::Shadow|DeploymentStage::LimitedWrite)
                ||command.expected_version!=current||!command.target_value.is_finite()||command.before_digest!=envelope.before_digest
                ||command.target_digest!=envelope.target_digest||[&command.prepared_digest,&command.interlock_digest,&command.alarm_digest].into_iter().any(|value|!digest(value))
                ||!approval_matches
                ||(limited_write&&envelope.physical_supervision.as_ref().is_none_or(|grant|Some(grant.approval_set_id)!=command.approval_set_id||Some(grant.supervision_id)!=command.supervision_id))
                ||(!limited_write&&command.supervision_id.is_some()){
                return Err(DomainProductionError::CommandInvalid);
            }
        }
        DomainKind::Industrial if matches!(envelope.operation.as_str(),"industrial.telemetry_read"|"industrial.simulation_run"|"industrial.operation_stop")=>{
            let command:IndustrialOperationCommand=serde_json::from_value(envelope.safe_command.clone()).map_err(|_|DomainProductionError::CommandInvalid)?;
            let current=envelope.binding.resource_version.saturating_sub(1);
            let stage_valid=match envelope.operation.as_str(){
                "industrial.telemetry_read"=>matches!(command.stage,DeploymentStage::ReadOnly|DeploymentStage::Shadow),
                "industrial.simulation_run"=>matches!(command.stage,DeploymentStage::Simulator|DeploymentStage::DigitalTwin),
                "industrial.operation_stop"=>matches!(command.stage,DeploymentStage::Simulator|DeploymentStage::DigitalTwin|DeploymentStage::Shadow|DeploymentStage::LimitedWrite),
                _=>false,
            };
            let shape_valid=match envelope.operation.as_str(){
                "industrial.telemetry_read"=>command.scenario_digest.is_none()&&command.safe_stop_profile_digest.is_none()&&command.reason_code.is_none(),
                "industrial.simulation_run"=>command.scenario_digest.as_deref().is_some_and(digest)&&command.safe_stop_profile_digest.is_none()&&command.reason_code.is_none(),
                "industrial.operation_stop"=>command.scenario_digest.is_none()&&command.safe_stop_profile_digest.as_deref().is_some_and(digest)&&command.reason_code.as_deref().is_some_and(|value|identifier(value,128)),
                _=>false,
            };
            if command.schema_version!=DOMAIN_PACKS_SCHEMA_VERSION||envelope.resource_key!=format!("industrial:{}",command.asset_id)
                ||envelope.deployment_stage!=Some(command.stage)||command.observed_resource_version!=current
                ||command.state_digest!=envelope.before_digest||command.outcome_digest!=envelope.target_digest
                ||!digest(&command.endpoint_manifest_digest)||!(1..=300_000).contains(&command.maximum_age_ms)
                ||!stage_valid||!shape_valid{return Err(DomainProductionError::CommandInvalid);}
        }
        DomainKind::Energy if matches!(envelope.operation.as_str(),"energy.optimize_plan"|"energy.dispatch_prepare"|"energy.dispatch_commit"|"energy.fallback_activate")=>{
            let command:EnergyCommand=serde_json::from_value(envelope.safe_command.clone()).map_err(|_|DomainProductionError::CommandInvalid)?;
            let supervised_write=command.stage==DeploymentStage::LimitedWrite&&matches!(envelope.operation.as_str(),"energy.dispatch_commit"|"energy.fallback_activate");
            let approval_required=tool.approval_required||supervised_write;
            let approval_matches=command.approval_set_id.is_some_and(|set|envelope.expert_approvals.iter().any(|approval|approval.approval_set_id==set));
            if command.schema_version!=DOMAIN_PACKS_SCHEMA_VERSION||envelope.resource_key!=format!("energy:{}",command.asset_id)
                ||envelope.deployment_stage!=Some(command.stage)||!matches!(command.algorithm.as_str(),"MPC"|"RL"|"CBF"|"RULE")
                ||[&command.algorithm_manifest_digest,&command.constraint_digest,&command.forecast_digest,&command.fallback_controller_digest].into_iter().any(|value|!digest(value))
                ||command.setpoints_kw.is_empty()||command.setpoints_kw.len()>10_000||command.setpoints_kw.iter().any(|value|!value.is_finite())
                ||!command.confidence.is_finite()||!(0.0..=1.0).contains(&command.confidence)||!command.requires_shadow_validation
                ||(command.out_of_distribution||command.confidence<0.8)&&command.fallback_reason.as_deref().is_none_or(|value|!identifier(value,256))
                ||(approval_required&&!approval_matches)||(!approval_required&&command.approval_set_id.is_some())
                ||(supervised_write&&envelope.physical_supervision.as_ref().is_none_or(|grant|Some(grant.approval_set_id)!=command.approval_set_id||Some(grant.supervision_id)!=command.supervision_id))
                ||(!supervised_write&&command.supervision_id.is_some()){
                return Err(DomainProductionError::CommandInvalid);
            }
        }
        DomainKind::Energy if matches!(envelope.operation.as_str(),"energy.telemetry_read"|"energy.forecast_run")=>{
            let command:EnergyObservationCommand=serde_json::from_value(envelope.safe_command.clone()).map_err(|_|DomainProductionError::CommandInvalid)?;
            let forecast_shape=if envelope.operation=="energy.forecast_run"{
                command.model_manifest_digest.as_deref().is_some_and(digest)
                    &&command.forecast_valid_until.is_some_and(|until|until>envelope.canonical_action.requested_at&&until<=envelope.canonical_action.requested_at+Duration::days(7))
            }else{command.model_manifest_digest.is_none()&&command.forecast_valid_until.is_none()};
            if command.schema_version!=DOMAIN_PACKS_SCHEMA_VERSION||envelope.resource_key!=format!("energy:{}",command.asset_id)
                ||envelope.deployment_stage!=Some(command.stage)||!matches!(command.stage,DeploymentStage::ReadOnly|DeploymentStage::Shadow)
                ||command.observed_resource_version!=envelope.binding.resource_version.saturating_sub(1)
                ||command.telemetry_digest!=envelope.before_digest||command.output_digest!=envelope.target_digest
                ||!digest(&command.endpoint_manifest_digest)||!forecast_shape{return Err(DomainProductionError::CommandInvalid);}
        }
        DomainKind::Medical if envelope.operation=="medical.review_request"=>{
            let command:MedicalReviewCommand=serde_json::from_value(envelope.safe_command.clone()).map_err(|_|DomainProductionError::CommandInvalid)?;
            let reviewer_valid=envelope.expert_approvals.iter().any(|approval|
                approval.reviewer_subject==command.reviewer_subject&&approval.reviewer_role==command.reviewer_role
                &&approval.qualification_digest==command.reviewer_qualification_digest
                &&approval.principal_assertion_digest==command.principal_assertion_digest
                &&approval.evidence_ref==command.evidence_ref&&approval.evidence_digest==command.evidence_digest);
            if command.schema_version!=DOMAIN_PACKS_SCHEMA_VERSION||command.tenant_id!=envelope.binding.tenant_id||envelope.deployment_stage.is_some()
                ||envelope.resource_key!=format!("medical-patient:{}",command.patient_ref_hash)||command.care_relationship_digest!=envelope.before_digest
                ||command.recommendation_digest!=envelope.target_digest||[&command.patient_ref_hash,&command.clinical_evidence_digest,&command.model_manifest_digest,&command.reviewer_qualification_digest,&command.principal_assertion_digest,&command.evidence_digest].into_iter().any(|value|!digest(value))
                ||command.review_id.is_nil()||!identifier(&command.reviewer_subject,512)
                ||!matches!(command.risk_level.as_str(),"LOW"|"MEDIUM"|"HIGH"|"CRITICAL")
                ||!matches!(command.reviewer_role.as_str(),"CLINICIAN"|"PHYSICIAN"|"PHARMACIST"|"LICENSED_REVIEWER")
                ||!matches!(command.decision.as_str(),"APPROVED"|"REJECTED"|"ESCALATED")||!reference(&command.evidence_ref)
                ||(matches!(command.risk_level.as_str(),"HIGH"|"CRITICAL")&&!reviewer_valid){return Err(DomainProductionError::CommandInvalid);}
        }
        DomainKind::Medical if matches!(envelope.operation.as_str(),"medical.patient_context_read"|"medical.document_search"|"medical.summary_generate"|"medical.coding_suggest"|"medical.risk_flag")=>{
            let command:MedicalAssistCommand=serde_json::from_value(envelope.safe_command.clone()).map_err(|_|DomainProductionError::CommandInvalid)?;
            let mut fields=BTreeSet::new();
            if command.schema_version!=DOMAIN_PACKS_SCHEMA_VERSION||command.tenant_id!=envelope.binding.tenant_id||envelope.deployment_stage.is_some()
                ||envelope.resource_key!=format!("medical-patient:{}",command.patient_ref_hash)
                ||command.care_relationship_digest!=envelope.before_digest||command.output_digest!=envelope.target_digest
                ||command.requested_fields.is_empty()||command.requested_fields.len()>256
                ||command.requested_fields.iter().any(|field|!safe_field_name(field)||!fields.insert(field.as_str()))
                ||!matches!(command.purpose_of_use.as_str(),"TREATMENT"|"OPERATIONS"|"CODING"|"SAFETY_REVIEW")
                ||!command.private_deployment||[&command.patient_ref_hash,&command.data_policy_decision_digest,&command.residency_decision_digest,&command.model_manifest_digest,&command.clinical_evidence_digest].into_iter().any(|value|!digest(value)){
                return Err(DomainProductionError::CommandInvalid);
            }
        }
        DomainKind::Sensitive if matches!(envelope.operation.as_str(),"sensitive.human_handoff"|"sensitive.crisis_escalate")=>{
            let command:SensitiveHandoffCommand=serde_json::from_value(envelope.safe_command.clone()).map_err(|_|DomainProductionError::CommandInvalid)?;
            if command.schema_version!=DOMAIN_PACKS_SCHEMA_VERSION||command.tenant_id!=envelope.binding.tenant_id||envelope.deployment_stage.is_some()
                ||envelope.resource_key!=format!("sensitive-conversation:{}",command.conversation_hash)||command.conversation_hash!=envelope.before_digest
                ||command.minimum_safe_context_digest!=envelope.target_digest||!digest(&command.dynamic_region_directory_digest)
                ||command.handoff_id.is_nil()||!valid_region(&command.region_code)||!command.ordinary_agent_paused
                ||!matches!(command.risk_level.as_str(),"LOW"|"ELEVATED"|"HIGH"|"IMMINENT")
                ||!matches!(command.destination_type.as_str(),"HUMAN_SUPPORT"|"EMERGENCY_SERVICE"|"TRUSTED_CONTACT")
                ||!matches!(command.status.as_str(),"REQUESTED"|"ACCEPTED"|"FAILED"|"CLOSED"|"MANUAL_RECOVERY"){
                return Err(DomainProductionError::CommandInvalid);
            }
        }
        DomainKind::Sensitive if matches!(envelope.operation.as_str(),"sensitive.content_retrieve"|"sensitive.reflection_generate"|"sensitive.mentor_review_request")=>{
            let command:SensitiveInteractionCommand=serde_json::from_value(envelope.safe_command.clone()).map_err(|_|DomainProductionError::CommandInvalid)?;
            let mut citations=BTreeSet::new();
            let mentor=envelope.operation=="sensitive.mentor_review_request";
            let approval_matches=command.approval_set_id.is_some_and(|set|envelope.expert_approvals.iter().any(|approval|approval.approval_set_id==set));
            let risk_valid=if mentor{matches!(command.risk_level.as_str(),"ELEVATED"|"HIGH")}else{matches!(command.risk_level.as_str(),"LOW"|"ELEVATED")};
            if command.schema_version!=DOMAIN_PACKS_SCHEMA_VERSION||command.tenant_id!=envelope.binding.tenant_id||envelope.deployment_stage.is_some()
                ||envelope.resource_key!=format!("sensitive-conversation:{}",command.conversation_hash)
                ||command.conversation_hash!=envelope.before_digest||command.minimum_safe_context_digest!=envelope.target_digest
                ||[&command.consent_digest,&command.relationship_boundary_digest,&command.source_snapshot_digest].into_iter().any(|value|!digest(value))
                ||command.citation_digests.is_empty()||command.citation_digests.len()>64
                ||command.citation_digests.iter().any(|value|!digest(value)||!citations.insert(value.as_str()))
                ||!risk_valid
                ||(mentor&&(!command.ordinary_agent_paused||!approval_matches))
                ||(!mentor&&(command.ordinary_agent_paused||command.approval_set_id.is_some())){
                return Err(DomainProductionError::CommandInvalid);
            }
        }
        _=>return Err(DomainProductionError::CommandInvalid),
    }
    Ok(())
}

fn authorize_coding(envelope:&DomainExecutionEnvelope,effect:EffectClass)->Result<(),DomainProductionError>{
    let lower=envelope.resource_key.to_ascii_lowercase();
    if lower.contains("/../")||lower.ends_with("/.env")||lower.contains("/.git/")||lower.ends_with(".pem")||lower.ends_with(".key")
        ||(effect!=EffectClass::Pure&&envelope.deployment_stage==Some(DeploymentStage::LimitedWrite))
        ||matches!(envelope.operation.as_str(),"shell"|"deploy.production"|"branch.write.main"|"branch.write.master")
    {return Err(DomainProductionError::ToolDenied);} Ok(())
}

fn authorize_physical(envelope:&DomainExecutionEnvelope,now:DateTime<Utc>)->Result<(),DomainProductionError>{
    let write=envelope.operation.ends_with("commit")||envelope.operation.ends_with("restore")||envelope.operation.ends_with("activate");
    if !write{return Ok(());}
    let stage=envelope.deployment_stage.ok_or(DomainProductionError::StageDenied)?;
    if !matches!(stage,DeploymentStage::Simulator|DeploymentStage::DigitalTwin|DeploymentStage::Shadow|DeploymentStage::LimitedWrite){return Err(DomainProductionError::StageDenied);}
    if stage!=DeploymentStage::LimitedWrite{return Ok(());}
    let approval_set_id=validate_approvals(envelope,now,2)?;
    let supervision=envelope.physical_supervision.as_ref().ok_or(DomainProductionError::SupervisionRequired)?;
    if supervision.domain!=envelope.domain||supervision.stage!=DeploymentStage::LimitedWrite
        ||supervision.approval_set_id!=approval_set_id
        ||supervision.resource_key!=envelope.resource_key||supervision.before_digest!=envelope.before_digest
        ||supervision.target_digest!=envelope.target_digest||supervision.resource_version!=envelope.binding.resource_version
        ||supervision.consumed||supervision.issued_at>now||supervision.expires_at<=now
        ||!postgres_timestamp(&supervision.issued_at)||!postgres_timestamp(&supervision.expires_at)
        ||!identifier(&supervision.supervisor_subject,512)||!digest(&supervision.supervisor_assertion_digest)
        ||!reference(&supervision.evidence_ref)||!digest(&supervision.evidence_digest)
        ||envelope.expert_approvals.iter().any(|approval|approval.approval_set_id==approval_set_id&&approval.reviewer_subject==supervision.supervisor_subject)
    {return Err(DomainProductionError::SupervisionRequired);} Ok(())
}

fn authorize_medical(envelope:&DomainExecutionEnvelope,now:DateTime<Utc>)->Result<(),DomainProductionError>{
    if envelope.operation.contains("diagnos")||envelope.operation.contains("prescri")||envelope.operation.contains("treatment")||envelope.operation.contains("device_control")
    {return Err(DomainProductionError::ToolDenied);}
    if envelope.operation=="medical.review_request"{let _=validate_approvals(envelope,now,1)?;} Ok(())
}

fn authorize_sensitive(envelope:&DomainExecutionEnvelope,now:DateTime<Utc>)->Result<(),DomainProductionError>{
    if envelope.operation=="sensitive.crisis_escalate"||envelope.operation=="sensitive.human_handoff"{
        let _=validate_approvals(envelope,now,1)?;
        if envelope.safe_command.get("ordinary_agent_paused")!=Some(&Value::Bool(true))
            ||envelope.safe_command.get("dynamic_region_directory_digest").and_then(Value::as_str).is_none_or(|value|!digest(value))
        {return Err(DomainProductionError::EscalationInvalid);}
    } Ok(())
}

pub(crate) fn validate_approvals(envelope:&DomainExecutionEnvelope,now:DateTime<Utc>,minimum:usize)->Result<Uuid,DomainProductionError>{
    if minimum==0||minimum>16||envelope.expert_approvals.len()<minimum||envelope.expert_approvals.len()>16{
        return Err(DomainProductionError::ApprovalRequired);
    }
    let mut sets:BTreeMap<Uuid,BTreeSet<&str>>=BTreeMap::new();
    let mut approval_ids=BTreeSet::new();
    for approval in &envelope.expert_approvals {
        if approval.approval_id.is_nil()||approval.approval_set_id.is_nil()
            ||approval.domain!=envelope.domain||approval.operation!=envelope.operation||approval.resource_key!=envelope.resource_key
            ||approval.before_digest!=envelope.before_digest||approval.target_digest!=envelope.target_digest
            ||approval.resource_version!=envelope.binding.resource_version||approval.approved_at>now||approval.expires_at<=now
            ||!postgres_timestamp(&approval.approved_at)||!postgres_timestamp(&approval.expires_at)
            ||approval.expires_at<=approval.approved_at||!digest(&approval.qualification_digest)||!digest(&approval.principal_assertion_digest)
            ||!identifier(&approval.reviewer_subject,512)||approval.reviewer_subject==envelope.actor_subject
            ||!valid_expert_role(envelope.domain,&approval.reviewer_role)
            ||!reference(&approval.evidence_ref)||!digest(&approval.evidence_digest)
            ||!approval_ids.insert(approval.approval_id)
            ||!sets.entry(approval.approval_set_id).or_default().insert(approval.reviewer_subject.as_str()){
            return Err(DomainProductionError::ApprovalRequired);
        }
    }
    if sets.len()!=1{return Err(DomainProductionError::ApprovalRequired);}
    sets.into_iter().find(|(_,reviewers)|reviewers.len()>=minimum).map(|(set,_)|set).ok_or(DomainProductionError::ApprovalRequired)
}

fn valid_expert_role(domain:DomainKind,role:&str)->bool{
    matches!((domain,role),
        (DomainKind::Coding,"CODE_REVIEWER"|"SECURITY_REVIEWER"|"REPOSITORY_MAINTAINER")
        |(DomainKind::Industrial,"CONTROL_ENGINEER"|"SAFETY_ENGINEER"|"SITE_OPERATOR")
        |(DomainKind::Energy,"POWER_SYSTEM_ENGINEER"|"ENERGY_OPERATOR"|"SAFETY_ENGINEER")
        |(DomainKind::Medical,"CLINICIAN"|"PHYSICIAN"|"PHARMACIST"|"LICENSED_REVIEWER")
        |(DomainKind::Sensitive,"TRUST_SAFETY_REVIEWER"|"LICENSED_PROFESSIONAL"|"CRISIS_SUPERVISOR"|"MENTOR")
    )
}

fn normalized_tools(tools:&[agent_trust_pack_supply_chain::PackToolDefinition])->BTreeMap<String,(EffectClass,bool,Option<String>,String)>{
    tools.iter().map(|tool|(tool.tool_id.clone(),(tool.effect_class,tool.approval_required,tool.compensation_ref.clone(),tool.executor_template.clone()))).collect()
}
fn immutable_reference(value:&str,kind:&str)->bool{value.strip_prefix(&format!("{kind}:sha256:")).is_some_and(digest)}
fn digest(value:&str)->bool{value.len()==64&&value.bytes().all(|byte|byte.is_ascii_hexdigit()&&!byte.is_ascii_uppercase())}
fn identifier(value:&str,maximum:usize)->bool{!value.is_empty()&&value.len()<=maximum&&!value.chars().any(char::is_control)}
fn reference(value:&str)->bool{identifier(value,1024)&&!value.contains("..")}
fn hex_length(value:&str,lengths:&[usize])->bool{lengths.contains(&value.len())&&value.bytes().all(|byte|byte.is_ascii_hexdigit()&&!byte.is_ascii_uppercase())}
fn https_reference(value:&str)->bool{url::Url::parse(value).is_ok_and(|parsed|parsed.scheme()=="https"&&parsed.host_str().is_some()&&parsed.username().is_empty()&&parsed.password().is_none()&&parsed.query().is_none()&&parsed.fragment().is_none())}
fn unsafe_repository_path(value:&str)->bool{let lower=value.to_ascii_lowercase();value.is_empty()||value.starts_with('/')||value.split('/').any(|part|part.is_empty()||part=="..")||lower==".env"||lower.starts_with(".git/")||lower.ends_with(".pem")||lower.ends_with(".key")||lower.contains("docker.sock")}
fn safe_field_name(value:&str)->bool{!value.is_empty()&&value.len()<=128&&value.bytes().all(|byte|byte.is_ascii_alphanumeric()||matches!(byte,b'_'|b'.'|b'-'|b'/'))}
fn valid_region(value:&str)->bool{let mut parts=value.split('-');let country=parts.next().is_some_and(|part|part.len()==2&&part.bytes().all(|byte|byte.is_ascii_uppercase()));let subdivision=parts.next();country&&parts.next().is_none()&&subdivision.is_none_or(|part|(1..=3).contains(&part.len())&&part.bytes().all(|byte|byte.is_ascii_uppercase()||byte.is_ascii_digit()))}
fn postgres_timestamp(value:&DateTime<Utc>)->bool{value.timestamp_subsec_nanos()%1_000==0}
fn idempotency(value:&str)->bool{(16..=256).contains(&value.len())&&value.bytes().all(|byte|byte.is_ascii_alphanumeric()||matches!(byte,b'.'|b'_'|b':'|b'/'|b'-'))}
fn json_limits(value:&Value,depth:usize)->Result<usize,DomainProductionError>{if depth>32{return Err(DomainProductionError::CommandInvalid);}match value{
    Value::Null|Value::Bool(_)|Value::Number(_)=>Ok(1),Value::String(value)if value.len()<=65_536&&!value.chars().any(char::is_control)=>Ok(value.len()),Value::String(_)=>Err(DomainProductionError::CommandInvalid),
    Value::Array(values)if values.len()<=1024=>values.iter().try_fold(0usize,|total,value|json_limits(value,depth+1).and_then(|size|total.checked_add(size).ok_or(DomainProductionError::CommandInvalid))),
    Value::Object(values)if values.len()<=256=>values.iter().try_fold(0usize,|total,(key,value)|{if !identifier(key,256){return Err(DomainProductionError::CommandInvalid);}json_limits(value,depth+1).and_then(|size|total.checked_add(key.len()+size).ok_or(DomainProductionError::CommandInvalid))}),
    _=>Err(DomainProductionError::CommandInvalid),}.and_then(|size|if size<=1_048_576{Ok(size)}else{Err(DomainProductionError::CommandInvalid)})}
pub fn safe_digest(value:&impl Serialize)->Result<String,DomainProductionError>{serde_jcs::to_vec(value).map(|raw|hex::encode(Sha256::digest(raw))).map_err(|_|DomainProductionError::CommandInvalid)}

#[derive(Debug,Error,Clone,PartialEq,Eq)]
pub enum DomainProductionError{
    #[error("DOMAIN_PACK_INVALID")]PackInvalid,#[error("DOMAIN_BINDING_INVALID")]BindingInvalid,
    #[error("DOMAIN_COMMAND_INVALID")]CommandInvalid,#[error("DOMAIN_TOOL_DENIED")]ToolDenied,
    #[error("DOMAIN_STAGE_DENIED")]StageDenied,#[error("DOMAIN_APPROVAL_REQUIRED")]ApprovalRequired,
    #[error("DOMAIN_PHYSICAL_SUPERVISION_REQUIRED")]SupervisionRequired,#[error("DOMAIN_ESCALATION_INVALID")]EscalationInvalid,
}
