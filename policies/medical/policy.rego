package agenttrust.medical

import rego.v1

default access_allowed := false
default publish_allowed := false

supported_purpose if { input.clinical.purpose in {"TREATMENT", "CARE_COORDINATION", "QUALITY_REVIEW"} }

scope_minimized if {
  every item in input.clinical.requested_scopes { item in input.clinical.approved_scopes }
}

base_access_allowed if {
  input.subject.tenant_id == input.resource.tenant_id
  input.clinical.care_relationship_active
  input.clinical.consent_valid
  supported_purpose
  scope_minimized
  input.clinical.break_glass == false
  input.environment.autonomous_diagnosis == false
  input.environment.autonomous_treatment == false
}

access_allowed if {
  input.intent.operation in {"read_record", "draft_summary"}
  base_access_allowed
}

access_allowed if {
  input.intent.operation == "read_record"
  input.subject.tenant_id == input.resource.tenant_id
  input.clinical.break_glass
  input.clinical.emergency_reason != ""
  input.clinical.human_identity_verified
  input.clinical.audit_sink_available
}

publish_allowed if {
  input.intent.operation == "publish_clinical_output"
  base_access_allowed
  input.review.status == "APPROVED"
  input.review.reviewer_is_licensed_clinician
  input.review.reviewer_subject != input.subject.subject_id
  input.review.evidence_digest != ""
}

decision := {"decision":"ALLOW","reason_codes":["MEDICAL_ACCESS_MINIMIZED"]} if {
  input.intent.operation != "publish_clinical_output"
  access_allowed
}
decision := {"decision":"DENY","reason_codes":["MEDICAL_FAIL_CLOSED"]} if {
  input.intent.operation != "publish_clinical_output"
  not access_allowed
}
decision := {"decision":"ALLOW","reason_codes":["MEDICAL_HUMAN_REVIEW_PASS"]} if publish_allowed
decision := {"decision":"DENY","reason_codes":["MEDICAL_PUBLICATION_DENIED"]} if {
  input.intent.operation == "publish_clinical_output"
  not publish_allowed
}
