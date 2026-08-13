package agenttrust.medical_test

import data.agenttrust.medical
import rego.v1

base := {
  "intent":{"operation":"draft_summary"},
  "subject":{"tenant_id":"tenant-1","subject_id":"agent-1"},
  "resource":{"tenant_id":"tenant-1"},
  "clinical":{"purpose":"TREATMENT","care_relationship_active":true,"consent_valid":true,"requested_scopes":["allergy"],"approved_scopes":["allergy","medication"],"break_glass":false,"emergency_reason":"","human_identity_verified":false,"audit_sink_available":true},
  "environment":{"autonomous_diagnosis":false,"autonomous_treatment":false},
  "review":{"status":"PENDING","reviewer_is_licensed_clinician":false,"reviewer_subject":"","evidence_digest":""}
}

test_minimized_draft_allowed if { medical.access_allowed with input as base }
test_scope_expansion_denied if { not medical.access_allowed with input as object.union(base, {"clinical":object.union(base.clinical, {"requested_scopes":["allergy","genome"]})}) }
test_autonomous_treatment_denied if { not medical.access_allowed with input as object.union(base, {"environment":{"autonomous_diagnosis":false,"autonomous_treatment":true}}) }
test_unreviewed_publication_denied if { not medical.publish_allowed with input as object.union(base, {"intent":{"operation":"publish_clinical_output"}}) }
test_reviewed_publication_allowed if { medical.publish_allowed with input as object.union(base, {"intent":{"operation":"publish_clinical_output"},"review":{"status":"APPROVED","reviewer_is_licensed_clinician":true,"reviewer_subject":"clinician-2","evidence_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}) }
test_break_glass_without_audit_denied if { not medical.access_allowed with input as object.union(base, {"intent":{"operation":"read_record"},"clinical":object.union(base.clinical, {"break_glass":true,"emergency_reason":"urgent","human_identity_verified":true,"audit_sink_available":false})}) }
