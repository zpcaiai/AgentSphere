package agenttrust.sensitive_test

import data.agenttrust.sensitive
import rego.v1

base := {
  "intent":{"operation":"supportive_response"},
  "subject":{"tenant_id":"tenant-1","subject_id":"person-1"},
  "resource":{"tenant_id":"tenant-1"},
  "consent":{"valid":true,"scope":"supportive_response","subject_id":"person-1"},
  "response":{"claims":["claim-1"],"citations":[{"verified":true,"source_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"contains_coercion":false,"contains_spiritual_scoring":false,"claims_human_authority":false,"shaming":false},
  "risk":{"level":"LOW","crisis_detected":false}
}

test_supported_response_allowed if { sensitive.response_allowed with input as base }
test_crisis_routes_to_human if { sensitive.human_escalation_required with input as object.union(base, {"risk":{"level":"CRITICAL","crisis_detected":true}}) }
test_coercion_denied if { not sensitive.response_allowed with input as object.union(base, {"response":object.union(base.response, {"contains_coercion":true})}) }
test_missing_citation_denied if { not sensitive.response_allowed with input as object.union(base, {"response":object.union(base.response, {"citations":[]})}) }
test_missing_consent_escalates if { sensitive.human_escalation_required with input as object.union(base, {"consent":{"valid":false,"scope":"supportive_response","subject_id":"person-1"}}) }
