package agenttrust.sensitive

import rego.v1

default response_allowed := false
default human_escalation_required := false

verified_citations if {
  count(input.response.claims) == count(input.response.citations)
  every citation in input.response.citations {
    citation.verified
    citation.source_digest != ""
  }
}

valid_consent if {
  input.consent.valid
  input.consent.scope == input.intent.operation
  input.consent.subject_id == input.subject.subject_id
}

safe_language if {
  not input.response.contains_coercion
  not input.response.contains_spiritual_scoring
  not input.response.claims_human_authority
  not input.response.shaming
}

response_allowed if {
  input.intent.operation in {"supportive_response", "educational_response"}
  input.subject.tenant_id == input.resource.tenant_id
  valid_consent
  safe_language
  verified_citations
  input.risk.level in {"LOW", "MEDIUM"}
  not input.risk.crisis_detected
}

human_escalation_required if {
  input.risk.crisis_detected
}

human_escalation_required if {
  input.risk.level in {"HIGH", "CRITICAL"}
}

human_escalation_required if {
  not valid_consent
}

decision := {"decision":"ALLOW","reason_codes":["SENSITIVE_GUARDS_PASS"],"human_escalation":false} if response_allowed
decision := {"decision":"DENY","reason_codes":["SENSITIVE_FAIL_CLOSED"],"human_escalation":human_escalation_required} if not response_allowed
