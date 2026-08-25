BEGIN;

ALTER TABLE enterprise_approval_intents
  ADD COLUMN IF NOT EXISTS response_payload jsonb,
  ADD COLUMN IF NOT EXISTS pep_policy_digest char(64),
  ADD COLUMN IF NOT EXISTS pep_evidence_ref text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conname = 'enterprise_approval_intent_pep_evidence_check'
       AND conrelid = 'enterprise_approval_intents'::regclass
  ) THEN
    -- Preserve legacy rows without inventing authorization evidence. PostgreSQL enforces a
    -- NOT VALID check for every new or updated row, and the BFF rejects legacy NULL bindings.
    ALTER TABLE enterprise_approval_intents
      ADD CONSTRAINT enterprise_approval_intent_pep_evidence_check
      CHECK (
        COALESCE((
          pep_policy_digest ~ '^[a-f0-9]{64}$'
          AND octet_length(pep_evidence_ref) BETWEEN 1 AND 2048
          AND pep_evidence_ref ~ '^[A-Za-z][A-Za-z0-9+.-]*:[^[:space:]]{1,2031}$'
        ), false)
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conname = 'enterprise_approval_intent_response_payload_check'
       AND conrelid = 'enterprise_approval_intents'::regclass
  ) THEN
    ALTER TABLE enterprise_approval_intents
      ADD CONSTRAINT enterprise_approval_intent_response_payload_check
      CHECK (
        response_payload IS NULL
        OR COALESCE((
          jsonb_typeof(response_payload) = 'object'
          AND response_payload ?& ARRAY[
            'schema_version', 'approval_case', 'evidence_receipt'
          ]
          AND response_payload - ARRAY[
            'schema_version', 'approval_case', 'evidence_receipt'
          ] = '{}'::jsonb
          AND response_payload ->> 'schema_version'
            = 'agenttrust.approval-decision-result.v1'
          AND jsonb_typeof(response_payload -> 'approval_case') = 'object'
          AND response_payload -> 'approval_case' ?& ARRAY[
            'schema_version', 'case_id', 'request', 'policy', 'status', 'decisions',
            'created_at', 'expires_at', 'post_review_due_at'
          ]
          AND (response_payload -> 'approval_case') - ARRAY[
            'schema_version', 'case_id', 'request', 'policy', 'status', 'decisions',
            'created_at', 'expires_at', 'post_review_due_at'
          ] = '{}'::jsonb
          AND response_payload #>> '{approval_case,schema_version}'
            = 'agenttrust.enterprise-approval-case.v2'
          AND jsonb_typeof(response_payload -> 'evidence_receipt') = 'object'
          AND response_payload -> 'evidence_receipt' ?& ARRAY[
            'schema_version', 'receipt_id', 'tenant_id', 'case_id', 'task_id',
            'decision', 'decision_reason_digest', 'request_digest', 'decision_digest',
            'idempotency_key_digest', 'actor_subject', 'principal_assertion_jti',
            'principal_assertion_request_digest', 'principal_assertion_digest',
            'approval_case_digest', 'action_hash', 'step_id', 'plan_hash',
            'parameter_hash', 'resource', 'resource_version', 'policy_version',
            'environment', 'risk', 'case_status', 'decided_at', 'evidence_ref',
            'evidence_digest', 'authority_request_digest', 'evidence_outbox_ref',
            'issuer', 'key_id', 'key_usage', 'signature'
          ]
          AND (response_payload -> 'evidence_receipt') - ARRAY[
            'schema_version', 'receipt_id', 'tenant_id', 'case_id', 'task_id',
            'decision', 'decision_reason_digest', 'request_digest', 'decision_digest',
            'idempotency_key_digest', 'actor_subject', 'principal_assertion_jti',
            'principal_assertion_request_digest', 'principal_assertion_digest',
            'approval_case_digest', 'action_hash', 'step_id', 'plan_hash',
            'parameter_hash', 'resource', 'resource_version', 'policy_version',
            'environment', 'risk', 'case_status', 'decided_at', 'evidence_ref',
            'evidence_digest', 'authority_request_digest', 'evidence_outbox_ref',
            'issuer', 'key_id', 'key_usage', 'signature'
          ] = '{}'::jsonb
          AND response_payload #>> '{evidence_receipt,schema_version}'
            = 'agenttrust.approval-decision-evidence.v1'
        ), false)
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conname = 'enterprise_approval_intent_completed_receipt_check'
       AND conrelid = 'enterprise_approval_intents'::regclass
  ) THEN
    -- NOT VALID preserves old COMPLETED rows which predate immutable decision receipts.
    -- PostgreSQL still enforces this check for every new or updated row; the BFF treats
    -- an old completed row without a response payload as fail-closed, never as success.
    ALTER TABLE enterprise_approval_intents
      ADD CONSTRAINT enterprise_approval_intent_completed_receipt_check
      CHECK (
        status <> 'COMPLETED'
        OR COALESCE((
          response_payload IS NOT NULL
          AND evidence_ref IS NOT NULL
          AND response_payload #>> '{approval_case,case_id}' = case_id::text
          AND response_payload #>> '{approval_case,request,tenant_id}' = tenant_id::text
          AND response_payload #>> '{approval_case,request,action_hash}'
            = observed_action_hash
          AND response_payload #>> '{approval_case,request,resource_version}'
            = observed_resource_version
          AND response_payload #>> '{evidence_receipt,tenant_id}' = tenant_id::text
          AND response_payload #>> '{evidence_receipt,case_id}' = case_id::text
          AND response_payload #>> '{evidence_receipt,decision}' = decision
          AND response_payload #>> '{evidence_receipt,actor_subject}' = actor_subject
          AND response_payload #>> '{evidence_receipt,decision_reason_digest}'
            = reason_digest::text
          AND response_payload #>> '{evidence_receipt,action_hash}'
            = observed_action_hash
          AND response_payload #>> '{evidence_receipt,resource_version}'
            = observed_resource_version
          AND response_payload #>> '{evidence_receipt,evidence_ref}' = evidence_ref
          AND response_payload #>> '{evidence_receipt,evidence_digest}'
            ~ '^[a-f0-9]{64}$'
          AND response_payload #>> '{evidence_receipt,signature}'
            ~ '^[A-Za-z0-9_-]{86}$'
        ), false)
      ) NOT VALID;
  END IF;
END
$$;

COMMIT;
