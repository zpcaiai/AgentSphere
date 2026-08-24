BEGIN;

-- V2 never invents review facts for V1 JSONB rows. Operators must first reject/revoke every
-- mutable legacy case and revoke or consume every grant derived from one. Terminal history stays
-- immutable and remains available to audit queries, but is excluded from the approval inbox.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM approval_cases c
     WHERE (NOT (c.request ? 'review_context') OR NOT (c.request ? 'review_evidence'))
       AND (
         c.status IN ('PENDING', 'APPROVED', 'POST_REVIEW_REQUIRED')
         OR EXISTS (
           SELECT 1
             FROM approval_grants g
            WHERE g.tenant_id = c.tenant_id
              AND g.case_id = c.case_id
              AND g.remaining_uses > 0
              AND g.revoked_at IS NULL
         )
       )
  ) THEN
    RAISE EXCEPTION 'APPROVAL_V2_LEGACY_MUTABLE_STATE_MUST_BE_DRAINED';
  END IF;
END
$$;

ALTER TABLE approval_cases
  DROP CONSTRAINT IF EXISTS approval_cases_review_evidence_v2_check;

ALTER TABLE approval_cases
  ADD CONSTRAINT approval_cases_review_evidence_v2_check
  CHECK (
    status NOT IN ('PENDING', 'APPROVED', 'POST_REVIEW_REQUIRED')
    OR COALESCE(
      request ? 'review_context'
      AND request ? 'review_evidence'
      AND request -> 'review_evidence' ->> 'schema_version'
        = 'agenttrust.approval-review-evidence-binding.v1'
      AND request -> 'review_evidence' -> 'material' ->> 'schema_version'
        = 'agenttrust.approval-review-material.v1'
      AND request -> 'review_evidence' -> 'material' ->> 'tenant_id'
        = request ->> 'tenant_id'
      AND request -> 'review_evidence' -> 'material' ->> 'task_id'
        = request ->> 'task_id'
      AND request -> 'review_evidence' -> 'material' ->> 'canonical_action_hash'
        = request ->> 'action_hash'
      AND request -> 'review_evidence' -> 'material' ->> 'resource'
        = request ->> 'resource'
      AND request -> 'review_evidence' -> 'material' ->> 'resource_version'
        = request ->> 'resource_version'
      AND request -> 'review_evidence' -> 'material' ->> 'policy_version'
        = request ->> 'policy_version'
      AND request -> 'review_evidence' -> 'material' ->> 'environment'
        = request ->> 'environment'
      AND request -> 'review_evidence' -> 'material' ->> 'risk' = request ->> 'risk'
      AND request -> 'review_evidence' -> 'material' -> 'review_context'
        = request -> 'review_context'
      AND request -> 'review_evidence' -> 'material' ->> 'risk_package_digest'
        ~ '^[0-9a-f]{64}$'
      AND request -> 'review_evidence' -> 'material' ->> 'state_snapshot_digest'
        ~ '^[0-9a-f]{64}$'
      AND request -> 'review_evidence' -> 'authority_request' ->> 'schema_version'
        = 'agenttrust.authority-evidence-event-request.v1'
      AND request -> 'review_evidence' -> 'authority_request' ->> 'source_kind'
        = 'AUTHENTICATED_EVENT'
      AND request -> 'review_evidence' -> 'authority_request' -> 'control_binding' = 'null'::jsonb
      AND request -> 'review_evidence' -> 'authority_request' -> 'event' ->> 'event_type'
        = 'APPROVAL_REVIEW_PREPARED'
      AND request -> 'review_evidence' -> 'receipt' ->> 'schema_version'
        = 'agenttrust.signed-authority-evidence-receipt.v1'
      AND request -> 'review_evidence' -> 'receipt' ->> 'key_usage'
        = 'AUTHORITY_EVIDENCE_RECEIPT'
      AND request -> 'review_evidence' -> 'receipt' ->> 'tenant_id'
        = request ->> 'tenant_id'
      AND request -> 'review_evidence' -> 'receipt' ->> 'task_id'
        = request ->> 'task_id'
      AND request -> 'review_evidence' -> 'receipt' ->> 'request_digest' ~ '^[0-9a-f]{64}$'
      AND request -> 'review_evidence' -> 'receipt' ->> 'payload_digest' ~ '^[0-9a-f]{64}$'
      AND request -> 'review_evidence' -> 'receipt' ->> 'evidence_digest' ~ '^[0-9a-f]{64}$'
      AND length(request -> 'review_evidence' -> 'receipt' ->> 'signature') = 86,
      false
    )
  ) NOT VALID;

ALTER TABLE approval_cases
  VALIDATE CONSTRAINT approval_cases_review_evidence_v2_check;

COMMIT;
