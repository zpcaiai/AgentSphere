from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import unittest

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.signing_broker import (
    prepare_broker_request,
    validate_broker_response,
)


def _payload(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


class SigningBrokerTests(unittest.TestCase):
    def request(self) -> dict[str, object]:
        payload = b"exact-production-certificate-jcs"
        return {
            "schema_version": "agenttrust.production-closure-signing-request.v1",
            "algorithm": "Ed25519",
            "key_id": "kms:closure:2026-01",
            "certificate": {"signature": ""},
            "signing_payload": _payload(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }

    def test_request_and_response_are_digest_bound(self) -> None:
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        request = prepare_broker_request(self.request(), "certificate")
        signature = "A" * 86
        audit_receipt = {
            "schema_version": "agenttrust.external-signing-audit-receipt.v1",
            "request_id": request["request_id"],
            "request_digest": request["request_digest"],
            "request_kind": request["request_kind"],
            "key_id": request["key_id"],
            "algorithm": "Ed25519",
            "payload_sha256": request["payload_sha256"],
            "document_signature_sha256": hashlib.sha256(
                signature.encode("ascii")
            ).hexdigest(),
            "signed_at": "2030-01-01T00:00:00Z",
        }
        response = {
            "schema_version": "agenttrust.external-signing-broker-response.v1",
            "request_id": request["request_id"],
            "request_digest": request["request_digest"],
            "request_kind": request["request_kind"],
            "key_id": request["key_id"],
            "algorithm": "Ed25519",
            "payload_sha256": request["payload_sha256"],
            "signature": signature,
            "signed_at": "2030-01-01T00:00:00Z",
            "audit_receipt_digest": hashlib.sha256(
                canonical_json(audit_receipt)
            ).hexdigest(),
            "audit_receipt": audit_receipt,
            "audit_signature": "B" * 86,
        }
        detached, signed_audit = validate_broker_response(
            response, request, kind="certificate", now=now
        )
        self.assertEqual(detached["request_digest"], request["request_digest"])
        self.assertEqual(
            detached["audit_receipt_digest"], signed_audit["receipt_digest"]
        )
        self.assertEqual(signed_audit["receipt"], audit_receipt)
        self.assertEqual(detached["signed_at"], "2030-01-01T00:00:00Z")
        self.assertEqual(
            detached["schema_version"],
            "agenttrust.production-closure-external-signature.v2",
        )
        response["payload_sha256"] = "c" * 64
        with self.assertRaisesRegex(GateError, "SIGNING_BROKER_RESPONSE_INVALID"):
            validate_broker_response(response, request, kind="certificate", now=now)

        response["payload_sha256"] = request["payload_sha256"]
        response["audit_receipt_digest"] = "b" * 64
        with self.assertRaisesRegex(GateError, "SIGNING_BROKER_RESPONSE_INVALID"):
            validate_broker_response(response, request, kind="certificate", now=now)

    def test_embedded_signature_must_be_empty(self) -> None:
        request = self.request()
        request["certificate"] = {"signature": "pre-signed"}
        with self.assertRaisesRegex(GateError, "SIGNING_BROKER_REQUEST_INVALID"):
            prepare_broker_request(request, "certificate")

    def test_revocation_request_requires_checkpoint_digest_binding(self) -> None:
        payload = b"exact-production-revocation-registry-jcs"
        signing_request = {
            "schema_version": (
                "agenttrust.production-closure-revocation-signing-request.v1"
            ),
            "algorithm": "Ed25519",
            "key_id": "kms:revocation:2030-01",
            "base_checkpoint_digest": "d" * 64,
            "registry": {"signature": ""},
            "signing_payload": _payload(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
        prepared = prepare_broker_request(signing_request, "revocation")
        self.assertEqual(
            prepared["request_digest"],
            hashlib.sha256(canonical_json(signing_request)).hexdigest(),
        )
        del signing_request["base_checkpoint_digest"]
        with self.assertRaisesRegex(GateError, "SIGNING_BROKER_REQUEST_INVALID"):
            prepare_broker_request(signing_request, "revocation")


if __name__ == "__main__":
    unittest.main()
