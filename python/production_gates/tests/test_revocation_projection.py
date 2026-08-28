from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.revocation_checkpoint import genesis_checkpoint
from python.production_gates.revocation_projection import (
    prepare_projection_request,
    validate_projection_response,
)


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class RevocationProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.revocation_private = Ed25519PrivateKey.generate()
        self.projection_private = Ed25519PrivateKey.generate()
        self.revocation_public = {
            "schema_version": "agenttrust.ed25519-public-key.v1",
            "key_id": "revocation-key-1",
            "public_key": b64(
                self.revocation_private.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ),
        }
        self.projection_public = {
            "schema_version": "agenttrust.ed25519-public-key.v1",
            "key_id": "projection-key-1",
            "public_key": b64(
                self.projection_private.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ),
        }
        self.checkpoint = genesis_checkpoint(
            registry_id="production-registry",
            key_id="revocation-key-1",
            initialized_at=self.now - timedelta(minutes=5),
        )
        self.registry = {
            "schema_version": "agenttrust.production-closure-revocation-registry.v1",
            "registry_id": "production-registry",
            "sequence": 1,
            "previous_registry_digest": None,
            "published_at": self.now.isoformat().replace("+00:00", "Z"),
            "expires_at": (self.now + timedelta(days=1)).isoformat().replace(
                "+00:00", "Z"
            ),
            "key_id": "revocation-key-1",
            "entries": [],
            "signature": "",
        }
        self.registry["signature"] = b64(
            self.revocation_private.sign(canonical_json(self.registry))
        )
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name).resolve()
        paths = {}
        for name, mode in (("ca.pem", 0o440), ("client.pem", 0o440), ("key.pem", 0o600)):
            path = root / name
            path.write_text("test-fixture\n", encoding="utf-8")
            os.chmod(path, mode)
            paths[name] = str(path)
        self.config = {
            "schema_version": "agenttrust.revocation-projection-broker-config.v1",
            "endpoint": "https://projection.example.test/v1/revocation-projections",
            "server_name": "projection.example.test",
            "oidc_audience": "agenttrust-revocation-projection",
            "environment_reference": "environment://production/us-east-1",
            "ca_file": paths["ca.pem"],
            "client_certificate_file": paths["client.pem"],
            "client_private_key_file": paths["key.pem"],
            "projection_public_key": self.projection_public,
            "timeout_seconds": 10,
            "maximum_response_bytes": 1024 * 1024,
            "head_ttl_seconds": 120,
            "ack_timeout_seconds": 60,
            "required_watcher_ids": [
                "execution/fleet",
                "platform-sre/activation-lease",
                "runtime/fleet",
            ],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _response(self, request: dict[str, object]) -> dict[str, object]:
        projected_at = self.now + timedelta(seconds=1)
        completed_at = self.now + timedelta(seconds=2)
        projection_id = "projection-20300101-000001"
        head = {
            "schema_version": "agenttrust.production-revocation-projection-head.v1",
            "projection_id": projection_id,
            "environment_reference": request["environment_reference"],
            "base_checkpoint_digest": request["base_checkpoint_digest"],
            "registry_id": request["registry_id"],
            "registry_key_id": request["registry_key_id"],
            "registry_sequence": request["registry_sequence"],
            "registry_digest": request["registry_digest"],
            "projected_at": projected_at.isoformat().replace("+00:00", "Z"),
            "expires_at": (projected_at + timedelta(seconds=90))
            .isoformat()
            .replace("+00:00", "Z"),
            "projection_key_id": self.projection_public["key_id"],
            "signature": "",
        }
        head["signature"] = b64(self.projection_private.sign(canonical_json(head)))
        acks = [
            {
                "schema_version": "agenttrust.production-revocation-watcher-ack.v1",
                "projection_id": projection_id,
                "watcher_id": watcher_id,
                "registry_sequence": request["registry_sequence"],
                "registry_digest": request["registry_digest"],
                "activation_receipt_digest": "a" * 64,
                "acknowledged_at": completed_at.isoformat().replace("+00:00", "Z"),
            }
            for watcher_id in request["required_watcher_ids"]
        ]
        response = {
            "schema_version": "agenttrust.production-revocation-projection-receipt.v1",
            "request_digest": digest(request),
            "projection_id": projection_id,
            "projection_head": head,
            "watcher_acks": acks,
            "committed": True,
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "projection_key_id": self.projection_public["key_id"],
            "signature": "",
        }
        response["signature"] = b64(
            self.projection_private.sign(canonical_json(response))
        )
        return response

    def test_signed_projection_requires_exact_complete_watcher_set(self) -> None:
        request = prepare_projection_request(
            self.registry,
            self.checkpoint,
            self.revocation_public,
            self.config,
            release_id="git:sha1:" + "1" * 40,
            requested_at=self.now,
        )
        response = self._response(request)
        verified = validate_projection_response(
            response, request, self.config, now=self.now + timedelta(seconds=3)
        )
        self.assertTrue(verified["committed"])
        self.assertEqual(
            [item["watcher_id"] for item in verified["watcher_acks"]],
            self.config["required_watcher_ids"],
        )

        missing = copy.deepcopy(response)
        missing["watcher_acks"].pop()
        missing["signature"] = ""
        missing["signature"] = b64(
            self.projection_private.sign(canonical_json(missing))
        )
        with self.assertRaisesRegex(GateError, "ACK_SET_INCOMPLETE"):
            validate_projection_response(
                missing, request, self.config, now=self.now + timedelta(seconds=3)
            )

    def test_stale_head_and_tampered_registry_binding_fail_closed(self) -> None:
        request = prepare_projection_request(
            self.registry,
            self.checkpoint,
            self.revocation_public,
            self.config,
            release_id="git:sha1:" + "2" * 40,
            requested_at=self.now,
        )
        response = self._response(request)
        with self.assertRaisesRegex(GateError, "HEAD_INVALID"):
            validate_projection_response(
                response, request, self.config, now=self.now + timedelta(minutes=3)
            )

        tampered = copy.deepcopy(response)
        tampered["projection_head"]["registry_digest"] = "b" * 64
        with self.assertRaisesRegex(GateError, "HEAD_INVALID"):
            validate_projection_response(
                tampered, request, self.config, now=self.now + timedelta(seconds=3)
            )


if __name__ == "__main__":
    unittest.main()
