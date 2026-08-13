from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import unittest

from python.production_gates.live_integrations import GateError
from python.production_gates.object_store_retention import probe_s3_compliance_retention


class FakeObjectLockS3:
    def __init__(self, mode: str = "COMPLIANCE") -> None:
        self.mode = mode

    def request(self, method, url, *, headers=None, body=None,
                maximum_bytes=1_048_576, allow_http_local=False):
        del body, maximum_bytes, allow_http_local
        assert headers and headers["Authorization"].startswith("AWS4-HMAC-SHA256 ")
        if "object-lock=" in url:
            return 200, {}, (
                f"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>"
                f"<Rule><DefaultRetention><Mode>{self.mode}</Mode><Days>365</Days>"
                f"</DefaultRetention></Rule></ObjectLockConfiguration>"
            ).encode()
        if "versioning=" in url:
            return 200, {}, b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
        if "retention=" in url:
            retain_until = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
            return 200, {}, (
                f"<Retention><Mode>{self.mode}</Mode>"
                f"<RetainUntilDate>{retain_until}</RetainUntilDate></Retention>"
            ).encode()
        if method == "HEAD" and "versionId=" in url:
            return 200, {"x-amz-version-id": "opaque-version"}, b""
        raise AssertionError((method, url))


class ObjectStoreRetentionTests(unittest.TestCase):
    def setUp(self):
        os.environ["AGENTTRUST_LOCK_ACCESS"] = "access"
        os.environ["AGENTTRUST_LOCK_SECRET"] = "secret"

    def tearDown(self):
        os.environ.pop("AGENTTRUST_LOCK_ACCESS", None)
        os.environ.pop("AGENTTRUST_LOCK_SECRET", None)

    def test_compliance_retention_and_versioning_are_verified_read_only(self):
        result = probe_s3_compliance_retention(
            "https://s3.example.test", "eu-west-1", "agenttrust-evidence",
            "releases/release-1/evidence.json", "version-opaque",
            "AGENTTRUST_LOCK_ACCESS", "AGENTTRUST_LOCK_SECRET",
            transport=FakeObjectLockS3(),
        )
        rendered = json.dumps(result.as_dict())
        self.assertTrue(result.checks["probe_is_read_only"])
        self.assertFalse(result.checks["delete_attempted"])
        self.assertNotIn("secret", rendered)

    def test_governance_mode_is_not_accepted_as_compliance_retention(self):
        with self.assertRaises(GateError):
            probe_s3_compliance_retention(
                "https://s3.example.test", "eu-west-1", "agenttrust-evidence",
                "releases/release-1/evidence.json", "version-opaque",
                "AGENTTRUST_LOCK_ACCESS", "AGENTTRUST_LOCK_SECRET",
                transport=FakeObjectLockS3("GOVERNANCE"),
            )


if __name__ == "__main__":
    unittest.main()
