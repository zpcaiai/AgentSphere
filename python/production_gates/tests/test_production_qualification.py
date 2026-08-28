from __future__ import annotations

import copy
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from python.production_gates.git_provenance import canonical_json
from python.production_gates.live_integrations import GateError
from python.production_gates.qualification import (
    EXTERNAL_CONDITIONS,
    GATE_CONDITION_REQUIREMENTS,
    compile_qualification,
    reviewer_keyring_digest,
    scope_digest,
)
from python.production_gates.tests.qualification_fixtures import QualificationFixture


ROOT = Path(__file__).parents[3]


class ProductionQualificationTests(unittest.TestCase):
    @staticmethod
    def _signed_approval(
        fixture: QualificationFixture,
        material: dict[str, object],
        *,
        artifact_kind: str,
        roles: set[str],
        expires_at: datetime | None = None,
    ) -> dict[str, object]:
        approval = {
            "schema_version": (
                "agenttrust.signed-risk-acceptance.v1"
                if artifact_kind == "RISK"
                else "agenttrust.signed-exception-approval.v1"
            ),
            "artifact_kind": artifact_kind,
            "artifact_digest": hashlib.sha256(canonical_json(material)).hexdigest(),
            "release_id": fixture.release_id,
            "scope_digest": fixture.scope_digest,
            "environment_reference": fixture.environment_reference,
            "issued_at": (fixture.now - timedelta(minutes=5)).isoformat().replace(
                "+00:00", "Z"
            ),
            "expires_at": (expires_at or fixture.valid_until).isoformat().replace(
                "+00:00", "Z"
            ),
            "reviewers": fixture._reviewers(roles),
        }
        return fixture._sign_assurance(approval)

    def test_compiler_derives_unique_complete_closure_input(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = QualificationFixture(Path(raw).resolve())
            first = compile_qualification(fixture.package, fixture.anchors, now=fixture.now)
            second = compile_qualification(fixture.package, fixture.anchors, now=fixture.now)
            self.assertEqual(first, second)
            self.assertEqual(len(first["batch_statuses"]), 35)
            self.assertEqual(len(first["gate_evidence"]), 15)
            self.assertEqual(
                [entry["batch"] for entry in first["batch_statuses"]], list(range(1, 36))
            )
            self.assertTrue(all(
                entry["status"] == "EVIDENCE_VERIFIED"
                and entry["scope_digest"] == scope_digest(first["scope"])
                for entry in first["batch_statuses"]
            ))
            self.assertEqual(
                first["scope"]["reviewer_keyring_digest"],
                reviewer_keyring_digest(fixture.reviewer_keyring),
            )
            supply = next(
                entry for entry in first["gate_evidence"]
                if entry["gate_id"] == "SUPPLY_CHAIN_PROVENANCE"
            )
            self.assertEqual(
                supply["evidence_digests"]["signed_git_provenance"],
                first["scope"]["signed_git_provenance_digest"],
            )
            self.assertEqual(
                supply["evidence_digests"]["signed_release_binding"],
                first["scope"]["signed_release_binding_digest"],
            )
            self.assertEqual(
                supply["evidence_digests"]["release"], first["scope"]["release_digest"]
            )
            self.assertTrue(all(
                entry["evidence_digests"].get("reviewer_keyring")
                == first["scope"]["reviewer_keyring_digest"]
                for entry in first["gate_evidence"]
                if entry["gate_id"] != "CONTRACT_COMPATIBILITY"
            ))

    def test_all_17_conditions_have_fixed_gate_consumers(self) -> None:
        consumed = set().union(*map(set, GATE_CONDITION_REQUIREMENTS.values()))
        self.assertEqual(consumed, set(EXTERNAL_CONDITIONS))
        self.assertEqual(len(EXTERNAL_CONDITIONS), 17)
        self.assertEqual(len(GATE_CONDITION_REQUIREMENTS), 15)

    def test_manual_status_and_evidence_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = QualificationFixture(Path(raw).resolve())
            injected = copy.deepcopy(fixture.package)
            injected["batch_statuses"] = [{
                "batch": batch,
                "status": "EVIDENCE_VERIFIED",
                "evidence_digest": "a" * 64,
            } for batch in range(1, 36)]
            with self.assertRaisesRegex(GateError, "QUALIFICATION_INPUT_INVALID"):
                compile_qualification(injected, fixture.anchors, now=fixture.now)

            tampered = copy.deepcopy(fixture.package)
            tampered["condition_records"][0]["evidence_digests"]["raw-evidence"] = "b" * 64
            with self.assertRaises(GateError):
                compile_qualification(tampered, fixture.anchors, now=fixture.now)

    def test_wrong_reviewer_identity_and_untrusted_worm_key_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = QualificationFixture(Path(raw).resolve())
            wrong_reviewer = copy.deepcopy(fixture.package)
            wrong_reviewer["external_assurances"][0]["reviewers"][0][
                "organization"
            ] = "attacker-organization"
            with self.assertRaises(GateError):
                compile_qualification(wrong_reviewer, fixture.anchors, now=fixture.now)

            wrong_worm = copy.deepcopy(fixture.package)
            wrong_worm["worm_receipts"][0]["receipt"]["artifact_digest"] = "c" * 64
            with self.assertRaises(GateError):
                compile_qualification(wrong_worm, fixture.anchors, now=fixture.now)

    def test_reviewer_keyring_requires_at_least_two_trusted_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = QualificationFixture(Path(raw).resolve())
            one_key = copy.deepcopy(fixture.reviewer_keyring)
            one_key["keys"] = one_key["keys"][:1]
            anchors = fixture.anchors.__class__(
                fixture.git_keyring,
                fixture.release_keyring,
                one_key,
                fixture.worm_keyring,
            )
            package = copy.deepcopy(fixture.package)
            package["scope"]["reviewer_keyring_digest"] = reviewer_keyring_digest(one_key)
            with self.assertRaisesRegex(GateError, "REVIEWER_KEYRING_INVALID"):
                compile_qualification(package, anchors, now=fixture.now)

    def test_risk_and_exception_require_digest_bound_signed_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = QualificationFixture(Path(raw).resolve())
            package = copy.deepcopy(fixture.package)
            risk_material: dict[str, object] = {
                "risk_id": "RISK-001",
                "severity": "P2",
                "description": "A bounded residual availability risk.",
                "owner": "service-owner",
            }
            exception_material: dict[str, object] = {
                "exception_id": "EXCEPTION-001",
                "gate_id": "HA_DR_RESTORE",
                "severity": "P2",
                "owner": "platform-owner",
                "compensating_control_digests": ["8" * 64],
                "expires_at": fixture.valid_until.isoformat().replace("+00:00", "Z"),
            }
            package["residual_risks"] = [{
                **risk_material,
                "acceptance": self._signed_approval(
                    fixture,
                    risk_material,
                    artifact_kind="RISK",
                    roles={"COMPLIANCE_OWNER"},
                ),
            }]
            package["exceptions"] = [{
                **exception_material,
                "approval": self._signed_approval(
                    fixture,
                    exception_material,
                    artifact_kind="EXCEPTION",
                    roles={"COMPLIANCE_OWNER", "SECURITY_OWNER"},
                ),
            }]

            compiled = compile_qualification(package, fixture.anchors, now=fixture.now)
            compliance = fixture.reviewers_by_role["COMPLIANCE_OWNER"]["reviewer_id"]
            security = fixture.reviewers_by_role["SECURITY_OWNER"]["reviewer_id"]
            self.assertEqual(compiled["residual_risks"][0]["accepted_by"], compliance)
            self.assertEqual(
                compiled["exceptions"][0]["approved_by"], sorted([compliance, security])
            )

            tampered = copy.deepcopy(package)
            tampered["residual_risks"][0]["description"] = "Attacker changed risk"
            with self.assertRaisesRegex(GateError, "RISK_ACCEPTANCE_INVALID"):
                compile_qualification(tampered, fixture.anchors, now=fixture.now)

            cross_scope = copy.deepcopy(package)
            cross_scope["exceptions"][0]["approval"]["scope_digest"] = "9" * 64
            with self.assertRaisesRegex(GateError, "EXCEPTION_APPROVAL_INVALID"):
                compile_qualification(cross_scope, fixture.anchors, now=fixture.now)

            expired_material = dict(risk_material)
            expired_material["risk_id"] = "RISK-EXPIRED"
            expired = copy.deepcopy(fixture.package)
            expired["residual_risks"] = [{
                **expired_material,
                "acceptance": self._signed_approval(
                    fixture,
                    expired_material,
                    artifact_kind="RISK",
                    roles={"COMPLIANCE_OWNER"},
                    expires_at=fixture.now - timedelta(minutes=1),
                ),
            }]
            with self.assertRaisesRegex(GateError, "RISK_ACCEPTANCE_INVALID"):
                compile_qualification(expired, fixture.anchors, now=fixture.now)

            sod_material = dict(risk_material)
            sod_material["risk_id"] = "RISK-SOD"
            sod_material["owner"] = fixture.reviewers_by_role["COMPLIANCE_OWNER"][
                "reviewer_id"
            ]
            sod = copy.deepcopy(fixture.package)
            sod["residual_risks"] = [{
                **sod_material,
                "acceptance": self._signed_approval(
                    fixture,
                    sod_material,
                    artifact_kind="RISK",
                    roles={"COMPLIANCE_OWNER"},
                ),
            }]
            with self.assertRaisesRegex(GateError, "RISK_ACCEPTANCE_INVALID"):
                compile_qualification(sod, fixture.anchors, now=fixture.now)

    def test_legacy_unsigned_risk_and_exception_strings_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = QualificationFixture(Path(raw).resolve())
            unsigned = copy.deepcopy(fixture.package)
            unsigned["residual_risks"] = [{
                "risk_id": "RISK-LEGACY",
                "severity": "P2",
                "description": "Unsigned acceptance must not qualify.",
                "owner": "service-owner",
                "accepted_by": "arbitrary-user",
            }]
            with self.assertRaisesRegex(GateError, "QUALIFICATION_RISKS_INVALID"):
                compile_qualification(unsigned, fixture.anchors, now=fixture.now)

    def test_new_contract_schemas_are_valid_draft_2020_12(self) -> None:
        for name in (
            "qualified-evidence-record.schema.json",
            "signed-worm-evidence-receipt.schema.json",
            "worm-evidence-keyring.schema.json",
            "production-qualification-input.schema.json",
            "production-evidence-bundle-manifest.schema.json",
            "signed-risk-acceptance.schema.json",
            "signed-exception-approval.schema.json",
            "external-signing-audit-receipt.schema.json",
            "signed-external-signing-audit-receipt.schema.json",
        ):
            schema = json.loads((ROOT / "schemas/release" / name).read_text())
            self.assertEqual(
                schema.get("$schema"), "https://json-schema.org/draft/2020-12/schema"
            )
            self.assertEqual(schema.get("type"), "object")

    def test_cli_writes_create_new_derived_closure_input(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw).resolve()
            fixture = QualificationFixture(directory)
            values = {
                "input": fixture.package,
                "git": fixture.git_keyring,
                "release": fixture.release_keyring,
                "reviewer": fixture.reviewer_keyring,
                "worm": fixture.worm_keyring,
            }
            paths = {}
            for name, value in values.items():
                path = directory / f"{name}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                paths[name] = path
            output = directory / "closure-input.json"
            command = [
                sys.executable,
                str(ROOT / "scripts/compile-production-qualification.py"),
                "--input", str(paths["input"]),
                "--git-provenance-keyring", str(paths["git"]),
                "--release-binding-keyring", str(paths["release"]),
                "--reviewer-keyring", str(paths["reviewer"]),
                "--worm-keyring", str(paths["worm"]),
                "--output", str(output),
            ]
            completed = subprocess.run(
                command, cwd=ROOT, text=True, capture_output=True, timeout=30
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            emitted = json.loads(output.read_text())
            self.assertEqual(len(emitted["batch_statuses"]), 35)
            repeated = subprocess.run(
                command, cwd=ROOT, text=True, capture_output=True, timeout=30
            )
            self.assertNotEqual(repeated.returncode, 0)

            duplicate = directory / "duplicate-input.json"
            duplicate.write_text(
                paths["input"].read_text(encoding="utf-8").replace(
                    "{", '{"schema_version":"attacker-selected",', 1
                ),
                encoding="utf-8",
            )
            duplicate_output = directory / "duplicate-output.json"
            duplicate_command = list(command)
            duplicate_command[duplicate_command.index("--input") + 1] = str(duplicate)
            duplicate_command[duplicate_command.index("--output") + 1] = str(
                duplicate_output
            )
            rejected = subprocess.run(
                duplicate_command, cwd=ROOT, text=True, capture_output=True, timeout=30
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(duplicate_output.exists())


if __name__ == "__main__":
    unittest.main()
