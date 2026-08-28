#!/usr/bin/env python3
"""Report release blockers without converting local code into production evidence."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Sequence

from python.production_gates.release_code_manifest import (
    ReleaseCodeManifestError,
    load_release_code_manifest,
    repository_file_is_safe,
)


ROOT = Path(__file__).resolve().parents[1]
class ReadinessError(RuntimeError):
    pass


def _reject_duplicate_key(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ReadinessError(f"READINESS_DUPLICATE_JSON_KEY:{key}")
        value[key] = item
    return value


def _json(path: Path) -> dict[str, Any]:
    if (
        path.is_symlink()
        or not path.is_file()
        or not 1 <= path.stat(follow_symlinks=False).st_size <= 16_000_000
    ):
        raise ReadinessError(f"READINESS_INPUT_INVALID:{path.relative_to(ROOT)}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_key,
        )
    except ReadinessError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ReadinessError(f"READINESS_INPUT_INVALID:{path.relative_to(ROOT)}") from None
    if not isinstance(value, dict):
        raise ReadinessError(f"READINESS_INPUT_INVALID:{path.relative_to(ROOT)}")
    return value


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=15,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )


def _git_candidate() -> dict[str, object]:
    head_result = _git("rev-parse", "HEAD")
    format_result = _git("rev-parse", "--show-object-format")
    status_result = _git("status", "--porcelain=v1", "--untracked-files=all")
    head = head_result.stdout.strip()
    object_format = format_result.stdout.strip()
    expected = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    valid_head = len(head) == expected and all(character in "0123456789abcdef" for character in head)
    commit_signed = valid_head and _git("verify-commit", head).returncode == 0
    signed_tags: list[str] = []
    if valid_head:
        for tag in _git("tag", "--points-at", head).stdout.splitlines():
            tag = tag.strip()
            if (
                tag
                and _git("cat-file", "-t", f"refs/tags/{tag}").stdout.strip() == "tag"
                and _git("verify-tag", f"refs/tags/{tag}").returncode == 0
            ):
                signed_tags.append(tag)
    immutable = (
        valid_head
        and status_result.returncode == 0
        and not status_result.stdout
        and commit_signed
        and len(signed_tags) == 1
    )
    remote_default_branch_ref: str | None = None
    remote_head: str | None = None
    remote_tag_object: str | None = None
    remote_tag_target: str | None = None
    remote_release_tag_verified = False
    if immutable:
        tag = signed_tags[0]
        remote = _git(
            "ls-remote",
            "--symref",
            "origin",
            "HEAD",
            f"refs/tags/{tag}",
            f"refs/tags/{tag}^{{}}",
        )
        if remote.returncode == 0:
            for line in remote.stdout.splitlines():
                fields = line.split("\t", 1)
                if len(fields) != 2:
                    continue
                value, reference = fields
                if value.startswith("ref: ") and reference == "HEAD":
                    remote_default_branch_ref = value.removeprefix("ref: ")
                elif reference == "HEAD":
                    remote_head = value
                elif reference == f"refs/tags/{tag}":
                    remote_tag_object = value
                elif reference == f"refs/tags/{tag}^{{}}":
                    remote_tag_target = value
            remote_release_tag_verified = (
                isinstance(remote_default_branch_ref, str)
                and remote_default_branch_ref.startswith("refs/heads/")
                and remote_head == head
                and remote_tag_object is not None
                and remote_tag_target == head
            )
    return {
        "release_id": f"git:{object_format}:{head}" if immutable else "WORKTREE-NO-GIT",
        "head": head if valid_head else None,
        "object_format": object_format if expected else None,
        "clean_worktree": status_result.returncode == 0 and not status_result.stdout,
        "commit_signature_verified": commit_signed,
        "signed_annotated_tags_at_head": signed_tags,
        "local_immutable_candidate_ready": immutable,
        "remote_default_branch_ref": remote_default_branch_ref,
        "remote_default_branch_head": remote_head,
        "remote_release_tag_object": remote_tag_object,
        "remote_release_tag_target": remote_tag_target,
        "remote_release_tag_verified": remote_release_tag_verified,
        "immutable_candidate_ready": immutable and remote_release_tag_verified,
    }


def build_report() -> dict[str, object]:
    statuses = [
        _json(ROOT / f"evidence/batch-{batch:02}/IMPLEMENTATION_STATUS.json")
        for batch in range(1, 37)
    ]
    batch_counts = Counter(str(item.get("status", "INVALID")) for item in statuses)
    matrix = _json(ROOT / "evidence/production-closure/external-condition-matrix.json")
    readiness = _json(ROOT / "evidence/production-closure/production-readiness-report.json")
    certificate = _json(ROOT / "evidence/production-closure/CERTIFICATE_NOT_ISSUED.json")
    conditions = matrix.get("conditions")
    if not isinstance(conditions, list) or len(conditions) != 17:
        raise ReadinessError("READINESS_EXTERNAL_CONDITION_MATRIX_INVALID")
    try:
        required_release_code = load_release_code_manifest(ROOT)
    except ReleaseCodeManifestError:
        raise ReadinessError("READINESS_RELEASE_CODE_MANIFEST_INVALID") from None
    missing_code = [
        path for path in required_release_code if not repository_file_is_safe(ROOT, path)
    ]
    external_tasks = []
    external_verified = 0
    for raw in conditions:
        if not isinstance(raw, dict) or not isinstance(raw.get("condition_id"), str):
            raise ReadinessError("READINESS_EXTERNAL_CONDITION_MATRIX_INVALID")
        status = str(raw.get("external_status", "INVALID"))
        if status == "EVIDENCE_VERIFIED":
            external_verified += 1
        else:
            external_tasks.append({
                "task_id": raw["condition_id"],
                "phase": "PRODUCTION_ENVIRONMENT",
                "status": status,
                "required_external_inputs": raw.get("required_external_inputs", []),
            })
    heavy = readiness.get("local_code_gates")
    current_validation_tasks = [
        {"task_id": name, "phase": "CURRENT_RELEASE_VALIDATION", "status": status}
        for name, status in sorted(heavy.items())
        if isinstance(heavy, dict) and not str(status).startswith("PASS")
    ] if isinstance(heavy, dict) else [{
        "task_id": "CURRENT_RELEASE_VALIDATION",
        "phase": "CURRENT_RELEASE_VALIDATION",
        "status": "INVALID",
    }]
    candidate = _git_candidate()
    workflow_tasks = [
        {
            "task_id": task_id,
            "phase": "RELEASE_EXECUTION",
            "status": "NOT_RUN",
        }
        for task_id in (
            "CONFIGURE_COMMITTED_CODEOWNERS_AND_DIGEST",
            "APPLY_GITHUB_RELEASE_GOVERNANCE",
            "CONFIGURE_PROTECTED_ENVIRONMENT_VARIABLES",
            "CONFIGURE_DEPLOYMENT_CUTOVER_BROKER",
            "PROVISION_DEDICATED_SELF_HOSTED_RUNNERS",
            "INITIALIZE_PROTECTED_REVOCATION_CHECKPOINT",
            "CONFIGURE_ROTATING_REVOCATION_DISTRIBUTION",
            "PROVISION_LOCKED_RELEASE_EVIDENCE_TARGET",
            "VERIFY_PRODUCTION_ACTIVATION_LEASE_AND_WRITER_FENCE",
            "RUN_PRODUCTION_RELEASE_CANDIDATE",
            "RUN_PRODUCTION_EVIDENCE_INTAKE",
            "RUN_PRODUCTION_ASSURANCE",
            "EXECUTE_SIGNED_BLUE_GREEN_DEPLOYMENT",
            "RUN_PRODUCTION_RELEASE",
        )
    ]
    blockers: list[dict[str, object]] = [
        *({
            "task_id": path,
            "phase": "PORTABLE_RELEASE_CODE",
            "status": "MISSING",
        } for path in missing_code),
        *current_validation_tasks,
        *external_tasks,
        *workflow_tasks,
    ]
    if candidate["release_id"] == "WORKTREE-NO-GIT":
        blockers.append({
            "task_id": "IMMUTABLE_SIGNED_GIT_RELEASE",
            "phase": "RELEASE_SOURCE",
            "status": "NOT_VERIFIED",
        })
    if certificate.get("decision") != "ISSUED":
        blockers.append({
            "task_id": "PRODUCTION_CLOSURE_CERTIFICATE",
            "phase": "CERTIFICATION",
            "status": str(certificate.get("decision", "INVALID")),
        })
    eligible = (
        not blockers
        and batch_counts == {"EVIDENCE_VERIFIED": 36}
        and external_verified == 17
        and candidate["immutable_candidate_ready"] is True
        and certificate.get("decision") == "ISSUED"
    )
    report: dict[str, object] = {
        "schema_version": "agenttrust.production-release-readiness-report.v1",
        "evaluated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "portable_release_code": "COMPLETE" if not missing_code else "INCOMPLETE",
        "candidate": candidate,
        "batch_status_summary": dict(sorted(batch_counts.items())),
        "external_condition_summary": {
            "total": 17,
            "evidence_verified": external_verified,
            "open": 17 - external_verified,
        },
        "production_closure_certificate": certificate.get("decision", "INVALID"),
        "eligible": eligible,
        "blocking_task_count": len(blockers),
        "blocking_tasks": blockers,
    }
    report["report_digest"] = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="report-production-release-readiness")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = build_report()
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        if not args.output.is_absolute() or args.output.exists() or not args.output.parent.is_dir():
            raise ReadinessError("READINESS_OUTPUT_INVALID")
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    print(payload, end="")
    return 0 if report["eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
