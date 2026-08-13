"""Read-only SigV4 gate for managed S3 Object Lock compliance retention."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
from urllib.parse import quote, urlparse
from xml.etree import ElementTree

from python.production_gates.live_integrations import (
    BoundedHttpClient,
    ConfigurationMissing,
    GateError,
    GateResult,
    HttpTransport,
)


_BUCKET = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])$")
_SAFE_ENV = re.compile(r"^[A-Z][A-Z0-9_]{1,79}$")
_SAFE_REGION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")


def _secret(name: str) -> str:
    if not _SAFE_ENV.fullmatch(name):
        raise GateError("OBJECT_LOCK_SECRET_REFERENCE_INVALID")
    value = os.environ.get(name, "")
    if not value:
        raise ConfigurationMissing("OBJECT_LOCK_SECRET_NOT_CONFIGURED")
    if len(value) > 16_384 or any(ord(character) < 32 for character in value):
        raise GateError("OBJECT_LOCK_SECRET_INVALID")
    return value


def _signing_key(secret_key: str, date: str, region: str) -> bytes:
    def sign(key: bytes, value: str) -> bytes:
        return hmac.new(key, value.encode(), hashlib.sha256).digest()

    return sign(sign(sign(sign(("AWS4" + secret_key).encode(), date), region), "s3"), "aws4_request")


def _request(
    transport: HttpTransport,
    endpoint: str,
    region: str,
    access_key: str,
    secret_key: str,
    bucket: str,
    object_key: str | None,
    query: Mapping[str, str],
    method: str,
) -> tuple[int, Mapping[str, str], bytes]:
    parsed = urlparse(endpoint)
    path = "/" + quote(bucket, safe="-_.~")
    if object_key is not None:
        path += "/" + quote(object_key, safe="/-_.~")
    canonical_query = "&".join(
        f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
        for key, value in sorted(query.items())
    )
    url = endpoint.rstrip("/") + path
    if canonical_query:
        url += "?" + canonical_query
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_headers = (
        f"host:{parsed.netloc}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    canonical_request = "\n".join(
        [
            method,
            path,
            canonical_query,
            canonical_headers,
            "host;x-amz-content-sha256;x-amz-date",
            payload_hash,
        ]
    )
    scope = f"{date}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )
    signature = hmac.new(
        _signing_key(secret_key, date, region), string_to_sign.encode(), hashlib.sha256
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        f"Signature={signature}"
    )
    return transport.request(
        method,
        url,
        headers={
            "Authorization": authorization,
            "Host": parsed.netloc,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        },
        maximum_bytes=1_048_576,
    )


def _xml(payload: bytes, code: str) -> ElementTree.Element:
    if len(payload) > 1_048_576 or b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise GateError(code)
    try:
        return ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        raise GateError(code) from None


def _find_text(root: ElementTree.Element, name: str) -> str | None:
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == name:
            return element.text.strip() if element.text else ""
    return None


def probe_s3_compliance_retention(
    endpoint: str,
    region: str,
    bucket: str,
    object_key: str,
    version_id: str,
    access_key_environment: str,
    secret_key_environment: str,
    *,
    minimum_remaining_days: int = 30,
    transport: HttpTransport | None = None,
) -> GateResult:
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not _SAFE_REGION.fullmatch(region)
        or not _BUCKET.fullmatch(bucket)
        or ".." in bucket
        or not object_key
        or len(object_key.encode()) > 1024
        or any(ord(character) < 32 for character in object_key)
        or not version_id
        or len(version_id) > 1024
        or any(ord(character) < 32 for character in version_id)
        or not 1 <= minimum_remaining_days <= 36500
    ):
        raise GateError("OBJECT_LOCK_CONFIGURATION_INVALID")
    access_key = _secret(access_key_environment)
    secret_key = _secret(secret_key_environment)
    client = transport or BoundedHttpClient(timeout_seconds=30)

    status, _, lock_payload = _request(
        client, endpoint, region, access_key, secret_key, bucket, None,
        {"object-lock": ""}, "GET",
    )
    lock = _xml(lock_payload, "OBJECT_LOCK_RESPONSE_INVALID")
    retention_unit = _find_text(lock, "Days") or _find_text(lock, "Years")
    if (
        status != 200
        or _find_text(lock, "ObjectLockEnabled") != "Enabled"
        or _find_text(lock, "Mode") != "COMPLIANCE"
        or retention_unit is None
        or not retention_unit.isdigit()
        or int(retention_unit) <= 0
    ):
        raise GateError("OBJECT_LOCK_COMPLIANCE_NOT_ENABLED")

    status, _, versioning_payload = _request(
        client, endpoint, region, access_key, secret_key, bucket, None,
        {"versioning": ""}, "GET",
    )
    versioning = _xml(versioning_payload, "OBJECT_VERSIONING_RESPONSE_INVALID")
    if status != 200 or _find_text(versioning, "Status") != "Enabled":
        raise GateError("OBJECT_VERSIONING_NOT_ENABLED")

    object_query = {"retention": "", "versionId": version_id}
    status, _, retention_payload = _request(
        client, endpoint, region, access_key, secret_key, bucket, object_key,
        object_query, "GET",
    )
    retention = _xml(retention_payload, "OBJECT_RETENTION_RESPONSE_INVALID")
    retain_until_text = _find_text(retention, "RetainUntilDate")
    if status != 200 or _find_text(retention, "Mode") != "COMPLIANCE" or not retain_until_text:
        raise GateError("OBJECT_RETENTION_COMPLIANCE_INVALID")
    try:
        retain_until = datetime.fromisoformat(retain_until_text.replace("Z", "+00:00"))
    except ValueError:
        raise GateError("OBJECT_RETENTION_COMPLIANCE_INVALID") from None
    if retain_until.tzinfo is None:
        raise GateError("OBJECT_RETENTION_COMPLIANCE_INVALID")
    remaining_seconds = (retain_until - datetime.now(timezone.utc)).total_seconds()
    if remaining_seconds < minimum_remaining_days * 86400:
        raise GateError("OBJECT_RETENTION_WINDOW_TOO_SHORT")

    status, headers, _ = _request(
        client, endpoint, region, access_key, secret_key, bucket, object_key,
        {"versionId": version_id}, "HEAD",
    )
    if status != 200:
        raise GateError("OBJECT_LOCKED_VERSION_NOT_READABLE")
    return GateResult(
        gate="OBJECT_STORE_S3_COMPLIANCE_RETENTION_REAL_PROTOCOL",
        status="PASS_REAL_PROTOCOL",
        environment_reference=f"s3-object-lock://{parsed.hostname}/{bucket}",
        checks={
            "object_lock_enabled": True,
            "default_retention_mode": "COMPLIANCE",
            "versioning_enabled": True,
            "protected_version_readable": True,
            "protected_object_key_digest": hashlib.sha256(object_key.encode()).hexdigest(),
            "protected_version_id_digest": hashlib.sha256(version_id.encode()).hexdigest(),
            "retention_remaining_seconds": int(remaining_seconds),
            "minimum_remaining_days": minimum_remaining_days,
            "object_lock_configuration_digest": hashlib.sha256(lock_payload).hexdigest(),
            "object_retention_digest": hashlib.sha256(retention_payload).hexdigest(),
            "head_metadata_digest": hashlib.sha256(
                json.dumps(dict(headers), sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "probe_is_read_only": True,
            "delete_attempted": False,
            "credentials_redacted": True,
        },
    )


def _write_new(path: Path, report: Mapping[str, Any]) -> None:
    if not path.is_absolute() or path.exists():
        raise GateError("OBJECT_LOCK_REPORT_PATH_INVALID")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrust-object-lock-gate")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--object-key", required=True)
    parser.add_argument("--version-id", required=True)
    parser.add_argument("--access-key-env", required=True)
    parser.add_argument("--secret-key-env", required=True)
    parser.add_argument("--minimum-remaining-days", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = probe_s3_compliance_retention(
            args.endpoint, args.region, args.bucket, args.object_key, args.version_id,
            args.access_key_env, args.secret_key_env,
            minimum_remaining_days=args.minimum_remaining_days,
        )
        exit_code = 0
    except ConfigurationMissing as error:
        result = GateResult(
            "OBJECT_STORE_S3_COMPLIANCE_RETENTION_REAL_PROTOCOL",
            "NOT_RUN_CONFIGURATION", "unconfigured", {"error_code": str(error)},
        )
        exit_code = 3
    except GateError as error:
        result = GateResult(
            "OBJECT_STORE_S3_COMPLIANCE_RETENTION_REAL_PROTOCOL",
            "FAIL", "configured-target", {"error_code": str(error)},
        )
        exit_code = 2
    _write_new(args.output, result.as_dict())
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
