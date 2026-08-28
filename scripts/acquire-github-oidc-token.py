#!/usr/bin/env python3
"""Acquire a GitHub Actions OIDC token without exposing it to command output."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import ssl
from typing import Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener


class OidcError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acquire-github-oidc-token")
    parser.add_argument("--audience", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    endpoint = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    parsed = urlparse(endpoint)
    if (
        not args.audience
        or len(args.audience) > 256
        or any(character.isspace() for character in args.audience)
        or parsed.scheme != "https"
        or parsed.hostname is None
        or not parsed.hostname.endswith(".actions.githubusercontent.com")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not request_token
        or any(character.isspace() for character in request_token)
        or not args.output.is_absolute()
        or args.output.exists()
        or not args.output.parent.is_dir()
    ):
        raise OidcError("GITHUB_OIDC_CONFIGURATION_INVALID")
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["audience"] = args.audience
    url = urlunparse(parsed._replace(query=urlencode(query)))
    request = Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {request_token}",
            "User-Agent": "AgentTrust-Production-Closure/1",
        },
    )
    opener = build_opener(
        _NoRedirect(), HTTPSHandler(context=ssl.create_default_context())
    )
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                raise OidcError("GITHUB_OIDC_RESPONSE_INVALID")
            payload = response.read(256 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError):
        raise OidcError("GITHUB_OIDC_UNAVAILABLE") from None
    if not payload or len(payload) > 256 * 1024:
        raise OidcError("GITHUB_OIDC_RESPONSE_INVALID")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OidcError("GITHUB_OIDC_RESPONSE_INVALID") from None
    if (
        not isinstance(document, dict)
        or set(document) not in ({"value"}, {"count", "value"})
        or not isinstance(document.get("value"), str)
        or not document["value"]
        or len(document["value"]) > 128 * 1024
        or any(character.isspace() for character in document["value"])
    ):
        raise OidcError("GITHUB_OIDC_RESPONSE_INVALID")
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(document["value"])
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OidcError as error:
        print(str(error))
        raise SystemExit(2) from None
