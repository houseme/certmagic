#!/usr/bin/env python3
"""Validate a redacted certmagic external-evidence/v1 record.

This validator is intentionally standard-library-only and offline. It is a CI
guard for evidence artifacts; it is not an issuer/API client and must never
receive provider credentials.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA = "certmagic.external-evidence/v1"
ROOT_KEYS = {"schema", "run", "subject", "contract", "evidence", "cleanup"}
RUN_KEYS = {"capability", "status", "started_at_utc", "finished_at_utc", "repository_revision", "runner"}
SUBJECT_KEYS = {"provider", "endpoint_class", "domain", "node_count"}
CONTRACT_KEYS = {"confirmation", "credential_source", "challenge_url", "expected_body"}
EVIDENCE_KEYS = {"order_id", "certificate_id", "observations"}
CLEANUP_KEYS = {"certificate_revoked", "temporary_storage_removed", "cleanup_status", "notes"}
CAPABILITIES = {
    "zerossl-rest", "zerossl-acme", "public-http-01", "public-tls-alpn-01",
    "distributed-http-01", "dns-01", "ocsp",
}
STATUSES = {"pass", "fail", "not-run"}
CLEANUP_VALUES = {"yes", "no", "not-applicable", "unknown"}
TEMPLATE_NOTES = "<no API keys, private keys, tokens, challenge bodies, or internal addresses>"

# Provider credentials, private key material, copied challenge data, and
# explicit internal addresses must not enter a CI evidence artifact.
SENSITIVE_TEXT = re.compile(
    r"(?:-----begin|private\s+key|api[_ -]?key\s*[:=]|"
    r"eab[_ -]?(?:key|hmac|secret)\s*[:=]|authorization\s*:\s*bearer|"
    r"password\s*[:=]|key\s+authorization\s*[:=]|challenge\s+body\s*[:=]|"
    r"(?:zero|cert)ssl_api_key\s*=|"
    r"certmagic_external_confirm\s*=\s*i_understand_external_network)",
    re.IGNORECASE,
)
PRIVATE_ADDRESS = re.compile(
    r"(?:https?://)?(?:localhost|127\.0\.0\.1|::1|"
    r"10\.(?:\d{1,3}\.){2}\d{1,3}|"
    r"192\.168\.(?:\d{1,3}\.)\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})",
    re.IGNORECASE,
)


class ValidationError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _keys(value: Any, expected: set[str], path: str) -> None:
    if not isinstance(value, dict):
        raise ValidationError(f"{path} must be an object")
    actual = set(value)
    missing = expected - actual
    extra = actual - expected
    if missing:
        raise ValidationError(f"{path} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ValidationError(f"{path} has unknown keys: {', '.join(sorted(extra))}")


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValidationError(f"{path} must be a non-empty string")
    if any(ord(char) < 0x20 for char in value):
        raise ValidationError(f"{path} contains a control character")
    return value


def _timestamp(value: Any, path: str) -> None:
    value = _string(value, path)
    if value == "<RFC3339>":
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{path} must be RFC3339 or <RFC3339>") from error
    if parsed.tzinfo is None:
        raise ValidationError(f"{path} must include a timezone")


def _safe_text(value: Any, path: str) -> str:
    value = _string(value, path)
    if value == TEMPLATE_NOTES:
        return value
    if SENSITIVE_TEXT.search(value):
        raise ValidationError(f"{path} contains credential or challenge material")
    if PRIVATE_ADDRESS.search(value):
        raise ValidationError(f"{path} contains a private/internal address")
    return value


def validate(record: Any) -> None:
    _keys(record, ROOT_KEYS, "record")
    if record["schema"] != SCHEMA:
        raise ValidationError(f"schema must be {SCHEMA}")

    run = record["run"]
    _keys(run, RUN_KEYS, "run")
    template_capability = (
        "<zerossl-rest|zerossl-acme|public-http-01|public-tls-alpn-01|"
        "distributed-http-01|dns-01|ocsp>"
    )
    if run["capability"] not in CAPABILITIES and run["capability"] != template_capability:
        raise ValidationError("run.capability is not a supported capability")
    if run["status"] not in STATUSES and run["status"] != "<pass|fail|not-run>":
        raise ValidationError("run.status is not a supported status")
    _timestamp(run["started_at_utc"], "run.started_at_utc")
    _timestamp(run["finished_at_utc"], "run.finished_at_utc")
    _safe_text(run["repository_revision"], "run.repository_revision")
    _safe_text(run["runner"], "run.runner")

    subject = record["subject"]
    _keys(subject, SUBJECT_KEYS, "subject")
    for key in ("provider", "endpoint_class", "domain"):
        _safe_text(subject[key], f"subject.{key}")
    if subject["node_count"] != "<integer or null>" and subject["node_count"] is not None:
        if isinstance(subject["node_count"], bool) or not isinstance(subject["node_count"], int):
            raise ValidationError("subject.node_count must be an integer or null")
        if subject["node_count"] < 0:
            raise ValidationError("subject.node_count must not be negative")

    contract = record["contract"]
    _keys(contract, CONTRACT_KEYS, "contract")
    if contract["confirmation"] != "not recorded":
        raise ValidationError("contract.confirmation must remain 'not recorded'")
    if contract["credential_source"] != "environment or secret manager; value not recorded":
        raise ValidationError("contract.credential_source must not contain a credential")
    if contract["challenge_url"] not in {"<keep outside repository logs>", "not recorded"}:
        raise ValidationError("contract.challenge_url must remain redacted")
    if contract["expected_body"] != "not recorded":
        raise ValidationError("contract.expected_body must remain redacted")

    evidence = record["evidence"]
    _keys(evidence, EVIDENCE_KEYS, "evidence")
    _safe_text(evidence["order_id"], "evidence.order_id")
    _safe_text(evidence["certificate_id"], "evidence.certificate_id")
    observations = evidence["observations"]
    if not isinstance(observations, list):
        raise ValidationError("evidence.observations must be an array")
    for index, observation in enumerate(observations):
        _safe_text(observation, f"evidence.observations[{index}]")

    cleanup = record["cleanup"]
    _keys(cleanup, CLEANUP_KEYS, "cleanup")
    for key in ("certificate_revoked", "temporary_storage_removed"):
        if cleanup[key] not in CLEANUP_VALUES and cleanup[key] != "<yes|no|not-applicable|unknown>":
            raise ValidationError(f"cleanup.{key} has an unsupported value")
    if cleanup["cleanup_status"] not in STATUSES and cleanup["cleanup_status"] != "<pass|fail|not-run>":
        raise ValidationError("cleanup.cleanup_status has an unsupported value")
    _safe_text(cleanup["notes"], "cleanup.notes")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} RECORD.json", file=sys.stderr)
        return 2
    path = Path(argv[1])
    try:
        with path.open(encoding="utf-8") as handle:
            record = json.load(handle, object_pairs_hook=_pairs)
        validate(record)
    except (OSError, json.JSONDecodeError, ValidationError) as error:
        print(f"external evidence validation failed: {error}", file=sys.stderr)
        return 1
    print(f"external evidence validation passed: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
