"""Load and validate simulated Suricata-style JSONL events."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


EXPECTED_LABELS = {
    "benign",
    "credential_access",
    "lateral_movement",
    "command_and_control",
    "exploit_attempt",
    "needs_human_review",
}

REQUIRED_TOP_LEVEL = [
    "event_id",
    "timestamp",
    "event_type",
    "src_ip",
    "dest_ip",
    "dest_port",
    "proto",
    "community_id",
    "pcap_filename",
    "asset_id",
    "asset_role",
    "asset_criticality",
    "expected_label",
    "scenario",
    "synthetic_ground_truth",
    "review_reason",
]

REQUIRED_NESTED = [
    ("alert", "signature"),
    ("alert", "severity"),
    ("http", "hostname"),
    ("http", "url"),
    ("http", "user_agent"),
    ("dns", "query"),
    ("flow", "bytes_toserver"),
    ("flow", "bytes_toclient"),
    ("flow", "pkts_toserver"),
    ("flow", "pkts_toclient"),
]


def load_events(path: str) -> list[dict]:
    """Return valid events with a small `_intake` metadata block attached."""
    events = []

    for record in load_event_records(path):
        if not record["valid"]:
            continue

        event = dict(record["event"])
        event["_intake"] = {
            "line_number": record["line_number"],
            "raw_sha256": record["raw_sha256"],
            "review_required": record["review_required"],
            "review_reasons": record["review_reasons"],
            "errors": record["errors"],
        }
        events.append(event)

    return events


def load_event_records(path: str) -> list[dict]:
    """Read every JSONL row and keep invalid rows as review records."""
    records = []

    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            raw_line = line.rstrip("\r\n")
            line_hash = raw_event_hash(raw_line)

            if not raw_line.strip():
                records.append(
                    _record(line_number, line_hash, None, False, ["blank line"])
                )
                continue

            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                records.append(
                    _record(
                        line_number,
                        line_hash,
                        None,
                        False,
                        [f"invalid JSON: {exc.msg}"],
                    )
                )
                continue

            errors = validate_event(event)
            records.append(_record(line_number, line_hash, event, not errors, errors))

    return records


def validate_event(event: dict) -> list[str]:
    """Return readable validation errors for one event dictionary."""
    errors = []

    if not isinstance(event, dict):
        return ["event is not a JSON object"]

    for field in REQUIRED_TOP_LEVEL:
        if field not in event:
            errors.append(f"missing field: {field}")

    for parent, child in REQUIRED_NESTED:
        if not isinstance(event.get(parent), dict) or child not in event[parent]:
            errors.append(f"missing field: {parent}.{child}")

    if "dest_port" in event and not _is_int_in_range(event["dest_port"], 1, 65535):
        errors.append("dest_port must be an integer from 1 to 65535")

    severity = _nested_value(event, "alert", "severity")
    if severity is not None and not _is_int_in_range(severity, 1, 4):
        errors.append("alert.severity must be an integer from 1 to 4")

    label = event.get("expected_label")
    if label is not None and label not in EXPECTED_LABELS:
        errors.append(f"expected_label is not recognized: {label}")

    timestamp = event.get("timestamp")
    if timestamp is not None and not _looks_like_timestamp(timestamp):
        errors.append("timestamp must be an ISO-style timestamp")

    return errors


def summarize_records(records: list[dict]) -> dict:
    """Build a simple summary for the CLI and tests."""
    labels = Counter()

    for record in records:
        event = record.get("event")
        if record.get("valid") and isinstance(event, dict):
            labels[event.get("expected_label", "unknown")] += 1

    valid = sum(1 for record in records if record["valid"])
    review_required = sum(1 for record in records if record["review_required"])

    return {
        "total": len(records),
        "valid": valid,
        "invalid": len(records) - valid,
        "review_required": review_required,
        "labels": dict(sorted(labels.items())),
    }


def raw_event_hash(raw_line: str) -> str:
    """Return the SHA-256 hash for one raw JSONL line."""
    return hashlib.sha256(raw_line.encode("utf-8")).hexdigest()


def _record(
    line_number: int,
    line_hash: str,
    event: dict | None,
    valid: bool,
    errors: list[str],
) -> dict:
    review_reasons = _review_reasons(event, errors) if valid else list(errors)

    return {
        "line_number": line_number,
        "raw_sha256": line_hash,
        "event": event,
        "valid": valid,
        "errors": errors,
        "review_required": bool(errors or review_reasons),
        "review_reasons": review_reasons,
    }


def _review_reasons(event: dict | None, errors: list[str]) -> list[str]:
    if errors or not isinstance(event, dict):
        return list(errors)

    reasons = []

    if event.get("expected_label") == "needs_human_review":
        reasons.append("expected_label requires human review")
    if event.get("review_reason"):
        reasons.append(str(event["review_reason"]))
    if event.get("obfuscation_flags"):
        reasons.append("obfuscation flags present")
    if event.get("missing_field_flags"):
        reasons.append("missing field flags present")
    if event.get("prompt_injection_like_text"):
        reasons.append("prompt-injection-like text present")

    return reasons


def _nested_value(event: dict, parent: str, child: str):
    value = event.get(parent)
    if isinstance(value, dict):
        return value.get(child)
    return None


def _is_int_in_range(value, minimum: int, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def _looks_like_timestamp(value) -> bool:
    if not isinstance(value, str) or not value:
        return False

    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False

    return True
