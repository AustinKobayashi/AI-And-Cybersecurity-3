"""Forensic export helpers for one simulated mini-SOC event."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


EXPORT_FILENAMES = [
    "raw_event.json",
    "decision_record.json",
    "model_metadata.json",
    "action_record.json",
    "analyst_summary.md",
]


class ExportEvidenceError(Exception):
    """Raised when an evidence export cannot be created safely."""


def export_evidence_package(
    event_id: str,
    events_path: str | Path,
    decisions_path: str | Path,
    outputs_dir: str | Path,
) -> dict:
    """Create a local evidence export package for one selected event."""
    raw_event = find_event_by_id(events_path, event_id)
    decision_record = find_decision_by_event_id(decisions_path, event_id)
    model_metadata = build_model_metadata(decision_record)
    action_record = build_action_record(raw_event, decision_record)

    export_dir = Path(outputs_dir) / "evidence_exports" / _safe_filename(event_id)
    export_dir.mkdir(parents=True, exist_ok=True)

    _write_json(export_dir / "raw_event.json", raw_event)
    _write_json(export_dir / "decision_record.json", decision_record)
    _write_json(export_dir / "model_metadata.json", model_metadata)
    _write_json(export_dir / "action_record.json", action_record)
    (export_dir / "analyst_summary.md").write_text(
        build_analyst_summary(raw_event, decision_record, model_metadata, action_record),
        encoding="utf-8",
    )

    manifest = build_hash_manifest(export_dir, EXPORT_FILENAMES, event_id)
    _write_json(export_dir / "hash_manifest.json", manifest)

    files_written = [*EXPORT_FILENAMES, "hash_manifest.json"]
    return {
        "event_id": event_id,
        "export_dir": str(export_dir),
        "files": [str(export_dir / filename) for filename in files_written],
    }


def find_event_by_id(path: str | Path, event_id: str) -> dict:
    """Return the raw event matching an event ID from a JSONL event file."""
    return _find_jsonl_record(path, event_id, "event")


def find_decision_by_event_id(path: str | Path, event_id: str) -> dict:
    """Return the decision record matching an event ID from decisions JSONL."""
    return _find_jsonl_record(path, event_id, "decision record")


def build_model_metadata(decision_record: dict) -> dict:
    """Extract compact model metadata from a decision record."""
    return {
        "event_id": _text(decision_record.get("event_id")),
        "model_name": _text(decision_record.get("model_name")),
        "model_version": _text(decision_record.get("model_version")),
        "model_sha256": _text(decision_record.get("model_sha256")),
        "model_persistence": "trained_in_memory_not_persisted",
        "model_hash_note": (
            "The classifier is trained in memory for each run; "
            "no model artifact is saved for this capstone prototype."
        ),
        "simulated_only": True,
    }


def build_action_record(raw_event: dict, decision_record: dict) -> dict:
    """Build a compact action record from saved evidence."""
    event_id = _text(decision_record.get("event_id") or raw_event.get("event_id"))
    action_taken = _text(decision_record.get("action_taken"))

    return {
        "event_id": event_id,
        "timestamp": _text(decision_record.get("timestamp") or raw_event.get("timestamp")),
        "action_taken": action_taken,
        "review_required": bool(decision_record.get("review_required")),
        "simulated_only": bool(decision_record.get("simulated_only", True)),
        "target": _action_target(action_taken, raw_event, event_id),
        "severity": _text(decision_record.get("severity")),
        "risk_score": int(_number(decision_record.get("risk_score"))),
        "reason_codes": _list_values(decision_record.get("reason_codes")),
        "guardrail_flags": _list_values(decision_record.get("guardrail_flags")),
    }


def build_hash_manifest(export_dir: Path, filenames: list[str], event_id: str) -> dict:
    """Build SHA-256 hash metadata for exported artifacts."""
    files = {}

    for filename in filenames:
        path = export_dir / filename
        files[filename] = {
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }

    return {
        "event_id": event_id,
        "generated_at": _utc_now(),
        "hash_algorithm": "sha256",
        "files": files,
    }


def sha256_file(path: str | Path) -> str:
    """Return the SHA-256 hash for a file's bytes."""
    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def build_analyst_summary(
    raw_event: dict,
    decision_record: dict,
    model_metadata: dict,
    action_record: dict,
) -> str:
    """Create a short analyst-readable Markdown summary."""
    reason_codes = _list_values(decision_record.get("reason_codes"))
    guardrail_flags = _list_values(decision_record.get("guardrail_flags"))

    lines = [
        "# Evidence Export Summary",
        "",
        f"Event ID: {_text(decision_record.get('event_id') or raw_event.get('event_id'))}",
        f"Timestamp: {_text(decision_record.get('timestamp') or raw_event.get('timestamp'))}",
        f"Source IP: {_text(raw_event.get('src_ip'))}",
        f"Destination IP: {_text(raw_event.get('dest_ip'))}",
        f"Predicted label: {_text(decision_record.get('predicted_label'))}",
        (
            "Risk: "
            f"{int(_number(decision_record.get('risk_score')))} "
            f"({_text(decision_record.get('severity'))})"
        ),
        f"Action taken: {_text(action_record.get('action_taken'))}",
        f"Review required: {str(bool(action_record.get('review_required'))).lower()}",
        (
            "Model: "
            f"{_text(model_metadata.get('model_name'))} "
            f"{_text(model_metadata.get('model_version'))}"
        ),
        f"Model hash: {_text(model_metadata.get('model_sha256'))}",
        "",
        "## Analyst Notes",
        "",
        (
            "This package was generated from AI-generated synthetic "
            "Suricata-style telemetry. All response actions are simulated "
            "and do not change a real firewall, endpoint, account, SIEM, "
            "or SOAR system."
        ),
        "",
        f"Reason codes: {_joined_values(reason_codes)}",
        f"Safety check flags: {_joined_values(guardrail_flags)}",
    ]
    return "\n".join(lines) + "\n"


def _find_jsonl_record(path: str | Path, event_id: str, record_name: str) -> dict:
    input_path = Path(path)

    if not input_path.exists():
        raise ExportEvidenceError(f"Input file not found: {input_path}")

    with input_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            raw_line = line.strip()
            if not raw_line:
                continue

            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ExportEvidenceError(
                    f"{input_path} line {line_number} is not valid JSON: {exc.msg}"
                ) from exc

            if isinstance(record, dict) and _text(record.get("event_id")) == str(event_id):
                return record

    raise ExportEvidenceError(f"No {record_name} found for event_id: {event_id}")


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _action_target(action_taken: str, raw_event: dict, event_id: str) -> str:
    if action_taken == "simulated_block_ip":
        return _text(raw_event.get("src_ip"))
    if action_taken in {"auto_close", "create_ticket", "log_only", "review_queue"}:
        return event_id
    return ""


def _safe_filename(value: str) -> str:
    safe = "".join(
        character if character.isalnum() or character in {"-", "_"} else "_"
        for character in str(value)
    )
    return safe or "event"


def _joined_values(values: list[str]) -> str:
    return ", ".join(values) if values else "none"


def _list_values(value) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item]
    if isinstance(value, str) and value:
        return [value]
    return []


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _number(value) -> float:
    if isinstance(value, bool) or value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
