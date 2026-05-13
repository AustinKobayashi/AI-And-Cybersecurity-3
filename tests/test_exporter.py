import hashlib
import json
from pathlib import Path

import pytest

from minisoc.exporter import ExportEvidenceError, export_evidence_package


def test_export_evidence_package_creates_expected_files(tmp_path):
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    outputs_dir = tmp_path / "outputs"
    event = _event("demo-0008")
    decision = _decision("demo-0008")
    _write_jsonl(events_path, [_event("demo-0001"), event])
    _write_jsonl(decisions_path, [_decision("demo-0001"), decision])

    export = export_evidence_package(
        "demo-0008",
        events_path,
        decisions_path,
        outputs_dir,
    )

    export_dir = outputs_dir / "evidence_exports" / "demo-0008"
    expected_files = {
        "raw_event.json",
        "decision_record.json",
        "model_metadata.json",
        "action_record.json",
        "analyst_summary.md",
        "hash_manifest.json",
    }

    assert export["event_id"] == "demo-0008"
    assert export["export_dir"] == str(export_dir)
    assert {path.name for path in export_dir.iterdir()} == expected_files
    assert {Path(path).name for path in export["files"]} == expected_files


def test_exported_records_preserve_selected_event_and_decision(tmp_path):
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    outputs_dir = tmp_path / "outputs"
    _write_jsonl(events_path, [_event("demo-0008")])
    _write_jsonl(decisions_path, [_decision("demo-0008")])

    export_evidence_package("demo-0008", events_path, decisions_path, outputs_dir)

    export_dir = outputs_dir / "evidence_exports" / "demo-0008"
    raw_event = _read_json(export_dir / "raw_event.json")
    decision_record = _read_json(export_dir / "decision_record.json")

    assert raw_event["event_id"] == "demo-0008"
    assert raw_event["synthetic_ground_truth"] == "AI-generated synthetic telemetry"
    assert decision_record["event_id"] == "demo-0008"
    assert decision_record["action_taken"] == "create_ticket"


def test_exported_model_and_action_records_are_modest_and_simulated(tmp_path):
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    outputs_dir = tmp_path / "outputs"
    _write_jsonl(events_path, [_event("demo-0008")])
    _write_jsonl(decisions_path, [_decision("demo-0008")])

    export_evidence_package("demo-0008", events_path, decisions_path, outputs_dir)

    export_dir = outputs_dir / "evidence_exports" / "demo-0008"
    model_metadata = _read_json(export_dir / "model_metadata.json")
    action_record = _read_json(export_dir / "action_record.json")
    analyst_summary = (export_dir / "analyst_summary.md").read_text(encoding="utf-8")

    assert model_metadata["model_sha256"] == "in_memory_not_persisted"
    assert model_metadata["model_persistence"] == "trained_in_memory_not_persisted"
    assert model_metadata["simulated_only"] is True
    assert action_record["event_id"] == "demo-0008"
    assert action_record["action_taken"] == "create_ticket"
    assert action_record["target"] == "demo-0008"
    assert action_record["simulated_only"] is True
    assert "AI-generated synthetic" in analyst_summary
    assert "All response actions are simulated" in analyst_summary


def test_hash_manifest_matches_exported_artifacts(tmp_path):
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    outputs_dir = tmp_path / "outputs"
    _write_jsonl(events_path, [_event("demo-0008")])
    _write_jsonl(decisions_path, [_decision("demo-0008")])

    export_evidence_package("demo-0008", events_path, decisions_path, outputs_dir)

    export_dir = outputs_dir / "evidence_exports" / "demo-0008"
    manifest = _read_json(export_dir / "hash_manifest.json")

    assert "hash_manifest.json" not in manifest["files"]
    assert set(manifest["files"]) == {
        "raw_event.json",
        "decision_record.json",
        "model_metadata.json",
        "action_record.json",
        "analyst_summary.md",
    }

    for filename, metadata in manifest["files"].items():
        artifact_path = export_dir / filename
        artifact_bytes = artifact_path.read_bytes()
        assert metadata["sha256"] == hashlib.sha256(artifact_bytes).hexdigest()
        assert metadata["bytes"] == len(artifact_bytes)


def test_missing_event_id_raises_safe_error(tmp_path):
    events_path = tmp_path / "events.jsonl"
    decisions_path = tmp_path / "decisions.jsonl"
    outputs_dir = tmp_path / "outputs"
    _write_jsonl(events_path, [_event("demo-0008")])
    _write_jsonl(decisions_path, [_decision("demo-0008")])

    with pytest.raises(ExportEvidenceError, match="No event found"):
        export_evidence_package("missing-event", events_path, decisions_path, outputs_dir)


def _event(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-05-12T20:00:00Z",
        "event_type": "alert",
        "src_ip": "203.0.113.10",
        "dest_ip": "10.10.5.20",
        "asset_id": "lab-server-01",
        "expected_label": "credential_access",
        "synthetic_ground_truth": "AI-generated synthetic telemetry",
        "alert": {
            "signature": "Synthetic repeated login failure",
            "severity": 2,
        },
    }


def _decision(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-05-12T20:00:00Z",
        "correlation_id": "corr-demo",
        "community_id": "community-demo",
        "raw_event_sha256": "a" * 64,
        "model_name": "mini_soc_decision_tree",
        "model_version": "0.1.0",
        "model_sha256": "in_memory_not_persisted",
        "feature_summary": {"failed_login_count": 60},
        "predicted_label": "credential_access",
        "confidence": 1.0,
        "risk_score": 71,
        "severity": "high",
        "reason_codes": ["failed_login_pattern", "routed_to_create_ticket"],
        "guardrail_flags": [],
        "action_taken": "create_ticket",
        "analyst_override": None,
        "review_required": False,
        "simulated_only": True,
    }


def _write_jsonl(path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))
