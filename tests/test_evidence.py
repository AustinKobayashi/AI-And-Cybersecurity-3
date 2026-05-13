from pathlib import Path

import pytest

from minisoc.classifier import classify_events, train_classifier
from minisoc.evidence import MODEL_SHA256_NOT_PERSISTED, build_evidence_record
from minisoc.features import extract_features
from minisoc.guardrails import apply_guardrails
from minisoc.intake import load_events
from minisoc.response import route_response
from minisoc.scoring import score_risk


ROOT = Path(__file__).resolve().parents[1]
COMBINED_DATASET = ROOT / "data" / "raw" / "synthetic_minisoc_events_combined_2200.eve.jsonl"
DEMO_DATASET = ROOT / "data" / "sample" / "demo_scenario_events_20.eve.jsonl"


@pytest.fixture(scope="module")
def evidence_demo_records() -> dict:
    return _evidence_demo_records()


def test_evidence_record_returns_expected_schema(evidence_demo_records):
    record = evidence_demo_records["demo-0008"]

    assert set(record) == {
        "event_id",
        "timestamp",
        "correlation_id",
        "community_id",
        "raw_event_sha256",
        "model_name",
        "model_version",
        "model_sha256",
        "feature_summary",
        "predicted_label",
        "confidence",
        "risk_score",
        "severity",
        "reason_codes",
        "guardrail_flags",
        "action_taken",
        "analyst_override",
        "review_required",
        "simulated_only",
    }


def test_evidence_record_preserves_raw_event_hash(evidence_demo_records):
    record = evidence_demo_records["demo-0008"]

    assert len(record["raw_event_sha256"]) == 64
    assert record["raw_event_sha256"].isalnum()


def test_evidence_record_includes_decision_details(evidence_demo_records):
    record = evidence_demo_records["demo-0008"]

    assert record["model_name"] == "mini_soc_decision_tree"
    assert record["model_version"] == "0.1.0"
    assert record["predicted_label"] == "credential_access"
    assert record["confidence"] == 1.0
    assert record["risk_score"] == 71
    assert record["severity"] == "high"
    assert record["guardrail_flags"] == []
    assert record["action_taken"] == "create_ticket"
    assert record["review_required"] is False
    assert record["simulated_only"] is True
    assert record["feature_summary"]["failed_login_count"] == 60


def test_reason_codes_are_deduplicated():
    record = build_evidence_record(
        {"event_id": "manual-dedupe", "_intake": {"raw_sha256": "abc"}},
        {
            "features": {"reason_codes": ["same", "feature"]},
            "classification": {
                "event_id": "manual-dedupe",
                "reason_codes": ["same", "classification"],
            },
            "risk": {"reason_codes": ["risk", "same"]},
            "response": {"action": "log_only", "reason_codes": ["response", "risk"]},
        },
    )

    assert record["reason_codes"] == [
        "same",
        "feature",
        "classification",
        "risk",
        "response",
    ]


def test_missing_or_malformed_inputs_default_safely():
    record = build_evidence_record(None, None)

    assert record["event_id"] == ""
    assert record["timestamp"] == ""
    assert record["raw_event_sha256"] == ""
    assert record["model_name"] == ""
    assert record["confidence"] == 0.0
    assert record["risk_score"] == 0
    assert record["guardrail_flags"] == []
    assert record["action_taken"] == ""
    assert record["review_required"] is False
    assert record["simulated_only"] is True


def test_model_hash_documents_in_memory_model():
    record = build_evidence_record({}, {})

    assert record["model_sha256"] == MODEL_SHA256_NOT_PERSISTED


def _evidence_demo_records() -> dict:
    training_features = [
        extract_features(event)
        for event in load_events(str(COMBINED_DATASET))
    ]
    demo_events = load_events(str(DEMO_DATASET))
    demo_features = [extract_features(event) for event in demo_events]
    model_bundle = train_classifier(training_features)
    classifications = classify_events(demo_features, model_bundle)
    records = {}

    for event, feature_record, classification in zip(
        demo_events,
        demo_features,
        classifications,
    ):
        risk = score_risk(classification, feature_record)
        guardrails = apply_guardrails(event, feature_record, classification, risk)
        response = route_response(event, classification, risk, guardrails)
        records[classification["event_id"]] = build_evidence_record(
            event,
            {
                "model": model_bundle,
                "features": feature_record,
                "classification": classification,
                "risk": risk,
                "guardrails": guardrails,
                "response": response,
            },
        )

    return records
