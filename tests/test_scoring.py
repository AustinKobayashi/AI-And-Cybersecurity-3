from pathlib import Path

import pytest

from minisoc.classifier import classify_events, train_classifier
from minisoc.features import extract_features
from minisoc.intake import load_events
from minisoc.scoring import score_risk


ROOT = Path(__file__).resolve().parents[1]
COMBINED_DATASET = ROOT / "data" / "raw" / "synthetic_minisoc_events_combined_2200.eve.jsonl"
DEMO_DATASET = ROOT / "data" / "sample" / "demo_scenario_events_20.eve.jsonl"


@pytest.fixture(scope="module")
def scored_demo_events() -> dict:
    return _scored_demo_events()


def test_benign_high_confidence_demo_event_scores_low(scored_demo_events):
    risk = scored_demo_events["demo-0001"]["risk"]

    assert set(risk) == {"event_id", "risk_score", "severity", "reason_codes"}
    assert risk["event_id"] == "demo-0001"
    assert risk["risk_score"] == 13
    assert risk["severity"] == "low"


def test_credential_access_demo_event_scores_high(scored_demo_events):
    risk = scored_demo_events["demo-0008"]["risk"]

    assert risk["risk_score"] == 71
    assert risk["severity"] == "high"
    assert "failed_login_risk" in risk["reason_codes"]


def test_lateral_movement_demo_event_scores_high(scored_demo_events):
    risk = scored_demo_events["demo-0009"]["risk"]

    assert risk["risk_score"] == 72
    assert risk["severity"] == "high"
    assert "internal_probe_risk" in risk["reason_codes"]


def test_command_and_control_demo_event_scores_high(scored_demo_events):
    risk = scored_demo_events["demo-0013"]["risk"]

    assert risk["risk_score"] == 85
    assert risk["severity"] == "high"
    assert "callback_risk" in risk["reason_codes"]
    assert "domain_entropy_risk" in risk["reason_codes"]


def test_exploit_attempt_demo_event_scores_high(scored_demo_events):
    risk = scored_demo_events["demo-0017"]["risk"]

    assert risk["risk_score"] == 80
    assert risk["severity"] == "high"
    assert "uri_entropy_risk" in risk["reason_codes"]


def test_needs_human_review_demo_event_scores_high_with_review_reasons(scored_demo_events):
    risk = scored_demo_events["demo-0018"]["risk"]

    assert risk["risk_score"] == 100
    assert risk["severity"] == "high"
    assert "obfuscation_flags_present" in risk["reason_codes"]
    assert "prompt_injection_like_text" in risk["reason_codes"]
    assert "prompt_injection_risk" in risk["reason_codes"]


def test_risk_score_is_clamped_to_one_hundred():
    risk = score_risk(
        {
            "event_id": "manual-clamp",
            "predicted_label": "needs_human_review",
            "confidence": 1.0,
            "reason_codes": [],
        },
        {
            "features": {
                "alert_severity": 4,
                "asset_criticality_score": 4,
                "failed_login_count": 100,
                "internal_probe_count": 100,
                "callback_interval_seconds": 60,
                "domain_entropy": 5.0,
                "uri_entropy": 5.0,
                "obfuscation_flag_count": 10,
                "missing_field_flag_count": 10,
                "prompt_injection_like_text_flag": 1,
            },
            "reason_codes": [],
        },
    )

    assert risk["risk_score"] == 100
    assert risk["severity"] == "high"


def test_malformed_numeric_inputs_default_to_zero():
    risk = score_risk(
        {
            "event_id": "manual-defaults",
            "predicted_label": "unknown",
            "confidence": "not-a-number",
            "reason_codes": [],
        },
        {
            "features": {
                "alert_severity": "bad",
                "asset_criticality_score": None,
                "failed_login_count": False,
                "internal_probe_count": "",
                "callback_interval_seconds": "never",
                "domain_entropy": "nope",
                "uri_entropy": object(),
                "obfuscation_flag_count": -2,
                "missing_field_flag_count": "missing",
                "prompt_injection_like_text_flag": 0,
            },
            "reason_codes": [],
        },
    )

    assert risk["risk_score"] == 25
    assert risk["severity"] == "low"


def test_reason_codes_are_deduplicated_in_original_order():
    risk = score_risk(
        {
            "event_id": "manual-reasons",
            "predicted_label": "benign",
            "confidence": 1.0,
            "reason_codes": ["shared_reason", "shared_reason", "classifier_reason"],
        },
        {
            "features": {
                "alert_severity": 0,
                "asset_criticality_score": 0,
            },
            "reason_codes": ["shared_reason", "feature_reason"],
        },
    )

    assert risk["reason_codes"] == [
        "shared_reason",
        "classifier_reason",
        "feature_reason",
    ]


def _scored_demo_events() -> dict:
    training_features = [
        extract_features(event)
        for event in load_events(str(COMBINED_DATASET))
    ]
    demo_features = [
        extract_features(event)
        for event in load_events(str(DEMO_DATASET))
    ]
    model_bundle = train_classifier(training_features)
    classifications = classify_events(demo_features, model_bundle)
    scored = {}

    for classification, feature_record in zip(classifications, demo_features):
        scored[classification["event_id"]] = {
            "classification": classification,
            "features": feature_record,
            "risk": score_risk(classification, feature_record),
        }

    return scored
