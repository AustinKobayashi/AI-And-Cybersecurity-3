from pathlib import Path

import pytest

from minisoc.classifier import classify_events, train_classifier
from minisoc.features import extract_features
from minisoc.guardrails import apply_guardrails
from minisoc.intake import load_events
from minisoc.scoring import score_risk


ROOT = Path(__file__).resolve().parents[1]
COMBINED_DATASET = ROOT / "data" / "raw" / "synthetic_minisoc_events_combined_2200.eve.jsonl"
DEMO_DATASET = ROOT / "data" / "sample" / "demo_scenario_events_20.eve.jsonl"


@pytest.fixture(scope="module")
def guarded_demo_events() -> dict:
    return _guarded_demo_events()


def test_high_confidence_benign_event_allows_automation(guarded_demo_events):
    guardrails = guarded_demo_events["demo-0001"]["guardrails"]

    assert set(guardrails) == {
        "event_id",
        "automation_allowed",
        "review_required",
        "guardrail_flags",
        "review_reasons",
    }
    assert guardrails["event_id"] == "demo-0001"
    assert guardrails["automation_allowed"] is True
    assert guardrails["review_required"] is False
    assert guardrails["guardrail_flags"] == []
    assert guardrails["review_reasons"] == []


def test_high_confidence_well_formed_malicious_event_allows_later_routing(
    guarded_demo_events,
):
    guardrails = guarded_demo_events["demo-0013"]["guardrails"]

    assert guardrails["automation_allowed"] is True
    assert guardrails["review_required"] is False
    assert guardrails["guardrail_flags"] == []


def test_needs_human_review_label_blocks_automation(guarded_demo_events):
    guardrails = guarded_demo_events["demo-0018"]["guardrails"]

    assert guardrails["automation_allowed"] is False
    assert guardrails["review_required"] is True
    assert "human_review_label" in guardrails["guardrail_flags"]
    assert "classifier predicted needs_human_review" in guardrails["review_reasons"]


def test_missing_analysis_fields_block_automation(guarded_demo_events):
    guardrails = guarded_demo_events["demo-0019"]["guardrails"]

    assert guardrails["automation_allowed"] is False
    assert "missing_field_flags" in guardrails["guardrail_flags"]
    assert "missing analysis fields require human review" in guardrails["review_reasons"]


def test_obfuscation_flags_block_automation(guarded_demo_events):
    guardrails = guarded_demo_events["demo-0020"]["guardrails"]

    assert guardrails["automation_allowed"] is False
    assert "obfuscation_flags" in guardrails["guardrail_flags"]
    assert "obfuscation indicators require human review" in guardrails["review_reasons"]


def test_prompt_injection_like_text_blocks_automation(guarded_demo_events):
    guardrails = guarded_demo_events["demo-0018"]["guardrails"]

    assert guardrails["automation_allowed"] is False
    assert "prompt_injection_like_text" in guardrails["guardrail_flags"]
    assert (
        "prompt-injection-like text requires human review"
        in guardrails["review_reasons"]
    )


def test_low_confidence_blocks_automation():
    guardrails = apply_guardrails(
        {},
        {"event_id": "manual-low-confidence", "features": {}},
        {
            "event_id": "manual-low-confidence",
            "predicted_label": "benign",
            "confidence": 0.5,
        },
        {"event_id": "manual-low-confidence", "severity": "low"},
    )

    assert guardrails["automation_allowed"] is False
    assert "low_classifier_confidence" in guardrails["guardrail_flags"]


def test_intake_review_metadata_blocks_automation():
    guardrails = apply_guardrails(
        {
            "event_id": "manual-intake-review",
            "_intake": {
                "review_required": True,
                "review_reasons": ["manual intake review"],
            },
        },
        {"features": {}},
        {
            "predicted_label": "benign",
            "confidence": 1.0,
        },
        {"severity": "low"},
    )

    assert guardrails["automation_allowed"] is False
    assert "intake_review_required" in guardrails["guardrail_flags"]
    assert "manual intake review" in guardrails["review_reasons"]


def test_benign_prediction_with_high_risk_blocks_automation():
    guardrails = apply_guardrails(
        {"event_id": "manual-contradiction"},
        {"features": {"alert_severity": 1}},
        {
            "predicted_label": "benign",
            "confidence": 1.0,
        },
        {"severity": "high"},
    )

    assert guardrails["automation_allowed"] is False
    assert "contradictory_benign_high_risk" in guardrails["guardrail_flags"]


def test_malformed_or_missing_inputs_default_safely():
    guardrails = apply_guardrails(None, None, None, None)

    assert guardrails == {
        "event_id": "",
        "automation_allowed": False,
        "review_required": True,
        "guardrail_flags": ["low_classifier_confidence"],
        "review_reasons": ["classifier confidence is below automation threshold"],
    }


def _guarded_demo_events() -> dict:
    training_features = [
        extract_features(event)
        for event in load_events(str(COMBINED_DATASET))
    ]
    demo_events = load_events(str(DEMO_DATASET))
    demo_features = [extract_features(event) for event in demo_events]
    model_bundle = train_classifier(training_features)
    classifications = classify_events(demo_features, model_bundle)
    guarded = {}

    for event, feature_record, classification in zip(
        demo_events,
        demo_features,
        classifications,
    ):
        risk = score_risk(classification, feature_record)
        guarded[classification["event_id"]] = {
            "event": event,
            "features": feature_record,
            "classification": classification,
            "risk": risk,
            "guardrails": apply_guardrails(
                event,
                feature_record,
                classification,
                risk,
            ),
        }

    return guarded
