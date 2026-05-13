from pathlib import Path

import pytest

from minisoc.classifier import classify_events, train_classifier
from minisoc.cli import main
from minisoc.features import extract_features
from minisoc.guardrails import apply_guardrails
from minisoc.intake import load_events
from minisoc.response import route_response
from minisoc.scoring import score_risk


ROOT = Path(__file__).resolve().parents[1]
COMBINED_DATASET = ROOT / "data" / "raw" / "synthetic_minisoc_events_combined_2200.eve.jsonl"
DEMO_DATASET = ROOT / "data" / "sample" / "demo_scenario_events_20.eve.jsonl"


@pytest.fixture(scope="module")
def routed_demo_events() -> dict:
    return _routed_demo_events()


def test_low_risk_benign_event_routes_to_auto_close(routed_demo_events):
    response = routed_demo_events["demo-0001"]["response"]

    assert set(response) == {
        "event_id",
        "action",
        "action_taken",
        "automation_allowed",
        "review_required",
        "target",
        "reason_codes",
    }
    assert response["action"] == "auto_close"
    assert response["action_taken"] == "auto_close"
    assert response["automation_allowed"] is True
    assert response["review_required"] is False
    assert response["target"] == "demo-0001"


def test_high_risk_credential_access_routes_to_ticket(routed_demo_events):
    response = routed_demo_events["demo-0008"]["response"]

    assert response["action"] == "create_ticket"
    assert response["target"] == "demo-0008"
    assert "routed_to_create_ticket" in response["reason_codes"]


def test_high_risk_lateral_movement_routes_to_ticket(routed_demo_events):
    response = routed_demo_events["demo-0009"]["response"]

    assert response["action"] == "create_ticket"
    assert response["target"] == "demo-0009"


def test_high_risk_command_and_control_routes_to_simulated_block(routed_demo_events):
    response = routed_demo_events["demo-0013"]["response"]

    assert response["action"] == "simulated_block_ip"
    assert response["target"] == routed_demo_events["demo-0013"]["event"]["src_ip"]
    assert "routed_to_simulated_block_ip" in response["reason_codes"]


def test_high_risk_exploit_attempt_routes_to_simulated_block(routed_demo_events):
    response = routed_demo_events["demo-0017"]["response"]

    assert response["action"] == "simulated_block_ip"
    assert response["target"] == routed_demo_events["demo-0017"]["event"]["src_ip"]


def test_review_gated_event_routes_to_review_queue(routed_demo_events):
    response = routed_demo_events["demo-0018"]["response"]

    assert response["action"] == "review_queue"
    assert response["review_required"] is True
    assert "human_review_label" in response["reason_codes"]


def test_routing_ignores_expected_label():
    response = route_response(
        {
            "event_id": "manual-ignore-label",
            "src_ip": "198.51.100.10",
            "expected_label": "benign",
        },
        {
            "event_id": "manual-ignore-label",
            "expected_label": "benign",
            "predicted_label": "command_and_control",
            "confidence": 0.99,
            "reason_codes": [],
        },
        {
            "event_id": "manual-ignore-label",
            "risk_score": 85,
            "severity": "high",
            "reason_codes": [],
        },
        {
            "event_id": "manual-ignore-label",
            "automation_allowed": True,
            "review_required": False,
            "guardrail_flags": [],
        },
    )

    assert response["action"] == "simulated_block_ip"
    assert response["target"] == "198.51.100.10"


def test_missing_or_malformed_inputs_default_to_review_queue():
    response = route_response(None, None, None, None)

    assert response == {
        "event_id": "",
        "action": "review_queue",
        "action_taken": "review_queue",
        "automation_allowed": False,
        "review_required": True,
        "target": "",
        "reason_codes": ["routed_to_review_queue"],
    }


def test_respond_cli_writes_simulated_outputs(tmp_path, capsys):
    exit_code = main(
        [
            "respond",
            str(DEMO_DATASET),
            "--train",
            str(COMBINED_DATASET),
            "--outputs",
            str(tmp_path),
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Action counts:" in output
    assert "  auto_close: 5" in output
    assert "  create_ticket: 8" in output
    assert "  review_queue: 3" in output
    assert "  simulated_block_ip: 4" in output

    review_path = tmp_path / "review_queue" / "review_queue.jsonl"
    ticket_paths = sorted((tmp_path / "tickets").glob("*.json"))
    blocklist_path = tmp_path / "simulated_blocklist.txt"

    assert review_path.exists()
    assert blocklist_path.exists()
    assert len(review_path.read_text(encoding="utf-8").splitlines()) == 3
    assert len(ticket_paths) == 8
    assert len(blocklist_path.read_text(encoding="utf-8").splitlines()) == 4


def _routed_demo_events() -> dict:
    training_features = [
        extract_features(event)
        for event in load_events(str(COMBINED_DATASET))
    ]
    demo_events = load_events(str(DEMO_DATASET))
    demo_features = [extract_features(event) for event in demo_events]
    model_bundle = train_classifier(training_features)
    classifications = classify_events(demo_features, model_bundle)
    routed = {}

    for event, feature_record, classification in zip(
        demo_events,
        demo_features,
        classifications,
    ):
        risk = score_risk(classification, feature_record)
        guardrails = apply_guardrails(event, feature_record, classification, risk)
        routed[classification["event_id"]] = {
            "event": event,
            "features": feature_record,
            "classification": classification,
            "risk": risk,
            "guardrails": guardrails,
            "response": route_response(
                event,
                classification,
                risk,
                guardrails,
            ),
        }

    return routed
