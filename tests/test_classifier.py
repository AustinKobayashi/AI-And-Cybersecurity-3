from pathlib import Path

import pytest

from minisoc.classifier import FEATURE_NAMES, classify_event, classify_events, train_classifier
from minisoc.cli import main
from minisoc.features import extract_features
from minisoc.intake import load_events


ROOT = Path(__file__).resolve().parents[1]
COMBINED_DATASET = ROOT / "data" / "raw" / "synthetic_minisoc_events_combined_2200.eve.jsonl"
DEMO_DATASET = ROOT / "data" / "sample" / "demo_scenario_events_20.eve.jsonl"
EXPECTED_LABELS = {
    "benign",
    "credential_access",
    "lateral_movement",
    "command_and_control",
    "exploit_attempt",
    "needs_human_review",
}


@pytest.fixture(scope="module")
def training_features():
    return _feature_records(COMBINED_DATASET)


@pytest.fixture(scope="module")
def demo_features():
    return _feature_records(DEMO_DATASET)


@pytest.fixture(scope="module")
def model_bundle(training_features):
    return train_classifier(training_features)


def test_train_classifier_supports_expected_labels(model_bundle):
    assert model_bundle["model_name"] == "mini_soc_decision_tree"
    assert model_bundle["model_version"] == "0.1.0"
    assert model_bundle["training_record_count"] == 2200
    assert set(model_bundle["labels"]) == EXPECTED_LABELS
    assert model_bundle["feature_names"] == FEATURE_NAMES


def test_classify_demo_dataset_returns_expected_schema(model_bundle, demo_features):
    classifications = classify_events(demo_features, model_bundle)

    assert len(classifications) == 20
    for item in classifications:
        assert set(item) == {
            "event_id",
            "expected_label",
            "predicted_label",
            "confidence",
            "model_name",
            "model_version",
            "reason_codes",
            "feature_names",
        }
        assert item["predicted_label"] in EXPECTED_LABELS
        assert 0.0 <= item["confidence"] <= 1.0
        assert item["model_name"] == "mini_soc_decision_tree"
        assert item["model_version"] == "0.1.0"
        assert item["feature_names"] == FEATURE_NAMES
        assert item["reason_codes"]


def test_key_demo_scenarios_classify_correctly(model_bundle, demo_features):
    classifications = {
        item["event_id"]: item
        for item in classify_events(demo_features, model_bundle)
    }

    assert classifications["demo-0001"]["predicted_label"] == "benign"
    assert classifications["demo-0008"]["predicted_label"] == "credential_access"
    assert classifications["demo-0009"]["predicted_label"] == "lateral_movement"
    assert classifications["demo-0013"]["predicted_label"] == "command_and_control"
    assert classifications["demo-0017"]["predicted_label"] == "exploit_attempt"
    assert classifications["demo-0018"]["predicted_label"] == "needs_human_review"
    assert classifications["demo-0019"]["predicted_label"] == "needs_human_review"
    assert classifications["demo-0020"]["predicted_label"] == "needs_human_review"


def test_single_event_classification_matches_batch(model_bundle, demo_features):
    single = classify_event(demo_features[7], model_bundle)
    batch = classify_events([demo_features[7]], model_bundle)[0]

    assert single == batch


def test_train_classifier_requires_labelled_records():
    with pytest.raises(ValueError, match="labelled feature record"):
        train_classifier([{"event_id": "manual", "features": {}}])


def test_evaluate_cli_reports_holdout_metrics(capsys):
    exit_code = main(["evaluate", str(COMBINED_DATASET)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Total labelled records: 2200" in output
    assert "Training records: 1760" in output
    assert "Test records: 440" in output
    assert "Accuracy: 0.9545" in output
    assert "Classification report:" in output
    assert "Confusion matrix:" in output
    assert "needs_human_review 1.0000 1.0000 1.0000 19" in output


def test_evaluate_cli_rejects_too_small_default_split(capsys):
    exit_code = main(["evaluate", str(DEMO_DATASET)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "evaluation split is too small" in output


def test_classify_cli_reports_risk_scores(capsys):
    exit_code = main(["classify", str(DEMO_DATASET), "--train", str(COMBINED_DATASET)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Severity counts:" in output
    assert "  high: 15" in output
    assert "  low: 5" in output
    assert "demo-0001: benign confidence=1.0000 risk=13 severity=low expected=benign" in output
    assert (
        "demo-0008: credential_access confidence=1.0000 "
        "risk=71 severity=high expected=credential_access"
    ) in output


def _feature_records(path: Path) -> list[dict]:
    return [extract_features(event) for event in load_events(str(path))]
