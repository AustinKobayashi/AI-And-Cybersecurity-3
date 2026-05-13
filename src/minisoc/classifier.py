"""Small explainable classifier for mini-SOC feature records."""

from __future__ import annotations

from sklearn.tree import DecisionTreeClassifier


MODEL_NAME = "mini_soc_decision_tree"
MODEL_VERSION = "0.1.0"

FEATURE_NAMES = [
    "domain_entropy",
    "uri_entropy",
    "byte_ratio",
    "packet_ratio",
    "alert_severity",
    "destination_port",
    "failed_login_count",
    "internal_probe_count",
    "callback_interval_seconds",
    "obfuscation_flag_count",
    "missing_field_flag_count",
    "prompt_injection_like_text_flag",
    "asset_criticality_score",
]


def train_classifier(feature_records: list[dict]) -> dict:
    """Train a bounded decision tree on labelled feature records."""
    labelled_records = [
        record
        for record in feature_records
        if isinstance(record, dict) and record.get("expected_label")
    ]
    if not labelled_records:
        raise ValueError("at least one labelled feature record is required")

    model = DecisionTreeClassifier(
        random_state=42,
        max_depth=6,
        class_weight="balanced",
    )
    model.fit(
        [_feature_vector(record, FEATURE_NAMES) for record in labelled_records],
        [record["expected_label"] for record in labelled_records],
    )

    return {
        "model": model,
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "labels": list(model.classes_),
        "training_record_count": len(labelled_records),
    }


def classify_event(feature_record: dict, model_bundle: dict) -> dict:
    """Classify one feature record and keep a compact explanation trail."""
    model = model_bundle["model"]
    feature_names = model_bundle.get("feature_names", FEATURE_NAMES)
    vector = _feature_vector(feature_record, feature_names)
    predicted_label = str(model.predict([vector])[0])
    confidence = _prediction_confidence(model, vector, predicted_label)

    return {
        "event_id": feature_record.get("event_id", ""),
        "expected_label": feature_record.get("expected_label", ""),
        "predicted_label": predicted_label,
        "confidence": confidence,
        "model_name": model_bundle.get("model_name", MODEL_NAME),
        "model_version": model_bundle.get("model_version", MODEL_VERSION),
        "reason_codes": list(feature_record.get("reason_codes", [])),
        "feature_names": list(feature_names),
    }


def classify_events(feature_records: list[dict], model_bundle: dict) -> list[dict]:
    """Classify many feature records with the same trained model bundle."""
    return [classify_event(record, model_bundle) for record in feature_records]


def _feature_vector(feature_record: dict, feature_names: list[str]) -> list[float]:
    features = feature_record.get("features", {})
    if not isinstance(features, dict):
        features = {}

    return [_number(features.get(name)) for name in feature_names]


def _prediction_confidence(
    model: DecisionTreeClassifier,
    vector: list[float],
    predicted_label: str,
) -> float:
    probabilities = model.predict_proba([vector])[0]
    classes = [str(label) for label in model.classes_]
    class_index = classes.index(predicted_label)
    return round(float(probabilities[class_index]), 4)


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
