"""Deterministic risk scoring for classified mini-SOC events."""

from __future__ import annotations


LABEL_BASE_RISK = {
    "benign": 5,
    "credential_access": 30,
    "lateral_movement": 35,
    "command_and_control": 40,
    "exploit_attempt": 40,
    "needs_human_review": 45,
}

ALERT_SEVERITY_RISK = {
    0: 0,
    1: 2,
    2: 8,
    3: 14,
    4: 18,
}

ASSET_CRITICALITY_RISK = {
    0: 0,
    1: 0,
    2: 3,
    3: 6,
    4: 10,
}


def score_risk(classification: dict, features: dict) -> dict:
    """Convert classification and context into a bounded risk score."""
    if not isinstance(classification, dict):
        classification = {}
    if not isinstance(features, dict):
        features = {}

    feature_values = features.get("features", {})
    if not isinstance(feature_values, dict):
        feature_values = {}

    predicted_label = classification.get("predicted_label")
    if not isinstance(predicted_label, str) or not predicted_label:
        predicted_label = "unknown"

    confidence = _number(classification.get("confidence"))
    confidence = min(max(confidence, 0.0), 1.0)

    score = LABEL_BASE_RISK.get(predicted_label, 25)
    reasons = _merged_reason_codes(
        classification.get("reason_codes"),
        features.get("reason_codes"),
    )

    if predicted_label == "benign":
        score += round((1 - confidence) * 20)
    else:
        score += round(confidence * 10)

    score += _mapped_points(
        ALERT_SEVERITY_RISK,
        feature_values.get("alert_severity"),
        "alert_severity_risk",
        reasons,
    )
    score += _mapped_points(
        ASSET_CRITICALITY_RISK,
        feature_values.get("asset_criticality_score"),
        "asset_criticality_risk",
        reasons,
    )
    score += _failed_login_points(feature_values, reasons)
    score += _internal_probe_points(feature_values, reasons)
    score += _callback_points(feature_values, reasons)
    score += _entropy_points(feature_values, reasons)
    score += _capped_flag_points(
        feature_values.get("obfuscation_flag_count"),
        8,
        16,
        "obfuscation_risk",
        reasons,
    )
    score += _capped_flag_points(
        feature_values.get("missing_field_flag_count"),
        5,
        15,
        "missing_field_risk",
        reasons,
    )

    if _number(feature_values.get("prompt_injection_like_text_flag")) > 0:
        score += 25
        reasons.append("prompt_injection_risk")

    score = _clamp_score(score)

    return {
        "event_id": classification.get("event_id") or features.get("event_id", ""),
        "risk_score": score,
        "severity": _severity(score),
        "reason_codes": _dedupe(reasons),
    }


def _mapped_points(
    mapping: dict[int, int],
    value,
    reason_code: str,
    reasons: list[str],
) -> int:
    points = mapping.get(int(_number(value)), 0)
    if points:
        reasons.append(reason_code)
    return points


def _failed_login_points(features: dict, reasons: list[str]) -> int:
    count = _number(features.get("failed_login_count"))
    points = 0

    if count > 0:
        points += 5
    if count >= 10:
        points += 7
    if count >= 25:
        points += 4
    if count >= 50:
        points += 4

    if points:
        reasons.append("failed_login_risk")
    return points


def _internal_probe_points(features: dict, reasons: list[str]) -> int:
    count = _number(features.get("internal_probe_count"))
    points = 0

    if count > 0:
        points += 6
    if count >= 10:
        points += 5
    if count >= 25:
        points += 5

    if points:
        reasons.append("internal_probe_risk")
    return points


def _callback_points(features: dict, reasons: list[str]) -> int:
    interval = _number(features.get("callback_interval_seconds"))
    if interval <= 0:
        return 0

    reasons.append("callback_risk")
    points = 6
    if interval <= 120:
        points += 5
        reasons.append("short_callback_interval")
    return points


def _entropy_points(features: dict, reasons: list[str]) -> int:
    points = 0

    if _number(features.get("domain_entropy")) >= 4.0:
        points += 6
        reasons.append("domain_entropy_risk")
    if _number(features.get("uri_entropy")) >= 4.0:
        points += 6
        reasons.append("uri_entropy_risk")

    return points


def _capped_flag_points(
    value,
    points_per_flag: int,
    cap: int,
    reason_code: str,
    reasons: list[str],
) -> int:
    count = max(int(_number(value)), 0)
    points = min(count * points_per_flag, cap)
    if points:
        reasons.append(reason_code)
    return points


def _merged_reason_codes(*sources) -> list[str]:
    merged = []
    for source in sources:
        if isinstance(source, (list, tuple, set)):
            merged.extend(str(item) for item in source if item)
        elif isinstance(source, str) and source:
            merged.append(source)
    return merged


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _clamp_score(score) -> int:
    return max(0, min(100, int(round(_number(score)))))


def _severity(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


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
