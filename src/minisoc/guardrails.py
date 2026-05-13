"""Deterministic safety checks before simulated automation."""

from __future__ import annotations


MINIMUM_AUTOMATION_CONFIDENCE = 0.75


def apply_guardrails(event: dict, features: dict, classification: dict, risk: dict) -> dict:
    """Decide whether a classified event needs human review."""
    if not isinstance(event, dict):
        event = {}
    if not isinstance(features, dict):
        features = {}
    if not isinstance(classification, dict):
        classification = {}
    if not isinstance(risk, dict):
        risk = {}

    feature_values = features.get("features", {})
    if not isinstance(feature_values, dict):
        feature_values = {}

    flags = []
    reasons = []

    _check_intake_review(event, flags, reasons)
    _check_human_review_label(classification, flags, reasons)
    _check_low_confidence(classification, flags, reasons)
    _check_missing_fields(event, feature_values, flags, reasons)
    _check_obfuscation(event, feature_values, flags, reasons)
    _check_prompt_injection(event, feature_values, flags, reasons)
    _check_contradictions(classification, risk, feature_values, flags, reasons)

    flags = _dedupe(flags)
    reasons = _dedupe(reasons)

    return {
        "event_id": _event_id(event, features, classification, risk),
        "automation_allowed": not flags,
        "review_required": bool(flags),
        "guardrail_flags": flags,
        "review_reasons": reasons,
    }


def _check_intake_review(event: dict, flags: list[str], reasons: list[str]) -> None:
    intake = event.get("_intake")
    if not isinstance(intake, dict) or not intake.get("review_required"):
        return

    flags.append("intake_review_required")
    intake_reasons = intake.get("review_reasons")
    if isinstance(intake_reasons, list) and intake_reasons:
        reasons.extend(str(reason) for reason in intake_reasons if reason)
    else:
        reasons.append("intake metadata requires human review")


def _check_human_review_label(
    classification: dict,
    flags: list[str],
    reasons: list[str],
) -> None:
    if classification.get("predicted_label") != "needs_human_review":
        return

    flags.append("human_review_label")
    reasons.append("classifier predicted needs_human_review")


def _check_low_confidence(
    classification: dict,
    flags: list[str],
    reasons: list[str],
) -> None:
    confidence = _number(classification.get("confidence"))
    if confidence >= MINIMUM_AUTOMATION_CONFIDENCE:
        return

    flags.append("low_classifier_confidence")
    reasons.append("classifier confidence is below automation threshold")


def _check_missing_fields(
    event: dict,
    feature_values: dict,
    flags: list[str],
    reasons: list[str],
) -> None:
    if not _has_flags(event.get("missing_field_flags")) and _number(
        feature_values.get("missing_field_flag_count")
    ) <= 0:
        return

    flags.append("missing_field_flags")
    reasons.append("missing analysis fields require human review")


def _check_obfuscation(
    event: dict,
    feature_values: dict,
    flags: list[str],
    reasons: list[str],
) -> None:
    if not _has_flags(event.get("obfuscation_flags")) and _number(
        feature_values.get("obfuscation_flag_count")
    ) <= 0:
        return

    flags.append("obfuscation_flags")
    reasons.append("obfuscation indicators require human review")


def _check_prompt_injection(
    event: dict,
    feature_values: dict,
    flags: list[str],
    reasons: list[str],
) -> None:
    if not event.get("prompt_injection_like_text") and _number(
        feature_values.get("prompt_injection_like_text_flag")
    ) <= 0:
        return

    flags.append("prompt_injection_like_text")
    reasons.append("prompt-injection-like text requires human review")


def _check_contradictions(
    classification: dict,
    risk: dict,
    feature_values: dict,
    flags: list[str],
    reasons: list[str],
) -> None:
    predicted_label = classification.get("predicted_label")
    severity = risk.get("severity")
    alert_severity = _number(feature_values.get("alert_severity"))

    if predicted_label == "benign" and severity == "high":
        flags.append("contradictory_benign_high_risk")
        reasons.append("benign prediction conflicts with high risk score")

    if severity == "low" and alert_severity >= 3:
        flags.append("contradictory_low_risk_high_alert_severity")
        reasons.append("low risk score conflicts with high alert severity")


def _event_id(*sources: dict) -> str:
    for source in sources:
        if isinstance(source, dict) and source.get("event_id"):
            return str(source["event_id"])
    return ""


def _has_flags(value) -> bool:
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    if isinstance(value, str):
        return bool(value.strip())
    return bool(value)


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


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
