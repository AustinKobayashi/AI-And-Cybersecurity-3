"""Evidence record helpers for simulated mini-SOC decisions."""

from __future__ import annotations


MODEL_SHA256_NOT_PERSISTED = "in_memory_not_persisted"


def build_evidence_record(event: dict, decision: dict) -> dict:
    """Create one stable decision log record for an event."""
    if not isinstance(event, dict):
        event = {}
    if not isinstance(decision, dict):
        decision = {}

    features = _dict_value(decision.get("features"))
    classification = _dict_value(decision.get("classification"))
    risk = _dict_value(decision.get("risk"))
    guardrails = _dict_value(decision.get("guardrails"))
    response = _dict_value(decision.get("response"))
    model = _dict_value(decision.get("model"))
    intake = _dict_value(event.get("_intake"))

    return {
        "event_id": _event_id(event, classification, risk, guardrails, response),
        "timestamp": _text(event.get("timestamp")),
        "correlation_id": _text(
            event.get("correlation_id")
            or event.get("community_id")
            or response.get("event_id")
        ),
        "community_id": _text(event.get("community_id")),
        "raw_event_sha256": _text(intake.get("raw_sha256")),
        "model_name": _text(
            classification.get("model_name")
            or model.get("model_name")
        ),
        "model_version": _text(
            classification.get("model_version")
            or model.get("model_version")
        ),
        "model_sha256": MODEL_SHA256_NOT_PERSISTED,
        "feature_summary": _feature_summary(features),
        "predicted_label": _text(classification.get("predicted_label")),
        "confidence": _number(classification.get("confidence")),
        "risk_score": int(_number(risk.get("risk_score"))),
        "severity": _text(risk.get("severity")),
        "reason_codes": _dedupe(
            [
                *_list_values(features.get("reason_codes")),
                *_list_values(classification.get("reason_codes")),
                *_list_values(risk.get("reason_codes")),
                *_list_values(response.get("reason_codes")),
            ]
        ),
        "guardrail_flags": _dedupe(_list_values(guardrails.get("guardrail_flags"))),
        "action_taken": _text(response.get("action_taken") or response.get("action")),
        "analyst_override": None,
        "review_required": bool(
            guardrails.get("review_required") or response.get("review_required")
        ),
        "simulated_only": True,
    }


def _feature_summary(features: dict) -> dict:
    values = _dict_value(features.get("features"))
    summary_keys = [
        "alert_severity",
        "asset_criticality_score",
        "failed_login_count",
        "internal_probe_count",
        "callback_interval_seconds",
        "domain_entropy",
        "uri_entropy",
        "obfuscation_flag_count",
        "missing_field_flag_count",
        "prompt_injection_like_text_flag",
    ]

    return {key: values.get(key, 0) for key in summary_keys}


def _event_id(*sources: dict) -> str:
    for source in sources:
        if isinstance(source, dict) and source.get("event_id"):
            return str(source["event_id"])
    return ""


def _dict_value(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list_values(value) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item]
    if isinstance(value, str) and value:
        return [value]
    return []


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


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
