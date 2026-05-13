"""Response routing for safe simulated SOC actions."""

from __future__ import annotations


AUTO_CLOSE_MAX_RISK = 25
REVIEW_MIN_RISK = 40
TICKET_MIN_RISK = 60
SIMULATED_BLOCK_MIN_RISK = 80
SIMULATED_BLOCK_LABELS = {"command_and_control", "exploit_attempt"}


def route_response(
    event: dict,
    classification: dict,
    risk: dict,
    guardrails: dict,
) -> dict:
    """Route an event to one safe simulated response path."""
    if not isinstance(event, dict):
        event = {}
    if not isinstance(classification, dict):
        classification = {}
    if not isinstance(risk, dict):
        risk = {}
    if not isinstance(guardrails, dict):
        guardrails = {}

    event_id = _event_id(event, classification, risk, guardrails)
    predicted_label = _text(classification.get("predicted_label"))
    risk_score = int(_number(risk.get("risk_score")))
    automation_allowed = bool(guardrails.get("automation_allowed"))
    guardrail_review_required = bool(guardrails.get("review_required"))

    action = _route_action(
        predicted_label,
        risk_score,
        automation_allowed,
        guardrail_review_required,
    )

    return {
        "event_id": event_id,
        "action": action,
        "action_taken": action,
        "automation_allowed": automation_allowed,
        "review_required": action == "review_queue",
        "target": _target_for_action(action, event, event_id),
        "reason_codes": _reason_codes(
            action,
            classification,
            risk,
            guardrails,
        ),
    }


def _route_action(
    predicted_label: str,
    risk_score: int,
    automation_allowed: bool,
    guardrail_review_required: bool,
) -> str:
    if guardrail_review_required:
        return "review_queue"
    if not predicted_label:
        return "review_queue"
    if predicted_label == "benign" and risk_score <= AUTO_CLOSE_MAX_RISK:
        return "auto_close"
    if risk_score < REVIEW_MIN_RISK:
        return "log_only"
    if (
        risk_score >= SIMULATED_BLOCK_MIN_RISK
        and automation_allowed
        and predicted_label in SIMULATED_BLOCK_LABELS
    ):
        return "simulated_block_ip"
    if risk_score >= TICKET_MIN_RISK:
        return "create_ticket"
    if risk_score >= REVIEW_MIN_RISK:
        return "review_queue"
    return "review_queue"


def _target_for_action(action: str, event: dict, event_id: str) -> str:
    if action == "simulated_block_ip":
        return _text(event.get("src_ip"))
    if action in {"review_queue", "create_ticket", "auto_close", "log_only"}:
        return event_id
    return ""


def _reason_codes(
    action: str,
    classification: dict,
    risk: dict,
    guardrails: dict,
) -> list[str]:
    reasons = []
    reasons.extend(_list_values(classification.get("reason_codes")))
    reasons.extend(_list_values(risk.get("reason_codes")))
    reasons.extend(_list_values(guardrails.get("guardrail_flags")))
    reasons.append(f"routed_to_{action}")
    return _dedupe(reasons)


def _event_id(*sources: dict) -> str:
    for source in sources:
        if isinstance(source, dict) and source.get("event_id"):
            return str(source["event_id"])
    return ""


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
