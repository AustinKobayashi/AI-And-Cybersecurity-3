"""Explainable feature extraction for validated mini-SOC events."""

from __future__ import annotations

import math
from collections import Counter


ASSET_CRITICALITY_SCORES = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

PROMPT_INJECTION_MARKERS = [
    "ignore previous instructions",
    "disregard previous instructions",
    "mark this alert benign",
    "override instructions",
    "system prompt",
]


def extract_features(event: dict) -> dict:
    """Convert one validated event into simple classifier-ready features."""
    if not isinstance(event, dict):
        event = {}

    flow = event.get("flow") if isinstance(event.get("flow"), dict) else {}
    features = {
        "domain_entropy": _entropy_feature(
            event,
            "domain_entropy_hint",
            [_nested_value(event, "dns", "query"), _nested_value(event, "http", "hostname")],
        ),
        "uri_entropy": _entropy_feature(
            event,
            "uri_entropy_hint",
            [_nested_value(event, "http", "url")],
        ),
        "byte_ratio": _ratio(
            _number(flow.get("bytes_toserver")),
            _number(flow.get("bytes_toclient")),
        ),
        "packet_ratio": _ratio(
            _number(flow.get("pkts_toserver")),
            _number(flow.get("pkts_toclient")),
        ),
        "alert_severity": int(_number(_nested_value(event, "alert", "severity"))),
        "destination_port": int(_number(event.get("dest_port"))),
        "failed_login_count": int(_number(event.get("failed_login_count"))),
        "internal_probe_count": int(_number(event.get("internal_probe_count"))),
        "callback_interval_seconds": int(_number(event.get("callback_interval_seconds"))),
        "obfuscation_flag_count": _count_flags(event.get("obfuscation_flags")),
        "missing_field_flag_count": _count_flags(event.get("missing_field_flags")),
        "prompt_injection_like_text_flag": _prompt_injection_flag(event),
        "asset_criticality_score": _asset_criticality_score(event.get("asset_criticality")),
    }

    return {
        "event_id": event.get("event_id", ""),
        "expected_label": event.get("expected_label", ""),
        "features": features,
        "reason_codes": _reason_codes(features),
    }


def shannon_entropy(text: str) -> float:
    """Return Shannon entropy for a string, rounded for readable output."""
    if not isinstance(text, str) or not text:
        return 0.0

    counts = Counter(text)
    length = len(text)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def _entropy_feature(event: dict, hint_key: str, text_values: list[object]) -> float:
    hint = _number(event.get(hint_key), default=None)
    if hint is not None:
        return round(hint, 3)

    entropies = [
        shannon_entropy(value)
        for value in text_values
        if isinstance(value, str) and value
    ]
    if not entropies:
        return 0.0

    return max(entropies)


def _reason_codes(features: dict) -> list[str]:
    reasons = []

    if features["alert_severity"] >= 3:
        reasons.append("high_alert_severity")
    elif features["alert_severity"] >= 2:
        reasons.append("elevated_alert_severity")

    if features["destination_port"] in {22, 445, 3389}:
        reasons.append("admin_or_file_sharing_port")
    if features["failed_login_count"] > 0:
        reasons.append("failed_logins_present")
    if features["failed_login_count"] >= 10:
        reasons.append("many_failed_logins")
    if features["internal_probe_count"] > 0:
        reasons.append("internal_probe_activity")
    if features["callback_interval_seconds"] > 0:
        reasons.append("periodic_callback_signal")
    if features["domain_entropy"] >= 4.0:
        reasons.append("high_domain_entropy")
    if features["uri_entropy"] >= 4.0:
        reasons.append("high_uri_entropy")
    if features["obfuscation_flag_count"] > 0:
        reasons.append("obfuscation_flags_present")
    if features["missing_field_flag_count"] > 0:
        reasons.append("missing_field_flags_present")
    if features["prompt_injection_like_text_flag"] > 0:
        reasons.append("prompt_injection_like_text")
    if features["asset_criticality_score"] >= 3:
        reasons.append("high_value_asset")
    if _is_asymmetric(features["byte_ratio"]):
        reasons.append("asymmetric_bytes")
    if _is_asymmetric(features["packet_ratio"]):
        reasons.append("asymmetric_packets")

    if not reasons:
        reasons.append("no_strong_signal")

    return reasons


def _nested_value(event: dict, parent: str, child: str):
    value = event.get(parent)
    if isinstance(value, dict):
        return value.get(child)
    return None


def _number(value, default=0.0):
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def _count_flags(value) -> int:
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, str):
        return 1 if value else 0
    return 1 if value else 0


def _prompt_injection_flag(event: dict) -> int:
    prompt_field = event.get("prompt_injection_like_text")
    if isinstance(prompt_field, str) and prompt_field.strip():
        return 1

    text_values = [
        _nested_value(event, "http", "url"),
        _nested_value(event, "http", "user_agent"),
        _nested_value(event, "dns", "query"),
        _nested_value(event, "alert", "signature"),
        event.get("review_reason"),
    ]
    joined = " ".join(value.lower() for value in text_values if isinstance(value, str))

    for marker in PROMPT_INJECTION_MARKERS:
        if marker in joined:
            return 1

    return 0


def _asset_criticality_score(value) -> int:
    if not isinstance(value, str):
        return 0
    return ASSET_CRITICALITY_SCORES.get(value.lower(), 0)


def _is_asymmetric(ratio: float) -> bool:
    return ratio >= 3.0 or 0.0 < ratio <= 0.33
