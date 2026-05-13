"""Deterministic guardrail stubs for safe automation."""


def apply_guardrails(event: dict, features: dict, classification: dict, risk: dict) -> dict:
    """Decide whether automation should be allowed or routed to review."""
    raise NotImplementedError("Guardrail implementation has not been added yet.")

