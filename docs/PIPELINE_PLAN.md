# Capstone Technical Track Pipeline Plan

This document is the project-local planning source for the proposed AI-supported cyber defence workflow. It describes what the pipeline should contain, what has been implemented, and how each part should be used.

## Objective

Design a small, safe, auditable AI-assisted detection and response workflow that demonstrates event intake, classification, risk scoring, deterministic safety checks, response routing, and forensic readiness.

The workflow should run on simulated logs, generated events, lab traffic, or controlled PCAP-derived records. It should not connect to a live production network.

Current implementation status: synthetic data, event intake, feature extraction, classification, deterministic risk scoring, a review gate for bypass and failure handling, simulated response routing, and evidence logging are implemented. Forensic export remains planned.

## Architecture

```text
Simulated Suricata-style events
  -> Event intake
  -> Feature extraction
  -> AI-assisted classification
  -> Risk scoring
  -> Deterministic safety checks
  -> Response routing
  -> Evidence preservation
  -> Forensic export
```

## Components

| Component | Purpose | Planned Input | Planned Output |
| --- | --- | --- | --- |
| Event intake | Load and validate Suricata-style JSON events | `data/sample/simulated_events.eve.jsonl` | Validated event records and raw event hashes |
| Feature extraction | Turn events into explainable security signals | Validated events | Normalized feature records and reason codes |
| AI-assisted classifier | Classify events into threat categories | Feature records | Label, confidence, and feature reasons |
| Risk scoring | Prioritize operational risk | Label, confidence, severity, asset criticality, evasion flags | Implemented risk score and severity lane |
| Deterministic safety checks | Prevent unsafe automation and support analyst oversight | Event quality, model output, risk score | Implemented automation allowed or review required decision |
| Response routing | Choose safe next action | Safety-check decision | Implemented log-only, review, ticket, or simulated block action |
| Evidence logging | Preserve the decision trail | Raw event, features, model output, action | Implemented decision log, model metadata, and action record |
| Forensic export | Bundle one event for review | Saved evidence records | Export package with hash manifest |

## Planned Labels

- `benign`
- `credential_access`
- `lateral_movement`
- `command_and_control`
- `exploit_attempt`
- `needs_human_review`

## Planned Response Paths

- `auto_close`: only for well-formed, low-risk, high-confidence benign events.
- `log_only`: for low-risk events that should be retained but do not require action.
- `review_queue`: for uncertain, malformed, evasive, or conflicting events.
- `create_ticket`: for medium or high risk events requiring SOC follow-up.
- `simulated_block_ip`: for high-confidence malicious activity when safety checks allow automation.

## Evidence Fields

The decision log should preserve:

- `timestamp`
- `event_id`
- `correlation_id`
- `community_id`
- `raw_event_sha256`
- `model_name`
- `model_version`
- `model_sha256`
- `feature_summary`
- `predicted_label`
- `confidence`
- `risk_score`
- `severity`
- `reason_codes`
- `guardrail_flags`
- `action_taken`
- `analyst_override`
- `review_required`

## Requirement Coverage

| Assignment Requirement | Planned Fulfillment |
| --- | --- |
| Autonomous or semi-autonomous agent | Explainable classifier plus bounded routing logic |
| Event intake pipeline | Simulated Suricata-style `eve.json` event intake |
| Threat classification | Labels for benign, credential access, lateral movement, command and control, exploit attempt, and human review |
| Logging and evidence preservation | Decision logs, raw-event hashes, model metadata, action records, and analyst override fields |
| Bypass or evasion handling | Malformed, obfuscated, high-entropy, and prompt-injection-like events are handled by deterministic review checks |
| Self-healing or response action | Implemented simulated ticket creation, review escalation, and simulated IP blocklist action |
| Walkthrough document | `docs/WALKTHROUGH_DRAFT.md` is the starting source |
| Video demo | Out of scope for now |

## Course Alignment

- Module 1: threat intelligence features, entropy, classification labels, and ATT&CK-style reasoning.
- Module 2: bounded autonomous agent and low-risk response actions.
- Module 3: bypass and evasion handling.
- Module 4: SOAR-style routing, validation, and review queues.
- Module 5: auditability, explainability, accountability, and human oversight.
- Module 6: Suricata-style telemetry, alert triage, risk scoring, and false-positive reduction.
- Module 7: forensic logging, model metadata, hashes, correlation IDs, and chain-of-custody evidence.
