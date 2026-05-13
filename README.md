# AI And Cybersecurity 3 Capstone

This folder contains the boilerplate for the Technical / Engineering Track capstone project.

The planned project is a simulated mini-SOC workflow:

```text
Simulated Suricata-style events
  -> Event intake
  -> Feature extraction
  -> AI-assisted classification
  -> Risk scoring
  -> Deterministic guardrails
  -> Response routing
  -> Evidence preservation
  -> Forensic export
```

The scaffold is intentionally not a finished pipeline. It provides the project layout, planning documents, config templates, sample data placeholders, and source stubs needed to implement the plan later.

## Safety Boundary

- Do not connect this project to a live production network.
- Do not process real malware.
- Do not trigger real firewall, endpoint isolation, account disablement, or production response actions.
- Use simulated logs, generated events, lab traffic, or controlled PCAPs only.

## Project Layout

```text
config/                  Example pipeline configuration
data/raw/                Future generated or controlled input data
data/sample/             Small safe sample events and asset inventory
docs/                    Planning and walkthrough source documents
models/                  Future trained model metadata and artefacts
outputs/                 Generated demo outputs, ignored by git
src/minisoc/             Python package stubs for future implementation
tests/                   Test stubs for future implementation
```

## Planned Demo Flow

1. Load simulated Suricata-style `eve.json` events.
2. Validate and normalize the records.
3. Extract explainable security features.
4. Classify each event with a bounded, explainable model.
5. Convert model output and context into a risk score.
6. Apply deterministic guardrails before any response action.
7. Route the event to log-only, review, ticket creation, or simulated blocking.
8. Preserve raw evidence, model metadata, decision records, and action records.
9. Export a forensic evidence package for one selected event.

## Key Documents

- [Pipeline Plan](docs/PIPELINE_PLAN.md)
- [Walkthrough Draft](docs/WALKTHROUGH_DRAFT.md)
- [Architecture Diagram](docs/architecture.mmd)

