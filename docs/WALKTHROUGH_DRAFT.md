# Technical Walkthrough Draft

This file is the source outline for the future 2-4 page capstone walkthrough PDF.

## 1. Design Rationale

Explain why the project uses a simulated mini-SOC design, Suricata-style JSON events, an explainable classifier, deterministic safety checks, and simulated response actions.

## 2. Architecture Diagram

Reference `docs/architecture.mmd` and describe the flow:

```text
Log Source -> Parser -> Feature Extractor -> Classifier -> Scoring Engine -> Review Gate -> Response Logic -> Evidence Logs
```

## 3. Model Or Logic Explanation

Describe the implemented event labels, model confidence, deterministic risk score, severity lanes, reason codes, review-gate decisions, simulated response routing, and evidence logging.

## 4. Bypass And Failure Handling

Explain how risk scoring raises priority for missing fields, high-entropy strings, obfuscated input, and prompt-injection-like text, and how deterministic safety checks hold suspicious or uncertain cases for human review.

## 5. Forensic Readiness Strategy

Explain what evidence is preserved:

- Raw event hash.
- Normalized features.
- Model metadata.
- Decision log.
- Action record.
- Analyst override field.
- SHA-256 manifest.
- Local forensic export package for one selected event.

## 6. Known Limitations

- Simulated data only.
- No live network connection.
- No real firewall or endpoint action.
- No production SIEM or SOAR integration.
- No LLM in the baseline version.
- Forensic export packages are local demo artifacts under `outputs/evidence_exports/`.

## Integrity Statement

I confirm that this submission is my original work. Any external tools, references, datasets, frameworks, or code libraries used in this project have been acknowledged. I understand that the work must represent my own design, analysis, and implementation decisions.
