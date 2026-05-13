# Technical Walkthrough Draft

This file is the source outline for the future 2-4 page capstone walkthrough PDF.

## 1. Design Rationale

Explain why the project uses a simulated mini-SOC design, Suricata-style JSON events, an explainable classifier, deterministic guardrails, and simulated response actions.

## 2. Architecture Diagram

Reference `docs/architecture.mmd` and describe the flow:

```text
Log Source -> Parser -> Feature Extractor -> Classifier -> Scoring Engine -> Guardrails -> Response Logic -> Evidence Logs
```

## 3. Model Or Logic Explanation

Describe the implemented event labels, model confidence, deterministic risk score, severity lanes, and reason codes. Note that guardrail overrides are still planned.

## 4. Bypass And Failure Handling

Explain how risk scoring raises priority for missing fields, high-entropy strings, obfuscated input, and prompt-injection-like text. Note that the planned guardrail layer will route these cases to human review.

## 5. Forensic Readiness Strategy

Explain what evidence is preserved:

- Raw event hash.
- Normalized features.
- Model metadata.
- Decision log.
- Action record.
- Analyst override field.
- SHA-256 manifest.

## 6. Known Limitations

- Simulated data only.
- No live network connection.
- No real firewall or endpoint action.
- No production SIEM or SOAR integration.
- No LLM in the baseline version.
- Guardrails, response routing, evidence logging, and forensic export are still planned.

## Integrity Statement

I confirm that this submission is my original work. Any external tools, references, datasets, frameworks, or code libraries used in this project have been acknowledged. I understand that the work must represent my own design, analysis, and implementation decisions.
