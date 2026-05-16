# Tests

This folder contains the pytest suite for the simulated mini-SOC pipeline.

Run tests from the capstone project root:

```powershell
python -m pytest
```

Run a single test module, for example:

```powershell
python -m pytest tests\test_features.py
```

Current coverage areas:

- Event intake and validation.
- Feature extraction and entropy calculations.
- Decision tree classifier label handling and CLI reporting.
- Risk scoring and reason code handling.
- Deterministic safety checks for missing, evasive, or instruction-like input.
- Simulated response routing for auto-close, tickets, review, and blocklist actions.
- Evidence decision records, raw event hashes, model metadata, and safe defaults.
- Forensic export package creation and hash manifest checks.

The tests use the synthetic datasets under `data/`. They do not require live traffic, real malware, production security tools, or generated files under `outputs/`.
