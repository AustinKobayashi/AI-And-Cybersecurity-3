# AI And Cybersecurity 3 Capstone

This folder contains the Technical / Engineering Track capstone project. It is a local mini-SOC demonstration that uses AI generated synthetic Suricata-style telemetry.

The project is a simulated mini-SOC workflow:

```text
AI generated synthetic Suricata-style events
  -> Event intake and validation
  -> Feature extraction
  -> Decision tree classification
  -> Risk scoring
  -> Deterministic safety checks
  -> Simulated response routing
  -> Decision logging
  -> Forensic evidence export
```

The project includes synthetic datasets, event intake, feature extraction, a bounded classifier trained in memory, deterministic risk scoring, a review gate for bypass and failure handling, simulated response routing, evidence logging, and forensic export.

## Safety Boundary

- Use AI generated synthetic telemetry or controlled lab data only.
- Do not connect this project to a live production network.
- Do not process real malware, production logs, or evidence from a real incident.
- Do not connect to a real firewall, endpoint isolation tool, account disablement workflow, production SIEM, or production SOAR platform.
- Treat all response actions as local simulations. Tickets, review records, and blocklist entries are files written under `outputs/`.

## Project Layout

```text
data/raw/                AI generated synthetic training and evaluation datasets
data/sample/             Small demo events and example asset inventory
docs/                    Planning and walkthrough source documents
minisoc/                 Root wrappers for `python -m minisoc.cli`
outputs/                 Local demo outputs, with generated files ignored by git
src/minisoc/             Mini-SOC pipeline implementation
tests/                   Pytest suite for the implemented workflow
pyproject.toml           Project metadata and pytest configuration
requirements.txt         Python dependencies for running the project and tests
```

## CLI Commands

Install the Python dependencies:

```powershell
pip install -r requirements.txt
```

Validate the combined synthetic dataset:

```powershell
python -m minisoc.cli validate data\raw\synthetic_minisoc_events_combined_2200.eve.jsonl
```

Validate the small demo dataset:

```powershell
python -m minisoc.cli validate data\sample\demo_scenario_events_20.eve.jsonl
```

Run the tests:

```powershell
python -m pytest
```

Run only the feature extraction tests:

```powershell
python -m pytest tests\test_features.py
```

Classify, score risk, and apply deterministic safety checks to the demo dataset after training on the combined synthetic dataset:

```powershell
python -m minisoc.cli classify data\sample\demo_scenario_events_20.eve.jsonl --train data\raw\synthetic_minisoc_events_combined_2200.eve.jsonl
```

Run the simulated response workflow and write local demo outputs:

```powershell
python -m minisoc.cli respond data\sample\demo_scenario_events_20.eve.jsonl --train data\raw\synthetic_minisoc_events_combined_2200.eve.jsonl --outputs outputs
```

Export a local forensic evidence package for one selected event. Run `respond` first so the decision log exists:

```powershell
python -m minisoc.cli export-evidence --event-id demo-0008 --events data\sample\demo_scenario_events_20.eve.jsonl --decisions outputs\decision_logs\decisions.jsonl --outputs outputs
```

Evaluate classifier performance with a 20 percent holdout split:

```powershell
python -m minisoc.cli evaluate data\raw\synthetic_minisoc_events_combined_2200.eve.jsonl
```
