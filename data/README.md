# Capstone Data

## AI-Generated Dataset Notice

The datasets in this folder are synthetic AI-generated security telemetry created for this capstone project. They are not production logs, live network captures, real malware traffic, or evidence from a real incident. Labels such as `benign`, `credential_access`, `lateral_movement`, `command_and_control`, `exploit_attempt`, and `needs_human_review` are proxy labels for the simulation and should be treated as demonstration ground truth only.

The records are intended for capstone demonstration, future local model training experiments, and evaluation only.

## Safety Boundary

Use simulated or controlled data only.

The baseline project should use Suricata-style line-delimited JSON events. These records should look like EVE JSON logs, but they should not come from a live production network.

Do not use these files as evidence from real systems. Do not connect this project to a live production network, real firewall, production SIEM, endpoint isolation tool, or real containment workflow.

## Included Files

- `sample/simulated_events.eve.jsonl`: small safe example event set.
- `sample/demo_scenario_events_20.eve.jsonl`: 20-record readable demo set for walkthrough and video narration.
- `sample/asset_inventory.example.csv`: example asset criticality metadata.
- `raw/synthetic_minisoc_events_2000.eve.jsonl`: 2,000-record Suricata-style synthetic dataset for future model training and evaluation.
- `raw/synthetic_minisoc_dataset_manifest.json`: manifest with generation metadata, schema, safety notes, class counts, and SHA-256 hashes.
- `raw/synthetic_minisoc_label_distribution.csv`: label counts and percentages for the full and demo datasets.
- `raw/`: location for generated events or controlled PCAP-derived logs.

## Validation Commands

Run these from the capstone project root:

```powershell
python -m minisoc.cli validate data\raw\synthetic_minisoc_events_2000.eve.jsonl
python -m minisoc.cli validate data\sample\demo_scenario_events_20.eve.jsonl
```

Expected summaries:

- Full dataset: 2,000 total records, 2,000 valid records, 60 review-required records.
- Demo dataset: 20 total records, 20 valid records, 3 review-required records.

## Full Dataset Class Distribution

| Label | Count | Percent |
| --- | ---: | ---: |
| `benign` | 1300 | 65% |
| `credential_access` | 220 | 11% |
| `lateral_movement` | 160 | 8% |
| `command_and_control` | 140 | 7% |
| `exploit_attempt` | 120 | 6% |
| `needs_human_review` | 60 | 3% |

## Demo Dataset Class Distribution

| Label | Count |
| --- | ---: |
| `benign` | 5 |
| `credential_access` | 3 |
| `lateral_movement` | 3 |
| `command_and_control` | 3 |
| `exploit_attempt` | 3 |
| `needs_human_review` | 3 |

## Event Categories To Cover

- Benign traffic.
- Credential access.
- Lateral movement.
- Command and control.
- Exploit attempt.
- Malformed or evasive input that should route to human review.
