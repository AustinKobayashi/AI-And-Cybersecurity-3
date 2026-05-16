# Outputs

Generated demo outputs are written here when the simulated response and evidence export commands run.

The `.gitignore` excludes generated output files while keeping the folder structure. These artifacts can be recreated locally and should not be treated as committed source data.

Run the response workflow from the project root to recreate the main output files:

```powershell
python -m minisoc.cli respond data\sample\demo_scenario_events_20.eve.jsonl --train data\raw\synthetic_minisoc_events_combined_2200.eve.jsonl --outputs outputs
```

Output categories:

- `decision_logs/`: JSONL decision records from the simulated response workflow. The main file is `decision_logs/decisions.jsonl`.
- `review_queue/`: JSONL records for events where automation was blocked and analyst review is required.
- `tickets/`: simulated incident tickets written as one JSON file per ticketed event.
- `simulated_blocklist.txt`: simulated containment output containing selected IP addresses. This is not a firewall blocklist.
- `evidence_exports/`: local evidence packages created by `export-evidence`. Each event export includes the raw event, decision record, action record, model metadata, analyst summary, and hash manifest.

Create an evidence package from an existing decision log with:

```powershell
python -m minisoc.cli export-evidence --event-id demo-0008 --events data\sample\demo_scenario_events_20.eve.jsonl --decisions outputs\decision_logs\decisions.jsonl --outputs outputs
```

All response actions are simulated. These files do not create real tickets, connect to a firewall, isolate endpoints, disable accounts, or send data to a production SIEM or SOAR platform.
