# Outputs

Generated demo outputs should be written here.

The `.gitignore` excludes generated output files while keeping the folder structure.

Output categories:

- `decision_logs/`: JSONL decision records from the simulated response workflow.
- `review_queue/`: events requiring analyst review from the simulated response workflow.
- `tickets/`: simulated incident tickets from the response workflow.
- `evidence_exports/`: local forensic export packages with raw event, decision record, action record, model metadata, analyst summary, and hash manifest.
- `simulated_blocklist.txt`: simulated response output, not a real firewall blocklist.
