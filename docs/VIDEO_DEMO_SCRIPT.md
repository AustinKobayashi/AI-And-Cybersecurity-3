# Video Demo Script

Target length: about 4 minutes. Maximum allowed length: under 5 minutes.

Purpose: show that the mini-SOC pipeline works end to end. Keep the recording focused on the running system, not on editing code.

## Pre-recording Checklist

- Start in the project root.
- Make the terminal large enough to read in the recording.
- If the terminal prompt shows a personal folder path, clear the terminal or use a shorter prompt before recording.
- Keep `README.md` open in the editor.
- Keep the file explorer or editor sidebar ready to show `data/`, `src/minisoc/`, `docs/`, and `outputs/`.
- Run the `respond` command live during the recording. If outputs already exist, that is okay because the command overwrites the demo outputs.
- Do not show unrelated browser tabs, personal files, or local folders outside the project.

## 0:00 to 0:25 - Intro And Safety Boundary

Screen action:

- Show `README.md`.
- Point briefly at the workflow diagram and the safety boundary section.

Narration:

"For the technical-track capstone, I built a simulated mini-SOC pipeline using AI-generated synthetic Suricata telemetry.

The workflow validates events, extracts features, classifies threats with a decision tree, scores risk, applies safety checks, routes simulated responses, and preserves evidence for review.

The safety boundary is important: this does not connect to live networks, real malware, firewalls, endpoint isolation, a production SIEM, or a production SOAR system."

## 0:25 to 0:55 - Project Setup

Screen action:

- Show the project folders: `data/`, `src/minisoc/`, `docs/`, and `outputs/`.
- In the terminal, run:

```powershell
python -m minisoc.cli --help
```

Narration:

"The project is organized as a small Python package. `data/` contains the synthetic datasets, `src/minisoc/` contains the real pipeline implementation, `docs/` contains the written deliverables, and `outputs/` holds generated demo artifacts.

The small root `minisoc/` folder is only there to make the command-line demo run directly from the project folder, without requiring an install step first.

The help output shows the available commands. In this demo I will use `validate`, `respond`, and `export-evidence`."


## 0:55 to 1:25 - Event Intake

Screen action:

- Run:

```powershell
python -m minisoc.cli validate data\sample\demo_scenario_events_20.eve.jsonl
```

Narration:

"First I validate the small 20-event demo dataset. These records are line-delimited JSON (JAY-sawn) events that resemble Suricata (soo-ri-KAH-tah) `eve.json` telemetry, but they are synthetic and safe.

The output shows that all 20 records are valid and none are rejected as malformed. It also shows that 3 records require review, which is intentional because the demo includes evasive or uncertain cases instead of only clean alerts.

The label counts show the scenario mix: 5 benign events, and 3 events each for command and control, credential access, exploit attempt, lateral movement, and human review. The intake stage also calculates a raw event hash in memory. It does not show up in this summary output, but it is carried into the decision log when the response workflow runs."

## 1:25 to 2:15 - Full SOC Pipeline

Screen action:

- Run:

```powershell
python -m minisoc.cli respond data\sample\demo_scenario_events_20.eve.jsonl --train data\raw\synthetic_minisoc_events_combined_2200.eve.jsonl --outputs outputs
```

- Pause on the action counts.

Narration:

"Now I run the full response workflow. The output shows two different files because the combined synthetic dataset is used for training, while the smaller demo file is the set of events being processed.

For each event, intake validates the JSON and carries forward the raw event hash. Feature extraction turns the log fields into signals the model can use, such as alert severity, ports, failed login counts, entropy, missing fields, and obfuscation flags. The decision tree uses those signals to predict a threat category, and the risk scorer turns the prediction and event context into a priority level.

Before the pipeline chooses a response, the deterministic safety checks look for cases that should not be handled automatically, such as malformed input, obfuscation, or text that resembles instructions. After that, the response router chooses a safe local action: auto-close, create a ticket, send to review, or write to the simulated blocklist.

The action counts summarize how the 20 events were handled. Five were auto-closed, eight created tickets, three went to the review queue, and four were written to the simulated blocklist. The output paths show where those artifacts were saved for the next part of the demo."


## 2:15 to 3:20 - Inspect Outputs

Screen action:

- Open or preview:
  - `outputs\decision_logs\decisions.jsonl`
  - `outputs\review_queue\review_queue.jsonl`
  - `outputs\simulated_blocklist.txt`

Narration:

"These are the local artifacts created by the response workflow.

`<OPEN DECISION LOG>`

Here I am looking at the decision log and you can see that `demo-0016` was classified as an `exploit_attempt`, with high severity and a risk score of 76. The reason codes show why it was escalated, including high alert severity, high URI entropy, and high-value asset context. The action is `create_ticket`, so the decision log ties together the model output, score, reasons, safety checks, raw event hash, and final action.

`<OPEN REVIEW QUEUE>`

The review queue shows events that should not be handled automatically. In `demo-0018`, automation is blocked because the event has obfuscation flags and text that resembles instructions in an untrusted log field. Even though it is high risk, the pipeline sends it to review instead of taking an automatic action.

`<OPEN SIMULATED BLOCKLIST>`

The ticket folder simulates SOC follow-up work by saving local JSON records for events that need investigation. The blocklist simulates a containment action by writing selected IP addresses to a text file instead of touching a real firewall. The blocklist only stores IP addresses, so the supporting metadata stays in the decision log. That keeps the response safe while still making the decision reviewable.
"

## 3:20 to 4:10 - Forensic Export

Screen action:

- Run:

```powershell
python -m minisoc.cli export-evidence --event-id demo-0008 --events data\sample\demo_scenario_events_20.eve.jsonl --decisions outputs\decision_logs\decisions.jsonl --outputs outputs
```

- Open or preview:
  - `outputs\evidence_exports\demo-0008\analyst_summary.md`
  - `outputs\evidence_exports\demo-0008\hash_manifest.json`

Narration:

"The export command creates a small evidence package for one event, here `demo-0008`. The folder includes the original synthetic event, the decision record, model metadata, action record, analyst summary, and hash manifest.

The main point is that a reviewer does not have to reconstruct the event from scattered output files, instead the package keeps the input, decision, action, summary, and file hashes together in one place."

## 4:10 to 4:40 - Closing

Screen action:

- Return to `README.md` or the walkthrough PDF.

Narration:

"So overall, this prototype demonstrates a safe local mini-SOC workflow: synthetic event intake, classification, risk scoring, safety checks, simulated response, and evidence preservation, without connecting to real security systems."

## Quick Command List

Use these commands during the recording:

```powershell
python -m minisoc.cli --help
python -m minisoc.cli validate data\sample\demo_scenario_events_20.eve.jsonl
python -m minisoc.cli respond data\sample\demo_scenario_events_20.eve.jsonl --train data\raw\synthetic_minisoc_events_combined_2200.eve.jsonl --outputs outputs
python -m minisoc.cli export-evidence --event-id demo-0008 --events data\sample\demo_scenario_events_20.eve.jsonl --decisions outputs\decision_logs\decisions.jsonl --outputs outputs
```

## Backup Line If The Recording Runs Long

"I will stop here because the core workflow is visible: the system ingests synthetic events, classifies and scores them, applies safety checks, routes simulated responses, and preserves evidence for review."
