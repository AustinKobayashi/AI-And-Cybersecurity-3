"""Small command-line helper for the capstone workflow."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from .classifier import classify_events, train_classifier
from .evidence import build_evidence_record
from .exporter import ExportEvidenceError, export_evidence_package
from .features import extract_features
from .guardrails import apply_guardrails
from .intake import load_event_records, summarize_records
from .intake import load_events
from .response import route_response
from .scoring import score_risk


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="minisoc")
    subparsers = parser.add_subparsers(dest="command")

    validate_parser = subparsers.add_parser("validate", help="validate a JSONL event file")
    validate_parser.add_argument("jsonl_path", help="path to a Suricata-style JSONL file")

    classify_parser = subparsers.add_parser("classify", help="classify a JSONL event file")
    classify_parser.add_argument("jsonl_path", help="path to the JSONL file to classify")
    classify_parser.add_argument(
        "--train",
        required=True,
        help="path to the labelled JSONL file used for training",
    )

    respond_parser = subparsers.add_parser(
        "respond",
        help="run the simulated response routing workflow",
    )
    respond_parser.add_argument("jsonl_path", help="path to the JSONL file to process")
    respond_parser.add_argument(
        "--train",
        required=True,
        help="path to the labelled JSONL file used for training",
    )
    respond_parser.add_argument(
        "--outputs",
        default="outputs",
        help="directory used for simulated response output files",
    )

    export_parser = subparsers.add_parser(
        "export-evidence",
        help="export a local evidence package for one event",
    )
    export_parser.add_argument(
        "--event-id",
        required=True,
        help="event ID to export",
    )
    export_parser.add_argument(
        "--events",
        required=True,
        help="path to the original JSONL event file",
    )
    export_parser.add_argument(
        "--decisions",
        required=True,
        help="path to the generated decision log JSONL file",
    )
    export_parser.add_argument(
        "--outputs",
        default="outputs",
        help="directory used for evidence export output files",
    )

    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="evaluate classifier performance with a stratified holdout split",
    )
    evaluate_parser.add_argument("jsonl_path", help="path to a labelled JSONL file")
    evaluate_parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="fraction of records held out for evaluation",
    )
    evaluate_parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="random seed used for the train/test split",
    )

    args = parser.parse_args(argv)

    if args.command == "validate":
        return _validate_command(args.jsonl_path)
    if args.command == "classify":
        return _classify_command(args.jsonl_path, args.train)
    if args.command == "respond":
        return _respond_command(args.jsonl_path, args.train, args.outputs)
    if args.command == "export-evidence":
        return _export_evidence_command(
            args.event_id,
            args.events,
            args.decisions,
            args.outputs,
        )
    if args.command == "evaluate":
        return _evaluate_command(args.jsonl_path, args.test_size, args.seed)

    parser.print_help()
    return 2


def _validate_command(path: str) -> int:
    records = load_event_records(path)
    summary = summarize_records(records)

    print(f"File: {path}")
    print(f"Total records: {summary['total']}")
    print(f"Valid records: {summary['valid']}")
    print(f"Invalid records: {summary['invalid']}")
    print(f"Review required: {summary['review_required']}")
    print("Labels:")

    for label, count in summary["labels"].items():
        print(f"  {label}: {count}")

    if summary["invalid"]:
        print("Invalid rows:")
        for record in [item for item in records if not item["valid"]][:5]:
            joined_errors = "; ".join(record["errors"])
            print(f"  line {record['line_number']}: {joined_errors}")
        return 1

    return 0


def _evaluate_command(path: str, test_size: float, seed: int) -> int:
    if not 0 < test_size < 1:
        print("Error: --test-size must be greater than 0 and less than 1.")
        return 1

    feature_records = [extract_features(event) for event in load_events(path)]
    labelled_records = [
        record
        for record in feature_records
        if isinstance(record, dict) and record.get("expected_label")
    ]
    if len(labelled_records) != len(feature_records):
        print("Error: every feature record must include an expected_label for evaluation.")
        return 1

    label_counts = Counter(record["expected_label"] for record in labelled_records)
    test_record_count = math.ceil(len(labelled_records) * test_size)
    train_record_count = len(labelled_records) - test_record_count
    label_count = len(label_counts)

    if min(label_counts.values()) < 2:
        print("Error: each label needs at least two records for stratified evaluation.")
        return 1
    if test_record_count < label_count or train_record_count < label_count:
        print("Error: evaluation split is too small for the number of labels.")
        print("Try a larger --test-size or use a larger labelled dataset.")
        return 1

    labels = [record["expected_label"] for record in labelled_records]
    train_records, test_records = train_test_split(
        labelled_records,
        test_size=test_size,
        random_state=seed,
        stratify=labels,
    )
    model_bundle = train_classifier(train_records)
    classifications = classify_events(test_records, model_bundle)
    expected_labels = [item["expected_label"] for item in classifications]
    predicted_labels = [item["predicted_label"] for item in classifications]
    label_order = sorted(model_bundle["labels"])
    accuracy = accuracy_score(expected_labels, predicted_labels)
    report = classification_report(
        expected_labels,
        predicted_labels,
        labels=label_order,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(expected_labels, predicted_labels, labels=label_order)

    print(f"File: {path}")
    print(f"Total labelled records: {len(labelled_records)}")
    print(f"Training records: {len(train_records)}")
    print(f"Test records: {len(test_records)}")
    print(f"Test size: {test_size:.2f}")
    print(f"Seed: {seed}")
    print(f"Model: {model_bundle['model_name']} {model_bundle['model_version']}")
    print(f"Accuracy: {accuracy:.4f}")
    print("Classification report:")
    print("  label precision recall f1 support")

    for label in label_order:
        metrics = report[label]
        print(
            f"  {label} "
            f"{metrics['precision']:.4f} "
            f"{metrics['recall']:.4f} "
            f"{metrics['f1-score']:.4f} "
            f"{int(metrics['support'])}"
        )

    print(
        f"  macro_avg "
        f"{report['macro avg']['precision']:.4f} "
        f"{report['macro avg']['recall']:.4f} "
        f"{report['macro avg']['f1-score']:.4f} "
        f"{int(report['macro avg']['support'])}"
    )
    print(
        f"  weighted_avg "
        f"{report['weighted avg']['precision']:.4f} "
        f"{report['weighted avg']['recall']:.4f} "
        f"{report['weighted avg']['f1-score']:.4f} "
        f"{int(report['weighted avg']['support'])}"
    )

    print("Confusion matrix:")
    print("  rows=expected columns=predicted")
    print("  labels: " + ", ".join(label_order))
    for label, row in zip(label_order, matrix):
        row_text = " ".join(str(int(value)) for value in row)
        print(f"  {label}: {row_text}")

    return 0


def _classify_command(path: str, train_path: str) -> int:
    pipeline = _run_pipeline(path, train_path)
    training_features = pipeline["training_features"]
    model_bundle = pipeline["model_bundle"]
    classifications = pipeline["classifications"]
    risk_scores = pipeline["risk_scores"]
    guardrail_results = pipeline["guardrail_results"]
    predicted_counts = Counter(item["predicted_label"] for item in classifications)
    severity_counts = Counter(item["severity"] for item in risk_scores)
    guardrail_flag_counts = Counter(
        flag
        for result in guardrail_results
        for flag in result["guardrail_flags"]
    )

    print(f"Training file: {train_path}")
    print(f"Classify file: {path}")
    print(f"Training records: {len(training_features)}")
    print(f"Classified records: {len(classifications)}")
    print(f"Model: {model_bundle['model_name']} {model_bundle['model_version']}")
    print("Predicted labels:")

    for label, count in sorted(predicted_counts.items()):
        print(f"  {label}: {count}")

    print("Severity counts:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")

    automation_allowed = sum(
        1 for result in guardrail_results if result["automation_allowed"]
    )
    review_required = sum(1 for result in guardrail_results if result["review_required"])
    print(f"Automation allowed: {automation_allowed}")
    print(f"Review required: {review_required}")

    if guardrail_flag_counts:
        print("Guardrail flags:")
        for flag, count in sorted(guardrail_flag_counts.items()):
            print(f"  {flag}: {count}")

    print("Sample classifications:")
    for item, risk, guardrails in zip(
        classifications[:10],
        risk_scores[:10],
        guardrail_results[:10],
    ):
        print(
            f"  {item['event_id']}: {item['predicted_label']} "
            f"confidence={item['confidence']:.4f} "
            f"risk={risk['risk_score']} "
            f"severity={risk['severity']} "
            f"automation_allowed={str(guardrails['automation_allowed']).lower()} "
            f"review_required={str(guardrails['review_required']).lower()} "
            f"expected={item['expected_label']}"
        )

    return 0


def _respond_command(path: str, train_path: str, outputs_path: str) -> int:
    pipeline = _run_pipeline(path, train_path)
    responses = [
        route_response(event, classification, risk, guardrails)
        for event, classification, risk, guardrails in zip(
            pipeline["target_events"],
            pipeline["classifications"],
            pipeline["risk_scores"],
            pipeline["guardrail_results"],
        )
    ]
    action_counts = Counter(response["action"] for response in responses)
    output_paths = _write_response_outputs(Path(outputs_path), pipeline, responses)

    print(f"Training file: {train_path}")
    print(f"Respond file: {path}")
    print(f"Training records: {len(pipeline['training_features'])}")
    print(f"Processed records: {len(responses)}")
    print(
        f"Model: {pipeline['model_bundle']['model_name']} "
        f"{pipeline['model_bundle']['model_version']}"
    )
    print("Action counts:")

    for action, count in sorted(action_counts.items()):
        print(f"  {action}: {count}")

    print("Output paths:")
    print(f"  Decision log: {output_paths['decision_log']}")
    print(f"  Review queue: {output_paths['review_queue']}")
    print(f"  Tickets directory: {output_paths['tickets_dir']}")
    print(f"  Simulated blocklist: {output_paths['simulated_blocklist']}")

    return 0


def _export_evidence_command(
    event_id: str,
    events_path: str,
    decisions_path: str,
    outputs_path: str,
) -> int:
    try:
        export = export_evidence_package(
            event_id,
            events_path,
            decisions_path,
            outputs_path,
        )
    except ExportEvidenceError as exc:
        print(f"Error: {exc}")
        return 1

    print(f"Event ID: {export['event_id']}")
    print(f"Export directory: {export['export_dir']}")
    print("Files written:")
    for path in export["files"]:
        print(f"  {path}")

    return 0


def _run_pipeline(path: str, train_path: str) -> dict:
    training_events = load_events(train_path)
    target_events = load_events(path)
    training_features = [extract_features(event) for event in training_events]
    target_features = [extract_features(event) for event in target_events]
    model_bundle = train_classifier(training_features)
    classifications = classify_events(target_features, model_bundle)
    risk_scores = [
        score_risk(classification, feature_record)
        for classification, feature_record in zip(classifications, target_features)
    ]
    guardrail_results = [
        apply_guardrails(event, feature_record, classification, risk)
        for event, feature_record, classification, risk in zip(
            target_events,
            target_features,
            classifications,
            risk_scores,
        )
    ]

    return {
        "training_features": training_features,
        "target_events": target_events,
        "target_features": target_features,
        "model_bundle": model_bundle,
        "classifications": classifications,
        "risk_scores": risk_scores,
        "guardrail_results": guardrail_results,
    }


def _write_response_outputs(
    outputs_dir: Path,
    pipeline: dict,
    responses: list[dict],
) -> dict:
    review_dir = outputs_dir / "review_queue"
    decision_dir = outputs_dir / "decision_logs"
    tickets_dir = outputs_dir / "tickets"
    review_dir.mkdir(parents=True, exist_ok=True)
    decision_dir.mkdir(parents=True, exist_ok=True)
    tickets_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    decision_path = decision_dir / "decisions.jsonl"
    review_path = review_dir / "review_queue.jsonl"
    blocklist_path = outputs_dir / "simulated_blocklist.txt"

    records = [
        _response_record(event, classification, risk, guardrails, response)
        for event, classification, risk, guardrails, response in zip(
            pipeline["target_events"],
            pipeline["classifications"],
            pipeline["risk_scores"],
            pipeline["guardrail_results"],
            responses,
        )
    ]

    with review_path.open("w", encoding="utf-8") as handle:
        for record in records:
            if record["action"] == "review_queue":
                handle.write(json.dumps(record, sort_keys=True) + "\n")

    evidence_records = [
        build_evidence_record(
            event,
            {
                "model": pipeline["model_bundle"],
                "features": feature_record,
                "classification": classification,
                "risk": risk,
                "guardrails": guardrails,
                "response": response,
            },
        )
        for event, feature_record, classification, risk, guardrails, response in zip(
            pipeline["target_events"],
            pipeline["target_features"],
            pipeline["classifications"],
            pipeline["risk_scores"],
            pipeline["guardrail_results"],
            responses,
        )
    ]

    with decision_path.open("w", encoding="utf-8") as handle:
        for record in evidence_records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    for record in records:
        if record["action"] != "create_ticket":
            continue
        ticket_path = tickets_dir / f"{_safe_filename(record['event_id'])}.json"
        ticket_path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    with blocklist_path.open("w", encoding="utf-8") as handle:
        for record in records:
            if record["action"] == "simulated_block_ip" and record["target"]:
                handle.write(f"{record['target']}\n")

    return {
        "decision_log": str(decision_path),
        "review_queue": str(review_path),
        "tickets_dir": str(tickets_dir),
        "simulated_blocklist": str(blocklist_path),
    }


def _response_record(
    event: dict,
    classification: dict,
    risk: dict,
    guardrails: dict,
    response: dict,
) -> dict:
    return {
        "event_id": response.get("event_id", ""),
        "timestamp": event.get("timestamp", "") if isinstance(event, dict) else "",
        "src_ip": event.get("src_ip", "") if isinstance(event, dict) else "",
        "dest_ip": event.get("dest_ip", "") if isinstance(event, dict) else "",
        "predicted_label": classification.get("predicted_label", ""),
        "confidence": classification.get("confidence", 0.0),
        "risk_score": risk.get("risk_score", 0),
        "severity": risk.get("severity", ""),
        "automation_allowed": response.get("automation_allowed", False),
        "review_required": response.get("review_required", False),
        "guardrail_flags": guardrails.get("guardrail_flags", []),
        "action": response.get("action", ""),
        "action_taken": response.get("action_taken", ""),
        "target": response.get("target", ""),
        "reason_codes": response.get("reason_codes", []),
        "simulated_only": True,
    }


def _safe_filename(value: str) -> str:
    safe = "".join(
        character if character.isalnum() or character in {"-", "_"} else "_"
        for character in str(value)
    )
    return safe or "event"


if __name__ == "__main__":
    sys.exit(main())
