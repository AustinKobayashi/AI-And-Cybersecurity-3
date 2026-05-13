"""Small command-line helper for the capstone workflow."""

from __future__ import annotations

import argparse
import sys

from .intake import load_event_records, summarize_records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="minisoc")
    subparsers = parser.add_subparsers(dest="command")

    validate_parser = subparsers.add_parser("validate", help="validate a JSONL event file")
    validate_parser.add_argument("jsonl_path", help="path to a Suricata-style JSONL file")

    args = parser.parse_args(argv)

    if args.command == "validate":
        return _validate_command(args.jsonl_path)

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


if __name__ == "__main__":
    sys.exit(main())
