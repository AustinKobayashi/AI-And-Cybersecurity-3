import json
from pathlib import Path

from minisoc.intake import load_event_records, load_events, raw_event_hash, summarize_records


ROOT = Path(__file__).resolve().parents[1]
FULL_DATASET = ROOT / "data" / "raw" / "synthetic_minisoc_events_2000.eve.jsonl"
DEMO_DATASET = ROOT / "data" / "sample" / "demo_scenario_events_20.eve.jsonl"


def test_full_dataset_loads_and_summarizes():
    records = load_event_records(str(FULL_DATASET))
    summary = summarize_records(records)

    assert summary["total"] == 2000
    assert summary["valid"] == 2000
    assert summary["invalid"] == 0
    assert summary["review_required"] == 60
    assert summary["labels"] == {
        "benign": 1300,
        "command_and_control": 140,
        "credential_access": 220,
        "exploit_attempt": 120,
        "lateral_movement": 160,
        "needs_human_review": 60,
    }


def test_demo_dataset_loads_and_summarizes():
    records = load_event_records(str(DEMO_DATASET))
    summary = summarize_records(records)

    assert summary["total"] == 20
    assert summary["valid"] == 20
    assert summary["invalid"] == 0
    assert summary["review_required"] == 3


def test_load_events_adds_intake_metadata():
    events = load_events(str(DEMO_DATASET))

    assert len(events) == 20
    assert all("_intake" in event for event in events)
    assert all(event["_intake"]["raw_sha256"] for event in events)


def test_invalid_json_is_kept_for_review(tmp_path):
    bad_file = tmp_path / "bad.eve.jsonl"
    bad_file.write_text('{"event_id": "evt-1"\n', encoding="utf-8")

    records = load_event_records(str(bad_file))

    assert len(records) == 1
    assert records[0]["valid"] is False
    assert records[0]["review_required"] is True
    assert "invalid JSON" in records[0]["errors"][0]


def test_missing_required_field_is_invalid(tmp_path):
    event = _first_demo_event()
    event.pop("src_ip")
    path = tmp_path / "missing-field.eve.jsonl"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    records = load_event_records(str(path))

    assert records[0]["valid"] is False
    assert records[0]["review_required"] is True
    assert "missing field: src_ip" in records[0]["errors"]


def test_review_needed_record_stays_valid_but_review_required():
    records = load_event_records(str(DEMO_DATASET))
    review_records = [record for record in records if record["review_required"]]

    assert len(review_records) == 3
    assert all(record["valid"] for record in review_records)
    assert all(record["review_reasons"] for record in review_records)


def test_raw_event_hash_is_stable():
    assert raw_event_hash("abc") == raw_event_hash("abc")
    assert raw_event_hash("abc") != raw_event_hash("abcd")


def _first_demo_event():
    with DEMO_DATASET.open("r", encoding="utf-8") as handle:
        return json.loads(handle.readline())
