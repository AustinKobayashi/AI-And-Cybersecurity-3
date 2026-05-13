from pathlib import Path

from minisoc.features import extract_features, shannon_entropy
from minisoc.intake import load_events


ROOT = Path(__file__).resolve().parents[1]
DEMO_DATASET = ROOT / "data" / "sample" / "demo_scenario_events_20.eve.jsonl"

FEATURE_KEYS = {
    "domain_entropy",
    "uri_entropy",
    "byte_ratio",
    "packet_ratio",
    "alert_severity",
    "destination_port",
    "failed_login_count",
    "internal_probe_count",
    "callback_interval_seconds",
    "obfuscation_flag_count",
    "missing_field_flag_count",
    "prompt_injection_like_text_flag",
    "asset_criticality_score",
}


def test_demo_events_produce_feature_schema():
    feature_records = [extract_features(event) for event in load_events(str(DEMO_DATASET))]

    assert len(feature_records) == 20

    for record in feature_records:
        assert set(record) == {"event_id", "expected_label", "features", "reason_codes"}
        assert set(record["features"]) == FEATURE_KEYS
        assert record["event_id"].startswith("demo-")
        assert record["expected_label"]
        assert record["reason_codes"]
        assert all(
            isinstance(value, (int, float)) and not isinstance(value, bool)
            for value in record["features"].values()
        )


def test_demo_scenarios_expose_label_specific_signals():
    records = {
        record["event_id"]: record
        for record in [extract_features(event) for event in load_events(str(DEMO_DATASET))]
    }

    credential_access = records["demo-0008"]
    assert credential_access["features"]["failed_login_count"] == 60
    assert "many_failed_logins" in credential_access["reason_codes"]

    lateral_movement = records["demo-0009"]
    assert lateral_movement["features"]["internal_probe_count"] == 35
    assert "internal_probe_activity" in lateral_movement["reason_codes"]

    command_and_control = records["demo-0013"]
    assert command_and_control["features"]["domain_entropy"] == 4.325
    assert command_and_control["features"]["callback_interval_seconds"] == 90
    assert "high_domain_entropy" in command_and_control["reason_codes"]
    assert "periodic_callback_signal" in command_and_control["reason_codes"]

    exploit_attempt = records["demo-0017"]
    assert exploit_attempt["features"]["uri_entropy"] == 4.681
    assert "high_uri_entropy" in exploit_attempt["reason_codes"]


def test_demo_review_cases_expose_evasion_signals():
    records = {
        record["event_id"]: record
        for record in [extract_features(event) for event in load_events(str(DEMO_DATASET))]
    }

    prompt_injection = records["demo-0018"]
    assert prompt_injection["features"]["prompt_injection_like_text_flag"] == 1
    assert prompt_injection["features"]["obfuscation_flag_count"] == 1
    assert "prompt_injection_like_text" in prompt_injection["reason_codes"]

    missing_fields = records["demo-0019"]
    assert missing_fields["features"]["missing_field_flag_count"] == 2
    assert "missing_field_flags_present" in missing_fields["reason_codes"]

    obfuscated = records["demo-0020"]
    assert obfuscated["features"]["obfuscation_flag_count"] == 2
    assert "obfuscation_flags_present" in obfuscated["reason_codes"]


def test_entropy_falls_back_to_event_text_when_hints_are_missing():
    event = {
        "event_id": "manual-entropy",
        "expected_label": "command_and_control",
        "dns": {"query": "aaaaabbbbb.example.test"},
        "http": {"hostname": "xy9z7q.example.test", "url": "/api/abc123xyz"},
        "flow": {
            "bytes_toserver": 30,
            "bytes_toclient": 10,
            "pkts_toserver": 6,
            "pkts_toclient": 2,
        },
        "alert": {"severity": 2},
        "dest_port": 443,
        "asset_criticality": "medium",
    }

    record = extract_features(event)

    assert record["features"]["domain_entropy"] == max(
        shannon_entropy("aaaaabbbbb.example.test"),
        shannon_entropy("xy9z7q.example.test"),
    )
    assert record["features"]["uri_entropy"] == shannon_entropy("/api/abc123xyz")
    assert record["features"]["byte_ratio"] == 3.0
    assert record["features"]["packet_ratio"] == 3.0


def test_missing_optional_fields_and_zero_denominators_are_safe():
    event = {
        "event_id": "manual-edge",
        "expected_label": "benign",
        "dns": {"query": ""},
        "http": {"hostname": "", "url": "", "user_agent": ""},
        "flow": {
            "bytes_toserver": 100,
            "bytes_toclient": 0,
            "pkts_toserver": 5,
            "pkts_toclient": 0,
        },
        "alert": {"severity": ""},
        "dest_port": "",
        "asset_criticality": "unknown",
    }

    record = extract_features(event)
    features = record["features"]

    assert features["domain_entropy"] == 0.0
    assert features["uri_entropy"] == 0.0
    assert features["byte_ratio"] == 0.0
    assert features["packet_ratio"] == 0.0
    assert features["alert_severity"] == 0
    assert features["destination_port"] == 0
    assert features["failed_login_count"] == 0
    assert features["internal_probe_count"] == 0
    assert features["callback_interval_seconds"] == 0
    assert features["obfuscation_flag_count"] == 0
    assert features["missing_field_flag_count"] == 0
    assert features["prompt_injection_like_text_flag"] == 0
    assert features["asset_criticality_score"] == 0
    assert record["reason_codes"] == ["no_strong_signal"]
