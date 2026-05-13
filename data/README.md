# Data Plan

Use simulated or controlled data only.

The baseline project should use Suricata-style line-delimited JSON events. These records should look like EVE JSON logs, but they should not come from a live production network.

## Included Placeholders

- `sample/simulated_events.eve.jsonl`: small safe example event set.
- `sample/asset_inventory.example.csv`: example asset criticality metadata.
- `raw/`: future location for generated events or controlled PCAP-derived logs.

## Event Categories To Cover

- Benign traffic.
- Credential access.
- Lateral movement.
- Command and control.
- Exploit attempt.
- Malformed or evasive input that should route to human review.

