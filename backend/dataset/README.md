# CIC-IDS-2017 Malicious Dataset Builder

This builder targets the `TrafficLabelling` version of CIC-IDS-2017 and produces a malicious-only cleaned dataset for MalBlock.

Outputs:

- `malicious_merged_cleaned.csv`: merged, cleaned, deduplicated malicious flows
- `manifest.json`: build configuration and dataset statistics

Design choices:

- Preserve original CSV features, but normalize column names to snake_case/canonical names.
- Add provenance fields: `source_file`, `source_day`, `original_row_id`.
- Add label metadata: `label_raw`, `label`, `attack_family`.
- Skip benign rows entirely.
- Drop invalid rows missing `timestamp`, `src_ip`, `dest_ip`, or `label`.
- Support two dedupe modes:
  - `flow`:
    `source_day + label + src_ip + src_port + dest_ip + dst_port + protocol + timestamp_minute`
  - `exact`: exact row equality after normalization

Recommended use:

1. Build the malicious dataset once and keep the output versioned by date/config.
2. Use `malicious_merged_cleaned.csv` as the unified malicious-flow source for later CSV-channel experiments.
3. Prefer `flow` dedupe for reducing repetitive attack bursts in CIC-IDS-2017.
