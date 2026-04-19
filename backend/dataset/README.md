# CIC-IDS-2017 Malicious Dataset Builder

This builder targets the `TrafficLabelling` version of CIC-IDS-2017 and produces both a malicious-only cleaned dataset and a mixed evaluation dataset for MalBlock.
The input path may point either to the `TrafficLabelling/` directory itself or to the parent `CSVs/` directory that contains it.

Outputs:

- `malicious_merged_cleaned.csv`: merged, cleaned, deduplicated malicious flows
- `mixed_eval_cleaned.csv`: malicious flows plus sampled benign flows for CSV-channel evaluation
- `manifest.json`: build configuration and dataset statistics

Design choices:

- Preserve original CSV features, but normalize column names to snake_case/canonical names.
- Add provenance fields: `source_file`, `source_day`, `original_row_id`.
- Add label metadata: `label_raw`, `label`, `attack_family`.
- Keep the malicious-only output free of benign rows.
- Deduplicate benign candidates separately, then sample them into `mixed_eval_cleaned.csv`.
- Drop invalid rows missing raw `timestamp`, `src_ip`, `dest_ip`, or raw `label`.
- Drop rows whose timestamp cannot be parsed into a normalized UTC time.
- Support two dedupe modes:
  - `flow`:
    `source_day + label + src_ip + src_port + dest_ip + dst_port + protocol + timestamp_minute`
  - `exact`: exact row equality after normalization

Manifest notes:

- `config.builder_version` identifies the normalization/validation logic version.
- `invalid_reason_counts` records why rows were rejected, for example `missing_label` or `invalid_timestamp`.

Recommended use:

1. Build the malicious dataset once and keep the output versioned by date/config.
2. Use `malicious_merged_cleaned.csv` as the unified malicious-flow source for later CSV-channel experiments.
3. Use `mixed_eval_cleaned.csv` when you need benign traffic for formal CSV-channel evaluation.
4. Prefer `flow` dedupe for reducing repetitive attack bursts in CIC-IDS-2017.
