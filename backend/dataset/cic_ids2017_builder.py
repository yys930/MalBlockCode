from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Sequence, Tuple

from path_utils import resolve_project_path


LABEL_BENIGN_VALUES = {"benign", "normal"}

FIELD_ALIASES = {
    "Flow ID": "flow_id",
    "Source IP": "src_ip",
    "Src IP": "src_ip",
    "Source Port": "src_port",
    "Src Port": "src_port",
    "Destination IP": "dest_ip",
    "Dst IP": "dest_ip",
    "Destination Port": "dst_port",
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Tot Fwd Pkts": "total_fwd_packets",
    "Total Backward Packets": "total_backward_packets",
    "Tot Bwd Pkts": "total_backward_packets",
    "Flow Bytes/s": "flow_bytes_s",
    "Flow Packets/s": "flow_packets_s",
    "Label": "label",
}

PRIORITY_COLUMNS = [
    "source_file",
    "source_day",
    "original_row_id",
    "label",
    "label_raw",
    "attack_family",
    "timestamp",
    "timestamp_epoch",
    "timestamp_minute",
    "src_ip",
    "src_port",
    "dest_ip",
    "dst_port",
    "protocol",
    "flow_id",
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "flow_bytes_s",
    "flow_packets_s",
]


@dataclass
class DatasetBuildResult:
    output_dir: str
    malicious_dataset_path: str
    manifest_path: str
    total_rows_read: int
    malicious_rows_seen: int
    malicious_rows_written: int
    benign_rows_skipped: int
    invalid_rows_dropped: int
    duplicate_rows_dropped: int


def _snake_case(name: str) -> str:
    text = str(name or "").replace("\ufeff", "").strip()
    text = re.sub(r"[^0-9A-Za-z]+", "_", text)
    return text.strip("_").lower()


def _canonical_field_name(name: str) -> str:
    text = str(name or "").replace("\ufeff", "").strip()
    return FIELD_ALIASES.get(text, _snake_case(text))


def _clean_cell(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered in {"nan", "na", "null", "none"}:
        return ""
    if lowered in {"inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"}:
        return ""
    return text


def _normalize_label(label: str) -> str:
    text = _clean_cell(label)
    if not text:
        return "UNKNOWN"
    compact = re.sub(r"\s+", " ", text).strip()
    if compact.lower() in LABEL_BENIGN_VALUES:
        return "BENIGN"
    return compact


def _attack_family_from_label(label: str) -> str:
    text = label.lower()
    if text in LABEL_BENIGN_VALUES or text == "benign":
        return "benign"
    if "ddos" in text or "dos" in text or "slowloris" in text or "hulk" in text or "goldeneye" in text:
        return "dos"
    if "brute" in text or "patator" in text or "ftp" in text or "ssh" in text:
        return "brute-force"
    if "portscan" in text or "scan" in text:
        return "scan"
    if "web attack" in text or "sql injection" in text or "xss" in text:
        return "web-attack"
    if "bot" in text or "infiltration" in text:
        return "botnet"
    if "heartbleed" in text:
        return "heartbleed"
    return "unknown"


def _parse_timestamp(value: str) -> datetime | None:
    text = _clean_cell(value)
    if not text:
        return None
    formats = [
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S.%f",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S %p",
        "%m/%d/%Y %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _to_int_string(value: str) -> str:
    text = _clean_cell(value)
    if not text:
        return ""
    try:
        return str(int(float(text)))
    except Exception:
        return ""


def _timestamp_minute(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.replace(second=0, microsecond=0).isoformat()


def _ordered_columns(columns: Sequence[str]) -> List[str]:
    column_set = set(columns)
    extra = sorted(key for key in column_set if key not in PRIORITY_COLUMNS)
    return [key for key in PRIORITY_COLUMNS if key in column_set] + extra


def _iter_source_files(input_dir: Path) -> Iterator[Path]:
    for path in sorted(input_dir.iterdir()):
        if path.is_file() and path.suffix.lower() == ".csv":
            yield path


def _collect_output_columns(source_files: Sequence[Path]) -> List[str]:
    all_columns = set(PRIORITY_COLUMNS)
    for csv_path in source_files:
        with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            for name in reader.fieldnames or []:
                all_columns.add(_canonical_field_name(name))
    return _ordered_columns(all_columns)


def _normalize_row(row: Dict[str, Any], source_file: str, row_id: int) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    for key, value in row.items():
        normalized[_canonical_field_name(key)] = _clean_cell(value)

    dt = _parse_timestamp(normalized.get("timestamp", ""))
    label_raw = normalized.get("label", "")
    label = _normalize_label(label_raw)

    normalized["source_file"] = source_file
    normalized["source_day"] = source_file.split(".pcap", 1)[0]
    normalized["original_row_id"] = str(row_id)
    normalized["label_raw"] = label_raw
    normalized["label"] = label
    normalized["attack_family"] = _attack_family_from_label(label)
    normalized["timestamp"] = dt.isoformat() if dt else normalized.get("timestamp", "")
    normalized["timestamp_epoch"] = str(int(dt.timestamp())) if dt else ""
    normalized["timestamp_minute"] = _timestamp_minute(dt)
    normalized["src_port"] = _to_int_string(normalized.get("src_port", ""))
    normalized["dst_port"] = _to_int_string(normalized.get("dst_port", ""))
    normalized["flow_duration"] = _to_int_string(normalized.get("flow_duration", ""))
    normalized["total_fwd_packets"] = _to_int_string(normalized.get("total_fwd_packets", ""))
    normalized["total_backward_packets"] = _to_int_string(normalized.get("total_backward_packets", ""))

    return normalized


def _is_valid_row(row: Dict[str, str]) -> bool:
    required = ("timestamp", "src_ip", "dest_ip", "label")
    return all(_clean_cell(row.get(field, "")) for field in required)


def _is_malicious_label(label: str) -> bool:
    return _normalize_label(label).lower() not in LABEL_BENIGN_VALUES


def _dedupe_key(row: Dict[str, str], dedupe_mode: str) -> Tuple[str, ...]:
    if dedupe_mode == "exact":
        return tuple(f"{key}={row.get(key, '')}" for key in sorted(row.keys()))
    if dedupe_mode == "flow":
        return (
            row.get("source_day", ""),
            row.get("label", ""),
            row.get("src_ip", ""),
            row.get("src_port", ""),
            row.get("dest_ip", ""),
            row.get("dst_port", ""),
            row.get("protocol", ""),
            row.get("timestamp_minute", ""),
        )
    raise ValueError(f"unsupported dedupe_mode: {dedupe_mode}")


def build_cic_ids2017_malicious_dataset(
    input_dir: str | Path,
    output_dir: str | Path,
    dedupe_mode: str = "flow",
    progress_every: int = 200000,
) -> DatasetBuildResult:
    input_dir = resolve_project_path(input_dir)
    output_dir = resolve_project_path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    source_files = list(_iter_source_files(input_dir))
    output_columns = _collect_output_columns(source_files)
    malicious_dataset_path = output_dir / "malicious_merged_cleaned.csv"
    manifest_path = output_dir / "manifest.json"

    total_rows_read = 0
    malicious_rows_seen = 0
    malicious_rows_written = 0
    benign_rows_skipped = 0
    invalid_rows_dropped = 0
    duplicate_rows_dropped = 0

    seen_dedupe_keys = set()
    label_counter: Counter[str] = Counter()
    attack_family_counter: Counter[str] = Counter()
    source_stats: Dict[str, Counter[str]] = {}

    def maybe_log_progress(force: bool = False) -> None:
        if progress_every <= 0 and not force:
            return
        if not force and total_rows_read % progress_every != 0:
            return
        print(
            (
                f"[malicious-dataset] rows_read={total_rows_read} malicious_seen={malicious_rows_seen} "
                f"written={malicious_rows_written} benign_skipped={benign_rows_skipped} "
                f"invalid={invalid_rows_dropped} duplicates={duplicate_rows_dropped}"
            ),
            file=sys.stderr,
            flush=True,
        )

    with malicious_dataset_path.open("w", encoding="utf-8", newline="") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=output_columns)
        writer.writeheader()

        for csv_path in source_files:
            stats = Counter()
            source_stats[csv_path.name] = stats
            with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
                reader = csv.DictReader(f)
                for row_id, row in enumerate(reader, start=1):
                    total_rows_read += 1
                    stats["rows_read"] += 1

                    normalized = _normalize_row(row, source_file=csv_path.name, row_id=row_id)
                    if not _is_valid_row(normalized):
                        invalid_rows_dropped += 1
                        stats["invalid_rows_dropped"] += 1
                        maybe_log_progress()
                        continue

                    if not _is_malicious_label(normalized.get("label", "")):
                        benign_rows_skipped += 1
                        stats["benign_rows_skipped"] += 1
                        maybe_log_progress()
                        continue

                    malicious_rows_seen += 1
                    stats["malicious_rows_seen"] += 1

                    dedupe_key = _dedupe_key(normalized, dedupe_mode=dedupe_mode)
                    if dedupe_key in seen_dedupe_keys:
                        duplicate_rows_dropped += 1
                        stats["duplicate_rows_dropped"] += 1
                        maybe_log_progress()
                        continue
                    seen_dedupe_keys.add(dedupe_key)

                    writer.writerow({key: normalized.get(key, "") for key in output_columns})
                    malicious_rows_written += 1
                    stats["malicious_rows_written"] += 1
                    label_counter[normalized["label"]] += 1
                    attack_family_counter[normalized["attack_family"]] += 1
                    maybe_log_progress()

    maybe_log_progress(force=True)

    manifest = {
        "input_dir": str(input_dir),
        "output_dir": str(output_dir),
        "config": {
            "dataset_scope": "malicious_only",
            "dedupe_mode": dedupe_mode,
        },
        "counts": {
            "total_rows_read": total_rows_read,
            "malicious_rows_seen": malicious_rows_seen,
            "malicious_rows_written": malicious_rows_written,
            "benign_rows_skipped": benign_rows_skipped,
            "invalid_rows_dropped": invalid_rows_dropped,
            "duplicate_rows_dropped": duplicate_rows_dropped,
        },
        "label_distribution": dict(sorted(label_counter.items())),
        "attack_family_distribution": dict(sorted(attack_family_counter.items())),
        "source_stats": {name: dict(counter) for name, counter in sorted(source_stats.items())},
        "outputs": {
            "malicious_dataset_csv": str(malicious_dataset_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return DatasetBuildResult(
        output_dir=str(output_dir),
        malicious_dataset_path=str(malicious_dataset_path),
        manifest_path=str(manifest_path),
        total_rows_read=total_rows_read,
        malicious_rows_seen=malicious_rows_seen,
        malicious_rows_written=malicious_rows_written,
        benign_rows_skipped=benign_rows_skipped,
        invalid_rows_dropped=invalid_rows_dropped,
        duplicate_rows_dropped=duplicate_rows_dropped,
    )
