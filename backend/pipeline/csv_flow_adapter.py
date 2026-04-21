from __future__ import annotations

import csv
import json
import math
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from path_utils import resolve_project_path


LABEL_BENIGN_VALUES = {"benign", "normal"}
TIMESTAMP_COLUMNS = ["Timestamp", "timestamp", "Flow Start", "FlowStart"]
SRC_IP_COLUMNS = ["Src IP", "Source IP", "src_ip"]
DST_IP_COLUMNS = ["Dst IP", "Destination IP", "dest_ip"]
SRC_PORT_COLUMNS = ["Src Port", "Source Port", "src_port"]
DST_PORT_COLUMNS = ["Dst Port", "Destination Port", "dst_port"]
PROTO_COLUMNS = ["Protocol", "protocol"]
LABEL_COLUMNS = ["Label", "label"]
FLOW_DURATION_COLUMNS = ["Flow Duration", "flow_duration"]
FWD_PKTS_COLUMNS = ["Total Fwd Packets", "Tot Fwd Pkts", "total_fwd_packets"]
BWD_PKTS_COLUMNS = ["Total Backward Packets", "Tot Bwd Pkts", "total_backward_packets"]
FLOW_BYTES_S_COLUMNS = ["Flow Bytes/s", "flow_bytes_s"]
FLOW_PKTS_S_COLUMNS = ["Flow Packets/s", "flow_packets_s"]


def _normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key, value in row.items():
        clean_key = str(key).replace("\ufeff", "").strip()
        normalized[clean_key] = value.strip() if isinstance(value, str) else value
    return normalized


def _pick(row: Dict[str, Any], names: List[str], default: Any = None) -> Any:
    for name in names:
        if name in row and row[name] not in {None, ""}:
            return row[name]
    return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(str(value).strip())
        return parsed if math.isfinite(parsed) else default
    except Exception:
        return default


def _parse_timestamp(value: str) -> Optional[datetime]:
    value = str(value or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        pass
    fmts = [
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S.%f",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for fmt in fmts:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _attack_family_from_label(label: str) -> str:
    text = label.lower()
    if "ddos" in text or "dos" in text or "slowloris" in text or "hulk" in text:
        return "dos"
    if "brute" in text or "ftp-patator" in text or "ssh-patator" in text:
        return "brute-force"
    if "portscan" in text or "scan" in text:
        return "scan"
    if "bot" in text or "infiltration" in text:
        return "botnet"
    if "web attack" in text or "xss" in text or "sql injection" in text:
        return "web-attack"
    return "benign" if text in LABEL_BENIGN_VALUES else "unknown"


def _severity_from_label(label: str) -> int:
    attack_family = _attack_family_from_label(label)
    if attack_family == "dos":
        return 1
    if attack_family in {"brute-force", "web-attack", "botnet"}:
        return 2
    if attack_family in {"scan", "unknown"}:
        return 3
    return 4


def _protocol_name(value: Any) -> str:
    protocol = _to_int(value, -1)
    mapping = {
        6: "TCP",
        17: "UDP",
        1: "ICMP",
    }
    return mapping.get(protocol, str(value or "UNKNOWN"))


def _top_signature(label: str) -> Dict[str, Any]:
    return {"signature": f"CSV_FLOW::{label}", "count": 1}


def _build_flow_window(row: Dict[str, Any], row_id: int) -> Dict[str, Any]:
    label = str(_pick(row, LABEL_COLUMNS, "UNKNOWN")).strip()
    ts = _parse_timestamp(_pick(row, TIMESTAMP_COLUMNS, "")) or datetime.fromtimestamp(row_id, tz=timezone.utc)
    epoch = int(ts.timestamp())
    src_ip = str(_pick(row, SRC_IP_COLUMNS, f"unknown-src-{row_id}"))
    src_port = _to_int(_pick(row, SRC_PORT_COLUMNS, 0))
    dst_ip = str(_pick(row, DST_IP_COLUMNS, f"unknown-dst-{row_id}"))
    dst_port = _to_int(_pick(row, DST_PORT_COLUMNS, 0))
    proto = _protocol_name(_pick(row, PROTO_COLUMNS, "UNKNOWN"))
    flow_duration = _to_int(_pick(row, FLOW_DURATION_COLUMNS, 0))
    fwd_pkts = _to_int(_pick(row, FWD_PKTS_COLUMNS, 0))
    bwd_pkts = _to_int(_pick(row, BWD_PKTS_COLUMNS, 0))
    total_packets = max(1, fwd_pkts + bwd_pkts)
    bytes_per_s = _to_float(_pick(row, FLOW_BYTES_S_COLUMNS, 0.0))
    pkts_per_s = _to_float(_pick(row, FLOW_PKTS_S_COLUMNS, 0.0))
    label_lower = label.lower()
    attack_family = _attack_family_from_label(label)
    severity = _severity_from_label(label)
    source_file = str(row.get("source_file") or "")
    source_day = str(row.get("source_day") or "")
    original_row_id = _to_int(row.get("original_row_id"), row_id)
    flow_uid = (
        f"{source_day}:{original_row_id}"
        if source_day and original_row_id
        else f"{src_ip}:{src_port}->{dst_ip}:{dst_port}@{epoch}"
    )

    return {
        "channel": "csv_flow",
        "flow_row_id": row_id,
        "flow_uid": flow_uid,
        "source_file": source_file,
        "source_day": source_day,
        "source_row_id": original_row_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "window_sec": max(1, flow_duration // 1_000_000) if flow_duration else 1,
        "window_start_epoch": epoch,
        "window_end_epoch": epoch + max(1, flow_duration // 1_000_000) if flow_duration else epoch + 1,
        "window_start_iso": ts.isoformat(),
        "window_end_iso": datetime.fromtimestamp(epoch + max(1, flow_duration // 1_000_000) if flow_duration else epoch + 1, tz=timezone.utc).isoformat(),
        "hits": 1,
        "severity_min": severity,
        "alert_density_per_sec": round(pkts_per_s if pkts_per_s > 0 else total_packets / max(1, flow_duration / 1_000_000 or 1), 4),
        "burst_duration_sec": max(1, flow_duration // 1_000_000) if flow_duration else 1,
        "unique_dest_ip_count": 1,
        "unique_dest_port_count": 1 if dst_port else 0,
        "signature_diversity": 1,
        "dominant_proto": proto,
        "top_signatures": [_top_signature(label)],
        "top_categories": [{"category": attack_family, "count": 1}],
        "dest_ports": [dst_port] if dst_port else [],
        "top_dest_port_counts": [{"dest_port": dst_port, "count": 1}] if dst_port else [],
        "top_dest_ips": [{"dest_ip": dst_ip, "count": 1}],
        "proto_top": [{"proto": proto, "count": 1}],
        "first_seen_iso": ts.isoformat(),
        "last_seen_iso": datetime.fromtimestamp(epoch + max(1, flow_duration // 1_000_000) if flow_duration else epoch + 1, tz=timezone.utc).isoformat(),
        "csv_features": {
            "label": label,
            "label_is_malicious": label_lower not in LABEL_BENIGN_VALUES,
            "attack_family": attack_family,
            "flow_duration_us": flow_duration,
            "fwd_packets": fwd_pkts,
            "bwd_packets": bwd_pkts,
            "flow_bytes_per_s": bytes_per_s,
            "flow_packets_per_s": pkts_per_s,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "source_file": source_file,
            "source_day": source_day,
            "source_row_id": original_row_id,
            "flow_uid": flow_uid,
        },
    }


@dataclass
class CSVFlowBuildResult:
    total_rows: int
    selected_rows: int
    benign_rows: int
    malicious_rows: int
    input_csv: str
    all_output: str
    selected_output: str
    selection_mode: str
    seed: int


@dataclass
class CSVWindowCandidate:
    offset: int
    label: str
    label_is_malicious: bool
    severity_min: int
    flow_packets_per_s: float


def _window_priority_key(item: Dict[str, Any] | CSVWindowCandidate) -> tuple[Any, ...]:
    if isinstance(item, CSVWindowCandidate):
        return (
            bool(item.label_is_malicious),
            -int(item.severity_min or 99),
            -int(item.flow_packets_per_s or 0),
        )
    return (
        bool(item["csv_features"]["label_is_malicious"]),
        -int(item.get("severity_min") or 99),
        -int(item["csv_features"].get("flow_packets_per_s") or 0),
    )


def _sample_with_label_buckets(
    candidates: List[CSVWindowCandidate],
    quota: int,
    rng: random.Random,
) -> List[CSVWindowCandidate]:
    if quota <= 0 or not candidates:
        return []
    if len(candidates) <= quota:
        sampled = list(candidates)
        rng.shuffle(sampled)
        return sampled

    buckets: Dict[str, List[CSVWindowCandidate]] = {}
    for item in candidates:
        buckets.setdefault(item.label or "UNKNOWN", []).append(item)

    labels = sorted(buckets)
    desired = {label: 0 for label in labels}
    remaining = quota

    shuffled_labels = labels[:]
    rng.shuffle(shuffled_labels)
    for label in shuffled_labels:
        if remaining <= 0:
            break
        if buckets[label]:
            desired[label] += 1
            remaining -= 1

    while remaining > 0:
        expandable = [label for label in labels if len(buckets[label]) > desired[label]]
        if not expandable:
            break
        rng.shuffle(expandable)
        for label in expandable:
            if remaining <= 0:
                break
            if len(buckets[label]) > desired[label]:
                desired[label] += 1
                remaining -= 1

    sampled: List[CSVWindowCandidate] = []
    for label in labels:
        take = desired[label]
        if take <= 0:
            continue
        group = buckets[label]
        if len(group) <= take:
            sampled.extend(group)
        else:
            sampled.extend(rng.sample(group, take))
    rng.shuffle(sampled)
    return sampled[:quota]


def _sample_jsonl_windows(
    candidates: List[CSVWindowCandidate],
    topk: int,
    selection_mode: str,
    seed: int,
) -> List[CSVWindowCandidate]:
    effective_topk = topk if topk > 0 else None

    if selection_mode == "priority":
        selected_windows = list(candidates)
        selected_windows.sort(key=_window_priority_key, reverse=True)
        return selected_windows if effective_topk is None else selected_windows[:effective_topk]

    rng = random.Random(seed)
    eligible_items = list(candidates)

    if selection_mode == "random":
        if effective_topk is None or len(eligible_items) <= effective_topk:
            rng.shuffle(eligible_items)
            return eligible_items
        return rng.sample(eligible_items, effective_topk)

    if selection_mode != "stratified_label":
        raise ValueError(f"unsupported selection_mode: {selection_mode}")

    if effective_topk is None or len(eligible_items) <= effective_topk:
        sampled = list(eligible_items)
        rng.shuffle(sampled)
        return sampled

    benign_candidates = [item for item in eligible_items if not item.label_is_malicious]
    malicious_candidates = [item for item in eligible_items if item.label_is_malicious]

    if benign_candidates and malicious_candidates:
        benign_quota = min(len(benign_candidates), effective_topk // 2)
        malicious_quota = min(len(malicious_candidates), effective_topk // 2)
        sampled = _sample_with_label_buckets(benign_candidates, benign_quota, rng)
        sampled.extend(_sample_with_label_buckets(malicious_candidates, malicious_quota, rng))

        remaining = effective_topk - len(sampled)
        if remaining > 0:
            remaining_candidates = [
                item
                for item in eligible_items
                if item not in sampled
            ]
            sampled.extend(_sample_with_label_buckets(remaining_candidates, remaining, rng))

        rng.shuffle(sampled)
        return sampled[:effective_topk]

    return _sample_with_label_buckets(eligible_items, effective_topk, rng)


def _load_windows_by_offsets(all_output: Path, candidates: List[CSVWindowCandidate]) -> List[Dict[str, Any]]:
    if not candidates:
        return []

    windows: List[Dict[str, Any]] = []
    with all_output.open("r", encoding="utf-8") as f:
        for candidate in candidates:
            f.seek(candidate.offset)
            line = f.readline()
            if not line:
                continue
            windows.append(json.loads(line))
    return windows


def build_csv_flow_inputs(
    csv_path: str | Path,
    job_dir: str | Path,
    include_benign: bool = True,
    topk: int = 5000,
    selection_mode: str = "priority",
    seed: int = 42,
) -> CSVFlowBuildResult:
    csv_path = resolve_project_path(csv_path)
    job_dir = resolve_project_path(job_dir)
    all_output = job_dir / "llm_inputs_all.jsonl"
    selected_output = job_dir / "llm_inputs_selected.jsonl"

    total_rows = 0
    selected_rows = 0
    benign_rows = 0
    malicious_rows = 0

    candidates: List[CSVWindowCandidate] = []

    with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as f, all_output.open("w", encoding="utf-8") as all_out:
        reader = csv.DictReader(f)
        for row_id, row in enumerate(reader, start=1):
            row = _normalize_row(row)
            total_rows += 1
            window = _build_flow_window(row, row_id)
            label_is_malicious = bool(window["csv_features"]["label_is_malicious"])
            if label_is_malicious:
                malicious_rows += 1
            else:
                benign_rows += 1

            line_offset = all_out.tell()
            all_out.write(json.dumps(window, ensure_ascii=False) + "\n")

            if include_benign or label_is_malicious:
                features = window.get("csv_features") or {}
                candidates.append(
                    CSVWindowCandidate(
                        offset=line_offset,
                        label=str(features.get("label") or "UNKNOWN"),
                        label_is_malicious=label_is_malicious,
                        severity_min=int(window.get("severity_min") or 99),
                        flow_packets_per_s=float(features.get("flow_packets_per_s") or 0.0),
                    )
                )

    selected_candidates = _sample_jsonl_windows(
        candidates=candidates,
        topk=topk,
        selection_mode=selection_mode,
        seed=seed,
    )
    selected_windows = _load_windows_by_offsets(all_output, selected_candidates)

    with selected_output.open("w", encoding="utf-8") as sel_out:
        for item in selected_windows:
            sel_out.write(json.dumps(item, ensure_ascii=False) + "\n")
            selected_rows += 1

    return CSVFlowBuildResult(
        total_rows=total_rows,
        selected_rows=selected_rows,
        benign_rows=benign_rows,
        malicious_rows=malicious_rows,
        input_csv=str(csv_path),
        all_output=str(all_output),
        selected_output=str(selected_output),
        selection_mode=selection_mode,
        seed=seed,
    )
