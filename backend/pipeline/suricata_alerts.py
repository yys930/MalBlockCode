from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


DEFAULT_IGNORE_SIGNATURES = {
    "SURICATA TCPv4 invalid checksum",
}

DEFAULT_IGNORE_SIGNATURE_KEYWORDS = {
    "invalid checksum",
    "invalid ack",
    "unable to match response to request",
    "request line incomplete",
    "request header invalid",
    "gzip decompression failed",
}


def iter_eve_lines(eve_path: Path) -> Iterable[Dict[str, Any]]:
    with eve_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def extract_alert_record(evt: Dict[str, Any]) -> Dict[str, Any]:
    alert = evt.get("alert") or {}
    return {
        "timestamp": evt.get("timestamp"),
        "flow_id": evt.get("flow_id"),
        "in_iface": evt.get("in_iface"),
        "src_ip": evt.get("src_ip"),
        "src_port": evt.get("src_port"),
        "dest_ip": evt.get("dest_ip"),
        "dest_port": evt.get("dest_port"),
        "proto": evt.get("proto"),
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        "severity": alert.get("severity"),
    }


def top_n(counter: Dict[str, int], n: int = 10) -> List[Tuple[str, int]]:
    return sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]


def parse_ignore_list(values: List[str]) -> Set[str]:
    values = values or []
    sigs = set(DEFAULT_IGNORE_SIGNATURES)
    for value in values:
        if value:
            sigs.add(value.strip())
    return sigs


def should_filter_alert(
    rec: Dict[str, Any],
    ignore_signatures: Set[str],
    ignore_signature_keywords: Set[str],
) -> Optional[str]:
    if not rec.get("timestamp"):
        return "missing_timestamp"
    if not rec.get("src_ip"):
        return "missing_src_ip"
    if not rec.get("dest_ip"):
        return "missing_dest_ip"

    signature = str(rec.get("signature") or "").strip()
    if not signature:
        return "missing_signature"
    if signature in ignore_signatures:
        return "ignore_signature_exact"

    signature_lower = signature.lower()
    if any(keyword in signature_lower for keyword in ignore_signature_keywords):
        return "ignore_signature_keyword"

    return None


def extract_alerts_from_eve(
    eve_path: Path,
    raw_path: Path,
    filt_path: Path,
    ignore_signatures: List[str] | None = None,
) -> Dict[str, Any]:
    ignore_sigs = parse_ignore_list(ignore_signatures or [])
    ignore_sig_keywords = set(DEFAULT_IGNORE_SIGNATURE_KEYWORDS)

    raw_count = 0
    filt_count = 0
    sig_raw: Dict[str, int] = {}
    src_raw: Dict[str, int] = {}
    sig_filt: Dict[str, int] = {}
    src_filt: Dict[str, int] = {}
    filter_reasons: Dict[str, int] = {}

    with raw_path.open("w", encoding="utf-8") as raw_out, filt_path.open("w", encoding="utf-8") as filt_out:
        for evt in iter_eve_lines(eve_path):
            if evt.get("event_type") != "alert":
                continue
            rec = extract_alert_record(evt)
            sig = rec.get("signature") or "UNKNOWN_SIGNATURE"
            src = rec.get("src_ip") or "UNKNOWN_SRC"

            raw_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            raw_count += 1
            sig_raw[sig] = sig_raw.get(sig, 0) + 1
            src_raw[src] = src_raw.get(src, 0) + 1

            filter_reason = should_filter_alert(rec, ignore_sigs, ignore_sig_keywords)
            if filter_reason:
                filter_reasons[filter_reason] = filter_reasons.get(filter_reason, 0) + 1
                continue

            filt_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            filt_count += 1
            sig_filt[sig] = sig_filt.get(sig, 0) + 1
            src_filt[src] = src_filt.get(src, 0) + 1

    return {
        "alert_count_raw": raw_count,
        "alert_count_filtered": filt_count,
        "ignore_signatures": sorted(ignore_sigs),
        "ignore_signature_keywords": sorted(ignore_sig_keywords),
        "filter_reason_counts": filter_reasons,
        "top_signatures_raw": top_n(sig_raw, 10),
        "top_src_ip_raw": top_n(src_raw, 10),
        "top_signatures_filtered": top_n(sig_filt, 10),
        "top_src_ip_filtered": top_n(src_filt, 10),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
