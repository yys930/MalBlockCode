# backend/pipeline/offline_detect.py
"""
PCAP 离线检测链路（Suricata Offline Pipeline）— 带“告警降噪”版本

输出：
- eve.json                (Suricata 原始事件，事实来源)
- alerts_raw.jsonl        (全量 alert 摘要)
- alerts_filtered.jsonl   (过滤噪声后的 alert 摘要，用于 LLM/阻断)
- summary.json            (包含 raw_count / filtered_count / topN 等)
"""

from __future__ import annotations

import json
import time
import subprocess
from pathlib import Path
from typing import Dict, Any, Iterable, Tuple, List, Set

DEFAULT_JOBS_ROOT = Path("/home/os/FinalCode/malblock/backend/jobs")
DEFAULT_SURICATA_CONF = Path("/etc/suricata/suricata.yaml")

# 默认过滤的“噪声类”signature（你也可以后续加更多）
DEFAULT_IGNORE_SIGNATURES = {
    "SURICATA TCPv4 invalid checksum",
}


def ts_job_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


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
    # 允许多次传入 ignore 签名
    s = set(DEFAULT_IGNORE_SIGNATURES)
    for v in values:
        if v:
            s.add(v.strip())
    return s


def run_offline_detect(
    pcap: str,
    jobs_root: str | Path = DEFAULT_JOBS_ROOT,
    suricata_conf: str | Path = DEFAULT_SURICATA_CONF,
    job_id: str = "",
    ignore_signatures: List[str] | None = None,
) -> Dict[str, Any]:
    ignore_signatures = ignore_signatures or []
    ignore_sigs = parse_ignore_list(ignore_signatures)

    pcap_path = Path(pcap).expanduser().resolve()
    if not pcap_path.exists():
        raise SystemExit(f"[!] PCAP not found: {pcap_path}")

    jobs_root = Path(jobs_root).expanduser().resolve()
    jobs_root.mkdir(parents=True, exist_ok=True)

    job_id = job_id.strip() or ts_job_id()
    job_dir = jobs_root / job_id
    if job_dir.exists():
        raise SystemExit(f"[!] job_dir already exists: {job_dir} (use another --job-id)")
    job_dir.mkdir(parents=True)

    suricata_conf = Path(suricata_conf).expanduser().resolve()
    if not suricata_conf.exists():
        raise SystemExit(f"[!] Suricata config not found: {suricata_conf}")

    cmd = ["sudo", "suricata", "-r", str(pcap_path), "-c", str(suricata_conf), "-l", str(job_dir)]
    print("[*] JOB_ID :", job_id)
    print("[*] JOB_DIR:", job_dir)
    print("[*] PCAP   :", pcap_path)
    print("[*] CMD    :", " ".join(cmd))
    print("[*] IGNORE signatures:", len(ignore_sigs))
    run(cmd)

    eve_path = job_dir / "eve.json"
    if not eve_path.exists():
        raise SystemExit(f"[!] eve.json not generated: {eve_path}")

    raw_path = job_dir / "alerts_raw.jsonl"
    filt_path = job_dir / "alerts_filtered.jsonl"

    raw_count = 0
    filt_count = 0

    sig_raw: Dict[str, int] = {}
    src_raw: Dict[str, int] = {}
    sig_filt: Dict[str, int] = {}
    src_filt: Dict[str, int] = {}

    with raw_path.open("w", encoding="utf-8") as raw_out, filt_path.open("w", encoding="utf-8") as filt_out:
        for evt in iter_eve_lines(eve_path):
            if evt.get("event_type") != "alert":
                continue

            rec = extract_alert_record(evt)
            sig = rec.get("signature") or "UNKNOWN_SIGNATURE"
            src = rec.get("src_ip") or "UNKNOWN_SRC"

            # 写 raw
            raw_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            raw_count += 1
            sig_raw[sig] = sig_raw.get(sig, 0) + 1
            src_raw[src] = src_raw.get(src, 0) + 1

            # 过滤噪声签名后写 filtered
            if sig in ignore_sigs:
                continue
            filt_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            filt_count += 1
            sig_filt[sig] = sig_filt.get(sig, 0) + 1
            src_filt[src] = src_filt.get(src, 0) + 1

    summary = {
        "job_id": job_id,
        "pcap": str(pcap_path),
        "job_dir": str(job_dir),
        "eve_json": str(eve_path),
        "alerts_raw_jsonl": str(raw_path),
        "alerts_filtered_jsonl": str(filt_path),
        "alert_count_raw": raw_count,
        "alert_count_filtered": filt_count,
        "ignore_signatures": sorted(ignore_sigs),
        "top_signatures_raw": top_n(sig_raw, 10),
        "top_src_ip_raw": top_n(src_raw, 10),
        "top_signatures_filtered": top_n(sig_filt, 10),
        "top_src_ip_filtered": top_n(src_filt, 10),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    (job_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print("[*] DONE")
    print("[*] raw_alert_count     =", raw_count)
    print("[*] filtered_alert_count=", filt_count)
    print("[*] outputs:")
    print("    -", eve_path)
    print("    -", raw_path)
    print("    -", filt_path)
    print("    -", job_dir / "summary.json")

    return summary
