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

import time
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from path_utils import BACKEND_ROOT, resolve_project_path
from pipeline.suricata_alerts import extract_alerts_from_eve

DEFAULT_JOBS_ROOT = BACKEND_ROOT / "jobs"
DEFAULT_SURICATA_CONF = Path("/etc/suricata/suricata.yaml")

def ts_job_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def run_offline_detect(
    pcap: str,
    jobs_root: str | Path = DEFAULT_JOBS_ROOT,
    suricata_conf: str | Path = DEFAULT_SURICATA_CONF,
    job_id: str = "",
    ignore_signatures: List[str] | None = None,
) -> Dict[str, Any]:
    ignore_signatures = ignore_signatures or []

    pcap_path = resolve_project_path(pcap)
    if not pcap_path.exists():
        raise SystemExit(f"[!] PCAP not found: {pcap_path}")

    jobs_root = resolve_project_path(jobs_root)
    jobs_root.mkdir(parents=True, exist_ok=True)

    job_id = job_id.strip() or ts_job_id()
    job_dir = jobs_root / job_id
    if job_dir.exists():
        raise SystemExit(f"[!] job_dir already exists: {job_dir} (use another --job-id)")
    job_dir.mkdir(parents=True)

    suricata_conf = resolve_project_path(suricata_conf)
    if not suricata_conf.exists():
        raise SystemExit(f"[!] Suricata config not found: {suricata_conf}")

    cmd = ["sudo", "suricata", "-r", str(pcap_path), "-c", str(suricata_conf), "-l", str(job_dir)]
    print("[*] JOB_ID :", job_id)
    print("[*] JOB_DIR:", job_dir)
    print("[*] PCAP   :", pcap_path)
    print("[*] CMD    :", " ".join(cmd))
    print("[*] IGNORE signatures:", len(ignore_signatures))
    run(cmd)

    eve_path = job_dir / "eve.json"
    if not eve_path.exists():
        raise SystemExit(f"[!] eve.json not generated: {eve_path}")

    raw_path = job_dir / "alerts_raw.jsonl"
    filt_path = job_dir / "alerts_filtered.jsonl"

    extraction = extract_alerts_from_eve(
        eve_path=eve_path,
        raw_path=raw_path,
        filt_path=filt_path,
        ignore_signatures=ignore_signatures,
    )

    summary = {
        "job_id": job_id,
        "pcap": str(pcap_path),
        "job_dir": str(job_dir),
        "eve_json": str(eve_path),
        "alerts_raw_jsonl": str(raw_path),
        "alerts_filtered_jsonl": str(filt_path),
        **extraction,
    }
    import json
    (job_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print("[*] DONE")
    print("[*] raw_alert_count     =", extraction["alert_count_raw"])
    print("[*] filtered_alert_count=", extraction["alert_count_filtered"])
    print("[*] outputs:")
    print("    -", eve_path)
    print("    -", raw_path)
    print("    -", filt_path)
    print("    -", job_dir / "summary.json")

    return summary
