#!/usr/bin/env python3
"""
PCAP 离线检测链路（Suricata Offline Pipeline）— CLI wrapper
"""

import argparse
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from pipeline.offline_detect import (
    DEFAULT_JOBS_ROOT,
    DEFAULT_SURICATA_CONF,
    run_offline_detect,
)

def main() -> None:
    p = argparse.ArgumentParser(description="PCAP offline detection pipeline with alert denoise.")
    p.add_argument("--pcap", required=True, help="Path to .pcap file")
    p.add_argument("--jobs-root", default=str(DEFAULT_JOBS_ROOT), help="Jobs root directory")
    p.add_argument("--suricata-conf", default=str(DEFAULT_SURICATA_CONF), help="Suricata YAML config path")
    p.add_argument("--job-id", default="", help="Optional job_id (default: timestamp)")
    p.add_argument(
        "--ignore-signature",
        action="append",
        default=[],
        help="Signature text to ignore (can be repeated). Default ignores checksum noise.",
    )
    args = p.parse_args()

    run_offline_detect(
        pcap=args.pcap,
        jobs_root=args.jobs_root,
        suricata_conf=args.suricata_conf,
        job_id=args.job_id,
        ignore_signatures=args.ignore_signature,
    )

if __name__ == "__main__":
    main()
