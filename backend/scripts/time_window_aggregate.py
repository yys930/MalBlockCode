#!/usr/bin/env python3
"""
time_window_aggregate.py (ALL + SELECTED) - CLI wrapper
"""

import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

load_dotenv()

from pipeline.window_aggregate import aggregate_time_windows


def main():
    ap = argparse.ArgumentParser(description="Aggregate alerts_filtered.jsonl by time windows (ALL + SELECTED).")
    ap.add_argument("--job-dir", required=True, help="Job directory containing alerts_filtered.jsonl")
    ap.add_argument("--window-sec", type=int, default=60, help="Window size in seconds (default: 60)")

    # 筛选机制（只影响 selected 输出）
    ap.add_argument("--min-hits", type=int, default=3,
                    help="selected: keep windows with hits >= min-hits (default: 3)")
    ap.add_argument("--topk", type=int, default=20,
                    help="selected: keep top K windows by score; 0=keep all (default: 20)")

    # 每条聚合记录里保留的 TopN 字段
    ap.add_argument("--top-sig-n", type=int, default=5, help="Top N signatures per record (default: 5)")
    ap.add_argument("--top-dest-ip-n", type=int, default=3, help="Top N dest_ip per record (default: 3)")

    args = ap.parse_args()

    aggregate_time_windows(
        job_dir=args.job_dir,
        window_sec=args.window_sec,
        min_hits=args.min_hits,
        topk=args.topk,
        top_sig_n=args.top_sig_n,
        top_dest_ip_n=args.top_dest_ip_n,
    )


if __name__ == "__main__":
    main()
