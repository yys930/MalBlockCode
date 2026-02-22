#!/usr/bin/env python3
"""
time_window_aggregate.py (ALL + SELECTED) - Final

输入：
- <job_dir>/alerts_filtered.jsonl

输出：
- <job_dir>/llm_inputs_all.jsonl         # 全部窗口（按 src_ip + 时间窗聚合）
- <job_dir>/llm_inputs_selected.jsonl    # 筛选后的窗口（min-hits/topk）
- <job_dir>/llm_inputs_summary.json      # 汇总（total_groups/selected_groups 等）

说明：
- “全部窗口”= 所有 (src_ip, window_id) 分组后的聚合结果（不做 topk 截断）
- “筛选机制”只作用于 selected 输出
- topk=0 表示 selected 不截断（输出全部满足 min-hits 的窗口）
"""

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional


# ---------- helpers ----------
def parse_ts(ts: str) -> datetime:
    """
    解析 Suricata timestamp，例如：
      2017-07-07T20:00:35.416233+0800
      2017-07-07T20:00:35+0800
    """
    ts = ts.strip()
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")


def dt_to_epoch(dt: datetime) -> int:
    """datetime -> epoch seconds"""
    return int(dt.timestamp())


def epoch_to_iso(epoch_s: int, tz: Optional[timezone] = None) -> str:
    """epoch seconds -> ISO string（默认 UTC 展示）"""
    dt = datetime.fromtimestamp(epoch_s, tz=tz or timezone.utc)
    return dt.isoformat()


def to_int(x) -> Optional[int]:
    """把 x 尝试转成 int（兼容 json 中的 '88'/'3' 字符串）"""
    if x is None:
        return None
    try:
        return int(x)
    except Exception:
        return None


# ---------- aggregation ----------
@dataclass
class WindowAgg:
    """一个窗口聚合单元：src_ip 在一个时间窗内的行为摘要"""
    src_ip: str
    window_id: int
    window_start: int
    window_end: int

    hits: int = 0
    severity_min: int = 999

    sig_counter: Counter = None
    dest_ip_counter: Counter = None
    dest_ports: set = None
    proto_counter: Counter = None

    first_ts_epoch: int = 2**31 - 1
    last_ts_epoch: int = 0

    def __post_init__(self):
        self.sig_counter = Counter()
        self.dest_ip_counter = Counter()
        self.dest_ports = set()
        self.proto_counter = Counter()

    def add(self, rec: Dict[str, Any], ts_epoch: int):
        """把一条 alert 记录汇入当前窗口统计"""
        self.hits += 1

        sev = to_int(rec.get("severity"))
        if sev is not None:
            self.severity_min = min(self.severity_min, sev)

        sig = rec.get("signature") or "UNKNOWN_SIGNATURE"
        self.sig_counter[sig] += 1

        dip = rec.get("dest_ip") or "UNKNOWN_DEST"
        self.dest_ip_counter[dip] += 1

        dport = to_int(rec.get("dest_port"))
        if dport is not None:
            self.dest_ports.add(dport)

        proto = rec.get("proto") or "UNKNOWN_PROTO"
        self.proto_counter[proto] += 1

        self.first_ts_epoch = min(self.first_ts_epoch, ts_epoch)
        self.last_ts_epoch = max(self.last_ts_epoch, ts_epoch)

    def to_llm_input(self, top_sig_n: int, top_dest_ip_n: int) -> Dict[str, Any]:
        """输出一条可直接喂给 LLM 的聚合 JSON"""
        top_sigs = [{"signature": s, "count": c} for s, c in self.sig_counter.most_common(top_sig_n)]
        top_dips = [{"dest_ip": ip, "count": c} for ip, c in self.dest_ip_counter.most_common(top_dest_ip_n)]
        protos = [{"proto": p, "count": c} for p, c in self.proto_counter.most_common(5)]

        return {
            "src_ip": self.src_ip,

            "window_sec": self.window_end - self.window_start,
            "window_start_epoch": self.window_start,
            "window_end_epoch": self.window_end,
            "window_start_iso": epoch_to_iso(self.window_start),
            "window_end_iso": epoch_to_iso(self.window_end),

            "hits": self.hits,
            "severity_min": None if self.severity_min == 999 else self.severity_min,

            "top_signatures": top_sigs,
            "dest_ports": sorted(self.dest_ports),
            "top_dest_ips": top_dips,
            "proto_top": protos,

            "first_seen_iso": epoch_to_iso(self.first_ts_epoch) if self.first_ts_epoch < 2**31 - 1 else None,
            "last_seen_iso": epoch_to_iso(self.last_ts_epoch) if self.last_ts_epoch else None,
        }


def score_for_rank(agg: WindowAgg) -> Tuple[int, int]:
    """selected 排序：hits 越多越靠前；severity_min 越小越靠前"""
    sev = agg.severity_min if agg.severity_min != 999 else 99
    return (agg.hits, -sev)


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Aggregate alerts_filtered.jsonl by time windows (ALL + SELECTED).")
    ap.add_argument("--job-dir", required=True, help="Job directory containing alerts_filtered.jsonl")
    ap.add_argument("--window-sec", type=int, default=60, help="Window size in seconds (default: 60)")

    # 筛选机制（只影响 selected 输出）
    ap.add_argument("--min-hits", type=int, default=3,
                    help="selected: keep windows with hits >= min-hits (default: 3)")
    ap.add_argument("--topk", type=int, default=200,
                    help="selected: keep top K windows by score; 0=keep all (default: 200)")

    # 每条聚合记录里保留的 TopN 字段
    ap.add_argument("--top-sig-n", type=int, default=5, help="Top N signatures per record (default: 5)")
    ap.add_argument("--top-dest-ip-n", type=int, default=3, help="Top N dest_ip per record (default: 3)")

    args = ap.parse_args()

    job_dir = Path(args.job_dir).expanduser().resolve()
    inp = job_dir / "alerts_filtered.jsonl"
    if not inp.exists():
        raise SystemExit(f"[!] not found: {inp}")

    window_sec = args.window_sec
    groups: Dict[Tuple[str, int], WindowAgg] = {}

    # 1) 读取 + 分组（全部窗口）
    with inp.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            ts = rec.get("timestamp")
            src_ip = rec.get("src_ip")
            if not ts or not src_ip:
                continue

            dt = parse_ts(ts)
            epoch = dt_to_epoch(dt)

            win_id = epoch // window_sec
            win_start = win_id * window_sec
            win_end = win_start + window_sec

            key = (src_ip, win_id)
            if key not in groups:
                groups[key] = WindowAgg(src_ip=src_ip, window_id=win_id, window_start=win_start, window_end=win_end)

            groups[key].add(rec, epoch)

    all_aggs = list(groups.values())

    # 2) 写 ALL 输出（排序保证可复现）
    all_aggs_sorted = sorted(all_aggs, key=lambda a: (a.window_start, a.src_ip))
    out_all = job_dir / "llm_inputs_all.jsonl"
    with out_all.open("w", encoding="utf-8") as out:
        for a in all_aggs_sorted:
            out.write(json.dumps(a.to_llm_input(args.top_sig_n, args.top_dest_ip_n), ensure_ascii=False) + "\n")

    # 3) 生成 SELECTED：保留筛选机制
    selected = [a for a in all_aggs if a.hits >= args.min_hits]
    selected.sort(key=score_for_rank, reverse=True)
    if args.topk is not None and args.topk > 0:
        selected = selected[: args.topk]  # topk>0 才截断；topk=0 表示保留全部

    out_sel = job_dir / "llm_inputs_selected.jsonl"
    with out_sel.open("w", encoding="utf-8") as out:
        for a in selected:
            out.write(json.dumps(a.to_llm_input(args.top_sig_n, args.top_dest_ip_n), ensure_ascii=False) + "\n")

    # 4) 摘要
    summary = {
        "job_dir": str(job_dir),
        "input": str(inp),
        "window_sec": window_sec,
        "total_groups": len(all_aggs),
        "all_output": str(out_all),

        "selected_groups": len(selected),
        "selected_output": str(out_sel),
        "min_hits": args.min_hits,
        "topk": args.topk,

        "top_preview_selected": [
            {
                "src_ip": a.src_ip,
                "window_start_iso": epoch_to_iso(a.window_start),
                "hits": a.hits,
                "severity_min": None if a.severity_min == 999 else a.severity_min,
                "top_signature": a.sig_counter.most_common(1)[0][0] if a.sig_counter else None,
            }
            for a in selected[:10]
        ],
    }
    (job_dir / "llm_inputs_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    print("[*] DONE")
    print("[*] total_groups    =", len(all_aggs))
    print("[*] wrote ALL       =", out_all)
    print("[*] selected_groups =", len(selected))
    print("[*] wrote SELECTED  =", out_sel)
    print("[*] wrote summary   =", job_dir / "llm_inputs_summary.json")


if __name__ == "__main__":
    main()