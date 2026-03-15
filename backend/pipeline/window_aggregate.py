# backend/pipeline/window_aggregate.py
"""
time_window_aggregate (ALL + SELECTED)

输入：
- <job_dir>/alerts_filtered.jsonl

输出：
- <job_dir>/llm_inputs_all.jsonl
- <job_dir>/llm_inputs_selected.jsonl
- <job_dir>/llm_inputs_summary.json
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional

from path_utils import resolve_project_path


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
    category_counter: Counter = None
    dest_ip_counter: Counter = None
    dest_port_counter: Counter = None
    proto_counter: Counter = None

    first_ts_epoch: int = 2**31 - 1
    last_ts_epoch: int = 0

    def __post_init__(self):
        self.sig_counter = Counter()
        self.category_counter = Counter()
        self.dest_ip_counter = Counter()
        self.dest_port_counter = Counter()
        self.proto_counter = Counter()

    def add(self, rec: Dict[str, Any], ts_epoch: int):
        """把一条 alert 记录汇入当前窗口统计"""
        self.hits += 1

        sev = to_int(rec.get("severity"))
        if sev is not None:
            self.severity_min = min(self.severity_min, sev)

        sig = rec.get("signature") or "UNKNOWN_SIGNATURE"
        self.sig_counter[sig] += 1

        category = rec.get("category") or "UNKNOWN_CATEGORY"
        self.category_counter[category] += 1

        dip = rec.get("dest_ip") or "UNKNOWN_DEST"
        self.dest_ip_counter[dip] += 1

        dport = to_int(rec.get("dest_port"))
        if dport is not None:
            self.dest_port_counter[dport] += 1

        proto = rec.get("proto") or "UNKNOWN_PROTO"
        self.proto_counter[proto] += 1

        self.first_ts_epoch = min(self.first_ts_epoch, ts_epoch)
        self.last_ts_epoch = max(self.last_ts_epoch, ts_epoch)

    def to_llm_input(self, top_sig_n: int, top_dest_ip_n: int) -> Dict[str, Any]:
        """输出一条可直接喂给 LLM 的聚合 JSON"""
        top_sigs = [{"signature": s, "count": c} for s, c in self.sig_counter.most_common(top_sig_n)]
        top_dips = [{"dest_ip": ip, "count": c} for ip, c in self.dest_ip_counter.most_common(top_dest_ip_n)]
        top_categories = [{"category": c, "count": n} for c, n in self.category_counter.most_common(3)]
        top_ports = [{"dest_port": p, "count": c} for p, c in self.dest_port_counter.most_common(5)]
        protos = [{"proto": p, "count": c} for p, c in self.proto_counter.most_common(5)]
        burst_duration_sec = (
            max(0, self.last_ts_epoch - self.first_ts_epoch)
            if self.first_ts_epoch < 2**31 - 1 and self.last_ts_epoch
            else None
        )
        alert_density_per_sec = round(self.hits / max(1, burst_duration_sec or self.window_end - self.window_start), 4)
        dominant_proto = protos[0]["proto"] if protos else None

        return {
            "src_ip": self.src_ip,

            "window_sec": self.window_end - self.window_start,
            "window_start_epoch": self.window_start,
            "window_end_epoch": self.window_end,
            "window_start_iso": epoch_to_iso(self.window_start),
            "window_end_iso": epoch_to_iso(self.window_end),

            "hits": self.hits,
            "severity_min": None if self.severity_min == 999 else self.severity_min,
            "alert_density_per_sec": alert_density_per_sec,
            "burst_duration_sec": burst_duration_sec,
            "unique_dest_ip_count": len(self.dest_ip_counter),
            "unique_dest_port_count": len(self.dest_port_counter),
            "signature_diversity": len(self.sig_counter),
            "dominant_proto": dominant_proto,

            "top_signatures": top_sigs,
            "top_categories": top_categories,
            "dest_ports": sorted(self.dest_port_counter.keys()),
            "top_dest_port_counts": top_ports,
            "top_dest_ips": top_dips,
            "proto_top": protos,

            "first_seen_iso": epoch_to_iso(self.first_ts_epoch) if self.first_ts_epoch < 2**31 - 1 else None,
            "last_seen_iso": epoch_to_iso(self.last_ts_epoch) if self.last_ts_epoch else None,
        }


def score_for_rank(agg: WindowAgg) -> Tuple[int, int, int, int]:
    """selected 排序：hits 越多越靠前；severity_min 越小越靠前；目标和签名越集中越优先"""
    sev = agg.severity_min if agg.severity_min != 999 else 99
    burst = max(0, agg.last_ts_epoch - agg.first_ts_epoch) if agg.last_ts_epoch and agg.first_ts_epoch < 2**31 - 1 else 0
    return (agg.hits, -sev, -len(agg.dest_ip_counter), -burst)


def aggregate_time_windows(
    job_dir: str | Path,
    window_sec: int = 60,
    min_hits: int = 3,
    topk: int = 200,
    top_sig_n: int = 5,
    top_dest_ip_n: int = 3,
) -> Dict[str, Any]:
    job_dir = resolve_project_path(job_dir)
    inp = job_dir / "alerts_filtered.jsonl"
    if not inp.exists():
        raise SystemExit(f"[!] not found: {inp}")

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
            out.write(json.dumps(a.to_llm_input(top_sig_n, top_dest_ip_n), ensure_ascii=False) + "\n")

    # 3) 生成 SELECTED：保留筛选机制
    selected = [a for a in all_aggs if a.hits >= min_hits]
    selected.sort(key=score_for_rank, reverse=True)
    if topk is not None and topk > 0:
        selected = selected[: topk]  # topk>0 才截断；topk=0 表示保留全部

    out_sel = job_dir / "llm_inputs_selected.jsonl"
    with out_sel.open("w", encoding="utf-8") as out:
        for a in selected:
            out.write(json.dumps(a.to_llm_input(top_sig_n, top_dest_ip_n), ensure_ascii=False) + "\n")

    # 4) 摘要
    summary = {
        "job_dir": str(job_dir),
        "input": str(inp),
        "window_sec": window_sec,
        "total_groups": len(all_aggs),
        "all_output": str(out_all),

        "selected_groups": len(selected),
        "selected_output": str(out_sel),
        "min_hits": min_hits,
        "topk": topk,

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

    return summary
