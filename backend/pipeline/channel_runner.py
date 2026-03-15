from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from agent.build_messages import build_messages
from agent.rag_store import default_rag_config
from agent.run_agent_batch import run_batch
from path_utils import BACKEND_ROOT, resolve_project_path
from pipeline.csv_flow_adapter import build_csv_flow_inputs
from pipeline.offline_detect import DEFAULT_JOBS_ROOT, DEFAULT_SURICATA_CONF, run_offline_detect, ts_job_id
from pipeline.suricata_alerts import extract_alerts_from_eve
from pipeline.window_aggregate import aggregate_time_windows


@dataclass
class ChannelJobConfig:
    channel: str
    job_id: str
    job_dir: Path
    source_path: str


def _wait_for_suricata_ready(job_dir: Path, proc: subprocess.Popen[str], timeout_sec: int) -> None:
    log_path = job_dir / "suricata.log"
    ready_markers = (
        "engine started",
        "packet processing threads",
    )
    deadline = time.time() + max(1, timeout_sec)
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"[!] Suricata exited before becoming ready, see {log_path}")
        if log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="ignore").lower()
            if any(marker in text for marker in ready_markers):
                return
        time.sleep(1)
    raise SystemExit(f"[!] Timed out waiting for Suricata readiness, see {log_path}")


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _job_paths(job_dir: Path) -> Dict[str, Path]:
    return {
        "llm_inputs_selected": job_dir / "llm_inputs_selected.jsonl",
        "llm_messages": job_dir / "llm_messages.jsonl",
        "llm_decisions": job_dir / "llm_decisions.jsonl",
    }


def _prepare_job(channel: str, source_path: str, job_id: str = "", jobs_root: str | Path = DEFAULT_JOBS_ROOT) -> ChannelJobConfig:
    jobs_root = resolve_project_path(jobs_root)
    jobs_root.mkdir(parents=True, exist_ok=True)
    final_job_id = job_id.strip() or f"{channel}_{ts_job_id()}"
    job_dir = jobs_root / final_job_id
    if job_dir.exists():
        raise SystemExit(f"[!] job_dir already exists: {job_dir}")
    job_dir.mkdir(parents=True)
    return ChannelJobConfig(channel=channel, job_id=final_job_id, job_dir=job_dir, source_path=str(resolve_project_path(source_path)))


def _run_messages_and_agent(job: ChannelJobConfig, rag_top_k: int = 3) -> Dict[str, Any]:
    paths = _job_paths(job.job_dir)
    rag_cfg = default_rag_config()
    build_messages(
        input_jsonl=str(paths["llm_inputs_selected"]),
        output_jsonl=str(paths["llm_messages"]),
        rag_db_dir=rag_cfg.db_dir,
        rag_archive_path=rag_cfg.archive_path,
        rag_top_k=rag_top_k,
        rag_collection=rag_cfg.collection_name,
        rag_embed_model=rag_cfg.embedding_model,
        rag_embed_api_key=rag_cfg.embedding_api_key,
        rag_embed_base_url=rag_cfg.embedding_base_url,
    )
    api_key = os.environ.get("SILICONFLOW_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Please set env SILICONFLOW_API_KEY")
    run_batch(
        in_path=str(paths["llm_messages"]),
        out_path=str(paths["llm_decisions"]),
        job_id=job.job_id,
        api_key=api_key,
        rag_cfg=rag_cfg,
        rag_top_k=rag_top_k,
    )
    return {name: str(path) for name, path in paths.items()}


def run_offline_channel(
    pcap: str,
    job_id: str = "",
    jobs_root: str | Path = DEFAULT_JOBS_ROOT,
    suricata_conf: str | Path = DEFAULT_SURICATA_CONF,
    window_sec: int = 60,
    min_hits: int = 3,
    topk: int = 20,
    rag_top_k: int = 3,
) -> Dict[str, Any]:
    summary = run_offline_detect(
        pcap=pcap,
        jobs_root=jobs_root,
        suricata_conf=suricata_conf,
        job_id=job_id,
    )
    job_dir = resolve_project_path(summary["job_dir"])
    aggregate_summary = aggregate_time_windows(job_dir=job_dir, window_sec=window_sec, min_hits=min_hits, topk=topk)
    job = ChannelJobConfig(channel="offline_pcap", job_id=summary["job_id"], job_dir=job_dir, source_path=str(resolve_project_path(pcap)))
    outputs = _run_messages_and_agent(job, rag_top_k=rag_top_k)
    channel_summary = {
        "channel": job.channel,
        "job_id": job.job_id,
        "job_dir": str(job.job_dir),
        "source_path": job.source_path,
        "detection": summary,
        "aggregation": aggregate_summary,
        "outputs": outputs,
    }
    _write_json(job.job_dir / "channel_summary.json", channel_summary)
    return channel_summary


def run_csv_channel(
    csv_path: str,
    job_id: str = "",
    jobs_root: str | Path = DEFAULT_JOBS_ROOT,
    include_benign: bool = True,
    topk: int = 5000,
    selection_mode: str = "priority",
    seed: int = 42,
    rag_top_k: int = 3,
) -> Dict[str, Any]:
    job = _prepare_job(channel="csv_flow", source_path=csv_path, job_id=job_id, jobs_root=jobs_root)
    result = build_csv_flow_inputs(
        csv_path=csv_path,
        job_dir=job.job_dir,
        include_benign=include_benign,
        topk=topk,
        selection_mode=selection_mode,
        seed=seed,
    )
    outputs = _run_messages_and_agent(job, rag_top_k=rag_top_k)
    summary = {
        "channel": job.channel,
        "job_id": job.job_id,
        "job_dir": str(job.job_dir),
        "source_path": job.source_path,
        "csv_flow_input": {
            "input_csv": result.input_csv,
            "total_rows": result.total_rows,
            "selected_rows": result.selected_rows,
            "benign_rows": result.benign_rows,
            "malicious_rows": result.malicious_rows,
            "all_output": result.all_output,
            "selected_output": result.selected_output,
            "selection_mode": result.selection_mode,
            "seed": result.seed,
        },
        "outputs": outputs,
    }
    _write_json(job.job_dir / "channel_summary.json", summary)
    return summary


def run_replay_channel(
    pcap: str,
    suricata_interface: str,
    replay_interface: str,
    job_id: str = "",
    jobs_root: str | Path = DEFAULT_JOBS_ROOT,
    suricata_conf: str | Path = DEFAULT_SURICATA_CONF,
    suricata_checksum_mode: str = "none",
    tcpreplay_bin: str = "tcpreplay",
    replay_speed: str = "topspeed",
    replay_netns: str = "",
    tcpreplay_extra_args: Optional[list[str]] = None,
    capture_wait_sec: int = 2,
    suricata_ready_timeout_sec: int = 180,
    window_sec: int = 60,
    min_hits: int = 3,
    topk: int = 20,
    rag_top_k: int = 3,
) -> Dict[str, Any]:
    job = _prepare_job(channel="replay_online", source_path=pcap, job_id=job_id, jobs_root=jobs_root)
    suricata_conf_path = resolve_project_path(suricata_conf)
    pcap_path = resolve_project_path(pcap)
    eve_path = job.job_dir / "eve.json"
    raw_path = job.job_dir / "alerts_raw.jsonl"
    filt_path = job.job_dir / "alerts_filtered.jsonl"

    suricata_cmd = ["sudo", "suricata", "-i", suricata_interface, "-c", str(suricata_conf_path), "-l", str(job.job_dir)]
    checksum_mode = suricata_checksum_mode.strip().lower()
    if checksum_mode:
        suricata_cmd.extend(["-k", checksum_mode])
    tcpreplay_extra_args = tcpreplay_extra_args or []
    replay_cmd = ["sudo"]
    if replay_netns:
        replay_cmd.extend(["ip", "netns", "exec", replay_netns])
    replay_cmd.extend([tcpreplay_bin, f"--{replay_speed}", *tcpreplay_extra_args, "--intf1", replay_interface, str(pcap_path)])

    proc = subprocess.Popen(suricata_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        _wait_for_suricata_ready(job.job_dir, proc, suricata_ready_timeout_sec)
        subprocess.run(replay_cmd, check=True)
        time.sleep(max(1, capture_wait_sec))
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    if not eve_path.exists():
        raise SystemExit(f"[!] eve.json not generated after replay: {eve_path}")

    extraction = extract_alerts_from_eve(eve_path=eve_path, raw_path=raw_path, filt_path=filt_path, ignore_signatures=[])
    summary = {
        "job_id": job.job_id,
        "channel": job.channel,
        "job_dir": str(job.job_dir),
        "pcap": str(pcap_path),
        "suricata_interface": suricata_interface,
        "replay_interface": replay_interface,
        "replay_netns": replay_netns or None,
        "eve_json": str(eve_path),
        "alerts_raw_jsonl": str(raw_path),
        "alerts_filtered_jsonl": str(filt_path),
        "replay_command": replay_cmd,
        "suricata_command": suricata_cmd,
        "suricata_checksum_mode": checksum_mode or None,
        "suricata_ready_timeout_sec": suricata_ready_timeout_sec,
        **extraction,
    }
    _write_json(job.job_dir / "summary.json", summary)

    aggregate_summary = aggregate_time_windows(job_dir=job.job_dir, window_sec=window_sec, min_hits=min_hits, topk=topk)
    outputs = _run_messages_and_agent(job, rag_top_k=rag_top_k)
    channel_summary = {
        "channel": job.channel,
        "job_id": job.job_id,
        "job_dir": str(job.job_dir),
        "source_path": str(pcap_path),
        "replay": summary,
        "aggregation": aggregate_summary,
        "outputs": outputs,
    }
    _write_json(job.job_dir / "channel_summary.json", channel_summary)
    return channel_summary
