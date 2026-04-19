from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agent.build_messages import build_messages
from agent.message_builder import build_message
from agent.rag_store import default_rag_config
from agent.run_agent_batch import run_batch
from agent.run_agent_batch import (
    add_decision_context,
    add_meta,
    inject_rag,
    update_decision_state,
)
from agent.llm_agent_sf import AgentConfig, LLMBlockAgent
from agent.mcp_enforcer_client import MCPEnforcerClient, MCPServerParams
from agent.rag_store import append_rag_case
from path_utils import BACKEND_ROOT, resolve_project_path
from pipeline.csv_flow_adapter import build_csv_flow_inputs
from pipeline.offline_detect import DEFAULT_JOBS_ROOT, DEFAULT_SURICATA_CONF, run_offline_detect, ts_job_id
from pipeline.suricata_alerts import (
    DEFAULT_IGNORE_SIGNATURE_KEYWORDS,
    extract_alert_record,
    extract_alerts_from_eve,
    parse_ignore_list,
    should_filter_alert,
)
from pipeline.window_aggregate import aggregate_alert_records, aggregate_time_windows

DEFAULT_SURICATA_READY_TIMEOUT_SEC = 300
DEFAULT_REPLAY_DRAIN_IDLE_SEC = 5


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
    started_at = time.time()
    deadline = started_at + max(1, timeout_sec)
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"[!] Suricata exited before becoming ready, see {log_path}")
        if log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="ignore").lower()
            if any(marker in text for marker in ready_markers):
                return
        time.sleep(1)
    detail = ""
    if log_path.exists():
        lines = [line.strip() for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
        if lines:
            detail = f"; last log line: {lines[-1]}"
    elapsed = int(time.time() - started_at)
    raise SystemExit(
        f"[!] Timed out waiting for Suricata readiness after {elapsed}s, see {log_path}{detail}"
    )


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _job_paths(job_dir: Path) -> Dict[str, Path]:
    return {
        "llm_inputs_all": job_dir / "llm_inputs_all.jsonl",
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


def _append_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    if not records:
        return
    with path.open("a", encoding="utf-8") as out:
        for record in records:
            out.write(json.dumps(record, ensure_ascii=False) + "\n")


def _ensure_output_files(paths: Dict[str, Path]) -> None:
    for path in paths.values():
        path.touch(exist_ok=True)


def _read_new_alerts_from_eve(
    eve_path: Path,
    offset: int,
    ignore_signatures: set[str],
    ignore_signature_keywords: set[str],
) -> Tuple[List[Dict[str, Any]], int, int, int]:
    if not eve_path.exists():
        return [], offset, 0, 0

    records: List[Dict[str, Any]] = []
    raw_count = 0
    filtered_count = 0
    with eve_path.open("rb") as f:
        f.seek(offset)
        while True:
            line_start = f.tell()
            line = f.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                f.seek(line_start)
                break
            try:
                evt = json.loads(line.decode("utf-8", errors="ignore"))
            except Exception:
                continue
            if evt.get("event_type") != "alert":
                continue
            raw_count += 1
            rec = extract_alert_record(evt)
            filter_reason = should_filter_alert(rec, ignore_signatures, ignore_signature_keywords)
            if filter_reason:
                continue
            filtered_count += 1
            records.append(rec)
        new_offset = f.tell()
    return records, new_offset, raw_count, filtered_count


def _flush_replay_batch(
    *,
    now: float,
    pending_records: List[Dict[str, Any]],
    pending_raw_count: int,
    pending_filtered_count: int,
    stream_batches: List[Dict[str, Any]],
    paths: Dict[str, Path],
    job: ChannelJobConfig,
    window_sec: int,
    min_hits: int,
    topk: int,
    rag_top_k: int,
    decision_state: Dict[str, Dict[str, Any]],
    agent: LLMBlockAgent,
    rag_cfg,
) -> int:
    batch = aggregate_alert_records(
        pending_records,
        window_sec=window_sec,
        min_hits=min_hits,
        topk=topk,
    )
    _append_jsonl(paths["llm_inputs_all"], batch["all_windows"])
    _append_jsonl(paths["llm_inputs_selected"], batch["selected_windows"])
    processed_count = _stream_messages_and_agent(
        job=job,
        selected_windows=batch["selected_windows"],
        rag_top_k=rag_top_k,
        decision_state=decision_state,
        agent=agent,
        rag_cfg=rag_cfg,
    )
    stream_batches.append(
        {
            "batch_index": len(stream_batches) + 1,
            "created_at": now,
            "raw_alerts": pending_raw_count,
            "filtered_alerts": pending_filtered_count,
            "buffered_alerts": len(pending_records),
            "selected_windows": batch["selected_groups"],
            "decisions_emitted": processed_count,
            "top_preview_selected": batch["top_preview_selected"],
        }
    )
    return processed_count


def _stream_messages_and_agent(
    job: ChannelJobConfig,
    selected_windows: List[Dict[str, Any]],
    rag_top_k: int,
    decision_state: Dict[str, Dict[str, Any]],
    agent: LLMBlockAgent,
    rag_cfg,
) -> int:
    paths = _job_paths(job.job_dir)
    if not selected_windows:
        return 0

    messages: List[Dict[str, Any]] = []
    decisions: List[Dict[str, Any]] = []
    for window in selected_windows:
        msg = build_message(window)
        msg = add_meta(msg, job.job_id)
        msg = inject_rag(msg, rag_cfg, rag_top_k)
        msg = add_decision_context(msg, decision_state)
        decision = agent.run_one(msg)
        append_rag_case(rag_cfg, msg, decision)
        update_decision_state(decision_state, msg, decision)
        messages.append(msg)
        decisions.append(decision)

    _append_jsonl(paths["llm_messages"], messages)
    _append_jsonl(paths["llm_decisions"], decisions)
    return len(decisions)


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
    suricata_ready_timeout_sec: int = DEFAULT_SURICATA_READY_TIMEOUT_SEC,
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
    replay_stdout_path = job.job_dir / "tcpreplay.stdout.log"
    replay_stderr_path = job.job_dir / "tcpreplay.stderr.log"

    suricata_cmd = ["sudo", "suricata", "-i", suricata_interface, "-c", str(suricata_conf_path), "-l", str(job.job_dir)]
    checksum_mode = suricata_checksum_mode.strip().lower()
    if checksum_mode:
        suricata_cmd.extend(["-k", checksum_mode])
    tcpreplay_extra_args = tcpreplay_extra_args or []
    replay_cmd = ["sudo"]
    if replay_netns:
        replay_cmd.extend(["ip", "netns", "exec", replay_netns])
    replay_cmd.extend([tcpreplay_bin, f"--{replay_speed}", *tcpreplay_extra_args, "--intf1", replay_interface, str(pcap_path)])
    ignore_sigs = parse_ignore_list([])
    ignore_sig_keywords = set(DEFAULT_IGNORE_SIGNATURE_KEYWORDS)
    raw_total = 0
    filtered_total = 0
    stream_batches: List[Dict[str, Any]] = []
    paths = _job_paths(job.job_dir)
    rag_cfg = default_rag_config()
    api_key = os.environ.get("SILICONFLOW_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Please set env SILICONFLOW_API_KEY")
    _ensure_output_files(paths)

    server_cmd = sys.executable
    server_args = [str(BACKEND_ROOT / "agent" / "mcp_enforcer_server.py")]
    mcp_client = MCPEnforcerClient(MCPServerParams(command=server_cmd, args=server_args))
    mcp_client.start()
    agent = LLMBlockAgent(
        AgentConfig(
            api_key=api_key,
            base_url=os.environ.get("SILICONFLOW_BASE_URL", "https://api.siliconflow.cn/v1"),
            model=os.environ.get("SF_MODEL", "deepseek-ai/DeepSeek-V3.2"),
            temperature=float(os.environ.get("TEMP", "0.1")),
        ),
        tool_executor=mcp_client,
    )
    decision_state: Dict[str, Dict[str, Any]] = {}
    eve_offset = 0
    pending_records: List[Dict[str, Any]] = []
    pending_raw_count = 0
    pending_filtered_count = 0
    next_flush_at = time.time() + max(1, window_sec)
    last_alert_activity_at: Optional[float] = None
    replay_stdout = ""
    replay_stderr = ""
    replay_returncode: Optional[int] = None

    proc = subprocess.Popen(suricata_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    replay_proc: Optional[subprocess.Popen[str]] = None
    try:
        _wait_for_suricata_ready(job.job_dir, proc, suricata_ready_timeout_sec)
        replay_proc = subprocess.Popen(replay_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        replay_finished_at: Optional[float] = None

        while True:
            new_records, eve_offset, raw_inc, filtered_inc = _read_new_alerts_from_eve(
                eve_path=eve_path,
                offset=eve_offset,
                ignore_signatures=ignore_sigs,
                ignore_signature_keywords=ignore_sig_keywords,
            )
            raw_total += raw_inc
            filtered_total += filtered_inc
            pending_raw_count += raw_inc
            pending_filtered_count += filtered_inc
            pending_records.extend(new_records)
            if raw_inc or filtered_inc:
                last_alert_activity_at = time.time()

            now = time.time()
            should_flush = now >= next_flush_at
            replay_done = replay_proc.poll() is not None if replay_proc else True
            if replay_done and replay_finished_at is None:
                replay_finished_at = now
            drain_idle_sec = max(DEFAULT_REPLAY_DRAIN_IDLE_SEC, capture_wait_sec)
            capture_drain_done = (
                replay_finished_at is not None
                and now >= replay_finished_at + max(1, capture_wait_sec)
                and (
                    last_alert_activity_at is None
                    or now >= last_alert_activity_at + drain_idle_sec
                )
            )
            final_flush = capture_drain_done and bool(pending_records)

            if should_flush or final_flush:
                _flush_replay_batch(
                    now=now,
                    pending_records=pending_records,
                    pending_raw_count=pending_raw_count,
                    pending_filtered_count=pending_filtered_count,
                    stream_batches=stream_batches,
                    paths=paths,
                    job=job,
                    window_sec=window_sec,
                    min_hits=min_hits,
                    topk=topk,
                    rag_top_k=rag_top_k,
                    decision_state=decision_state,
                    agent=agent,
                    rag_cfg=rag_cfg,
                )
                pending_records = []
                pending_raw_count = 0
                pending_filtered_count = 0
                next_flush_at = now + max(1, window_sec)

            if replay_done and capture_drain_done and not pending_records:
                break
            time.sleep(1)
    finally:
        if replay_proc:
            if replay_proc.poll() is None:
                replay_proc.terminate()
                try:
                    replay_stdout, replay_stderr = replay_proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    replay_proc.kill()
                    replay_stdout, replay_stderr = replay_proc.communicate(timeout=5)
            else:
                replay_stdout, replay_stderr = replay_proc.communicate()
            replay_returncode = replay_proc.returncode
            _write_text(replay_stdout_path, replay_stdout)
            _write_text(replay_stderr_path, replay_stderr)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        try:
            mcp_client.close()
        except Exception:
            pass

    new_records, eve_offset, raw_inc, filtered_inc = _read_new_alerts_from_eve(
        eve_path=eve_path,
        offset=eve_offset,
        ignore_signatures=ignore_sigs,
        ignore_signature_keywords=ignore_sig_keywords,
    )
    raw_total += raw_inc
    filtered_total += filtered_inc
    pending_raw_count += raw_inc
    pending_filtered_count += filtered_inc
    pending_records.extend(new_records)
    if pending_records:
        _flush_replay_batch(
            now=time.time(),
            pending_records=pending_records,
            pending_raw_count=pending_raw_count,
            pending_filtered_count=pending_filtered_count,
            stream_batches=stream_batches,
            paths=paths,
            job=job,
            window_sec=window_sec,
            min_hits=min_hits,
            topk=topk,
            rag_top_k=rag_top_k,
            decision_state=decision_state,
            agent=agent,
            rag_cfg=rag_cfg,
        )
        pending_records = []
        pending_raw_count = 0
        pending_filtered_count = 0

    if not eve_path.exists():
        raise SystemExit(f"[!] eve.json not generated after replay: {eve_path}")

    if replay_returncode not in (None, 0):
        raise SystemExit(
            f"[!] tcpreplay exited with code {replay_returncode}, see {replay_stderr_path}"
        )

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
        "tcpreplay_stdout_log": str(replay_stdout_path),
        "tcpreplay_stderr_log": str(replay_stderr_path),
        "replay_command": replay_cmd,
        "suricata_command": suricata_cmd,
        "suricata_checksum_mode": checksum_mode or None,
        "suricata_ready_timeout_sec": suricata_ready_timeout_sec,
        "stream_window_sec": window_sec,
        "stream_topk": topk,
        "stream_batches": stream_batches,
        "stream_alert_count_raw": raw_total,
        "stream_alert_count_filtered": filtered_total,
        **extraction,
    }
    _write_json(job.job_dir / "summary.json", summary)

    aggregate_summary = {
        "mode": "streaming_replay",
        "window_sec": window_sec,
        "min_hits": min_hits,
        "topk": topk,
        "batch_count": len(stream_batches),
        "selected_groups": sum(int(batch.get("selected_windows") or 0) for batch in stream_batches),
        "all_output": str(paths["llm_inputs_all"]),
        "selected_output": str(paths["llm_inputs_selected"]),
        "top_preview_selected": [preview for batch in stream_batches for preview in (batch.get("top_preview_selected") or [])][:10],
    }
    outputs = {name: str(path) for name, path in paths.items()}
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
