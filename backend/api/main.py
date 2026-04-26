from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agent.window_reader import iter_jsonl
from path_utils import resolve_project_path
from pipeline.channel_runner import DEFAULT_SURICATA_READY_TIMEOUT_SEC


JOBS_ROOT = BACKEND_ROOT / "jobs"
PYTHON_BIN = BACKEND_ROOT / "MBvenv" / "bin" / "python"
RUNNER_SCRIPT = BACKEND_ROOT / "scripts" / "run_channel.py"
EVAL_SCRIPT = BACKEND_ROOT / "scripts" / "evaluate_channel.py"
REPLAY_COMPARE_SCRIPT = BACKEND_ROOT / "scripts" / "evaluate_replay_comparison.py"
NFT_TABLE = os.environ.get("NFT_TABLE", "inet")
NFT_FAMILY_TABLE = os.environ.get("NFT_FAMILY_TABLE", "filter")
NFT_BLOCK_SET = os.environ.get("NFT_SET", "blocklist_v4")
NFT_RATE_LIMIT_SET = os.environ.get("NFT_RATE_LIMIT_SET", "ratelimit_v4")
NFT_WATCH_SET = os.environ.get("NFT_WATCH_SET", "watchlist_v4")

DEFAULT_CSV_PATH = str(resolve_project_path("backend/datasets/cic_ids2017_trafficlabelling/mixed_eval_cleaned.csv"))


class RunRequest(BaseModel):
    channel: str
    job_id: str = ""
    rag_top_k: int = 3

    csv: str = DEFAULT_CSV_PATH
    topk: int = 100
    exclude_benign: bool = True
    selection_mode: str = "stratified_label"
    seed: int = 42

    pcap: str = ""
    window_sec: int = 60
    min_hits: int = 3
    suricata_interface: str = ""
    replay_interface: str = ""
    suricata_checksum_mode: str = "none"
    replay_speed: str = "topspeed"
    replay_netns: str = ""
    tcpreplay_extra_args: List[str] = Field(default_factory=list)
    capture_wait_sec: int = 2
    suricata_ready_timeout_sec: int = DEFAULT_SURICATA_READY_TIMEOUT_SEC


class ReplayComparisonRequest(BaseModel):
    exec_job_dir: str
    baseline_job_dir: str


@dataclass
class RunRecord:
    run_id: str
    channel: str
    job_id: str
    command: List[str]
    created_at: float
    status: str = "queued"
    pid: Optional[int] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    return_code: Optional[int] = None
    stdout: List[str] = field(default_factory=list)
    stderr: List[str] = field(default_factory=list)
    error: str = ""
    job_dir: str = ""


RUNS: Dict[str, RunRecord] = {}
RUN_ORDER: List[str] = []


def _ts_job_id(channel: str) -> str:
    return f"web_{channel}_{time.strftime('%Y%m%d_%H%M%S')}"


def _safe_json_load(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _nft_list_set(set_name: str) -> Dict[str, Any]:
    cmd = ["sudo", "nft", "-j", "list", "set", f"{NFT_TABLE} {NFT_FAMILY_TABLE}", set_name]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        return {
            "ok": False,
            "set_name": set_name,
            "error": (exc.stderr or str(exc)).strip(),
            "members": [],
            "count": 0,
        }

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {
            "ok": False,
            "set_name": set_name,
            "error": "failed to parse nft json output",
            "members": [],
            "count": 0,
        }

    members: List[Dict[str, Any]] = []
    nftables = payload.get("nftables") or []
    for item in nftables:
        rule_set = item.get("set")
        if not isinstance(rule_set, dict):
            continue
        for elem in rule_set.get("elem") or []:
            if isinstance(elem, str):
                members.append({"value": elem, "timeout": None, "expires": None})
                continue
            if not isinstance(elem, dict):
                continue
            value = elem.get("elem")
            timeout = elem.get("timeout")
            expires = elem.get("expires")
            if isinstance(value, str):
                members.append({"value": value, "timeout": timeout, "expires": expires})
            elif isinstance(value, dict):
                val = value.get("val")
                members.append(
                    {
                        "value": val,
                        "timeout": value.get("timeout", timeout),
                        "expires": value.get("expires", expires),
                    }
                )

    return {
        "ok": True,
        "set_name": set_name,
        "members": members,
        "count": len(members),
    }


def _nft_snapshot() -> Dict[str, Any]:
    sets = {
        "block": _nft_list_set(NFT_BLOCK_SET),
        "rate_limit": _nft_list_set(NFT_RATE_LIMIT_SET),
        "watch": _nft_list_set(NFT_WATCH_SET),
    }
    return {
        "table": f"{NFT_TABLE} {NFT_FAMILY_TABLE}",
        "updated_at": time.time(),
        "sets": sets,
    }


def _load_decisions(job_dir: Path, limit: int = 0) -> List[Dict[str, Any]]:
    path = job_dir / "llm_decisions.jsonl"
    if not path.exists():
        return []
    decisions = list(iter_jsonl(str(path)))
    return decisions[-limit:] if limit > 0 else decisions


def _distribution(decisions: List[Dict[str, Any]], getter) -> Dict[str, int]:
    counter: Dict[str, int] = {}
    for item in decisions:
        key = str(getter(item) or "unknown")
        counter[key] = counter.get(key, 0) + 1
    return counter


def _build_timeline(decisions: List[Dict[str, Any]], limit: int = 0) -> List[Dict[str, Any]]:
    visible = decisions[-limit:] if limit > 0 else decisions
    start_index = max(1, len(decisions) - len(visible) + 1)
    items = []
    for index, decision in enumerate(visible, start=start_index):
        tool = decision.get("tool_result") or {}
        items.append(
            {
                "index": index,
                "action": decision.get("action"),
                "target_ip": (decision.get("target") or {}).get("value"),
                "execution_mode": (decision.get("strategy") or {}).get("execution_mode"),
                "ttl_sec": decision.get("ttl_sec"),
                "decision_state": decision.get("decision_state"),
                "ttl_reason": decision.get("ttl_reason"),
                "tool_ok": bool(tool.get("ok")),
                "skipped_execution": bool(tool.get("skipped_execution")),
                "covered_by_existing_action": bool(tool.get("covered_by_existing_action")),
                "already_present": bool(tool.get("already_present")),
                "reason": ((decision.get("reasons") or [""])[:1] or [""])[0],
            }
        )
    return list(reversed(items))


def _list_jobs(limit: int = 30) -> List[Dict[str, Any]]:
    if not JOBS_ROOT.exists():
        return []

    jobs = []
    for path in sorted(JOBS_ROOT.iterdir(), key=lambda item: item.stat().st_mtime, reverse=True):
        if not path.is_dir():
            continue
        summary = _safe_json_load(path / "channel_summary.json")
        evaluation = _safe_json_load(path / "evaluation_report.json")
        execution_eval = evaluation.get("execution_eval") or {}
        jobs.append(
            {
                "job_id": summary.get("job_id") or path.name,
                "job_dir": str(path),
                "channel": summary.get("channel"),
                "source_path": summary.get("source_path"),
                "updated_at": path.stat().st_mtime,
                "decision_count": (evaluation.get("decision_eval") or {}).get("decision_count"),
                "repeat_enforcement_ratio": execution_eval.get("repeat_enforcement_ratio"),
                "skipped_execution_count": execution_eval.get("skipped_execution_count"),
                "has_evaluation": bool(evaluation),
            }
        )
        if len(jobs) >= limit:
            break
    return jobs


def _job_snapshot(job_dir: Path) -> Dict[str, Any]:
    summary = _safe_json_load(job_dir / "channel_summary.json")
    evaluation = _safe_json_load(job_dir / "evaluation_report.json")
    decisions = _load_decisions(job_dir)
    decision_eval = evaluation.get("decision_eval") or {}

    return {
        "job_id": summary.get("job_id") or job_dir.name,
        "job_dir": str(job_dir),
        "channel": summary.get("channel"),
        "source_path": summary.get("source_path"),
        "summary": summary,
        "evaluation": evaluation,
        "decision_count": decision_eval.get("decision_count") or len(decisions),
        "timeline": _build_timeline(decisions),
        "distributions": {
            "action": _distribution(decisions, lambda item: item.get("action")),
            "execution_mode": _distribution(decisions, lambda item: (item.get("strategy") or {}).get("execution_mode")),
            "decision_state": _distribution(decisions, lambda item: item.get("decision_state")),
            "ttl_reason": _distribution(decisions, lambda item: item.get("ttl_reason")),
        },
    }


def _make_command(payload: RunRequest) -> RunRecord:
    channel = payload.channel.strip()
    if channel not in {"csv", "offline", "replay"}:
        raise HTTPException(status_code=400, detail="channel must be one of csv/offline/replay")

    job_id = payload.job_id.strip() or _ts_job_id(channel)
    command = [str(PYTHON_BIN), str(RUNNER_SCRIPT), channel]

    if channel == "csv":
        command.extend(["--csv", payload.csv, "--job-id", job_id])
        command.extend(["--topk", str(payload.topk)])
        if payload.exclude_benign:
            command.append("--exclude-benign")
        command.extend(["--selection-mode", payload.selection_mode, "--seed", str(payload.seed)])
        command.extend(["--rag-top-k", str(payload.rag_top_k)])
    elif channel == "offline":
        if not payload.pcap:
            raise HTTPException(status_code=400, detail="pcap is required for offline channel")
        command.extend(["--pcap", payload.pcap, "--job-id", job_id])
        command.extend(["--window-sec", str(payload.window_sec), "--min-hits", str(payload.min_hits)])
        command.extend(["--topk", str(payload.topk), "--rag-top-k", str(payload.rag_top_k)])
    else:
        missing = [key for key in ("pcap", "suricata_interface", "replay_interface") if not getattr(payload, key)]
        if missing:
            raise HTTPException(status_code=400, detail=f"missing replay fields: {', '.join(missing)}")
        command.extend(["--pcap", payload.pcap, "--job-id", job_id])
        command.extend(["--suricata-interface", payload.suricata_interface, "--replay-interface", payload.replay_interface])
        command.extend(["--suricata-checksum-mode", payload.suricata_checksum_mode, "--replay-speed", payload.replay_speed])
        if payload.replay_netns:
            command.extend(["--replay-netns", payload.replay_netns])
        for extra in payload.tcpreplay_extra_args:
            if extra.strip():
                command.extend(["--tcpreplay-extra-arg", extra.strip()])
        command.extend(["--capture-wait-sec", str(payload.capture_wait_sec)])
        command.extend(["--suricata-ready-timeout-sec", str(payload.suricata_ready_timeout_sec)])
        command.extend(["--window-sec", str(payload.window_sec), "--min-hits", str(payload.min_hits)])
        command.extend(["--topk", str(payload.topk), "--rag-top-k", str(payload.rag_top_k)])

    return RunRecord(
        run_id=uuid.uuid4().hex[:12],
        channel=channel,
        job_id=job_id,
        command=command,
        created_at=time.time(),
        job_dir=str(JOBS_ROOT / job_id),
    )


async def _capture_stream(stream: asyncio.StreamReader, bucket: List[str]) -> None:
    while True:
        line = await stream.readline()
        if not line:
            break
        bucket.append(line.decode("utf-8", errors="ignore").rstrip())
        if len(bucket) > 300:
            del bucket[: len(bucket) - 300]


async def _run_and_evaluate(record: RunRecord) -> None:
    record.status = "running"
    record.started_at = time.time()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    proc = await asyncio.create_subprocess_exec(
        *record.command,
        cwd=str(PROJECT_ROOT),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    record.pid = proc.pid
    await asyncio.gather(
        _capture_stream(proc.stdout, record.stdout),  # type: ignore[arg-type]
        _capture_stream(proc.stderr, record.stderr),  # type: ignore[arg-type]
    )
    record.return_code = await proc.wait()

    if record.return_code == 0:
        eval_proc = await asyncio.create_subprocess_exec(
            str(PYTHON_BIN),
            str(EVAL_SCRIPT),
            "--job-dir",
            record.job_dir,
            cwd=str(PROJECT_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        await asyncio.gather(
            _capture_stream(eval_proc.stdout, record.stdout),  # type: ignore[arg-type]
            _capture_stream(eval_proc.stderr, record.stderr),  # type: ignore[arg-type]
        )
        eval_code = await eval_proc.wait()
        record.return_code = eval_code

    record.finished_at = time.time()
    record.status = "completed" if record.return_code == 0 else "failed"
    if record.return_code != 0 and not record.error:
        record.error = "\n".join(record.stderr[-12:])


app = FastAPI(title="MalBlock API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/config")
def config() -> Dict[str, Any]:
    return {
        "jobs_root": str(JOBS_ROOT),
        "python_bin": str(PYTHON_BIN),
        "runner_script": str(RUNNER_SCRIPT),
        "defaults": RunRequest(channel="csv").model_dump(),
    }


@app.get("/api/jobs")
def jobs(limit: int = 30) -> Dict[str, Any]:
    return {"items": _list_jobs(limit)}


@app.get("/api/jobs/{job_id}")
def job_detail(job_id: str) -> Dict[str, Any]:
    job_dir = JOBS_ROOT / job_id
    if not job_dir.exists():
        raise HTTPException(status_code=404, detail=f"job not found: {job_id}")
    return _job_snapshot(job_dir)


@app.get("/api/nft/status")
def nft_status() -> Dict[str, Any]:
    return _nft_snapshot()


@app.post("/api/jobs/{job_id}/evaluate")
async def evaluate_job(job_id: str) -> Dict[str, Any]:
    job_dir = JOBS_ROOT / job_id
    if not job_dir.exists():
        raise HTTPException(status_code=404, detail=f"job not found: {job_id}")
    proc = await asyncio.create_subprocess_exec(
        str(PYTHON_BIN),
        str(EVAL_SCRIPT),
        "--job-dir",
        str(job_dir),
        cwd=str(PROJECT_ROOT),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=os.environ.copy(),
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=stderr.decode("utf-8", errors="ignore"))
    return {"ok": True, "job": _job_snapshot(job_dir), "stdout": stdout.decode("utf-8", errors="ignore")}


@app.post("/api/replay/compare")
async def compare_replay_jobs(payload: ReplayComparisonRequest) -> Dict[str, Any]:
    proc = await asyncio.create_subprocess_exec(
        str(PYTHON_BIN),
        str(REPLAY_COMPARE_SCRIPT),
        "--exec-job-dir",
        payload.exec_job_dir,
        "--baseline-job-dir",
        payload.baseline_job_dir,
        cwd=str(PROJECT_ROOT),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=os.environ.copy(),
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        detail = stderr.decode("utf-8", errors="ignore").strip() or stdout.decode("utf-8", errors="ignore").strip() or "replay comparison failed"
        raise HTTPException(status_code=500, detail=detail)

    try:
        report = json.loads(stdout.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"failed to parse comparison report: {exc}") from exc

    return {
        "ok": True,
        "report": report,
        "exec_job": report.get("exec_job") or {},
        "baseline_job": report.get("baseline_job") or {},
    }


@app.get("/api/runs")
def runs() -> Dict[str, Any]:
    return {"items": [asdict(RUNS[run_id]) for run_id in reversed(RUN_ORDER)]}


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str) -> Dict[str, Any]:
    record = RUNS.get(run_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    payload = asdict(record)
    if record.job_dir and Path(record.job_dir).exists():
        payload["job_snapshot"] = _job_snapshot(Path(record.job_dir))
    return payload


@app.post("/api/runs")
async def start_run(payload: RunRequest) -> Dict[str, Any]:
    record = _make_command(payload)
    RUNS[record.run_id] = record
    RUN_ORDER.append(record.run_id)
    asyncio.create_task(_run_and_evaluate(record))
    return {"run_id": record.run_id, "job_id": record.job_id, "command": record.command}
