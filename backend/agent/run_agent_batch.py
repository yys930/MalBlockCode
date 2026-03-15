# backend/agent/run_agent_batch.py
import json
import os
import sys
from typing import Any, Dict
from pathlib import Path
from dotenv import load_dotenv

SCRIPT_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_BACKEND_ROOT))

load_dotenv()

from agent.window_reader import iter_jsonl
from agent.llm_agent_sf import AgentConfig, LLMBlockAgent
from agent.mcp_enforcer_client import MCPEnforcerClient, MCPServerParams
from agent.rag_store import VectorRAGConfig, append_rag_case, retrieve_evidence, default_rag_config
from path_utils import resolve_project_path


def add_meta(message: Dict[str, Any], job_id: str) -> Dict[str, Any]:
    evidence_window = message.get("evidence_window", message.get("window", {}))
    w = evidence_window
    window_key = f'{w.get("src_ip")}:{w.get("window_start_epoch")}-{w.get("window_end_epoch")}'
    message.setdefault("meta", {})
    message["meta"].update({"job_id": job_id, "window_key": window_key})
    return message


def inject_rag(message: Dict[str, Any], rag_cfg: VectorRAGConfig | None, rag_top_k: int) -> Dict[str, Any]:
    if not rag_cfg:
        message.setdefault("retrieved_evidence", [])
        return message
    message["retrieved_evidence"] = retrieve_evidence(message, rag_cfg, top_k=rag_top_k)
    return message


def add_decision_context(message: Dict[str, Any], state: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    window = message.get("evidence_window", message.get("window", {}))
    features = window.get("csv_features", {}) if isinstance(window.get("csv_features"), dict) else {}
    src_ip = str(window.get("src_ip") or "")
    ip_state = state.get(src_ip, {})
    retrieved = message.get("retrieved_evidence", [])
    retrieved_block_count = sum(1 for item in retrieved if (item.get("historical_strategy", {}) or {}).get("action") == "block")
    retrieved_effective_count = sum(1 for item in retrieved if (item.get("feedback", {}) or {}).get("is_effective") is True)
    attack_family = str(features.get("attack_family") or message.get("hints", {}).get("attack_family") or "")
    label = str(features.get("label") or "")
    message["decision_context"] = {
        "src_ip_window_count_before": int(ip_state.get("total_windows", 0)),
        "prior_block_count": int(ip_state.get("block_count", 0)),
        "prior_rate_limit_count": int(ip_state.get("rate_limit_count", 0)),
        "prior_watch_count": int(ip_state.get("watch_count", 0)),
        "prior_monitor_count": int(ip_state.get("monitor_count", 0)),
        "prior_allow_count": int(ip_state.get("allow_count", 0)),
        "last_action": ip_state.get("last_action"),
        "current_enforcement_mode": ip_state.get("current_enforcement_mode", "none"),
        "current_enforcement_ttl_sec": int(ip_state.get("current_enforcement_ttl_sec", 0)),
        "recent_attack_families": sorted(ip_state.get("attack_families", set())),
        "recent_labels": sorted(ip_state.get("labels", set())),
        "same_attack_family_seen_count": int(ip_state.get("attack_family_counts", {}).get(attack_family, 0)),
        "same_label_seen_count": int(ip_state.get("label_counts", {}).get(label, 0)),
        "already_blocked_in_job": bool(ip_state.get("block_count", 0) > 0),
        "already_rate_limited_in_job": bool(ip_state.get("rate_limit_count", 0) > 0),
        "max_block_ttl_sec_seen": int(ip_state.get("max_block_ttl_sec", 0)),
        "last_block_ttl_sec": int(ip_state.get("last_block_ttl_sec", 0)),
        "retrieved_case_count": len(retrieved),
        "retrieved_block_count": retrieved_block_count,
        "retrieved_effective_count": retrieved_effective_count,
    }
    return message


def update_decision_state(state: Dict[str, Dict[str, Any]], message: Dict[str, Any], decision: Dict[str, Any]) -> None:
    window = message.get("evidence_window", message.get("window", {}))
    hints = message.get("hints", {})
    features = window.get("csv_features", {}) if isinstance(window.get("csv_features"), dict) else {}
    src_ip = str(window.get("src_ip") or "")
    if not src_ip:
        return
    ip_state = state.setdefault(
        src_ip,
        {
            "total_windows": 0,
            "block_count": 0,
            "monitor_count": 0,
            "allow_count": 0,
            "review_count": 0,
            "rate_limit_count": 0,
            "watch_count": 0,
            "attack_families": set(),
            "labels": set(),
            "attack_family_counts": {},
            "label_counts": {},
            "last_action": None,
            "max_block_ttl_sec": 0,
            "last_block_ttl_sec": 0,
            "current_enforcement_mode": "none",
            "current_enforcement_ttl_sec": 0,
        },
    )
    ip_state["total_windows"] += 1
    action = str(decision.get("action") or "")
    key = f"{action}_count"
    if key in ip_state:
        ip_state[key] += 1
    ip_state["last_action"] = action or ip_state.get("last_action")
    attack_family = hints.get("attack_family")
    if attack_family:
        attack_family = str(attack_family)
        ip_state["attack_families"].add(attack_family)
        counts = ip_state.setdefault("attack_family_counts", {})
        counts[attack_family] = int(counts.get(attack_family, 0)) + 1
    label = str(features.get("label") or "")
    if label:
        ip_state["labels"].add(label)
        label_counts = ip_state.setdefault("label_counts", {})
        label_counts[label] = int(label_counts.get(label, 0)) + 1
    tool_result = decision.get("tool_result") or {}
    execution_mode = str((decision.get("strategy") or {}).get("execution_mode") or "")
    if tool_result.get("ok"):
        if execution_mode == "rate_limit":
            ip_state["rate_limit_count"] = int(ip_state.get("rate_limit_count", 0)) + 1
        elif execution_mode == "watch":
            ip_state["watch_count"] = int(ip_state.get("watch_count", 0)) + 1
    if action == "block":
        ttl_sec = int(decision.get("ttl_sec") or 0)
        if ttl_sec > 0:
            ip_state["last_block_ttl_sec"] = ttl_sec
            ip_state["max_block_ttl_sec"] = max(int(ip_state.get("max_block_ttl_sec", 0)), ttl_sec)
    execution_mode = str((decision.get("strategy") or {}).get("execution_mode") or "")
    current_mode = str(ip_state.get("current_enforcement_mode") or "none")
    rank = {"none": 0, "watch": 1, "rate_limit": 2, "drop": 3}
    if execution_mode in rank and rank[execution_mode] >= rank.get(current_mode, 0):
        ip_state["current_enforcement_mode"] = execution_mode
        ttl_candidate = int(decision.get("ttl_sec") or 0)
        if ttl_candidate > 0:
            ip_state["current_enforcement_ttl_sec"] = max(int(ip_state.get("current_enforcement_ttl_sec", 0)), ttl_candidate)


def run_batch(
    in_path: str,
    out_path: str,
    job_id: str,
    api_key: str,
    rag_cfg: VectorRAGConfig | None = None,
    rag_top_k: int = 3,
    model: str | None = None,
    temperature: float | None = None,
) -> str:
    in_path = str(resolve_project_path(in_path))
    out_path = str(resolve_project_path(out_path))
    out_dir = os.path.dirname(out_path)
    os.makedirs(out_dir, exist_ok=True)

    rag_cfg = rag_cfg or default_rag_config()

    # Empty batches are valid for replay/offline runs with no surviving alerts.
    if os.path.exists(in_path) and os.path.getsize(in_path) == 0:
        Path(out_path).write_text("", encoding="utf-8")
        return out_path

    server_cmd = sys.executable
    server_args = [str(SCRIPT_BACKEND_ROOT / "agent" / "mcp_enforcer_server.py")]
    mcp_client = MCPEnforcerClient(MCPServerParams(command=server_cmd, args=server_args))
    mcp_client.start()

    cfg = AgentConfig(
        api_key=api_key,
        base_url=os.environ.get("SILICONFLOW_BASE_URL", "https://api.siliconflow.cn/v1"),
        model=model or os.environ.get("SF_MODEL", "deepseek-ai/DeepSeek-V3.2"),
        temperature=temperature if temperature is not None else float(os.environ.get("TEMP", "0.1")),
    )
    agent = LLMBlockAgent(cfg, tool_executor=mcp_client)
    decision_state: Dict[str, Dict[str, Any]] = {}

    try:
        with open(out_path, "w", encoding="utf-8") as fout:
            for msg in iter_jsonl(in_path):
                msg = add_meta(msg, job_id)
                msg = inject_rag(msg, rag_cfg, rag_top_k)
                msg = add_decision_context(msg, decision_state)
                decision = agent.run_one(msg)
                fout.write(json.dumps(decision, ensure_ascii=False) + "\n")
                append_rag_case(rag_cfg, msg, decision)
                update_decision_state(decision_state, msg, decision)
    finally:
        try:
            mcp_client.close()
        except Exception:
            pass

    return out_path


if __name__ == "__main__":
    # 1) SiliconFlow API Key
    api_key = os.environ.get("SILICONFLOW_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Please set env SILICONFLOW_API_KEY")

    # 2) 你的 job_id & paths
    job_id = os.environ.get("JOB_ID", "cic_monday_001")
    base = str(resolve_project_path(f"backend/jobs/{job_id}"))
    in_path = os.path.join(base, "llm_messages.jsonl")
    out_path = os.path.join(base, "llm_decisions.jsonl")
    rag_top_k = int(os.environ.get("RAG_TOP_K", "3"))
    rag_cfg = default_rag_config()

    run_batch(in_path=in_path, out_path=out_path, job_id=job_id, api_key=api_key, rag_cfg=rag_cfg, rag_top_k=rag_top_k)
    print(f"done -> {out_path}")
    print("note: set DRY_RUN=0 to really execute nft in mcp_enforcer_server.py")
