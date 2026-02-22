# backend/agent/run_agent_batch.py
import json
import os
from typing import Any, Dict
from dotenv import load_dotenv
load_dotenv()

from agent.window_reader import iter_jsonl
from agent.llm_agent_sf import AgentConfig, LLMBlockAgent
from agent.mcp_enforcer_client import MCPEnforcerClient, MCPServerParams


def add_meta(message: Dict[str, Any], job_id: str) -> Dict[str, Any]:
    w = message.get("window", {})
    window_key = f'{w.get("src_ip")}:{w.get("window_start_epoch")}-{w.get("window_end_epoch")}'
    message.setdefault("meta", {})
    message["meta"].update({"job_id": job_id, "window_key": window_key})
    return message


if __name__ == "__main__":
    # 1) SiliconFlow API Key
    api_key = os.environ.get("SILICONFLOW_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Please set env SILICONFLOW_API_KEY")

    # 2) 你的 job_id & paths
    job_id = os.environ.get("JOB_ID", "20260222_165812")
    base = f"/home/os/FinalCode/malblock/backend/jobs/{job_id}"
    in_path = os.path.join(base, "llm_messages.jsonl")
    out_path = os.path.join(base, "llm_decisions.jsonl")

    # 3) 启动 MCP enforcer server（stdio 子进程方式）
    server_cmd = "python3"
    server_args = ["-m", "agent.mcp_enforcer_server"]
    mcp_client = MCPEnforcerClient(MCPServerParams(command=server_cmd, args=server_args))
    mcp_client.start()

    # 4) LLM Agent config
    cfg = AgentConfig(
        api_key=api_key,
        base_url="https://api.siliconflow.cn/v1",
        model=os.environ.get("SF_MODEL", "deepseek-ai/DeepSeek-V3.2"),  # 建议先用 V2.5 跑通 tools
        temperature=float(os.environ.get("TEMP", "0.1")),
    )
    agent = LLMBlockAgent(cfg, tool_executor=mcp_client)

    # 5) batch run（✅必须在 if 块内）
    os.makedirs(base, exist_ok=True)

    try:
        with open(out_path, "w", encoding="utf-8") as fout:
            for msg in iter_jsonl(in_path):
                msg = add_meta(msg, job_id)
                decision = agent.run_one(msg)
                fout.write(json.dumps(decision, ensure_ascii=False) + "\n")

        print(f"done -> {out_path}")
        print("note: set DRY_RUN=0 to really execute nft in mcp_enforcer_server.py")

    finally:
        # ✅ 无论成功/失败都关闭 MCP 子进程与 session
        try:
            mcp_client.close()
        except Exception:
            pass