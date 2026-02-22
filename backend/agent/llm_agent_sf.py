# backend/agent/llm_agent_sf.py
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from openai import OpenAI

from agent.prompt import SYSTEM_PROMPT
from agent.decision_schema import parse_json_only, validate_decision


def build_tools_schema() -> List[Dict[str, Any]]:
    # 给模型注册可调用工具（function calling / tools）
    return [
        {
            "type": "function",
            "function": {
                "name": "block_ip",
                "description": "Block an IP for ttl_sec seconds. Only use when action=block and constraints allow.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "ttl_sec": {"type": "integer"},
                        "reason": {"type": "string"},
                        "meta": {"type": "object"},
                    },
                    "required": ["ip", "ttl_sec", "reason", "meta"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "unblock_ip",
                "description": "Unblock an IP.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "reason": {"type": "string"},
                        "meta": {"type": "object"},
                    },
                    "required": ["ip", "reason", "meta"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_blocked",
                "description": "List currently blocked IPs.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
    ]


@dataclass
class AgentConfig:
    api_key: str
    base_url: str = "https://api.siliconflow.cn/v1"
    model: str = "deepseek-ai/DeepSeek-V2.5"
    temperature: float = 0.1
    max_tool_rounds: int = 3


class LLMBlockAgent:
    """
    - 输入：message（task/constraints/hints/window）
    - 模型：SiliconFlow OpenAI-compatible chat.completions + tools
    - 工具执行：由外部 tool_executor 提供（这里接 MCP enforcer client）
    - 输出：最终决策 JSON（并可附 tool_result）
    """

    def __init__(self, cfg: AgentConfig, tool_executor: Any):
        self.cfg = cfg
        self.tool_executor = tool_executor
        self.client = OpenAI(api_key=cfg.api_key, base_url=cfg.base_url)

    def run_one(self, message: Dict[str, Any]) -> Dict[str, Any]:
        tools = build_tools_schema()

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(message, ensure_ascii=False)},
        ]

        # 多轮：模型 -> tool_calls -> 执行工具 -> tool result -> 模型 -> 最终 JSON
        for _ in range(self.cfg.max_tool_rounds):
            resp = self.client.chat.completions.create(
                model=self.cfg.model,
                messages=messages,
                tools=tools,
                temperature=self.cfg.temperature,
                stream=False,
            )
            m = resp.choices[0].message

            # 工具调用
            if getattr(m, "tool_calls", None):
                messages.append(m)
                for tc in m.tool_calls:
                    fn = tc.function.name
                    args = json.loads(tc.function.arguments or "{}")

                    tool_out = self._exec_tool(fn, args)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": json.dumps(tool_out, ensure_ascii=False),
                        }
                    )
                continue

            # 结束：必须是 JSON-only 决策
            final_text = (m.content or "").strip()
            dec = parse_json_only(final_text)

            ok, err = validate_decision(dec, message.get("constraints", {}))
            if not ok:
                # 不合规直接打回成保守策略（也可选择 raise）
                return self._fallback(message, f"decision invalid: {err}")

            return dec

        return self._fallback(message, "tool calling rounds exceeded")

    def _exec_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        # 这里工具执行走 MCP client（或者你也能换成本地 skill）
        if name == "block_ip":
            return self.tool_executor.block_ip(args["ip"], int(args["ttl_sec"]), args["reason"], args["meta"])
        if name == "unblock_ip":
            return self.tool_executor.unblock_ip(args["ip"], args["reason"], args["meta"])
        if name == "list_blocked":
            return self.tool_executor.list_blocked()
        return {"ok": False, "error": f"unknown tool {name}"}

    @staticmethod
    def _fallback(message: Dict[str, Any], why: str) -> Dict[str, Any]:
        c = message.get("constraints", {})
        w = message.get("window", {})
        required = c.get("required_evidence_fields", [])
        return {
            "action": c.get("default_action_if_uncertain", "review"),
            "target": {"type": "ip", "value": w.get("src_ip")},
            "ttl_sec": 0,
            "confidence": 0.0,
            "risk_score": 0,
            "labels": ["fallback"],
            "reasons": [why][:3],
            "evidence": {k: w.get(k) for k in required},
        }