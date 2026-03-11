# backend/agent/llm_agent_sf.py
import json
from dataclasses import dataclass
from typing import Any, Dict, List

from openai import OpenAI

from agent.decision_schema import parse_json_only, validate_decision
from agent.policy import precheck_action, recommend_block_ttl
from agent.prompt import SYSTEM_PROMPT


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
        prechecked = precheck_action(message)
        if prechecked is not None:
            return prechecked

        tools = build_tools_schema()
        tool_results: List[Dict[str, Any]] = []

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(message, ensure_ascii=False)},
        ]

        # 多轮：模型 -> tool_calls -> 执行工具 -> tool result -> 模型 -> 最终 JSON
        for _ in range(self.cfg.max_tool_rounds):
            try:
                resp = self.client.chat.completions.create(
                    model=self.cfg.model,
                    messages=messages,
                    tools=tools,
                    temperature=self.cfg.temperature,
                    stream=False,
                )
            except Exception as exc:
                return self._fallback(message, f"llm request failed: {exc}", tool_results=tool_results)
            m = resp.choices[0].message

            # 工具调用
            if getattr(m, "tool_calls", None):
                messages.append(m)
                for tc in m.tool_calls:
                    fn = tc.function.name
                    args = self._decode_tool_args(tc.function.arguments)
                    args = self._prepare_tool_args(name=fn, args=args, message=message)

                    tool_out = self._exec_tool(fn, args)
                    tool_results.append({"name": fn, "arguments": args, "result": tool_out})
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": json.dumps(tool_out, ensure_ascii=False),
                        }
                    )
                continue

            # 结束：必须是 JSON-only 决策
            try:
                final_text = (m.content or "").strip()
                dec = parse_json_only(final_text)
            except Exception as exc:
                return self._fallback(message, f"invalid model output: {exc}", tool_results=tool_results)

            dec = self._normalize_decision(dec=dec, message=message, tool_results=tool_results)

            ok, err = validate_decision(dec, message.get("constraints", {}))
            if not ok:
                # 不合规直接打回成保守策略（也可选择 raise）
                return self._fallback(message, f"decision invalid: {err}", tool_results=tool_results)

            return dec

        return self._fallback(message, "tool calling rounds exceeded", tool_results=tool_results)

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
    def _decode_tool_args(raw_arguments: str) -> Dict[str, Any]:
        try:
            parsed = json.loads(raw_arguments or "{}")
        except json.JSONDecodeError:
            parsed = {}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _prepare_tool_args(name: str, args: Dict[str, Any], message: Dict[str, Any]) -> Dict[str, Any]:
        args = dict(args)
        window = message.get("window", {})
        hints = message.get("hints", {})
        meta = dict(message.get("meta", {}))

        meta.setdefault("src_ip", window.get("src_ip"))
        meta.setdefault("window_start_epoch", window.get("window_start_epoch"))
        meta.setdefault("window_end_epoch", window.get("window_end_epoch"))
        meta.setdefault("attack_family", hints.get("attack_family"))

        if name in {"block_ip", "unblock_ip"}:
            args["ip"] = window.get("src_ip")
            args.setdefault("meta", meta)
            if not isinstance(args["meta"], dict):
                args["meta"] = meta

        if name == "block_ip":
            args["ttl_sec"] = int(args.get("ttl_sec") or recommend_block_ttl(hints, message.get("constraints", {})))
            args["reason"] = str(args.get("reason") or "llm mitigation decision")
        elif name == "unblock_ip":
            args["reason"] = str(args.get("reason") or "llm unblock decision")

        return args

    @staticmethod
    def _normalize_decision(dec: Dict[str, Any], message: Dict[str, Any], tool_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        constraints = message.get("constraints", {})
        window = message.get("window", {})
        hints = message.get("hints", {})
        src_ip = window.get("src_ip")

        dec = dict(dec)
        dec["target"] = {"type": "ip", "value": src_ip}

        reasons = dec.get("reasons")
        if not isinstance(reasons, list) or not reasons:
            dec["reasons"] = ["model returned incomplete reasoning"]

        labels = dec.get("labels")
        if not isinstance(labels, list) or not labels:
            dec["labels"] = ["llm"]

        evidence = dec.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        for key in constraints.get("required_evidence_fields", []):
            evidence.setdefault(key, window.get(key))
        dec["evidence"] = evidence

        action = dec.get("action")
        block_tool = next((item for item in reversed(tool_results) if item["name"] == "block_ip"), None)
        executed_block = bool(block_tool and block_tool["result"].get("ok"))

        if action != "block":
            if executed_block:
                dec["action"] = "review"
                dec["ttl_sec"] = 0
                dec["tool_result"] = block_tool["result"]
                dec["labels"] = list(dec.get("labels", [])) + ["tool-mismatch"]
                dec["reasons"] = ["block_ip already executed but final action was not block"]
                return dec
            dec.pop("tool_result", None)
            dec["ttl_sec"] = 0
            return dec

        if not block_tool:
            return LLMBlockAgent._fallback(message, "action=block without block_ip tool call", tool_results=tool_results)

        tool_result = block_tool["result"]
        if not tool_result.get("ok"):
            return LLMBlockAgent._fallback(message, "block_ip tool failed", tool_results=tool_results)

        dec["ttl_sec"] = int(dec.get("ttl_sec") or block_tool["arguments"]["ttl_sec"])
        dec["tool_result"] = tool_result
        dec.setdefault("labels", [])
        if "executed" not in dec["labels"]:
            dec["labels"].append("executed")
        return dec

    @staticmethod
    def _fallback(message: Dict[str, Any], why: str, tool_results: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        c = message.get("constraints", {})
        w = message.get("window", {})
        required = c.get("required_evidence_fields", [])
        decision = {
            "action": c.get("default_action_if_uncertain", "review"),
            "target": {"type": "ip", "value": w.get("src_ip")},
            "ttl_sec": 0,
            "confidence": 0.0,
            "risk_score": 0,
            "labels": ["fallback"],
            "reasons": [why][:3],
            "evidence": {k: w.get(k) for k in required},
        }
        if tool_results:
            decision["tool_result"] = tool_results[-1]["result"]
        return decision
