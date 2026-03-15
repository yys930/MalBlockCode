# backend/agent/llm_agent_sf.py
import json
from dataclasses import dataclass
from typing import Any, Dict, List

from openai import OpenAI

from agent.decision_schema import parse_json_only, validate_decision
from agent.policy import build_strategy, precheck_action, recommend_block_ttl
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
                "name": "rate_limit_ip",
                "description": "Apply rate limiting to an IP for ttl_sec seconds. Use when action=block and strategy.execution_mode=rate_limit.",
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
                "name": "watch_ip",
                "description": "Add an IP to the watch list for ttl_sec seconds. Use when action=monitor and strategy.execution_mode=watch.",
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
            return self._apply_prechecked_decision(message, prechecked)

        tools = build_tools_schema()
        tool_results: List[Dict[str, Any]] = []

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(message, ensure_ascii=False)},
        ]
        json_retry_used = False

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

                    tool_out = self._maybe_short_circuit_tool(fn, args, message) or self._exec_tool(fn, args)
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
                if not json_retry_used:
                    json_retry_used = True
                    messages.append(
                        {
                            "role": "assistant",
                            "content": m.content or "",
                        }
                    )
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Your previous reply was not valid JSON-only. "
                                "Reply again with exactly one valid JSON object that matches the required schema. "
                                "Do not add markdown, comments, or trailing text."
                            ),
                        }
                    )
                    continue
                return self._fallback(message, f"invalid model output: {exc}", tool_results=tool_results)

            dec = self._normalize_decision(dec=dec, message=message, tool_results=tool_results)
            dec = self._ensure_required_execution(dec=dec, message=message, tool_results=tool_results)

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
        if name == "rate_limit_ip":
            return self.tool_executor.rate_limit_ip(args["ip"], int(args["ttl_sec"]), args["reason"], args["meta"])
        if name == "watch_ip":
            return self.tool_executor.watch_ip(args["ip"], int(args["ttl_sec"]), args["reason"], args["meta"])
        if name == "unblock_ip":
            return self.tool_executor.unblock_ip(args["ip"], args["reason"], args["meta"])
        if name == "list_blocked":
            return self.tool_executor.list_blocked()
        return {"ok": False, "error": f"unknown tool {name}"}

    @staticmethod
    def _enforcement_rank(mode: str) -> int:
        return {"none": 0, "watch": 1, "rate_limit": 2, "drop": 3}.get(str(mode or "none"), 0)

    @staticmethod
    def _maybe_short_circuit_tool(name: str, args: Dict[str, Any], message: Dict[str, Any]) -> Dict[str, Any] | None:
        ctx = message.get("decision_context", {}) if isinstance(message.get("decision_context"), dict) else {}
        current_mode = str(ctx.get("current_enforcement_mode") or "none")
        requested_mode = {
            "block_ip": "drop",
            "rate_limit_ip": "rate_limit",
            "watch_ip": "watch",
        }.get(name)
        if not requested_mode:
            return None
        if LLMBlockAgent._enforcement_rank(current_mode) < LLMBlockAgent._enforcement_rank(requested_mode):
            return None
        return {
            "ok": True,
            "skipped_execution": True,
            "covered_by_existing_action": True,
            "action": name,
            "ip": args.get("ip"),
            "ttl_sec": int(args.get("ttl_sec") or 0),
            "reason": args.get("reason"),
            "meta": args.get("meta"),
            "current_enforcement_mode": current_mode,
        }

    @staticmethod
    def _annotate_block_decision(
        dec: Dict[str, Any],
        prior_block_count: int,
        ttl_reason: str,
        covered_by_existing_action: bool = False,
    ) -> Dict[str, Any]:
        out = dict(dec)
        out["decision_state"] = "covered_by_existing_block" if covered_by_existing_action else ("escalated_block" if prior_block_count > 0 else "new_block")
        out["ttl_reason"] = ttl_reason
        out.setdefault("labels", [])
        if prior_block_count > 0 and "repeat-offender" not in out["labels"]:
            out["labels"].append("repeat-offender")
        reasons = out.get("reasons")
        if isinstance(reasons, list) and prior_block_count > 0:
            repeat_reason = "Same source IP had prior malicious decisions in this batch, so the containment policy was escalated."
            if repeat_reason not in reasons:
                out["reasons"] = (reasons + [repeat_reason])[:3]
        return out

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
        window = message.get("evidence_window", message.get("window", {}))
        hints = message.get("hints", {})
        meta = dict(message.get("meta", {}))

        meta.setdefault("src_ip", window.get("src_ip"))
        meta.setdefault("window_start_epoch", window.get("window_start_epoch"))
        meta.setdefault("window_end_epoch", window.get("window_end_epoch"))
        meta.setdefault("attack_family", hints.get("attack_family"))

        if name in {"block_ip", "rate_limit_ip", "watch_ip", "unblock_ip"}:
            args["ip"] = window.get("src_ip")
            args.setdefault("meta", meta)
            if not isinstance(args["meta"], dict):
                args["meta"] = meta

        if name in {"block_ip", "rate_limit_ip", "watch_ip"}:
            recommended_ttl = recommend_block_ttl(hints, message.get("constraints", {}), message=message)
            requested_ttl = int(args.get("ttl_sec") or 0)
            args["ttl_sec"] = max(requested_ttl, recommended_ttl)
            args["reason"] = str(args.get("reason") or "llm mitigation decision")
        elif name == "unblock_ip":
            args["reason"] = str(args.get("reason") or "llm unblock decision")

        return args

    @staticmethod
    def _required_tool_name(action: str, strategy: Dict[str, Any]) -> str | None:
        execution_mode = str(strategy.get("execution_mode") or "none")
        if action == "block":
            if execution_mode == "drop":
                return "block_ip"
            if execution_mode == "rate_limit":
                return "rate_limit_ip"
        if action == "monitor" and execution_mode == "watch":
            return "watch_ip"
        return None

    @staticmethod
    def _last_mitigation_tool(tool_results: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        mitigation_tools = {"block_ip", "rate_limit_ip", "watch_ip"}
        return next((item for item in reversed(tool_results) if item["name"] in mitigation_tools), None)

    def _apply_prechecked_decision(self, message: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
        strategy = decision.get("strategy")
        if not isinstance(strategy, dict):
            return decision
        required_tool = self._required_tool_name(decision.get("action"), strategy)
        if not required_tool:
            return decision
        args = self._prepare_tool_args(required_tool, {}, message)
        if required_tool in {"block_ip", "rate_limit_ip"}:
            args["ttl_sec"] = int(decision.get("ttl_sec") or args.get("ttl_sec") or 0)
        elif required_tool == "watch_ip":
            args["ttl_sec"] = int(message.get("constraints", {}).get("min_ttl_sec_if_block", 300))
        tool_out = self._maybe_short_circuit_tool(required_tool, args, message) or self._exec_tool(required_tool, args)
        if not tool_out.get("ok"):
            return self._fallback(
                message,
                f"{required_tool} tool failed during precheck",
                tool_results=[{"name": required_tool, "arguments": args, "result": tool_out}],
            )
        out = dict(decision)
        out["tool_result"] = tool_out
        out.setdefault("labels", [])
        if "executed" not in out["labels"]:
            out["labels"].append("executed")
        if str(out.get("action") or "") == "block":
            ctx = message.get("decision_context", {}) if isinstance(message.get("decision_context"), dict) else {}
            out = self._annotate_block_decision(
                out,
                prior_block_count=int(ctx.get("prior_block_count") or 0),
                ttl_reason="covered_by_existing_action" if tool_out.get("covered_by_existing_action") else "precheck_execution",
                covered_by_existing_action=bool(tool_out.get("covered_by_existing_action")),
            )
        return out

    @staticmethod
    def _canonical_evidence(window: Dict[str, Any], constraints: Dict[str, Any]) -> Dict[str, Any]:
        evidence = {key: window.get(key) for key in constraints.get("required_evidence_fields", [])}
        for key in ("flow_uid", "source_day", "source_file", "source_row_id", "src_port", "dst_ip", "dst_port"):
            if key in window and window.get(key) not in {None, ""}:
                evidence[key] = window.get(key)
        return evidence

    @staticmethod
    def _normalize_decision(dec: Dict[str, Any], message: Dict[str, Any], tool_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        constraints = message.get("constraints", {})
        window = message.get("evidence_window", message.get("window", {}))
        hints = message.get("hints", {})
        ctx = message.get("decision_context", {}) if isinstance(message.get("decision_context"), dict) else {}
        src_ip = window.get("src_ip")

        dec = dict(dec)
        dec["target"] = {"type": "ip", "value": src_ip}

        reasons = dec.get("reasons")
        if not isinstance(reasons, list) or not reasons:
            dec["reasons"] = ["model returned incomplete reasoning"]

        labels = dec.get("labels")
        if not isinstance(labels, list) or not labels:
            dec["labels"] = ["llm"]

        dec["evidence"] = LLMBlockAgent._canonical_evidence(window, constraints)

        action = dec.get("action")
        raw_ttl = dec.get("ttl_sec", 0)
        try:
            requested_ttl = int(raw_ttl)
        except Exception:
            requested_ttl = 0
        strategy = dec.get("strategy")
        if not isinstance(strategy, dict):
            strategy = build_strategy(action, hints, constraints, ttl_sec=requested_ttl if action == "block" else 0, message=message)
        required_tool = LLMBlockAgent._required_tool_name(action, strategy)
        mitigation_tool = LLMBlockAgent._last_mitigation_tool(tool_results)
        executed_tool = bool(mitigation_tool and mitigation_tool["result"].get("ok"))
        recommended_ttl = recommend_block_ttl(hints, constraints, message=message) if action == "block" else 0
        prior_max_ttl = int(ctx.get("max_block_ttl_sec_seen") or 0)
        prior_block_count = int(ctx.get("prior_block_count") or 0)
        same_attack_family_seen = int(ctx.get("same_attack_family_seen_count") or 0)
        same_label_seen = int(ctx.get("same_label_seen_count") or 0)

        def normalize_block_ttl(candidate_ttl: int) -> int:
            final_ttl = max(int(candidate_ttl or 0), recommended_ttl)
            if prior_max_ttl > 0:
                final_ttl = max(final_ttl, prior_max_ttl)
            repeat_signal = max(prior_block_count, same_attack_family_seen, same_label_seen)
            if repeat_signal >= 1:
                final_ttl = max(final_ttl, recommended_ttl)
            max_ttl = int(constraints.get("max_ttl_sec") or 86400)
            if repeat_signal <= 1:
                ttl_cap = min(max_ttl, max(recommended_ttl, int(recommended_ttl * 1.5)))
            elif repeat_signal == 2:
                ttl_cap = min(max_ttl, max(recommended_ttl, int(recommended_ttl * 2.0)))
            else:
                ttl_cap = min(max_ttl, max(recommended_ttl, int(recommended_ttl * 3.0)))
            if prior_max_ttl > 0:
                ttl_cap = max(ttl_cap, prior_max_ttl)
            final_ttl = min(final_ttl, ttl_cap)
            return final_ttl

        if required_tool is None:
            if executed_tool:
                dec["action"] = "review"
                dec["ttl_sec"] = 0
                dec["strategy"] = build_strategy("review", hints, constraints, ttl_sec=0, message=message)
                dec["tool_result"] = mitigation_tool["result"]
                dec["labels"] = list(dec.get("labels", [])) + ["tool-mismatch"]
                dec["reasons"] = ["mitigation tool already executed but final action does not require execution"]
                return dec
            dec.pop("tool_result", None)
            dec["ttl_sec"] = 0
            dec["strategy"] = build_strategy(action, hints, constraints, ttl_sec=0, message=message)
            return dec

        expected_tool = next((item for item in reversed(tool_results) if item["name"] == required_tool), None)
        if not expected_tool:
            final_ttl = requested_ttl if action == "block" else 0
            if action == "block" and final_ttl <= 0:
                final_ttl = recommended_ttl
            if action == "block":
                final_ttl = normalize_block_ttl(final_ttl)
            dec["ttl_sec"] = final_ttl
            dec["strategy"] = build_strategy(action, hints, constraints, ttl_sec=final_ttl, message=message)
            dec.pop("tool_result", None)
            if action == "block":
                dec = LLMBlockAgent._annotate_block_decision(
                    dec,
                    prior_block_count=prior_block_count,
                    ttl_reason="policy_recommended_or_escalated_minimum",
                )
            return dec

        tool_result = expected_tool["result"]
        if not tool_result.get("ok"):
            return LLMBlockAgent._fallback(message, f"{required_tool} tool failed", tool_results=tool_results)

        final_ttl = 0
        if action == "block":
            final_ttl = normalize_block_ttl(requested_ttl or int(expected_tool["arguments"]["ttl_sec"]))
        dec["ttl_sec"] = final_ttl
        dec["strategy"] = build_strategy(action, hints, constraints, ttl_sec=final_ttl, message=message)
        dec["tool_result"] = tool_result
        if action == "block":
            ttl_reason = "repeat_offender_escalation" if prior_block_count > 0 else "policy_recommended"
            dec = LLMBlockAgent._annotate_block_decision(
                dec,
                prior_block_count=prior_block_count,
                ttl_reason="covered_by_existing_action" if tool_result.get("covered_by_existing_action") else ttl_reason,
                covered_by_existing_action=bool(tool_result.get("covered_by_existing_action")),
            )
        dec.setdefault("labels", [])
        if "executed" not in dec["labels"]:
            dec["labels"].append("executed")
        return dec

    def _ensure_required_execution(
        self,
        dec: Dict[str, Any],
        message: Dict[str, Any],
        tool_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        action = str(dec.get("action") or "")
        strategy = dec.get("strategy") or {}
        if not isinstance(strategy, dict):
            return dec
        required_tool = self._required_tool_name(action, strategy)
        if not required_tool:
            return dec
        tool_result = dec.get("tool_result") or {}
        if isinstance(tool_result, dict) and tool_result.get("ok"):
            return dec

        args = self._prepare_tool_args(required_tool, {}, message)
        reasons = dec.get("reasons") or []
        if reasons:
            args["reason"] = str(reasons[0])
        if required_tool in {"block_ip", "rate_limit_ip"}:
            args["ttl_sec"] = int(dec.get("ttl_sec") or args.get("ttl_sec") or 0)
        elif required_tool == "watch_ip":
            args["ttl_sec"] = int(message.get("constraints", {}).get("min_ttl_sec_if_block", 300))

        tool_out = self._maybe_short_circuit_tool(required_tool, args, message) or self._exec_tool(required_tool, args)
        tool_results.append({"name": required_tool, "arguments": args, "result": tool_out})
        if not tool_out.get("ok"):
            return self._fallback(message, f"{required_tool} tool failed during runtime repair", tool_results=tool_results)

        out = dict(dec)
        out["tool_result"] = tool_out
        out.setdefault("labels", [])
        if "executed" not in out["labels"]:
            out["labels"].append("executed")
        if action == "block":
            final_ttl = int(dec.get("ttl_sec") or args.get("ttl_sec") or 0)
            out["ttl_sec"] = final_ttl
            out["strategy"] = build_strategy("block", message.get("hints", {}), message.get("constraints", {}), ttl_sec=final_ttl, message=message)
            ctx = message.get("decision_context", {}) if isinstance(message.get("decision_context"), dict) else {}
            out = LLMBlockAgent._annotate_block_decision(
                out,
                prior_block_count=int(ctx.get("prior_block_count") or 0),
                ttl_reason="covered_by_existing_action" if tool_out.get("covered_by_existing_action") else "runtime_repair_execution",
                covered_by_existing_action=bool(tool_out.get("covered_by_existing_action")),
            )
        else:
            out["ttl_sec"] = 0
            out["strategy"] = build_strategy(action, message.get("hints", {}), message.get("constraints", {}), ttl_sec=0, message=message)
        return out

    @staticmethod
    def _fallback(message: Dict[str, Any], why: str, tool_results: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        c = message.get("constraints", {})
        w = message.get("evidence_window", message.get("window", {}))
        required = c.get("required_evidence_fields", [])
        decision = {
            "action": c.get("default_action_if_uncertain", "review"),
            "target": {"type": "ip", "value": w.get("src_ip")},
            "ttl_sec": 0,
            "confidence": 0.0,
            "risk_score": 0,
            "labels": ["fallback"],
            "reasons": [why][:3],
            "strategy": build_strategy(c.get("default_action_if_uncertain", "review"), message.get("hints", {}), c, ttl_sec=0, message=message),
            "evidence": {k: w.get(k) for k in required},
        }
        if tool_results:
            decision["tool_result"] = tool_results[-1]["result"]
        return decision
