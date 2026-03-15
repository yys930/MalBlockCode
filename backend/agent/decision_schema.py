# backend/agent/decision_schema.py
import ipaddress
from typing import Any, Dict, Tuple, Optional


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def parse_json_only(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not (text.startswith("{") and text.endswith("}")):
        raise ValueError("LLM output is not JSON-only")
    import json
    return json.loads(text)


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def _is_signature_list(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    for item in value:
        if not isinstance(item, dict):
            return False
        if not isinstance(item.get("signature"), str) or not str(item.get("signature")).strip():
            return False
        try:
            int(item.get("count"))
        except Exception:
            return False
    return True


def _is_dest_ip_list(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    for item in value:
        if not isinstance(item, dict):
            return False
        if not isinstance(item.get("dest_ip"), str) or not str(item.get("dest_ip")).strip():
            return False
        try:
            int(item.get("count"))
        except Exception:
            return False
    return True


def _is_port_list(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    for item in value:
        try:
            int(item)
        except Exception:
            return False
    return True


def validate_decision(dec: Dict[str, Any], constraints: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    allowed_actions = set(constraints.get("allowed_actions", []))
    action = dec.get("action")
    if action not in allowed_actions:
        return False, f"invalid action: {action}"

    tgt = dec.get("target", {})
    if tgt.get("type") != "ip":
        return False, "target.type must be ip"
    ip = tgt.get("value")
    if not isinstance(ip, str) or not _valid_ip(ip):
        return False, f"invalid target ip: {ip}"

    max_ttl = int(constraints.get("max_ttl_sec", 0))
    min_ttl = int(constraints.get("min_ttl_sec_if_block", 0))
    ttl = dec.get("ttl_sec", 0)
    try:
        ttl = int(ttl)
    except Exception:
        return False, "ttl_sec must be int"
    if ttl < 0 or ttl > max_ttl:
        return False, f"ttl out of range: {ttl}"
    if action == "block" and ttl < min_ttl:
        return False, f"ttl too small for block: {ttl} < {min_ttl}"
    if action != "block" and ttl != 0:
        return False, f"ttl_sec must be 0 when action={action}"

    never_block = set(constraints.get("never_block_ips", []))
    if action == "block" and ip in never_block:
        return False, f"attempt to block never_block_ips: {ip}"

    labels = dec.get("labels", [])
    if not isinstance(labels, list) or len(labels) == 0:
        return False, "labels must be non-empty list"
    if any(not isinstance(item, str) or not item.strip() for item in labels):
        return False, "labels must contain non-empty strings"

    # evidence fields
    evidence = dec.get("evidence")
    if not isinstance(evidence, dict):
        return False, "evidence must be object"
    required = set(constraints.get("required_evidence_fields", []))
    missing = [k for k in required if k not in evidence]
    if missing:
        return False, f"missing evidence fields: {missing}"
    if "src_ip" in evidence and evidence.get("src_ip") != ip:
        return False, "evidence.src_ip must match target.value"
    if "top_signatures" in evidence and not _is_signature_list(evidence.get("top_signatures")):
        return False, "evidence.top_signatures must be [{'signature', 'count'} ...]"
    if "top_dest_ips" in evidence and not _is_dest_ip_list(evidence.get("top_dest_ips")):
        return False, "evidence.top_dest_ips must be [{'dest_ip', 'count'} ...]"
    if "dest_ports" in evidence and not _is_port_list(evidence.get("dest_ports")):
        return False, "evidence.dest_ports must be [int, ...]"
    if "window_start_iso" in evidence and not isinstance(evidence.get("window_start_iso"), str):
        return False, "evidence.window_start_iso must be string"
    if "window_end_iso" in evidence and not isinstance(evidence.get("window_end_iso"), str):
        return False, "evidence.window_end_iso must be string"
    if "hits" in evidence:
        try:
            int(evidence.get("hits"))
        except Exception:
            return False, "evidence.hits must be int"
    if "severity_min" in evidence and evidence.get("severity_min") is not None:
        try:
            int(evidence.get("severity_min"))
        except Exception:
            return False, "evidence.severity_min must be int|null"

    # reasons
    reasons = dec.get("reasons", [])
    if not isinstance(reasons, list) or len(reasons) == 0 or len(reasons) > 3:
        return False, "reasons must be list (1~3 items)"
    if any(not isinstance(item, str) or not item.strip() for item in reasons):
        return False, "reasons must contain non-empty strings"

    # confidence/risk_score basic
    conf = dec.get("confidence", 0.0)
    try:
        conf = float(conf)
    except Exception:
        return False, "confidence must be float"
    if conf < 0.0 or conf > 1.0:
        return False, "confidence out of range"

    score = dec.get("risk_score", 0)
    try:
        score = int(score)
    except Exception:
        return False, "risk_score must be int"
    if score < 0 or score > 100:
        return False, "risk_score out of range"

    strategy = dec.get("strategy")
    if not isinstance(strategy, dict):
        return False, "strategy must be object"

    block_scope = strategy.get("block_scope")
    if block_scope not in set(constraints.get("allowed_block_scopes", [])):
        return False, f"invalid strategy.block_scope: {block_scope}"

    duration_tier = strategy.get("duration_tier")
    if duration_tier not in set(constraints.get("allowed_duration_tiers", [])):
        return False, f"invalid strategy.duration_tier: {duration_tier}"

    priority = strategy.get("priority")
    if priority not in set(constraints.get("allowed_priorities", [])):
        return False, f"invalid strategy.priority: {priority}"

    follow_up = strategy.get("follow_up")
    if follow_up not in set(constraints.get("allowed_followups", [])):
        return False, f"invalid strategy.follow_up: {follow_up}"

    execution_mode = strategy.get("execution_mode")
    if execution_mode not in set(constraints.get("allowed_execution_modes", [])):
        return False, f"invalid strategy.execution_mode: {execution_mode}"

    template_id = strategy.get("template_id")
    if template_id is not None and (not isinstance(template_id, str) or not template_id.strip()):
        return False, "strategy.template_id must be non-empty string when provided"

    escalation_level = strategy.get("escalation_level")
    if escalation_level is not None:
        try:
            escalation_level = int(escalation_level)
        except Exception:
            return False, "strategy.escalation_level must be int when provided"
        if escalation_level < 0 or escalation_level > 3:
            return False, "strategy.escalation_level out of range"

    if action == "block":
        if block_scope != "src_ip":
            return False, "block action requires strategy.block_scope=src_ip"
        if duration_tier == "none":
            return False, "block action requires non-none duration_tier"
        if execution_mode not in {"drop", "rate_limit"}:
            return False, "block action requires execution_mode in {drop, rate_limit}"
    elif action == "monitor":
        if block_scope != "none":
            return False, f"monitor action requires strategy.block_scope=none, got {block_scope}"
        if duration_tier != "none":
            return False, f"monitor action requires strategy.duration_tier=none, got {duration_tier}"
        if execution_mode != "watch":
            return False, "monitor action requires execution_mode=watch"
    else:
        if block_scope != "none":
            return False, f"non-block action requires strategy.block_scope=none, got {block_scope}"
        if duration_tier != "none":
            return False, f"non-block action requires strategy.duration_tier=none, got {duration_tier}"
        if execution_mode != "none":
            return False, f"{action} action requires execution_mode=none"

    tool_result = dec.get("tool_result")
    if tool_result is not None and not isinstance(tool_result, dict):
        return False, "tool_result must be object when provided"

    return True, None
