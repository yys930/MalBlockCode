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

    never_block = set(constraints.get("never_block_ips", []))
    if action == "block" and ip in never_block:
        return False, f"attempt to block never_block_ips: {ip}"

    # evidence fields
    evidence = dec.get("evidence")
    if not isinstance(evidence, dict):
        return False, "evidence must be object"
    required = set(constraints.get("required_evidence_fields", []))
    missing = [k for k in required if k not in evidence]
    if missing:
        return False, f"missing evidence fields: {missing}"

    # reasons
    reasons = dec.get("reasons", [])
    if not isinstance(reasons, list) or len(reasons) == 0 or len(reasons) > 3:
        return False, "reasons must be list (1~3 items)"

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

    return True, None