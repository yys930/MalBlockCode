# backend/agent/policy.py
from typing import Dict, Any, List, Optional

# 1) 噪声与强可疑关键词：你可随时扩展
NOISE_SIGNATURE_KEYWORDS: List[str] = [
    "invalid checksum",
    "invalid ack",
    "unable to match response to request",
    "request header invalid",
]

STRONG_SUSPICIOUS_KEYWORDS: List[str] = [
    "likely hostile",
    "often malware related",
]

MEDIUM_SUSPICIOUS_KEYWORDS: List[str] = [
    "dns query for .to",
    "observed dns query to .biz",
]


def get_constraints() -> Dict[str, Any]:
    """
    constraints：系统安全策略（不是从数据“获得”，是你制定的规则）
    """
    return {
        "allowed_actions": ["block", "observe", "ignore", "review"],
        "default_action_if_uncertain": "review",
        "require_json_only": True,
        "max_ttl_sec": 86400,               # 24h
        "min_ttl_sec_if_block": 300,         # 5min
        "prefer_not_block_on_noise_only": True,
        "high_noise_threshold": 0.8,
        # 关键基础设施/白名单：你可继续加
        "never_block_ips": [
            "192.168.10.3",   # 内网 DNS（示例：来自你的数据）
            "192.168.71.1",   # VMware 网关（示例）
            "127.0.0.1",
        ],
        # 可选：如果你不希望自动封内网主机，可设 True
        "never_block_private_src": False,
        # 需要 LLM 必须引用的证据字段（用于可解释性）
        "required_evidence_fields": [
            "src_ip",
            "window_start_iso",
            "window_end_iso",
            "hits",
            "severity_min",
            "top_signatures",
            "dest_ports",
            "top_dest_ips",
        ],
    }


def recommend_block_ttl(hints: Dict[str, Any], constraints: Dict[str, Any]) -> int:
    min_ttl = int(constraints.get("min_ttl_sec_if_block", 300))
    max_ttl = int(constraints.get("max_ttl_sec", 86400))

    hits = int(hints.get("hits") or 0)
    severity_min = hints.get("severity_min")
    severity_min = 99 if severity_min is None else int(severity_min)

    ttl = min_ttl
    if hits >= 20:
        ttl = max(ttl, 3600)
    elif hits >= 10:
        ttl = max(ttl, 1800)
    elif hits >= 5:
        ttl = max(ttl, 900)

    if severity_min <= 1:
        ttl = max(ttl, 3600)
    elif severity_min == 2:
        ttl = max(ttl, 1800)

    return min(ttl, max_ttl)


def precheck_action(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    constraints = message.get("constraints", {})
    hints = message.get("hints", {})
    window = message.get("window", {})

    src_ip = window.get("src_ip")
    default_action = constraints.get("default_action_if_uncertain", "review")
    required = constraints.get("required_evidence_fields", [])

    def build_decision(action: str, reason: str, labels: List[str]) -> Dict[str, Any]:
        return {
            "action": action,
            "target": {"type": "ip", "value": src_ip},
            "ttl_sec": 0 if action != "block" else recommend_block_ttl(hints, constraints),
            "confidence": 0.99 if action in {"ignore", "observe"} else 0.0,
            "risk_score": 0 if action == "ignore" else 20,
            "labels": labels,
            "reasons": [reason],
            "evidence": {k: window.get(k) for k in required},
        }

    if not hints.get("src_ip_valid", False):
        return build_decision(default_action, "src_ip invalid, skip autonomous action", ["precheck", "invalid-ip"])

    if hints.get("noise_only"):
        return build_decision("ignore", "noise_only=true, suppress automatic blocking", ["precheck", "noise-only"])

    noise_threshold = float(constraints.get("high_noise_threshold", 0.8))
    if float(hints.get("noise_ratio") or 0.0) >= noise_threshold and not hints.get("has_strong_suspicious"):
        return build_decision("observe", "high noise ratio without strong suspicious evidence", ["precheck", "high-noise"])

    if src_ip in set(constraints.get("never_block_ips", [])):
        return build_decision("observe", "src_ip is protected by never_block_ips", ["precheck", "protected-ip"])

    if constraints.get("never_block_private_src") and hints.get("src_ip_private"):
        return build_decision("observe", "private source IP excluded by policy", ["precheck", "private-src"])

    return None
