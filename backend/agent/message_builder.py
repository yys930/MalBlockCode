# backend/agent/message_builder.py
import ipaddress
from typing import Any, Dict, List, Tuple

# 1) 噪声与强可疑关键词：你可随时扩展
NOISE_SIGNATURE_KEYWORDS = [
    "invalid checksum",
    "invalid ack",
    "unable to match response to request",
    "request header invalid",
]

STRONG_SUSPICIOUS_KEYWORDS = [
    "likely hostile",
    "often malware related",
]

MEDIUM_SUSPICIOUS_KEYWORDS = [
    "dns query for .to",
    "observed dns query to .biz",
]

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def signature_stats(top_signatures: List[Dict[str, Any]]) -> Tuple[int, int, float, bool, bool, bool]:
    """
    返回：
    total_sig_hits, noise_hits, noise_ratio,
    has_strong, has_medium, has_noise_keyword
    """
    total = 0
    noise = 0
    has_strong = False
    has_medium = False
    has_noise = False

    for item in top_signatures or []:
        sig = str(item.get("signature", ""))
        cnt = int(item.get("count", 0))
        total += cnt
        sig_lower = sig.lower()

        if any(k in sig_lower for k in NOISE_SIGNATURE_KEYWORDS):
            noise += cnt
            has_noise = True

        if any(k in sig_lower for k in STRONG_SUSPICIOUS_KEYWORDS):
            has_strong = True

        if any(k in sig_lower for k in MEDIUM_SUSPICIOUS_KEYWORDS):
            has_medium = True

    noise_ratio = (noise / total) if total > 0 else 0.0
    return total, noise, noise_ratio, has_strong, has_medium, has_noise

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

def build_hints(window: Dict[str, Any]) -> Dict[str, Any]:
    """
    hints：从 window 计算出来的二次特征
    """
    src_ip = str(window.get("src_ip", ""))
    dest_ports = window.get("dest_ports", []) or []
    top_sigs = window.get("top_signatures", []) or []
    top_dest_ips = window.get("top_dest_ips", []) or []

    total_sig_hits, noise_hits, noise_ratio, has_strong, has_medium, has_noise = signature_stats(top_sigs)

    # 简单 burst 估计：你目前 first/last 是 ISO，无 epoch，先不算（后续可从 eve.json enrich）
    burst_seconds = None

    return {
        "src_ip_valid": is_valid_ip(src_ip),
        "src_ip_private": is_private_ip(src_ip),
        "dns_port_present": 53 in dest_ports,
        "http_port_present": (80 in dest_ports) or (443 in dest_ports),
        "noise_ratio": round(noise_ratio, 4),
        "noise_only": (total_sig_hits > 0 and noise_hits == total_sig_hits),
        "has_noise_keyword": has_noise,
        "has_strong_suspicious": has_strong,
        "has_medium_suspicious": has_medium,
        "hits": window.get("hits"),
        "severity_min": window.get("severity_min"),
        "top_dest_ip": (top_dest_ips[0].get("dest_ip") if top_dest_ips else None),
        "burst_seconds": burst_seconds,
    }

def build_message(window: Dict[str, Any]) -> Dict[str, Any]:
    """
    message = {task, constraints, hints, window}
    你会把这个 JSON 作为 user message content 给 LLM
    """
    return {
        "task": "decide_mitigation",
        "constraints": get_constraints(),
        "hints": build_hints(window),
        "window": window,
    }