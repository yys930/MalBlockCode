# backend/agent/message_builder.py
import ipaddress
from typing import Any, Dict, List, Tuple

from agent.policy import (
    NOISE_SIGNATURE_KEYWORDS,
    STRONG_SUSPICIOUS_KEYWORDS,
    MEDIUM_SUSPICIOUS_KEYWORDS,
    get_constraints,
)

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


def classify_attack_family(top_signatures: List[Dict[str, Any]]) -> str:
    joined = " | ".join(str(item.get("signature", "")).lower() for item in top_signatures or [])

    if any(k in joined for k in ["scan", "portscan", "port scan"]):
        return "portscan"
    if any(k in joined for k in ["dos", "ddos", "flood"]):
        return "dos"
    if any(k in joined for k in ["bot", "trojan", "malware", "c2", "command and control"]):
        return "botnet"
    if any(k in joined for k in ["sql injection", "xss", "web attack", "http exploit"]):
        return "web-attack"
    if any(k in joined for k in ["brute force", "ssh", "ftp login"]):
        return "brute-force"
    return "unknown"

def build_hints(window: Dict[str, Any]) -> Dict[str, Any]:
    """
    hints：从 window 计算出来的二次特征
    """
    src_ip = str(window.get("src_ip", ""))
    dest_ports = window.get("dest_ports", []) or []
    top_sigs = window.get("top_signatures", []) or []
    top_dest_ips = window.get("top_dest_ips", []) or []

    total_sig_hits, noise_hits, noise_ratio, has_strong, has_medium, has_noise = signature_stats(top_sigs)

    first_epoch = window.get("window_start_epoch")
    last_epoch = window.get("window_end_epoch")
    burst_seconds = None
    if isinstance(first_epoch, int) and isinstance(last_epoch, int) and last_epoch >= first_epoch:
        burst_seconds = last_epoch - first_epoch

    attack_family = classify_attack_family(top_sigs)
    top_signature = top_sigs[0].get("signature") if top_sigs else None

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
        "attack_family": attack_family,
        "hits": window.get("hits"),
        "severity_min": window.get("severity_min"),
        "top_signature": top_signature,
        "signature_count": len(top_sigs),
        "top_dest_ip": (top_dest_ips[0].get("dest_ip") if top_dest_ips else None),
        "burst_seconds": burst_seconds,
    }

def build_message(window: Dict[str, Any], retrieved_evidence: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """
    message = {task, constraints, hints, window}
    你会把这个 JSON 作为 user message content 给 LLM
    """
    return {
        "task": "decide_mitigation",
        "constraints": get_constraints(),
        "hints": build_hints(window),
        "window": window,
        "retrieved_evidence": retrieved_evidence or [],
    }
