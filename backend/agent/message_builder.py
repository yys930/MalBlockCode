# backend/agent/message_builder.py
import copy
import ipaddress
from typing import Any, Dict, List, Tuple

from agent.policy import (
    NOISE_SIGNATURE_KEYWORDS,
    STRONG_SUSPICIOUS_KEYWORDS,
    MEDIUM_SUSPICIOUS_KEYWORDS,
    get_constraints,
)

MAX_LLM_DEST_PORTS = 12
MAX_LLM_TOP_CATEGORIES = 2
MAX_LLM_TOP_DEST_PORT_COUNTS = 5


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


def classify_attack_family(
    top_signatures: List[Dict[str, Any]],
    top_categories: List[Dict[str, Any]] | None = None,
) -> str:
    joined = " | ".join(str(item.get("signature", "")).lower() for item in top_signatures or [])
    categories_joined = " | ".join(str(item.get("category", "")).lower() for item in (top_categories or []))
    text = f"{joined} | {categories_joined}"

    if any(k in text for k in ["hulk", "slowloris", "slowhttptest", "goldeneye", "heartbleed", "dos", "ddos", "flood"]):
        return "dos"
    if any(k in text for k in ["portscan", "port scan", "scan ", "scan|", "nmap", "recon"]):
        return "scan"
    if any(k in text for k in ["ftp-patator", "ssh-patator", "brute force", "ftp login", "ssh login", "credential"]):
        return "brute-force"
    if any(k in text for k in ["sql injection", "xss", "web attack", "http exploit", "web-attack"]):
        return "web-attack"
    if any(k in text for k in ["bot", "trojan", "malware", "c2", "command and control", "infiltration"]):
        return "botnet"
    if any(k in text for k in [".pw domain", ".top domain", ".to domain", ".biz", "suspicious domain", "likely hostile", "dns query"]):
        return "suspicious-dns"
    if any(k in text for k in ["session traversal utilities for nat", "stun binding request", "discord domain", "*.tw domain", "adult site"]):
        return "suspicious-web"
    if any(k in text for k in ["wrong seq wrong ack", "bad window update", "closewait fin out of window", "excessive retransmissions", "invalid ack", "wrong direction first data"]):
        return "tcp-anomaly"
    if any(k in text for k in ["apt user-agent outbound", "package management", "ubuntu apt", "debian apt"]):
        return "benign-software"
    return "unknown"


def dominant_category(top_categories: List[Dict[str, Any]]) -> str | None:
    if not top_categories:
        return None
    category = top_categories[0].get("category")
    return str(category) if category else None


def compact_dest_ports(window: Dict[str, Any]) -> List[int]:
    dest_ports = [int(p) for p in (window.get("dest_ports", []) or []) if isinstance(p, int) or str(p).isdigit()]
    if len(dest_ports) <= MAX_LLM_DEST_PORTS:
        return sorted(dest_ports)

    top_port_counts = window.get("top_dest_port_counts", []) or []
    ranked_ports = [int(item.get("dest_port")) for item in top_port_counts if str(item.get("dest_port", "")).isdigit()]
    well_known = sorted([p for p in dest_ports if p <= 1024])

    compacted: List[int] = []
    seen = set()
    for port in well_known + ranked_ports:
        if port not in seen:
            compacted.append(port)
            seen.add(port)
        if len(compacted) >= MAX_LLM_DEST_PORTS:
            break
    return compacted


def compact_window(window: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "src_ip": window.get("src_ip"),
        "window_sec": window.get("window_sec"),
        "window_start_epoch": window.get("window_start_epoch"),
        "window_end_epoch": window.get("window_end_epoch"),
        "window_start_iso": window.get("window_start_iso"),
        "window_end_iso": window.get("window_end_iso"),
        "hits": window.get("hits"),
        "severity_min": window.get("severity_min"),
        "alert_density_per_sec": window.get("alert_density_per_sec"),
        "burst_duration_sec": window.get("burst_duration_sec"),
        "unique_dest_ip_count": window.get("unique_dest_ip_count"),
        "unique_dest_port_count": window.get("unique_dest_port_count"),
        "signature_diversity": window.get("signature_diversity"),
        "dominant_proto": window.get("dominant_proto"),
        "top_signatures": window.get("top_signatures", []),
        "top_categories": (window.get("top_categories", []) or [])[:MAX_LLM_TOP_CATEGORIES],
        "dest_ports": compact_dest_ports(window),
        "top_dest_port_counts": (window.get("top_dest_port_counts", []) or [])[:MAX_LLM_TOP_DEST_PORT_COUNTS],
        "top_dest_ips": window.get("top_dest_ips", []),
    }

def build_hints(window: Dict[str, Any]) -> Dict[str, Any]:
    """
    hints：从 window 计算出来的二次特征
    """
    src_ip = str(window.get("src_ip", ""))
    dest_ports = window.get("dest_ports", []) or []
    top_sigs = window.get("top_signatures", []) or []
    top_dest_ips = window.get("top_dest_ips", []) or []
    top_categories = window.get("top_categories", []) or []
    top_dest_port_counts = window.get("top_dest_port_counts", []) or []

    total_sig_hits, noise_hits, noise_ratio, has_strong, has_medium, has_noise = signature_stats(top_sigs)

    burst_seconds = window.get("burst_duration_sec")
    if burst_seconds is None:
        first_epoch = window.get("window_start_epoch")
        last_epoch = window.get("window_end_epoch")
        if isinstance(first_epoch, int) and isinstance(last_epoch, int) and last_epoch >= first_epoch:
            burst_seconds = last_epoch - first_epoch

    attack_family = classify_attack_family(top_sigs, top_categories)
    top_signature = top_sigs[0].get("signature") if top_sigs else None
    top_dest_port = top_dest_port_counts[0].get("dest_port") if top_dest_port_counts else None
    category_hint = dominant_category(top_categories)

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
        "dominant_category": category_hint,
        "hits": window.get("hits"),
        "severity_min": window.get("severity_min"),
        "alert_density_per_sec": window.get("alert_density_per_sec"),
        "unique_dest_ip_count": window.get("unique_dest_ip_count"),
        "unique_dest_port_count": window.get("unique_dest_port_count"),
        "signature_diversity": window.get("signature_diversity"),
        "dominant_proto": window.get("dominant_proto"),
        "top_signature": top_signature,
        "top_dest_port": top_dest_port,
        "signature_count": len(top_sigs),
        "top_dest_ip": (top_dest_ips[0].get("dest_ip") if top_dest_ips else None),
        "burst_seconds": burst_seconds,
    }

def build_message(window: Dict[str, Any], retrieved_evidence: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """
    message = {task, constraints, hints, window}
    你会把这个 JSON 作为 user message content 给 LLM
    """
    llm_window = copy.deepcopy(window)
    csv_features = llm_window.get("csv_features")
    if isinstance(csv_features, dict):
        csv_features.pop("label_is_malicious", None)
    compacted_window = compact_window(llm_window)
    return {
        "task": "decide_mitigation",
        "constraints": get_constraints(),
        "hints": build_hints(llm_window),
        "window": compacted_window,
        "evidence_window": llm_window,
        "retrieved_evidence": retrieved_evidence or [],
    }
