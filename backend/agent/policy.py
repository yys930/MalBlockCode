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
    "command and control",
    "trojan",
    "botnet",
    ".pw domain",
]

MEDIUM_SUSPICIOUS_KEYWORDS: List[str] = [
    "dns query for .to",
    "observed dns query to .biz",
    "session traversal utilities for nat",
    "stun binding request",
    "*.tw domain",
    "discord domain",
    "adult site",
]

ATTACK_STRATEGY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "dos": {
        "template_id": "dos_containment",
        "base_action": "block",
        "base_execution_mode": "drop",
        "base_ttl_sec": 7200,
        "priority": "critical",
        "follow_up": "raise_alert",
    },
    "brute-force": {
        "template_id": "credential_abuse_control",
        "base_action": "block",
        "base_execution_mode": "drop",
        "base_ttl_sec": 3600,
        "priority": "high",
        "follow_up": "track_recurrence",
    },
    "scan": {
        "template_id": "recon_escalation",
        "base_action": "monitor",
        "base_execution_mode": "watch",
        "base_ttl_sec": 1800,
        "priority": "high",
        "follow_up": "collect_more_windows",
    },
    "suspicious-dns": {
        "template_id": "dns_abuse_watch",
        "base_action": "block",
        "base_execution_mode": "rate_limit",
        "base_ttl_sec": 3600,
        "priority": "high",
        "follow_up": "track_recurrence",
    },
    "botnet": {
        "template_id": "botnet_containment",
        "base_action": "block",
        "base_execution_mode": "drop",
        "base_ttl_sec": 7200,
        "priority": "critical",
        "follow_up": "raise_alert",
    },
    "web-attack": {
        "template_id": "web_attack_block",
        "base_action": "block",
        "base_execution_mode": "drop",
        "base_ttl_sec": 3600,
        "priority": "high",
        "follow_up": "raise_alert",
    },
    "suspicious-web": {
        "template_id": "suspicious_web_escalation",
        "base_action": "monitor",
        "base_execution_mode": "watch",
        "base_ttl_sec": 1800,
        "priority": "high",
        "follow_up": "track_recurrence",
    },
    "tcp-anomaly": {
        "template_id": "tcp_anomaly_containment",
        "base_action": "monitor",
        "base_execution_mode": "watch",
        "base_ttl_sec": 1800,
        "priority": "high",
        "follow_up": "track_recurrence",
    },
    "benign-software": {
        "template_id": "benign_software_allow",
        "base_action": "allow",
        "base_execution_mode": "none",
        "base_ttl_sec": 0,
        "priority": "low",
        "follow_up": "none",
    },
    "unknown": {
        "template_id": "generic_triage",
        "base_action": "review",
        "base_execution_mode": "none",
        "base_ttl_sec": 900,
        "priority": "medium",
        "follow_up": "manual_review",
    },
}


def get_constraints() -> Dict[str, Any]:
    """
    constraints：系统安全策略（不是从数据“获得”，是你制定的规则）
    """
    return {
        "allowed_actions": ["block", "monitor", "allow", "review"],
        "default_action_if_uncertain": "review",
        "require_json_only": True,
        "max_ttl_sec": 86400,               # 24h
        "min_ttl_sec_if_block": 300,         # 5min
        "prefer_not_block_on_noise_only": True,
        "high_noise_threshold": 0.8,
        "allowed_priorities": ["low", "medium", "high", "critical"],
        "allowed_duration_tiers": ["none", "short", "medium", "long"],
        "allowed_followups": ["none", "collect_more_windows", "track_recurrence", "manual_review", "raise_alert"],
        "allowed_block_scopes": ["none", "src_ip"],
        "allowed_execution_modes": ["none", "drop", "rate_limit", "watch"],
        # 关键基础设施/白名单：你可继续加
        "never_block_ips": [
            "127.0.0.1",
            "192.168.71.1",   # VMware 网关
            # "192.168.10.1",   # 内网 DNS
            # "192.168.10.3",   # AD/DNS/LDAP/Kerberos/SMB 基础设施主机
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


def ttl_to_duration_tier(ttl_sec: int) -> str:
    ttl_sec = int(ttl_sec or 0)
    if ttl_sec <= 0:
        return "none"
    if ttl_sec < 1800:
        return "short"
    if ttl_sec < 7200:
        return "medium"
    return "long"


def get_strategy_template(hints: Dict[str, Any]) -> Dict[str, Any]:
    attack_family = str(hints.get("attack_family") or "unknown")
    return dict(ATTACK_STRATEGY_TEMPLATES.get(attack_family, ATTACK_STRATEGY_TEMPLATES["unknown"]))


def decision_context(message: Dict[str, Any]) -> Dict[str, Any]:
    ctx = message.get("decision_context", {})
    return ctx if isinstance(ctx, dict) else {}


def escalation_level(message: Dict[str, Any], hints: Dict[str, Any]) -> int:
    ctx = decision_context(message)
    seen_before = int(ctx.get("src_ip_window_count_before") or 0)
    prior_block_count = int(ctx.get("prior_block_count") or 0)
    prior_monitor_count = int(ctx.get("prior_monitor_count") or 0)
    historical_block_count = int(ctx.get("retrieved_block_count") or 0)
    high_risk_now = int(hints.get("hits") or 0) >= 20 or int(hints.get("severity_min") or 99) <= 2
    level = 0
    if seen_before >= 1:
        level += 1
    if seen_before >= 3 or prior_monitor_count >= 2:
        level += 1
    if prior_block_count >= 1 or historical_block_count >= 1:
        level += 1
    if high_risk_now:
        level += 1
    return min(level, 3)


def derive_priority(action: str, hints: Dict[str, Any], template: Dict[str, Any], escalation: int) -> str:
    risk_inputs = [
        int(hints.get("hits") or 0) >= 20,
        int(hints.get("severity_min") or 99) <= 2,
        bool(hints.get("has_strong_suspicious")),
    ]
    score = sum(1 for item in risk_inputs if item)
    template_priority = str(template.get("priority") or "medium")
    levels = ["low", "medium", "high", "critical"]
    base_idx = levels.index(template_priority) if template_priority in levels else 1
    score = max(score, base_idx)
    score = min(score + escalation, len(levels) - 1)
    if action == "review":
        return levels[max(1, min(score, 2))]
    if action == "allow":
        return "low"
    return levels[score]


def derive_follow_up(action: str, template: Dict[str, Any], escalation: int) -> str:
    if action == "block":
        return "raise_alert" if escalation >= 2 else "track_recurrence"
    if action == "monitor":
        return "track_recurrence" if escalation >= 2 else str(template.get("follow_up") or "collect_more_windows")
    if action == "review":
        return "manual_review"
    return "none"


def choose_action(message: Dict[str, Any], hints: Dict[str, Any]) -> str:
    template = get_strategy_template(hints)
    escalation = escalation_level(message, hints)
    attack_family = str(hints.get("attack_family") or "unknown")
    base_action = str(template.get("base_action") or "review")
    hits = int(hints.get("hits") or 0)
    severity_min = int(hints.get("severity_min") or 99)
    high_risk = hits >= 20 or severity_min <= 2 or bool(hints.get("has_strong_suspicious"))

    if attack_family == "benign-software":
        return "monitor" if escalation >= 2 and high_risk else "allow"
    if attack_family in {"botnet", "web-attack", "brute-force", "dos"}:
        return "block"
    if attack_family in {"suspicious-dns", "tcp-anomaly", "suspicious-web", "scan"}:
        if high_risk or escalation >= 1:
            return "block"
        return "monitor"

    if base_action == "monitor" and escalation >= 2 and bool(hints.get("has_strong_suspicious")):
        return "block"
    if base_action == "review" and escalation >= 2 and (int(hints.get("hits") or 0) >= 10):
        return "monitor"
    if base_action == "allow" and escalation >= 1:
        return "monitor"
    return base_action


def choose_execution_mode(action: str, hints: Dict[str, Any], message: Dict[str, Any]) -> str:
    template = get_strategy_template(hints)
    escalation = escalation_level(message, hints)
    base_mode = str(template.get("base_execution_mode") or "none")
    attack_family = str(hints.get("attack_family") or "unknown")

    if action in {"allow", "review"}:
        return "none"
    if action == "monitor":
        return "watch"
    if action != "block":
        return "none"
    if attack_family in {"dos", "brute-force", "botnet", "web-attack"}:
        return "drop"
    if attack_family in {"scan", "suspicious-dns", "suspicious-web", "tcp-anomaly"}:
        return "drop" if escalation >= 2 and bool(hints.get("has_strong_suspicious")) else "rate_limit"
    return "drop" if base_mode == "drop" else "rate_limit"


def build_strategy(action: str, hints: Dict[str, Any], constraints: Dict[str, Any], ttl_sec: int | None = None, message: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    template = get_strategy_template(hints)
    escalation = escalation_level(message or {}, hints)
    ttl = int(ttl_sec if ttl_sec is not None else (recommend_block_ttl(hints, constraints) if action == "block" else 0))
    return {
        "block_scope": "src_ip" if action == "block" else "none",
        "duration_tier": ttl_to_duration_tier(ttl),
        "priority": derive_priority(action, hints, template, escalation),
        "follow_up": derive_follow_up(action, template, escalation),
        "execution_mode": choose_execution_mode(action, hints, message or {}),
        "template_id": str(template.get("template_id") or "generic_triage"),
        "escalation_level": escalation,
    }


def recommend_block_ttl(hints: Dict[str, Any], constraints: Dict[str, Any], message: Optional[Dict[str, Any]] = None) -> int:
    min_ttl = int(constraints.get("min_ttl_sec_if_block", 300))
    max_ttl = int(constraints.get("max_ttl_sec", 86400))

    hits = int(hints.get("hits") or 0)
    severity_min = hints.get("severity_min")
    severity_min = 99 if severity_min is None else int(severity_min)
    attack_family = str(hints.get("attack_family") or "unknown")
    density = float(hints.get("alert_density_per_sec") or 0.0)
    unique_dest_ip_count = int(hints.get("unique_dest_ip_count") or 0)
    signature_diversity = int(hints.get("signature_diversity") or 0)
    template = get_strategy_template(hints)
    escalation = escalation_level(message or {}, hints)

    ttl = max(min_ttl, int(template.get("base_ttl_sec") or min_ttl))
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

    if attack_family in {"brute-force", "dos", "botnet"}:
        ttl = max(ttl, 7200)
    elif attack_family in {"web-attack"}:
        ttl = max(ttl, 3600)
    elif attack_family in {"scan", "suspicious-dns", "suspicious-web", "tcp-anomaly"}:
        ttl = max(ttl, 1800)

    if density >= 1.0:
        ttl = max(ttl, 3600)
    if unique_dest_ip_count >= 10 or signature_diversity >= 4:
        ttl = max(ttl, 1800)
    if escalation >= 1:
        ttl = max(ttl, min(max_ttl, int(ttl * 1.5)))
    if escalation >= 2:
        ttl = max(ttl, min(max_ttl, int(ttl * 2.0)))

    return min(ttl, max_ttl)


def precheck_action(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    constraints = message.get("constraints", {})
    hints = message.get("hints", {})
    window = message.get("evidence_window", message.get("window", {}))

    src_ip = window.get("src_ip")
    default_action = constraints.get("default_action_if_uncertain", "review")
    required = constraints.get("required_evidence_fields", [])

    def build_decision(action: str, reason: str, labels: List[str]) -> Dict[str, Any]:
        ttl_sec = 0 if action != "block" else recommend_block_ttl(hints, constraints, message=message)
        return {
            "action": action,
            "target": {"type": "ip", "value": src_ip},
            "ttl_sec": ttl_sec,
            "confidence": 0.99 if action in {"allow", "monitor"} else 0.0,
            "risk_score": 0 if action == "allow" else 20,
            "labels": labels,
            "reasons": [reason],
            "evidence": {k: window.get(k) for k in required},
            "strategy": build_strategy(action, hints, constraints, ttl_sec=ttl_sec, message=message),
        }

    if not hints.get("src_ip_valid", False):
        return build_decision(default_action, "src_ip invalid, skip autonomous action", ["precheck", "invalid-ip"])

    if hints.get("noise_only"):
        return build_decision("allow", "noise_only=true, suppress automatic blocking", ["precheck", "noise-only"])

    noise_threshold = float(constraints.get("high_noise_threshold", 0.8))
    if float(hints.get("noise_ratio") or 0.0) >= noise_threshold and not hints.get("has_strong_suspicious"):
        return build_decision("monitor", "high noise ratio without strong suspicious evidence", ["precheck", "high-noise"])

    if src_ip in set(constraints.get("never_block_ips", [])):
        return build_decision("monitor", "src_ip is protected by never_block_ips", ["precheck", "protected-ip"])

    if constraints.get("never_block_private_src") and hints.get("src_ip_private"):
        return build_decision("monitor", "private source IP excluded by policy", ["precheck", "private-src"])

    preferred_action = choose_action(message, hints)
    if preferred_action == "block" and not hints.get("has_strong_suspicious") and float(hints.get("noise_ratio") or 0.0) >= 0.4:
        return build_decision("monitor", "template suggested escalation but evidence remains mixed", ["precheck", "mixed-evidence"])

    return None
