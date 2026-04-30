from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from agent.decision_schema import validate_decision
from agent.policy import get_constraints
from agent.window_reader import iter_jsonl
from path_utils import resolve_project_path


CSV_EVAL_KEY = Tuple[str, str, int, str, Tuple[str, ...], Tuple[int, ...], str]
CSV_COMPACT_SOURCE = Tuple[str, str, str, str, str, str, bool]
CSV_COMPACT_DECISION = Tuple[str, str, bool, bool, str, str, str]
CSV_SOURCE_INDEX = Dict[CSV_EVAL_KEY, List[CSV_COMPACT_SOURCE]]
ACTION_STRENGTH = {
    ("allow", "none"): 0,
    ("review", "none"): 0,
    ("monitor", "watch"): 1,
    ("block", "rate_limit"): 2,
    ("block", "drop"): 3,
}
STRONG_FAMILY_KEYWORDS = (
    "likely hostile",
    "often malware related",
    "command and control",
    "trojan",
    "botnet",
    ".pw domain",
)
NOISE_SIGNATURE_KEYWORDS = (
    "invalid checksum",
    "invalid ack",
    "unable to match response to request",
    "request header invalid",
    "request line incomplete",
    "gzip decompression failed",
)
EXPERT_RULE_VERSION = "v2.0-thesis"
RISK_TIER_CRITERIA = {
    "high": "severity_min <= 2, hits >= 20, or repeat-offender style recurrence",
    "medium": "malicious or suspicious evidence that does not meet the high-risk threshold",
    "low": "protected-ip, noise-only, high-noise, benign-software, or similar conservative-handling cases",
}
RULE_CONSTRUCTION_PRINCIPLES = [
    "minimum_necessary_mitigation: avoid over-blocking when observation or rate-limit is sufficient",
    "high_risk_containment_first: destructive and confirmed attack families should prefer rapid containment",
    "progressive_escalation: reconnaissance and weak-signal anomalies should escalate with stronger evidence or recurrence",
    "safety_first_for_noise_and_protected_assets: protected infrastructure and noise-dominated evidence should default to conservative handling",
]


def _rule(
    *,
    allowed_actions: set[str],
    allowed_execution_modes: set[str],
    min_strength: int,
    max_strength: int,
    rationale: str,
    preferred_actions: set[str] | None = None,
    preferred_execution_modes: set[str] | None = None,
) -> Dict[str, Any]:
    return {
        "allowed_actions": set(allowed_actions),
        "allowed_execution_modes": set(allowed_execution_modes),
        "preferred_actions": set(preferred_actions or allowed_actions),
        "preferred_execution_modes": set(preferred_execution_modes or allowed_execution_modes),
        "min_strength": int(min_strength),
        "max_strength": int(max_strength),
        "rationale": rationale,
    }


EXPERT_RULES: Dict[str, Dict[str, Any]] = {
    "dos": {
        "label": "Denial of Service",
        "family_rationale": "DoS / DDoS flows are direct availability threats and usually benefit from prompt containment.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"block"}, allowed_execution_modes={"drop"}, preferred_actions={"block"}, preferred_execution_modes={"drop"}, min_strength=3, max_strength=3, rationale="High-risk DoS evidence should be immediately dropped to limit service disruption."),
            "medium": _rule(allowed_actions={"block"}, allowed_execution_modes={"drop"}, preferred_actions={"block"}, preferred_execution_modes={"drop"}, min_strength=3, max_strength=3, rationale="Even medium-risk DoS evidence remains an availability threat and should still prefer hard containment."),
            "low": _rule(allowed_actions={"monitor", "review"}, allowed_execution_modes={"watch", "none"}, preferred_actions={"monitor"}, preferred_execution_modes={"watch"}, min_strength=0, max_strength=1, rationale="When the evidence is noise-dominated or protected, DoS-like signatures should be handled conservatively."),
        },
    },
    "botnet": {
        "label": "Botnet / Malware Control",
        "family_rationale": "Botnet, C2, and infiltration behaviors represent sustained malicious control or payload delivery risk.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"block"}, allowed_execution_modes={"drop"}, preferred_actions={"block"}, preferred_execution_modes={"drop"}, min_strength=3, max_strength=3, rationale="High-risk botnet evidence should be rapidly dropped to interrupt control or payload channels."),
            "medium": _rule(allowed_actions={"block"}, allowed_execution_modes={"drop"}, preferred_actions={"block"}, preferred_execution_modes={"drop"}, min_strength=3, max_strength=3, rationale="Botnet-style evidence is high consequence even when medium confidence, so hard containment remains appropriate."),
            "low": _rule(allowed_actions={"monitor", "review"}, allowed_execution_modes={"watch", "none"}, preferred_actions={"monitor"}, preferred_execution_modes={"watch"}, min_strength=0, max_strength=1, rationale="Low-risk or protected botnet-like signals should be observed rather than immediately blocked."),
        },
    },
    "brute-force": {
        "label": "Credential Abuse / Brute Force",
        "family_rationale": "Credential attacks are active intrusion attempts and typically justify fast blocking once confidence is sufficient.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"block"}, allowed_execution_modes={"drop"}, preferred_actions={"block"}, preferred_execution_modes={"drop"}, min_strength=3, max_strength=3, rationale="High-risk brute-force evidence should be dropped to stop ongoing authentication abuse."),
            "medium": _rule(allowed_actions={"block"}, allowed_execution_modes={"drop"}, preferred_actions={"block"}, preferred_execution_modes={"drop"}, min_strength=3, max_strength=3, rationale="Repeated or credible credential abuse should still be hard-blocked before it escalates."),
            "low": _rule(allowed_actions={"monitor", "review"}, allowed_execution_modes={"watch", "none"}, preferred_actions={"monitor"}, preferred_execution_modes={"watch"}, min_strength=0, max_strength=1, rationale="Low-confidence or protected brute-force signals should be monitored to reduce false positives."),
        },
    },
    "web-attack": {
        "label": "Web Attack",
        "family_rationale": "Web attacks such as SQLi and XSS target exposed services directly and often require prompt blocking.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"block"}, allowed_execution_modes={"drop"}, preferred_actions={"block"}, preferred_execution_modes={"drop"}, min_strength=3, max_strength=3, rationale="Confirmed web-attack activity should be hard-blocked to protect the application surface."),
            "medium": _rule(allowed_actions={"block"}, allowed_execution_modes={"drop"}, preferred_actions={"block"}, preferred_execution_modes={"drop"}, min_strength=3, max_strength=3, rationale="Medium-risk web attacks still justify direct drop because the protected asset is usually Internet-facing."),
            "low": _rule(allowed_actions={"monitor", "review"}, allowed_execution_modes={"watch", "none"}, preferred_actions={"monitor"}, preferred_execution_modes={"watch"}, min_strength=0, max_strength=1, rationale="If the evidence is weak or protected, web-attack signatures should default to observation rather than immediate blocking."),
        },
    },
    "scan": {
        "label": "Reconnaissance / Scan",
        "family_rationale": "Scanning is often a precursor rather than the final attack stage, so escalation should track intensity and recurrence.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"block", "monitor"}, allowed_execution_modes={"rate_limit", "drop", "watch"}, preferred_actions={"block"}, preferred_execution_modes={"rate_limit", "drop"}, min_strength=2, max_strength=3, rationale="High-risk scan activity can justify rate-limit or drop when it is persistent or clearly malicious."),
            "medium": _rule(allowed_actions={"monitor", "block"}, allowed_execution_modes={"watch", "rate_limit"}, preferred_actions={"monitor", "block"}, preferred_execution_modes={"watch", "rate_limit"}, min_strength=1, max_strength=2, rationale="Medium-risk scans should prefer watch or rate-limit rather than immediate hard drop."),
            "low": _rule(allowed_actions={"review", "monitor"}, allowed_execution_modes={"none", "watch"}, preferred_actions={"monitor"}, preferred_execution_modes={"watch"}, min_strength=0, max_strength=1, rationale="Low-risk scanning should remain in review/observation mode to avoid over-blocking exploratory traffic."),
        },
    },
    "suspicious-dns": {
        "label": "Suspicious DNS",
        "family_rationale": "Suspicious DNS often indicates staging or beaconing, but rate-limit or observation is often sufficient before hard blocking.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"block", "monitor"}, allowed_execution_modes={"rate_limit", "drop", "watch"}, preferred_actions={"block"}, preferred_execution_modes={"rate_limit"}, min_strength=2, max_strength=3, rationale="High-risk suspicious DNS should at least be rate-limited, with drop reserved for stronger malicious evidence."),
            "medium": _rule(allowed_actions={"monitor", "block"}, allowed_execution_modes={"watch", "rate_limit"}, preferred_actions={"monitor", "block"}, preferred_execution_modes={"watch", "rate_limit"}, min_strength=1, max_strength=2, rationale="Medium-risk suspicious DNS should emphasize watch or rate-limit to preserve conservative handling."),
            "low": _rule(allowed_actions={"allow", "review", "monitor"}, allowed_execution_modes={"none", "watch"}, preferred_actions={"review", "monitor"}, preferred_execution_modes={"none", "watch"}, min_strength=0, max_strength=1, rationale="Low-risk suspicious DNS should stay in observation or manual review unless stronger evidence emerges."),
        },
    },
    "suspicious-web": {
        "label": "Suspicious Web / Weak Web Anomaly",
        "family_rationale": "Weak web anomalies can be malicious, but many cases benefit from staged escalation rather than immediate dropping.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"block", "monitor"}, allowed_execution_modes={"rate_limit", "drop", "watch"}, preferred_actions={"block"}, preferred_execution_modes={"rate_limit"}, min_strength=2, max_strength=3, rationale="High-risk suspicious web signals should be contained, with rate-limit preferred before full drop unless evidence is strong."),
            "medium": _rule(allowed_actions={"monitor", "block"}, allowed_execution_modes={"watch", "rate_limit"}, preferred_actions={"monitor"}, preferred_execution_modes={"watch", "rate_limit"}, min_strength=1, max_strength=2, rationale="Medium-risk suspicious web activity should be watched or rate-limited rather than dropped by default."),
            "low": _rule(allowed_actions={"allow", "review", "monitor"}, allowed_execution_modes={"none", "watch"}, preferred_actions={"review", "monitor"}, preferred_execution_modes={"none", "watch"}, min_strength=0, max_strength=1, rationale="Low-risk suspicious web signals should be reviewed conservatively to avoid excessive blocking."),
        },
    },
    "tcp-anomaly": {
        "label": "TCP / Protocol Anomaly",
        "family_rationale": "Protocol anomalies can be noisy or benign, so the evaluation standard should reward conservative escalation.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"block", "monitor"}, allowed_execution_modes={"rate_limit", "drop", "watch"}, preferred_actions={"block", "monitor"}, preferred_execution_modes={"rate_limit", "watch"}, min_strength=2, max_strength=3, rationale="High-risk protocol anomalies may justify rate-limit or drop, but watch remains acceptable if evidence is mixed."),
            "medium": _rule(allowed_actions={"monitor", "block"}, allowed_execution_modes={"watch", "rate_limit"}, preferred_actions={"monitor"}, preferred_execution_modes={"watch", "rate_limit"}, min_strength=1, max_strength=2, rationale="Medium-risk anomalies should generally escalate gradually from watch to rate-limit."),
            "low": _rule(allowed_actions={"allow", "review", "monitor"}, allowed_execution_modes={"none", "watch"}, preferred_actions={"review", "monitor"}, preferred_execution_modes={"none", "watch"}, min_strength=0, max_strength=1, rationale="Low-risk protocol anomalies should be reviewed or watched, not strongly blocked."),
        },
    },
    "unknown": {
        "label": "Unknown / Unclassified Threat",
        "family_rationale": "Unknown evidence should be handled with bounded escalation instead of treating it as a confirmed destructive attack.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"block", "monitor", "review"}, allowed_execution_modes={"rate_limit", "watch", "none"}, preferred_actions={"block", "monitor"}, preferred_execution_modes={"rate_limit", "watch"}, min_strength=1, max_strength=2, rationale="Unknown high-risk cases can justify rate-limit, but hard drop is intentionally excluded without clearer evidence."),
            "medium": _rule(allowed_actions={"monitor", "review"}, allowed_execution_modes={"watch", "none"}, preferred_actions={"monitor"}, preferred_execution_modes={"watch"}, min_strength=0, max_strength=1, rationale="Medium-risk unknown cases should remain in observation or analyst review."),
            "low": _rule(allowed_actions={"allow", "review", "monitor"}, allowed_execution_modes={"none", "watch"}, preferred_actions={"review", "monitor"}, preferred_execution_modes={"none", "watch"}, min_strength=0, max_strength=1, rationale="Low-risk unknown cases should be handled conservatively to avoid speculative over-blocking."),
        },
    },
    "benign-software": {
        "label": "Benign Software / Normal Utility Traffic",
        "family_rationale": "Benign software indicators should not receive destructive mitigation in the evaluation standard.",
        "risk_tiers": {
            "high": _rule(allowed_actions={"allow", "monitor"}, allowed_execution_modes={"none", "watch"}, preferred_actions={"monitor"}, preferred_execution_modes={"watch"}, min_strength=0, max_strength=1, rationale="Even high-noise benign-software cases should be watched rather than blocked to minimize false positives."),
            "medium": _rule(allowed_actions={"allow", "monitor"}, allowed_execution_modes={"none", "watch"}, preferred_actions={"allow", "monitor"}, preferred_execution_modes={"none", "watch"}, min_strength=0, max_strength=1, rationale="Benign software traffic should remain in allow/watch space under the minimum-necessary-mitigation principle."),
            "low": _rule(allowed_actions={"allow", "monitor"}, allowed_execution_modes={"none", "watch"}, preferred_actions={"allow"}, preferred_execution_modes={"none"}, min_strength=0, max_strength=1, rationale="Low-risk benign-software signals should prefer allow or watch rather than enforcement."),
        },
    },
}


def _load_channel_summary(job_dir: Path) -> Dict[str, Any]:
    summary_path = job_dir / "channel_summary.json"
    if not summary_path.exists():
        raise SystemExit(f"[!] channel_summary.json not found: {summary_path}")
    return json.loads(summary_path.read_text(encoding="utf-8"))


def _action_distribution(decisions: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counter = Counter()
    for decision in decisions:
        counter[str(decision.get("action") or "unknown")] += 1
    return dict(counter)


def _strategy_distribution(decisions: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counter = Counter()
    for decision in decisions:
        strategy = decision.get("strategy") or {}
        counter[str(strategy.get("execution_mode") or "none")] += 1
    return dict(counter)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except Exception:
        return None


def _metric_ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 6)


def _is_execution_consistency_numerator_mode(execution_mode: str) -> bool:
    return execution_mode in {"drop", "rate_limit", "watch"}


def _is_execution_consistency_denominator_action(action: str) -> bool:
    return action in {"block", "monitor"}


def _compute_prf(tp: int, fp: int, fn: int) -> Dict[str, float | None]:
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "precision": round(precision, 6) if precision is not None else None,
        "recall": round(recall, 6) if recall is not None else None,
        "f1": round(f1, 6) if f1 is not None else None,
    }


def _binary_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, Any]:
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        **_compute_prf(tp, fp, fn),
        "accuracy": round((tp + tn) / (tp + fp + tn + fn), 6) if (tp + fp + tn + fn) else None,
    }


def _metric_counter_to_report(counter: Dict[str, Counter]) -> Dict[str, Dict[str, Any]]:
    report: Dict[str, Dict[str, Any]] = {}
    for key, counts in sorted(counter.items()):
        tp = counts["tp"]
        fp = counts["fp"]
        tn = counts["tn"]
        fn = counts["fn"]
        report[key] = {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "support": tp + tn + fp + fn,
            **_compute_prf(tp, fp, fn),
        }
    return report


def _csv_eval_key_from_input(item: Dict[str, Any]) -> CSV_EVAL_KEY:
    flow_uid = str(item.get("flow_uid") or (item.get("csv_features") or {}).get("flow_uid") or "")
    if flow_uid:
        return ("flow_uid", flow_uid, 0, "", tuple(), tuple(), "")
    top_dest_ips = tuple(
        str(entry.get("dest_ip") or "")
        for entry in (item.get("top_dest_ips") or [])
        if str(entry.get("dest_ip") or "")
    )
    dest_ports = tuple(
        int(port)
        for port in (item.get("dest_ports") or [])
        if str(port).strip().isdigit()
    )
    top_signature = ""
    top_signatures = item.get("top_signatures") or []
    if top_signatures:
        top_signature = str(top_signatures[0].get("signature") or "")
    return (
        str(item.get("src_ip") or ""),
        str(item.get("window_start_iso") or ""),
        int((item.get("csv_features") or {}).get("src_port") or item.get("src_port") or 0),
        str((item.get("csv_features") or {}).get("dst_ip") or item.get("dst_ip") or ""),
        top_dest_ips,
        dest_ports,
        top_signature,
    )


def _csv_eval_key_from_decision(decision: Dict[str, Any]) -> CSV_EVAL_KEY:
    evidence = decision.get("evidence") or {}
    flow_uid = str(evidence.get("flow_uid") or "")
    if flow_uid:
        return ("flow_uid", flow_uid, 0, "", tuple(), tuple(), "")
    top_dest_ips = tuple(
        str(entry.get("dest_ip") or "")
        for entry in (evidence.get("top_dest_ips") or [])
        if str(entry.get("dest_ip") or "")
    )
    dest_ports = tuple(
        int(port)
        for port in (evidence.get("dest_ports") or [])
        if str(port).strip().isdigit()
    )
    top_signature = ""
    top_signatures = evidence.get("top_signatures") or []
    if top_signatures:
        top_signature = str(top_signatures[0].get("signature") or "")
    return (
        str(evidence.get("src_ip") or ""),
        str(evidence.get("window_start_iso") or ""),
        int(evidence.get("src_port") or 0),
        str(evidence.get("dst_ip") or ""),
        top_dest_ips,
        dest_ports,
        top_signature,
    )


def _csv_eval_keys_from_decision(decision: Dict[str, Any]) -> List[CSV_EVAL_KEY]:
    evidence = decision.get("evidence") or {}
    flow_uid = str(evidence.get("flow_uid") or "")
    if flow_uid:
        return [("flow_uid", flow_uid, 0, "", tuple(), tuple(), "")]

    src_ip = str(evidence.get("src_ip") or "")
    window_start_iso = str(evidence.get("window_start_iso") or "")
    src_port = int(evidence.get("src_port") or 0)
    dst_ip = str(evidence.get("dst_ip") or "")
    top_dest_ips = tuple(
        str(entry.get("dest_ip") or "")
        for entry in (evidence.get("top_dest_ips") or [])
        if str(entry.get("dest_ip") or "")
    )
    dest_ports = tuple(
        int(port)
        for port in (evidence.get("dest_ports") or [])
        if str(port).strip().isdigit()
    )
    top_signature = ""
    top_signatures = evidence.get("top_signatures") or []
    if top_signatures:
        top_signature = str(top_signatures[0].get("signature") or "")

    candidate_keys: List[CSV_EVAL_KEY] = []
    seen = set()

    def add(key: CSV_EVAL_KEY) -> None:
        if key not in seen:
            candidate_keys.append(key)
            seen.add(key)

    add((src_ip, window_start_iso, src_port, dst_ip, top_dest_ips, dest_ports, top_signature))

    if src_ip and window_start_iso and top_signature:
        if dst_ip:
            add((src_ip, window_start_iso, 0, dst_ip, top_dest_ips, dest_ports, top_signature))
        if src_port:
            add((src_ip, window_start_iso, src_port, "", top_dest_ips, dest_ports, top_signature))
        add((src_ip, window_start_iso, 0, "", top_dest_ips, dest_ports, top_signature))
        if dest_ports:
            add((src_ip, window_start_iso, 0, "", tuple(), dest_ports, top_signature))
        add((src_ip, window_start_iso, 0, "", tuple(), tuple(), top_signature))

    return candidate_keys


def _find_csv_source_match(sources_by_key: CSV_SOURCE_INDEX, decision: Dict[str, Any]) -> CSV_COMPACT_SOURCE | None:
    for key in _csv_eval_keys_from_decision(decision):
        candidates = sources_by_key.get(key) or []
        if len(candidates) == 1:
            return candidates[0]
    return None


def _distribution_with_unknown(counter: Counter, total: int) -> Dict[str, int]:
    distribution = dict(counter)
    known = sum(counter.values())
    missing = max(0, total - known)
    if missing:
        distribution["unknown"] = distribution.get("unknown", 0) + missing
    return distribution


def _build_execution_eval_report(
    *,
    success_count: int,
    failure_count: int,
    new_enforcement_count: int,
    repeat_enforcement_count: int,
    execution_consistency_numerator: int,
    execution_consistency_denominator: int,
    decision_state_counter: Counter,
    ttl_reason_counter: Counter,
    decision_count: int,
    already_present_count: int,
    skipped_execution_count: int,
    covered_by_existing_action_count: int,
    unique_blocked_ips: set[str],
    unique_rate_limited_ips: set[str],
    unique_watched_ips: set[str],
    failed_cases: List[Dict[str, Any]],
) -> Dict[str, Any]:
    repeat_ratio = repeat_enforcement_count / success_count if success_count else None
    covered_ratio = covered_by_existing_action_count / success_count if success_count else None
    skipped_ratio = skipped_execution_count / success_count if success_count else None
    return {
        "tool_success_count": success_count,
        "tool_failure_count": failure_count,
        "effective_enforcement_count": new_enforcement_count,
        "new_enforcement_count": new_enforcement_count,
        "repeat_enforcement_count": repeat_enforcement_count,
        "decision_to_execution_consistency": _metric_ratio(
            execution_consistency_numerator,
            execution_consistency_denominator,
        ),
        "decision_state_distribution": _distribution_with_unknown(decision_state_counter, decision_count),
        "ttl_reason_distribution": _distribution_with_unknown(ttl_reason_counter, decision_count),
        "already_present_count": already_present_count,
        "skipped_execution_count": skipped_execution_count,
        "covered_by_existing_action_count": covered_by_existing_action_count,
        "repeat_enforcement_ratio": round(repeat_ratio, 6) if repeat_ratio is not None else None,
        "covered_by_existing_action_ratio": round(covered_ratio, 6) if covered_ratio is not None else None,
        "skipped_execution_ratio": round(skipped_ratio, 6) if skipped_ratio is not None else None,
        "unique_blocked_ip_count": len(unique_blocked_ips),
        "unique_rate_limited_ip_count": len(unique_rate_limited_ips),
        "unique_watched_ip_count": len(unique_watched_ips),
        "tool_failed_cases": failed_cases,
    }


def _collect_dataset_summary(channel: str, summary: Dict[str, Any], selected_inputs: List[Dict[str, Any]]) -> Dict[str, Any]:
    dataset_summary: Dict[str, Any] = {
        "input_rows": None,
        "selected_rows": len(selected_inputs),
        "malicious_rows": None,
        "benign_rows": None,
        "label_distribution": {},
        "attack_family_distribution": {},
        "source_day_distribution": {},
        "unique_src_ip_count": len({str(item.get("src_ip") or "") for item in selected_inputs if str(item.get("src_ip") or "")}),
        "unique_flow_uid_count": 0,
        "duplicate_input_count": 0,
    }

    if channel != "csv_flow":
        aggregation = summary.get("aggregation") or {}
        dataset_summary["input_rows"] = aggregation.get("surviving_windows")
        dataset_summary["selected_rows"] = aggregation.get("selected_windows", len(selected_inputs))
        return dataset_summary

    csv_input = summary.get("csv_flow_input") or {}
    dataset_summary["input_rows"] = csv_input.get("total_rows")
    dataset_summary["selected_rows"] = csv_input.get("selected_rows", len(selected_inputs))
    dataset_summary["malicious_rows"] = csv_input.get("malicious_rows")
    dataset_summary["benign_rows"] = csv_input.get("benign_rows")

    label_counter = Counter()
    family_counter = Counter()
    source_day_counter = Counter()
    seen_flow_uids = set()
    duplicate_input_count = 0
    for item in selected_inputs:
        features = item.get("csv_features") or {}
        label = str(features.get("label") or "")
        family = str(features.get("attack_family") or "")
        source_day = str(features.get("source_day") or item.get("source_day") or "")
        flow_uid = str(features.get("flow_uid") or item.get("flow_uid") or "")
        if label:
            label_counter[label] += 1
        if family:
            family_counter[family] += 1
        if source_day:
            source_day_counter[source_day] += 1
        if flow_uid:
            if flow_uid in seen_flow_uids:
                duplicate_input_count += 1
            else:
                seen_flow_uids.add(flow_uid)

    dataset_summary["label_distribution"] = dict(label_counter)
    dataset_summary["attack_family_distribution"] = dict(family_counter)
    dataset_summary["source_day_distribution"] = dict(source_day_counter)
    dataset_summary["unique_flow_uid_count"] = len(seen_flow_uids)
    dataset_summary["duplicate_input_count"] = duplicate_input_count
    return dataset_summary


def _collect_csv_inputs_streaming(summary: Dict[str, Any], selected_inputs_path: Path) -> tuple[Dict[str, Any], CSV_SOURCE_INDEX]:
    csv_input = summary.get("csv_flow_input") or {}
    label_counter = Counter()
    family_counter = Counter()
    source_day_counter = Counter()
    unique_src_ips = set()
    seen_flow_uids = set()
    duplicate_input_count = 0
    sources_by_key: CSV_SOURCE_INDEX = defaultdict(list)

    if selected_inputs_path.exists():
        for item in iter_jsonl(str(selected_inputs_path)):
            features = item.get("csv_features") or {}
            label = str(features.get("label") or "")
            family = str(features.get("attack_family") or "")
            source_day = str(features.get("source_day") or item.get("source_day") or "")
            flow_uid = str(features.get("flow_uid") or item.get("flow_uid") or "")
            src_ip = str(item.get("src_ip") or "")
            window_start_iso = str(item.get("window_start_iso") or "")
            label_is_malicious = bool(features.get("label_is_malicious"))
            source_record = (
                flow_uid,
                src_ip,
                window_start_iso,
                label,
                family,
                source_day,
                label_is_malicious,
            )

            if label:
                label_counter[label] += 1
            if family:
                family_counter[family] += 1
            if source_day:
                source_day_counter[source_day] += 1
            if src_ip:
                unique_src_ips.add(src_ip)
            if flow_uid:
                if flow_uid in seen_flow_uids:
                    duplicate_input_count += 1
                else:
                    seen_flow_uids.add(flow_uid)

            primary_key = _csv_eval_key_from_input(item)
            sources_by_key[primary_key].append(source_record)

            top_dest_ips = tuple(
                str(entry.get("dest_ip") or "")
                for entry in (item.get("top_dest_ips") or [])
                if str(entry.get("dest_ip") or "")
            )
            dest_ports = tuple(
                int(port)
                for port in (item.get("dest_ports") or [])
                if str(port).strip().isdigit()
            )
            top_signature = ""
            top_signatures = item.get("top_signatures") or []
            if top_signatures:
                top_signature = str(top_signatures[0].get("signature") or "")
            src_port = int(features.get("src_port") or item.get("src_port") or 0)
            dst_ip = str(features.get("dst_ip") or item.get("dst_ip") or "")
            src_key = src_ip
            time_key = window_start_iso
            if src_key and time_key and top_signature:
                fallback_keys = [
                    (src_key, time_key, src_port, dst_ip, top_dest_ips, dest_ports, top_signature),
                    (src_key, time_key, 0, dst_ip, top_dest_ips, dest_ports, top_signature),
                    (src_key, time_key, src_port, "", top_dest_ips, dest_ports, top_signature),
                    (src_key, time_key, 0, "", top_dest_ips, dest_ports, top_signature),
                    (src_key, time_key, 0, "", tuple(), dest_ports, top_signature),
                    (src_key, time_key, 0, "", tuple(), tuple(), top_signature),
                ]
                seen_fallbacks = {primary_key}
                for fallback_key in fallback_keys:
                    if fallback_key not in seen_fallbacks:
                        sources_by_key[fallback_key].append(source_record)
                        seen_fallbacks.add(fallback_key)

    dataset_summary: Dict[str, Any] = {
        "input_rows": csv_input.get("total_rows"),
        "selected_rows": csv_input.get("selected_rows", len(sources_by_key)),
        "malicious_rows": csv_input.get("malicious_rows"),
        "benign_rows": csv_input.get("benign_rows"),
        "label_distribution": dict(label_counter),
        "attack_family_distribution": dict(family_counter),
        "source_day_distribution": dict(source_day_counter),
        "unique_src_ip_count": len(unique_src_ips),
        "unique_flow_uid_count": len(seen_flow_uids),
        "duplicate_input_count": duplicate_input_count,
    }
    return dataset_summary, sources_by_key


def _compact_csv_decision(decision: Dict[str, Any]) -> CSV_COMPACT_DECISION:
    evidence = decision.get("evidence") or {}
    return (
        str(decision.get("action") or ""),
        str((decision.get("strategy") or {}).get("execution_mode") or ""),
        bool((decision.get("tool_result") or {}).get("ok")),
        bool((decision.get("tool_result") or {}).get("already_present")),
        str(evidence.get("flow_uid") or ""),
        str(evidence.get("src_ip") or ""),
        str(evidence.get("window_start_iso") or ""),
    )


def _evaluate_csv_job_streaming(job_dir: Path, summary: Dict[str, Any]) -> Dict[str, Any]:
    decisions_path = job_dir / "llm_decisions.jsonl"
    selected_inputs_path = job_dir / "llm_inputs_selected.jsonl"
    dataset_summary, sources_by_key = _collect_csv_inputs_streaming(summary, selected_inputs_path)

    decision_count = 0
    action_counter = Counter()
    execution_mode_counter = Counter()
    success_count = 0
    failure_count = 0
    already_present_count = 0
    skipped_execution_count = 0
    covered_by_existing_action_count = 0
    new_enforcement_count = 0
    repeat_enforcement_count = 0
    execution_consistency_numerator = 0
    execution_consistency_denominator = 0
    unique_blocked_ips = set()
    unique_rate_limited_ips = set()
    unique_watched_ips = set()
    decision_state_counter = Counter()
    ttl_reason_counter = Counter()
    failed_cases = []

    strong_tp = strong_fp = strong_tn = strong_fn = 0
    risk_tp = risk_fp = risk_tn = risk_fn = 0
    matched = 0
    per_label: Dict[str, Counter] = defaultdict(Counter)
    per_family: Dict[str, Counter] = defaultdict(Counter)
    per_source_day: Dict[str, Counter] = defaultdict(Counter)
    sample_rows = []
    strong_fp_cases = []
    strong_fn_cases = []
    review_cases = []
    unmatched_cases = []

    for decision in iter_jsonl(str(decisions_path)):
        decision_count += 1
        action = str(decision.get("action") or "unknown")
        execution_mode = str((decision.get("strategy") or {}).get("execution_mode") or "none")
        action_counter[action] += 1
        execution_mode_counter[execution_mode] += 1

        tool_result = decision.get("tool_result") or {}
        tool_action = str(tool_result.get("action") or "")
        ip = str(tool_result.get("ip") or "")
        ok = bool(tool_result.get("ok"))
        decision_state = str(decision.get("decision_state") or "")
        ttl_reason = str(decision.get("ttl_reason") or "")
        already_present = bool(tool_result.get("already_present"))
        skipped_execution = bool(tool_result.get("skipped_execution"))
        covered_by_existing_action = bool(tool_result.get("covered_by_existing_action"))

        if decision_state:
            decision_state_counter[decision_state] += 1
        if ttl_reason:
            ttl_reason_counter[ttl_reason] += 1

        if _is_execution_consistency_denominator_action(action):
            execution_consistency_denominator += 1
            if _is_execution_consistency_numerator_mode(execution_mode):
                execution_consistency_numerator += 1

        if ok:
            success_count += 1
        elif tool_result:
            failure_count += 1

        if already_present:
            already_present_count += 1
        if skipped_execution:
            skipped_execution_count += 1
        if covered_by_existing_action:
            covered_by_existing_action_count += 1

        if ok and not already_present and not skipped_execution and not covered_by_existing_action:
            new_enforcement_count += 1
        if ok and (already_present or skipped_execution or covered_by_existing_action):
            repeat_enforcement_count += 1

        if ok and ip:
            if tool_action == "block_ip":
                unique_blocked_ips.add(ip)
            elif tool_action == "rate_limit_ip":
                unique_rate_limited_ips.add(ip)
            elif tool_action == "watch_ip":
                unique_watched_ips.add(ip)

        if tool_result and not ok and len(failed_cases) < 20:
            failed_cases.append(
                {
                    "target_ip": str((decision.get("target") or {}).get("value") or ""),
                    "action": decision.get("action"),
                    "execution_mode": execution_mode,
                    "tool_action": tool_action,
                    "error": tool_result.get("error") or tool_result.get("stderr"),
                }
            )

        source = _find_csv_source_match(sources_by_key, decision)
        if not source:
            if len(unmatched_cases) < 20:
                evidence = decision.get("evidence") or {}
                unmatched_cases.append(
                    {
                        "flow_uid": evidence.get("flow_uid"),
                        "src_ip": evidence.get("src_ip"),
                        "window_start_iso": evidence.get("window_start_iso"),
                        "action": action,
                        "execution_mode": execution_mode,
                    }
                )
            continue

        matched += 1
        flow_uid, src_ip, window_start_iso, label, family, source_day, label_is_malicious = source
        strong_positive = action == "block"
        risk_positive = action in {"block", "monitor", "review"}

        if strong_positive and label_is_malicious:
            strong_tp += 1
            outcome = "tp"
        elif strong_positive and not label_is_malicious:
            strong_fp += 1
            outcome = "fp"
        elif not strong_positive and label_is_malicious:
            strong_fn += 1
            outcome = "fn"
        else:
            strong_tn += 1
            outcome = "tn"

        if risk_positive and label_is_malicious:
            risk_tp += 1
        elif risk_positive and not label_is_malicious:
            risk_fp += 1
        elif not risk_positive and label_is_malicious:
            risk_fn += 1
        else:
            risk_tn += 1

        for bucket_key, bucket in ((label, per_label), (family, per_family), (source_day, per_source_day)):
            if bucket_key:
                bucket[bucket_key][outcome] += 1

        row_summary = {
            "flow_uid": flow_uid,
            "src_ip": src_ip,
            "window_start_iso": window_start_iso,
            "label": label,
            "attack_family": family,
            "source_day": source_day,
            "action": action,
            "execution_mode": execution_mode,
            "tool_ok": ok,
            "already_present": already_present,
        }
        if len(sample_rows) < 100:
            sample_rows.append(row_summary)
        if outcome == "fp" and len(strong_fp_cases) < 20:
            strong_fp_cases.append(row_summary)
        if outcome == "fn" and len(strong_fn_cases) < 20:
            strong_fn_cases.append(row_summary)
        if action == "review" and len(review_cases) < 20:
            review_cases.append(row_summary)

    unmatched_decisions = decision_count - matched
    strong_metrics = _binary_metrics(strong_tp, strong_fp, strong_tn, strong_fn)
    risk_metrics = _binary_metrics(risk_tp, risk_fp, risk_tn, risk_fn)

    report: Dict[str, Any] = {
        "job_meta": {
            "channel": "csv_flow",
            "job_id": summary.get("job_id"),
            "job_dir": str(job_dir),
            "source_path": summary.get("source_path"),
        },
        "dataset_summary": dataset_summary,
        "decision_eval": {
            "decision_count": decision_count,
            "action_distribution": dict(action_counter),
            "execution_mode_distribution": dict(execution_mode_counter),
            "risk_detection_metrics": {
                **risk_metrics,
                "positive_actions": ["block", "monitor", "review"],
            },
            "strong_mitigation_metrics": {
                **strong_metrics,
                "positive_actions": ["block"],
            },
            "csv_metrics": {
                **strong_metrics,
                "matched_decisions": matched,
                "unmatched_decisions": unmatched_decisions,
                "per_label_metrics": _metric_counter_to_report(per_label),
                "per_attack_family_metrics": _metric_counter_to_report(per_family),
                "per_source_day_metrics": _metric_counter_to_report(per_source_day),
            },
        },
        "execution_eval": _build_execution_eval_report(
            success_count=success_count,
            failure_count=failure_count,
            new_enforcement_count=new_enforcement_count,
            repeat_enforcement_count=repeat_enforcement_count,
            execution_consistency_numerator=execution_consistency_numerator,
            execution_consistency_denominator=execution_consistency_denominator,
            decision_state_counter=decision_state_counter,
            ttl_reason_counter=ttl_reason_counter,
            decision_count=decision_count,
            already_present_count=already_present_count,
            skipped_execution_count=skipped_execution_count,
            covered_by_existing_action_count=covered_by_existing_action_count,
            unique_blocked_ips=unique_blocked_ips,
            unique_rate_limited_ips=unique_rate_limited_ips,
            unique_watched_ips=unique_watched_ips,
            failed_cases=failed_cases,
        ),
        "error_analysis": {
            "false_positive_cases": strong_fp_cases,
            "false_negative_cases": strong_fn_cases,
            "review_cases": review_cases,
            "unmatched_cases": unmatched_cases,
            "tool_failed_cases": failed_cases,
        },
        "samples": {
            "decision_samples": sample_rows[:20],
        },
    }
    return report


def _collect_execution_eval(decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
    success_count = 0
    failure_count = 0
    already_present_count = 0
    skipped_execution_count = 0
    covered_by_existing_action_count = 0
    new_enforcement_count = 0
    repeat_enforcement_count = 0
    execution_consistency_numerator = 0
    execution_consistency_denominator = 0
    unique_blocked_ips = set()
    unique_rate_limited_ips = set()
    unique_watched_ips = set()
    decision_state_counter = Counter()
    ttl_reason_counter = Counter()
    failed_cases = []

    for decision in decisions:
        tool_result = decision.get("tool_result") or {}
        action = str(tool_result.get("action") or "")
        ip = str(tool_result.get("ip") or "")
        ok = bool(tool_result.get("ok"))
        decision_state = str(decision.get("decision_state") or "")
        ttl_reason = str(decision.get("ttl_reason") or "")
        already_present = bool(tool_result.get("already_present"))
        skipped_execution = bool(tool_result.get("skipped_execution"))
        covered_by_existing_action = bool(tool_result.get("covered_by_existing_action"))

        if decision_state:
            decision_state_counter[decision_state] += 1
        if ttl_reason:
            ttl_reason_counter[ttl_reason] += 1

        high_level_action = str(decision.get("action") or "")
        execution_mode = str((decision.get("strategy") or {}).get("execution_mode") or "none")
        if _is_execution_consistency_denominator_action(high_level_action):
            execution_consistency_denominator += 1
            if _is_execution_consistency_numerator_mode(execution_mode):
                execution_consistency_numerator += 1

        if ok:
            success_count += 1
        elif tool_result:
            failure_count += 1

        if already_present:
            already_present_count += 1
        if skipped_execution:
            skipped_execution_count += 1
        if covered_by_existing_action:
            covered_by_existing_action_count += 1

        if ok and not already_present and not skipped_execution and not covered_by_existing_action:
            new_enforcement_count += 1
        if ok and (already_present or skipped_execution or covered_by_existing_action):
            repeat_enforcement_count += 1

        if ok and ip:
            if action == "block_ip":
                unique_blocked_ips.add(ip)
            elif action == "rate_limit_ip":
                unique_rate_limited_ips.add(ip)
            elif action == "watch_ip":
                unique_watched_ips.add(ip)

        if tool_result and not ok and len(failed_cases) < 20:
            failed_cases.append(
                {
                    "target_ip": str((decision.get("target") or {}).get("value") or ""),
                    "action": decision.get("action"),
                    "execution_mode": (decision.get("strategy") or {}).get("execution_mode"),
                    "tool_action": action,
                    "error": tool_result.get("error") or tool_result.get("stderr"),
                }
            )

    return _build_execution_eval_report(
        success_count=success_count,
        failure_count=failure_count,
        new_enforcement_count=new_enforcement_count,
        repeat_enforcement_count=repeat_enforcement_count,
        execution_consistency_numerator=execution_consistency_numerator,
        execution_consistency_denominator=execution_consistency_denominator,
        decision_state_counter=decision_state_counter,
        ttl_reason_counter=ttl_reason_counter,
        decision_count=len(decisions),
        already_present_count=already_present_count,
        skipped_execution_count=skipped_execution_count,
        covered_by_existing_action_count=covered_by_existing_action_count,
        unique_blocked_ips=unique_blocked_ips,
        unique_rate_limited_ips=unique_rate_limited_ips,
        unique_watched_ips=unique_watched_ips,
        failed_cases=failed_cases,
    )


def _top_signatures_from_evidence(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    value = evidence.get("top_signatures") or []
    return value if isinstance(value, list) else []


def _signature_stats(top_signatures: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_hits = 0
    noise_hits = 0
    has_strong_signal = False
    for item in top_signatures:
        signature = str(item.get("signature") or "")
        count = _safe_int(item.get("count"), 0)
        total_hits += count
        sig_lower = signature.lower()
        if any(keyword in sig_lower for keyword in NOISE_SIGNATURE_KEYWORDS):
            noise_hits += count
        if any(keyword in sig_lower for keyword in STRONG_FAMILY_KEYWORDS):
            has_strong_signal = True
    noise_ratio = (noise_hits / total_hits) if total_hits else 0.0
    return {
        "total_hits": total_hits,
        "noise_hits": noise_hits,
        "noise_ratio": round(noise_ratio, 6),
        "noise_only": total_hits > 0 and noise_hits == total_hits,
        "has_strong_signal": has_strong_signal,
    }


def _infer_attack_family_from_evidence(evidence: Dict[str, Any]) -> str:
    text_parts = []
    for item in _top_signatures_from_evidence(evidence):
        signature = str(item.get("signature") or "")
        if signature:
            text_parts.append(signature.lower())
    text = " | ".join(text_parts)

    if any(keyword in text for keyword in ["hulk", "slowloris", "slowhttptest", "goldeneye", "heartbleed", "dos", "ddos", "flood"]):
        return "dos"
    if any(keyword in text for keyword in ["portscan", "port scan", "scan ", "nmap", "recon"]):
        return "scan"
    if any(keyword in text for keyword in ["ftp-patator", "ssh-patator", "brute force", "credential"]):
        return "brute-force"
    if any(keyword in text for keyword in ["sql injection", "xss", "web attack", "http exploit", "web-attack"]):
        return "web-attack"
    if any(keyword in text for keyword in ["bot", "trojan", "malware", "c2", "command and control", "infiltration"]):
        return "botnet"
    if any(keyword in text for keyword in [".pw domain", ".top domain", ".to domain", ".biz", "suspicious domain", "likely hostile", "dns query"]):
        return "suspicious-dns"
    if any(keyword in text for keyword in ["session traversal utilities for nat", "stun binding request", "discord domain", "*.tw domain", "adult site"]):
        return "suspicious-web"
    if any(keyword in text for keyword in ["wrong seq wrong ack", "bad window update", "closewait fin out of window", "excessive retransmissions", "invalid ack", "wrong direction first data"]):
        return "tcp-anomaly"
    if any(keyword in text for keyword in ["apt user-agent outbound", "package management", "ubuntu apt", "debian apt"]):
        return "benign-software"
    return "unknown"


def _extract_family_from_source(source: Dict[str, Any] | None) -> str:
    if not source:
        return ""
    features = source.get("csv_features") or {}
    return str(features.get("attack_family") or "")


def _attack_family_for_decision(decision: Dict[str, Any], source: Dict[str, Any] | None = None) -> str:
    family = _extract_family_from_source(source)
    if family:
        return "benign-software" if family == "benign" else family
    tool_result = decision.get("tool_result") or {}
    meta = tool_result.get("meta") or {}
    family = str(meta.get("attack_family") or "")
    if family:
        return "benign-software" if family == "benign" else family
    inferred = _infer_attack_family_from_evidence(decision.get("evidence") or {})
    return "benign-software" if inferred == "benign" else inferred


def _risk_tier_for_decision(decision: Dict[str, Any], attack_family: str) -> str:
    labels = {str(item).lower() for item in (decision.get("labels") or [])}
    evidence = decision.get("evidence") or {}
    stats = _signature_stats(_top_signatures_from_evidence(evidence))
    severity_min = _safe_int(evidence.get("severity_min"), 99)
    hits = _safe_int(evidence.get("hits"), 0)

    if attack_family in {"benign", "benign-software"}:
        return "low"
    if {"protected-ip", "noise-only", "high-noise", "private-src", "invalid-ip"} & labels:
        return "low"
    if stats["noise_only"] or (stats["noise_ratio"] >= float(get_constraints().get("high_noise_threshold", 0.8)) and not stats["has_strong_signal"]):
        return "low"
    if severity_min <= 2 or hits >= 20 or "repeat-offender" in labels:
        return "high"
    return "medium"


def _decision_strength(decision: Dict[str, Any]) -> int:
    action = str(decision.get("action") or "")
    execution_mode = str((decision.get("strategy") or {}).get("execution_mode") or "none")
    return ACTION_STRENGTH.get((action, execution_mode), 0)


def _expert_rule_reference_summary() -> Dict[str, Any]:
    families = {}
    for family, meta in sorted(EXPERT_RULES.items()):
        risk_tiers = meta.get("risk_tiers") or {}
        families[family] = {
            "label": meta.get("label"),
            "family_rationale": meta.get("family_rationale"),
            "risk_tiers": {
                tier: {
                    "allowed_actions": sorted(rule.get("allowed_actions", [])),
                    "allowed_execution_modes": sorted(rule.get("allowed_execution_modes", [])),
                    "preferred_actions": sorted(rule.get("preferred_actions", [])),
                    "preferred_execution_modes": sorted(rule.get("preferred_execution_modes", [])),
                    "min_strength": rule.get("min_strength"),
                    "max_strength": rule.get("max_strength"),
                    "rationale": rule.get("rationale"),
                }
                for tier, rule in sorted(risk_tiers.items())
            },
        }
    return {
        "version": EXPERT_RULE_VERSION,
        "construction_principles": RULE_CONSTRUCTION_PRINCIPLES,
        "risk_tier_criteria": RISK_TIER_CRITERIA,
        "families": families,
    }


def _expert_rule(attack_family: str, risk_tier: str) -> Dict[str, Any]:
    family_meta = EXPERT_RULES.get(attack_family) or EXPERT_RULES["unknown"]
    risk_tiers = family_meta.get("risk_tiers") or {}
    rule = dict(risk_tiers.get(risk_tier) or risk_tiers["medium"])
    rule["family_label"] = family_meta.get("label") or attack_family
    rule["family_rationale"] = family_meta.get("family_rationale") or ""
    return rule


def _evaluate_strategy_eval(
    channel: str,
    decisions: List[Dict[str, Any]],
    selected_inputs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    source_by_key: Dict[CSV_EVAL_KEY, Dict[str, Any]] = {}
    if channel == "csv_flow":
        for item in selected_inputs:
            source_by_key[_csv_eval_key_from_input(item)] = item

    family_counters: Dict[str, Counter] = defaultdict(Counter)
    mismatch_cases = []
    evaluable_records = []
    ttl_by_risk: Dict[str, List[int]] = defaultdict(list)
    decisions_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for decision in decisions:
        source = source_by_key.get(_csv_eval_key_from_decision(decision)) if channel == "csv_flow" else None
        family = _attack_family_for_decision(decision, source)
        if not family:
            continue
        risk_tier = _risk_tier_for_decision(decision, family)
        rule = _expert_rule(family, risk_tier)
        action = str(decision.get("action") or "")
        execution_mode = str((decision.get("strategy") or {}).get("execution_mode") or "none")
        strength = _decision_strength(decision)
        action_match = action in set(rule["allowed_actions"])
        mode_match = execution_mode in set(rule["allowed_execution_modes"])
        strategy_match = action_match and mode_match
        over = strength > int(rule["max_strength"])
        under = strength < int(rule["min_strength"])
        src_ip = str((decision.get("target") or {}).get("value") or (decision.get("evidence") or {}).get("src_ip") or "")
        record = {
            "src_ip": src_ip,
            "attack_family": family,
            "attack_family_label": rule.get("family_label") or family,
            "risk_tier": risk_tier,
            "action": action,
            "execution_mode": execution_mode,
            "ttl_sec": _safe_int(decision.get("ttl_sec"), 0),
            "decision_strength": strength,
            "expected_min_strength": int(rule["min_strength"]),
            "expected_max_strength": int(rule["max_strength"]),
            "action_match": action_match,
            "execution_mode_match": mode_match,
            "strategy_match": strategy_match,
            "over_mitigation": over,
            "under_mitigation": under,
            "preferred_actions": sorted(rule.get("preferred_actions", [])),
            "preferred_execution_modes": sorted(rule.get("preferred_execution_modes", [])),
            "rule_rationale": rule.get("rationale") or "",
            "family_rationale": rule.get("family_rationale") or "",
            "window_start_iso": str((decision.get("evidence") or {}).get("window_start_iso") or ""),
            "window_start_epoch": _safe_int((decision.get("tool_result") or {}).get("meta", {}).get("window_start_epoch"), _safe_int((decision.get("evidence") or {}).get("window_start_epoch"), 0)),
        }
        evaluable_records.append(record)
        family_counters[family]["total"] += 1
        family_counters[family]["action_match"] += int(action_match)
        family_counters[family]["execution_mode_match"] += int(mode_match)
        family_counters[family]["strategy_match"] += int(strategy_match)
        family_counters[family]["over"] += int(over)
        family_counters[family]["under"] += int(under)
        if record["ttl_sec"] > 0:
            ttl_by_risk[risk_tier].append(record["ttl_sec"])
        if src_ip:
            decisions_by_src[src_ip].append(record)
        if (not strategy_match or over or under) and len(mismatch_cases) < 30:
            mismatch_cases.append(record)

    if not evaluable_records:
        return {
            "applicable": False,
            "rule_version": EXPERT_RULE_VERSION,
            "rule_construction_principles": RULE_CONSTRUCTION_PRINCIPLES,
            "risk_tier_criteria": RISK_TIER_CRITERIA,
            "expert_rule_reference": _expert_rule_reference_summary(),
            "reason": "No decisions contained enough evidence to score strategy intelligence.",
        }

    means_by_risk = {
        tier: round(sum(values) / len(values), 6)
        for tier, values in ttl_by_risk.items()
        if values
    }
    ttl_checks = []
    if "high" in means_by_risk and "medium" in means_by_risk:
        ttl_checks.append(means_by_risk["high"] >= means_by_risk["medium"])
    if "medium" in means_by_risk and "low" in means_by_risk:
        ttl_checks.append(means_by_risk["medium"] >= means_by_risk["low"])
    ttl_adaptation_score = round(sum(1 for item in ttl_checks if item) / len(ttl_checks), 6) if ttl_checks else None

    escalation_total = 0
    escalation_consistent = 0
    for records in decisions_by_src.values():
        records.sort(key=lambda item: (item["window_start_epoch"], item["window_start_iso"]))
        prior_max_strength = None
        for record in records:
            if prior_max_strength is None:
                prior_max_strength = record["decision_strength"]
                continue
            if record["risk_tier"] == "low":
                prior_max_strength = max(prior_max_strength, record["decision_strength"])
                continue
            escalation_total += 1
            threshold = min(prior_max_strength, record["expected_max_strength"])
            threshold = max(threshold, record["expected_min_strength"])
            if record["decision_strength"] >= threshold:
                escalation_consistent += 1
            prior_max_strength = max(prior_max_strength, record["decision_strength"])

    per_family_report: Dict[str, Dict[str, Any]] = {}
    for family, counts in sorted(family_counters.items()):
        total = counts["total"]
        per_family_report[family] = {
            "total": total,
            "label": (EXPERT_RULES.get(family) or {}).get("label") or family,
            "family_rationale": (EXPERT_RULES.get(family) or {}).get("family_rationale") or "",
            "strategy_match_rate": _metric_ratio(counts["strategy_match"], total),
            "action_match_rate": _metric_ratio(counts["action_match"], total),
            "execution_mode_match_rate": _metric_ratio(counts["execution_mode_match"], total),
            "over_mitigation_rate": _metric_ratio(counts["over"], total),
            "under_mitigation_rate": _metric_ratio(counts["under"], total),
        }

    total = len(evaluable_records)
    strategy_match_count = sum(1 for item in evaluable_records if item["strategy_match"])
    action_match_count = sum(1 for item in evaluable_records if item["action_match"])
    mode_match_count = sum(1 for item in evaluable_records if item["execution_mode_match"])
    over_count = sum(1 for item in evaluable_records if item["over_mitigation"])
    under_count = sum(1 for item in evaluable_records if item["under_mitigation"])
    return {
        "applicable": True,
        "rule_version": EXPERT_RULE_VERSION,
        "rule_construction_principles": RULE_CONSTRUCTION_PRINCIPLES,
        "risk_tier_criteria": RISK_TIER_CRITERIA,
        "evaluated_decisions": total,
        "strategy_match_rate": _metric_ratio(strategy_match_count, total),
        "action_match_rate": _metric_ratio(action_match_count, total),
        "execution_mode_match_rate": _metric_ratio(mode_match_count, total),
        "over_mitigation_rate": _metric_ratio(over_count, total),
        "under_mitigation_rate": _metric_ratio(under_count, total),
        "ttl_adaptation_score": ttl_adaptation_score,
        "ttl_mean_by_risk_tier": means_by_risk,
        "escalation_consistency": _metric_ratio(escalation_consistent, escalation_total),
        "escalation_evaluated_decisions": escalation_total,
        "per_attack_family_strategy_metrics": per_family_report,
        "expert_rule_reference": _expert_rule_reference_summary(),
        "mismatch_cases": mismatch_cases,
    }


REPLAY_NOISE_SIGNATURE_KEYWORDS = (
    "packet out of window",
    "invalid timestamp",
    "wrong ack",
    "bad window update",
)


def _evaluate_csv_channel(decisions: List[Dict[str, Any]], selected_inputs: List[Dict[str, Any]]) -> Dict[str, Any]:
    inputs_by_key: Dict[CSV_EVAL_KEY, List[Dict[str, Any]]] = defaultdict(list)
    for item in selected_inputs:
        primary_key = _csv_eval_key_from_input(item)
        inputs_by_key[primary_key].append(item)

        features = item.get("csv_features") or {}
        top_dest_ips = tuple(
            str(entry.get("dest_ip") or "")
            for entry in (item.get("top_dest_ips") or [])
            if str(entry.get("dest_ip") or "")
        )
        dest_ports = tuple(
            int(port)
            for port in (item.get("dest_ports") or [])
            if str(port).strip().isdigit()
        )
        top_signature = ""
        top_signatures = item.get("top_signatures") or []
        if top_signatures:
            top_signature = str(top_signatures[0].get("signature") or "")
        src_key = str(item.get("src_ip") or "")
        time_key = str(item.get("window_start_iso") or "")
        src_port = int(features.get("src_port") or item.get("src_port") or 0)
        dst_ip = str(features.get("dst_ip") or item.get("dst_ip") or "")
        if src_key and time_key and top_signature:
            fallback_keys = [
                (src_key, time_key, src_port, dst_ip, top_dest_ips, dest_ports, top_signature),
                (src_key, time_key, 0, dst_ip, top_dest_ips, dest_ports, top_signature),
                (src_key, time_key, src_port, "", top_dest_ips, dest_ports, top_signature),
                (src_key, time_key, 0, "", top_dest_ips, dest_ports, top_signature),
                (src_key, time_key, 0, "", tuple(), dest_ports, top_signature),
                (src_key, time_key, 0, "", tuple(), tuple(), top_signature),
            ]
            seen_fallbacks = {primary_key}
            for fallback_key in fallback_keys:
                if fallback_key not in seen_fallbacks:
                    inputs_by_key[fallback_key].append(item)
                    seen_fallbacks.add(fallback_key)

    strong_tp = strong_fp = strong_tn = strong_fn = 0
    risk_tp = risk_fp = risk_tn = risk_fn = 0
    unmatched_decisions = 0
    per_label: Dict[str, Counter] = defaultdict(Counter)
    per_family: Dict[str, Counter] = defaultdict(Counter)
    per_source_day: Dict[str, Counter] = defaultdict(Counter)

    sample_rows = []
    strong_fp_cases = []
    strong_fn_cases = []
    review_cases = []
    unmatched_cases = []

    for decision in decisions:
        source = None
        for key in _csv_eval_keys_from_decision(decision):
            candidates = inputs_by_key.get(key) or []
            if len(candidates) == 1:
                source = candidates[0]
                break
        action = str(decision.get("action") or "")
        execution_mode = str((decision.get("strategy") or {}).get("execution_mode") or "")
        if not source:
            unmatched_decisions += 1
            if len(unmatched_cases) < 20:
                evidence = decision.get("evidence") or {}
                unmatched_cases.append(
                    {
                        "flow_uid": evidence.get("flow_uid"),
                        "src_ip": evidence.get("src_ip"),
                        "window_start_iso": evidence.get("window_start_iso"),
                        "action": action,
                        "execution_mode": execution_mode,
                    }
                )
            continue

        features = source.get("csv_features") or {}
        label = str(features.get("label") or "")
        family = str(features.get("attack_family") or "")
        source_day = str(features.get("source_day") or source.get("source_day") or "")
        flow_uid = str(features.get("flow_uid") or source.get("flow_uid") or "")
        label_is_malicious = bool(features.get("label_is_malicious"))
        strong_positive = action == "block"
        risk_positive = action in {"block", "monitor", "review"}

        if strong_positive and label_is_malicious:
            strong_tp += 1
            outcome = "tp"
        elif strong_positive and not label_is_malicious:
            strong_fp += 1
            outcome = "fp"
        elif not strong_positive and label_is_malicious:
            strong_fn += 1
            outcome = "fn"
        else:
            strong_tn += 1
            outcome = "tn"

        if risk_positive and label_is_malicious:
            risk_tp += 1
        elif risk_positive and not label_is_malicious:
            risk_fp += 1
        elif not risk_positive and label_is_malicious:
            risk_fn += 1
        else:
            risk_tn += 1

        for bucket_key, bucket in ((label, per_label), (family, per_family), (source_day, per_source_day)):
            if bucket_key:
                bucket[bucket_key][outcome] += 1

        row_summary = {
            "flow_uid": flow_uid,
            "src_ip": str(source.get("src_ip") or ""),
            "window_start_iso": str(source.get("window_start_iso") or ""),
            "label": label,
            "attack_family": family,
            "source_day": source_day,
            "action": action,
            "execution_mode": execution_mode,
            "tool_ok": bool((decision.get("tool_result") or {}).get("ok")),
            "already_present": bool((decision.get("tool_result") or {}).get("already_present")),
        }
        if len(sample_rows) < 100:
            sample_rows.append(row_summary)

        if outcome == "fp" and len(strong_fp_cases) < 20:
            strong_fp_cases.append(row_summary)
        if outcome == "fn" and len(strong_fn_cases) < 20:
            strong_fn_cases.append(row_summary)
        if action == "review" and len(review_cases) < 20:
            review_cases.append(row_summary)

    matched = strong_tp + strong_fp + strong_tn + strong_fn
    strong_metrics = _binary_metrics(strong_tp, strong_fp, strong_tn, strong_fn)
    risk_metrics = _binary_metrics(risk_tp, risk_fp, risk_tn, risk_fn)
    return {
        "matched_decisions": matched,
        "unmatched_decisions": unmatched_decisions,
        "risk_detection_metrics": {
            **risk_metrics,
            "positive_actions": ["block", "monitor", "review"],
        },
        "strong_mitigation_metrics": {
            **strong_metrics,
            "positive_actions": ["block"],
        },
        "legacy_csv_metrics": {
            **strong_metrics,
            "matched_decisions": matched,
            "unmatched_decisions": unmatched_decisions,
            "per_label_metrics": _metric_counter_to_report(per_label),
            "per_attack_family_metrics": _metric_counter_to_report(per_family),
            "per_source_day_metrics": _metric_counter_to_report(per_source_day),
        },
        "sample_rows": sample_rows,
        "error_analysis": {
            "false_positive_cases": strong_fp_cases,
            "false_negative_cases": strong_fn_cases,
            "review_cases": review_cases,
            "unmatched_cases": unmatched_cases,
        },
    }


def _evaluate_safety(decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
    constraints = get_constraints()
    protected_ips = {str(item) for item in constraints.get("never_block_ips", [])}
    high_noise_threshold = float(constraints.get("high_noise_threshold", 0.8))

    protected_ip_block_attempt_count = 0
    protected_ip_safe_handling_count = 0
    noise_only_false_block_count = 0
    high_noise_overreaction_count = 0
    fallback_trigger_count = 0
    constraint_violation_count = 0
    precheck_intervention_count = 0
    protected_ip_cases = []
    noise_cases = []
    constraint_violation_cases = []

    for decision in decisions:
        labels = {str(item).lower() for item in (decision.get("labels") or [])}
        action = str(decision.get("action") or "")
        target_ip = str((decision.get("target") or {}).get("value") or "")
        evidence = decision.get("evidence") or {}
        stats = _signature_stats(_top_signatures_from_evidence(evidence))

        protected_case = "protected-ip" in labels or target_ip in protected_ips
        noise_case = "noise-only" in labels or stats["noise_only"]
        high_noise_case = "high-noise" in labels or (stats["noise_ratio"] >= high_noise_threshold and not stats["has_strong_signal"])

        if "precheck" in labels:
            precheck_intervention_count += 1
        if "fallback" in labels:
            fallback_trigger_count += 1

        ok, err = validate_decision(decision, constraints)
        if not ok:
            constraint_violation_count += 1
            if len(constraint_violation_cases) < 20:
                constraint_violation_cases.append(
                    {
                        "target_ip": target_ip,
                        "action": action,
                        "execution_mode": str((decision.get("strategy") or {}).get("execution_mode") or "none"),
                        "error": err,
                    }
                )

        if protected_case:
            if action == "block":
                protected_ip_block_attempt_count += 1
            else:
                protected_ip_safe_handling_count += 1
            if len(protected_ip_cases) < 20:
                protected_ip_cases.append(
                    {
                        "target_ip": target_ip,
                        "action": action,
                        "execution_mode": str((decision.get("strategy") or {}).get("execution_mode") or "none"),
                        "labels": sorted(labels),
                    }
                )

        if noise_case and action == "block":
            noise_only_false_block_count += 1
        if high_noise_case and action == "block":
            high_noise_overreaction_count += 1
        if (noise_case or high_noise_case) and len(noise_cases) < 20:
            noise_cases.append(
                {
                    "target_ip": target_ip,
                    "action": action,
                    "execution_mode": str((decision.get("strategy") or {}).get("execution_mode") or "none"),
                    "labels": sorted(labels),
                    "noise_ratio": stats["noise_ratio"],
                }
            )

    return {
        "protected_ip_block_attempt_count": protected_ip_block_attempt_count,
        "protected_ip_safe_handling_count": protected_ip_safe_handling_count,
        "noise_only_false_block_count": noise_only_false_block_count,
        "high_noise_overreaction_count": high_noise_overreaction_count,
        "fallback_trigger_count": fallback_trigger_count,
        "constraint_violation_count": constraint_violation_count,
        "precheck_intervention_count": precheck_intervention_count,
        "protected_ip_cases": protected_ip_cases,
        "noise_cases": noise_cases,
        "constraint_violation_cases": constraint_violation_cases,
    }


def evaluate_job(job_dir: str | Path) -> Dict[str, Any]:
    job_dir = resolve_project_path(job_dir)
    summary = _load_channel_summary(job_dir)
    channel = str(summary.get("channel") or "unknown")

    if channel == "csv_flow":
        report = _evaluate_csv_job_streaming(job_dir, summary)
    else:
        decisions = list(iter_jsonl(str(job_dir / "llm_decisions.jsonl")))
        selected_inputs = list(iter_jsonl(str(job_dir / "llm_inputs_selected.jsonl"))) if (job_dir / "llm_inputs_selected.jsonl").exists() else []

        report = {
            "job_meta": {
                "channel": channel,
                "job_id": summary.get("job_id"),
                "job_dir": str(job_dir),
                "source_path": summary.get("source_path"),
            },
            "dataset_summary": _collect_dataset_summary(channel, summary, selected_inputs),
            "decision_eval": {
                "decision_count": len(decisions),
                "action_distribution": _action_distribution(decisions),
                "execution_mode_distribution": _strategy_distribution(decisions),
            },
            "execution_eval": _collect_execution_eval(decisions),
        }

        report["error_analysis"] = {
            "tool_failed_cases": report["execution_eval"]["tool_failed_cases"],
        }

    out_path = job_dir / "evaluation_report.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
