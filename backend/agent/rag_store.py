import json
import math
import os
from typing import Any, Dict, Iterable, List, Tuple

from agent.window_reader import iter_jsonl


def _safe_set(items: Iterable[Any]) -> set[str]:
    return {str(item) for item in items if item is not None}


def _extract_top_signatures(window: Dict[str, Any]) -> List[str]:
    return [str(item.get("signature")) for item in window.get("top_signatures", []) if item.get("signature")]


def _extract_top_dest_ips(window: Dict[str, Any]) -> List[str]:
    return [str(item.get("dest_ip")) for item in window.get("top_dest_ips", []) if item.get("dest_ip")]


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _score_similarity(message: Dict[str, Any], case: Dict[str, Any]) -> float:
    hints = message.get("hints", {})
    window = message.get("window", {})
    profile = case.get("incident_profile", {})
    case_hints = profile.get("hints", {})
    case_window = profile.get("window", {})
    case_strategy = case.get("historical_strategy", {})
    feedback = case.get("feedback", {})

    score = 0.0

    if hints.get("attack_family") and hints.get("attack_family") == case_hints.get("attack_family"):
        score += 4.0

    if hints.get("top_signature") and hints.get("top_signature") == case_hints.get("top_signature"):
        score += 3.0

    sig_score = _jaccard(_safe_set(_extract_top_signatures(window)), _safe_set(_extract_top_signatures(case_window)))
    score += sig_score * 3.0

    port_score = _jaccard(_safe_set(window.get("dest_ports", [])), _safe_set(case_window.get("dest_ports", [])))
    score += port_score * 2.0

    dest_ip_score = _jaccard(_safe_set(_extract_top_dest_ips(window)), _safe_set(_extract_top_dest_ips(case_window)))
    score += dest_ip_score * 1.5

    sev = window.get("severity_min")
    case_sev = case_window.get("severity_min")
    if isinstance(sev, int) and isinstance(case_sev, int):
        score += max(0.0, 1.0 - min(abs(sev - case_sev), 5) / 5.0)

    hits = int(window.get("hits") or 0)
    case_hits = int(case_window.get("hits") or 0)
    if hits > 0 and case_hits > 0:
        log_gap = abs(math.log1p(hits) - math.log1p(case_hits))
        score += max(0.0, 1.0 - min(log_gap, 3.0) / 3.0)

    if case_strategy.get("action") == "block":
        score += 0.25
    if feedback.get("is_effective") is True:
        score += 0.75
    if feedback.get("false_positive") is True:
        score -= 1.0

    return round(score, 4)


def _build_feedback_stub(decision: Dict[str, Any]) -> Dict[str, Any]:
    action = decision.get("action")
    tool_result = decision.get("tool_result") or {}

    return {
        "status": "pending_evaluation",
        "is_effective": None,
        "false_positive": None,
        "alert_drop_ratio": None,
        "notes": [],
        "execution_status": (
            "executed"
            if action == "block" and tool_result.get("ok")
            else "not_executed"
        ),
    }


def build_rag_case(message: Dict[str, Any], decision: Dict[str, Any], feedback: Dict[str, Any] | None = None) -> Dict[str, Any]:
    window = message.get("window", {})
    hints = message.get("hints", {})
    meta = message.get("meta", {})
    retrieved = message.get("retrieved_evidence", [])
    feedback = feedback or _build_feedback_stub(decision)

    return {
        "case_version": 2,
        "window_key": meta.get("window_key"),
        "job_id": meta.get("job_id"),
        "incident_profile": {
            "hints": hints,
            "window": {
                "src_ip": window.get("src_ip"),
                "window_start_iso": window.get("window_start_iso"),
                "window_end_iso": window.get("window_end_iso"),
                "hits": window.get("hits"),
                "severity_min": window.get("severity_min"),
                "top_signatures": window.get("top_signatures", []),
                "dest_ports": window.get("dest_ports", []),
                "top_dest_ips": window.get("top_dest_ips", []),
            },
        },
        "historical_strategy": {
            "action": decision.get("action"),
            "ttl_sec": decision.get("ttl_sec"),
            "confidence": decision.get("confidence"),
            "risk_score": decision.get("risk_score"),
            "labels": decision.get("labels", []),
            "reasons": decision.get("reasons", []),
        },
        "execution_result": decision.get("tool_result"),
        "feedback": feedback,
        "retrieval_context": {
            "used_history_count": len(retrieved),
            "source_window_key": meta.get("window_key"),
        },
    }


def load_rag_cases(store_path: str) -> List[Dict[str, Any]]:
    if not store_path or not os.path.exists(store_path):
        return []
    return list(iter_jsonl(store_path))


def retrieve_evidence(message: Dict[str, Any], store_path: str, top_k: int = 3) -> List[Dict[str, Any]]:
    ranked: List[Tuple[float, Dict[str, Any]]] = []
    for case in load_rag_cases(store_path):
        score = _score_similarity(message, case)
        if score <= 0:
            continue
        ranked.append((score, case))

    ranked.sort(key=lambda item: item[0], reverse=True)

    results: List[Dict[str, Any]] = []
    for score, case in ranked[:top_k]:
        profile = case.get("incident_profile", {})
        strategy = case.get("historical_strategy", {})
        feedback = case.get("feedback", {})
        results.append(
            {
                "similarity": score,
                "job_id": case.get("job_id"),
                "window_key": case.get("window_key"),
                "incident_profile": profile,
                "historical_strategy": strategy,
                "feedback": feedback,
                "execution_result": case.get("execution_result"),
                "strategy_summary": {
                    "action": strategy.get("action"),
                    "ttl_sec": strategy.get("ttl_sec"),
                    "reason_summary": strategy.get("reasons", [])[:2],
                    "status": feedback.get("status"),
                    "is_effective": feedback.get("is_effective"),
                    "false_positive": feedback.get("false_positive"),
                },
            }
        )
    return results


def append_rag_case(
    store_path: str,
    message: Dict[str, Any],
    decision: Dict[str, Any],
    feedback: Dict[str, Any] | None = None,
) -> None:
    if not store_path:
        return
    os.makedirs(os.path.dirname(store_path), exist_ok=True)
    record = build_rag_case(message, decision, feedback=feedback)
    with open(store_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
