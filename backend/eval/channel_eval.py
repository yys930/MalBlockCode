from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from agent.window_reader import iter_jsonl
from path_utils import resolve_project_path


CSV_EVAL_KEY = Tuple[str, str, int, str, Tuple[str, ...], Tuple[int, ...], str]


def _load_channel_summary(job_dir: Path) -> Dict[str, Any]:
    summary_path = job_dir / "channel_summary.json"
    if not summary_path.exists():
        raise SystemExit(f"[!] channel_summary.json not found: {summary_path}")
    return json.loads(summary_path.read_text(encoding="utf-8"))


def _tool_success(decision: Dict[str, Any]) -> bool:
    tool_result = decision.get("tool_result") or {}
    return bool(tool_result.get("ok"))


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
    flow_uids: List[str] = []
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
            flow_uids.append(flow_uid)

    dataset_summary["label_distribution"] = dict(label_counter)
    dataset_summary["attack_family_distribution"] = dict(family_counter)
    dataset_summary["source_day_distribution"] = dict(source_day_counter)
    dataset_summary["unique_flow_uid_count"] = len(set(flow_uids))
    dataset_summary["duplicate_input_count"] = len(flow_uids) - len(set(flow_uids))
    return dataset_summary


def _collect_execution_eval(decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
    success_count = 0
    failure_count = 0
    already_present_count = 0
    skipped_execution_count = 0
    covered_by_existing_action_count = 0
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

        if decision_state:
            decision_state_counter[decision_state] += 1
        if ttl_reason:
            ttl_reason_counter[ttl_reason] += 1

        if ok:
            success_count += 1
        elif tool_result:
            failure_count += 1

        if tool_result.get("already_present"):
            already_present_count += 1
        if tool_result.get("skipped_execution"):
            skipped_execution_count += 1
        if tool_result.get("covered_by_existing_action"):
            covered_by_existing_action_count += 1

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

    repeat_ratio = already_present_count / success_count if success_count else None
    covered_ratio = covered_by_existing_action_count / success_count if success_count else None
    skipped_ratio = skipped_execution_count / success_count if success_count else None
    return {
        "tool_success_count": success_count,
        "tool_failure_count": failure_count,
        "decision_state_distribution": dict(decision_state_counter),
        "ttl_reason_distribution": dict(ttl_reason_counter),
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


def _evaluate_alert_suppression(job_dir: Path, decisions: List[Dict[str, Any]], aggregated_inputs: List[Dict[str, Any]]) -> Dict[str, Any]:
    windows_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in aggregated_inputs:
        windows_by_src[str(item.get("src_ip") or "")].append(item)
    for src_ip in windows_by_src:
        windows_by_src[src_ip].sort(key=lambda x: int(x.get("window_start_epoch") or 0))

    per_decision = []
    ratios: List[float] = []
    for decision in decisions:
        strategy = decision.get("strategy") or {}
        if str(strategy.get("execution_mode")) not in {"drop", "rate_limit"}:
            continue
        evidence = decision.get("evidence") or {}
        src_ip = str((decision.get("target") or {}).get("value") or evidence.get("src_ip") or "")
        start_iso = evidence.get("window_start_iso")
        ttl_sec = int(decision.get("ttl_sec") or 0)
        windows = windows_by_src.get(src_ip, [])
        before_hits = int(evidence.get("hits") or 0)
        after_hits = 0
        decision_start = None
        for window in windows:
            if window.get("window_start_iso") == start_iso:
                decision_start = int(window.get("window_start_epoch") or 0)
                break
        if decision_start is None:
            continue
        cutoff = decision_start + max(1, ttl_sec)
        for window in windows:
            start_epoch = int(window.get("window_start_epoch") or 0)
            if decision_start < start_epoch <= cutoff:
                after_hits += int(window.get("hits") or 0)
        ratio = 1.0 if before_hits <= 0 else round(max(0.0, 1.0 - (after_hits / before_hits)), 6)
        ratios.append(ratio)
        per_decision.append(
            {
                "src_ip": src_ip,
                "decision_window_start_iso": start_iso,
                "execution_mode": strategy.get("execution_mode"),
                "before_hits": before_hits,
                "after_hits_within_ttl": after_hits,
                "suppression_ratio": ratio,
            }
        )

    return {
        "applicable": True,
        "evaluated_decisions": len(per_decision),
        "mean_suppression_ratio": round(sum(ratios) / len(ratios), 6) if ratios else None,
        "per_decision": per_decision[:100],
    }


def _evaluate_csv_channel(decisions: List[Dict[str, Any]], selected_inputs: List[Dict[str, Any]]) -> Dict[str, Any]:
    inputs_by_key: Dict[CSV_EVAL_KEY, Dict[str, Any]] = {}
    for item in selected_inputs:
        inputs_by_key[_csv_eval_key_from_input(item)] = item

    tp = fp = tn = fn = 0
    unmatched_decisions = 0
    per_label: Dict[str, Counter] = defaultdict(Counter)
    per_family: Dict[str, Counter] = defaultdict(Counter)
    per_source_day: Dict[str, Counter] = defaultdict(Counter)

    sample_rows = []
    fp_cases = []
    fn_cases = []
    review_cases = []
    unmatched_cases = []

    for decision in decisions:
        key = _csv_eval_key_from_decision(decision)
        source = inputs_by_key.get(key)
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
        mitigated = action == "block"

        if mitigated and label_is_malicious:
            tp += 1
            outcome = "tp"
        elif mitigated and not label_is_malicious:
            fp += 1
            outcome = "fp"
        elif not mitigated and label_is_malicious:
            fn += 1
            outcome = "fn"
        else:
            tn += 1
            outcome = "tn"

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

        if outcome == "fp" and len(fp_cases) < 20:
            fp_cases.append(row_summary)
        if outcome == "fn" and len(fn_cases) < 20:
            fn_cases.append(row_summary)
        if action == "review" and len(review_cases) < 20:
            review_cases.append(row_summary)

    matched = tp + fp + tn + fn
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        **_compute_prf(tp, fp, fn),
        "matched_decisions": matched,
        "unmatched_decisions": unmatched_decisions,
        "per_label_metrics": _metric_counter_to_report(per_label),
        "per_attack_family_metrics": _metric_counter_to_report(per_family),
        "per_source_day_metrics": _metric_counter_to_report(per_source_day),
        "sample_rows": sample_rows,
        "error_analysis": {
            "false_positive_cases": fp_cases,
            "false_negative_cases": fn_cases,
            "review_cases": review_cases,
            "unmatched_cases": unmatched_cases,
        },
    }


def evaluate_job(job_dir: str | Path) -> Dict[str, Any]:
    job_dir = resolve_project_path(job_dir)
    summary = _load_channel_summary(job_dir)
    channel = str(summary.get("channel") or "unknown")
    decisions = list(iter_jsonl(str(job_dir / "llm_decisions.jsonl")))
    selected_inputs = list(iter_jsonl(str(job_dir / "llm_inputs_selected.jsonl"))) if (job_dir / "llm_inputs_selected.jsonl").exists() else []
    all_inputs = list(iter_jsonl(str(job_dir / "llm_inputs_all.jsonl"))) if (job_dir / "llm_inputs_all.jsonl").exists() else selected_inputs

    report: Dict[str, Any] = {
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

    if channel == "csv_flow":
        csv_eval = _evaluate_csv_channel(decisions, selected_inputs)
        report["decision_eval"]["csv_metrics"] = {
            key: csv_eval[key]
            for key in [
                "tp",
                "fp",
                "tn",
                "fn",
                "precision",
                "recall",
                "f1",
                "matched_decisions",
                "unmatched_decisions",
                "per_label_metrics",
                "per_attack_family_metrics",
                "per_source_day_metrics",
            ]
        }
        report["error_analysis"] = csv_eval["error_analysis"]
        report["samples"] = {"decision_samples": csv_eval["sample_rows"][:20]}
        report["effect_eval"] = {
            "applicable": False,
            "reason": "csv_flow is a structured-flow decision evaluation channel, not a live mitigation-effect channel.",
        }
    else:
        suppression_eval = _evaluate_alert_suppression(job_dir, decisions, all_inputs)
        report["effect_eval"] = suppression_eval
        report["error_analysis"] = {"tool_failed_cases": report["execution_eval"]["tool_failed_cases"]}
        report["samples"] = {"suppression_samples": suppression_eval.get("per_decision", [])[:20]}

    out_path = job_dir / "evaluation_report.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
