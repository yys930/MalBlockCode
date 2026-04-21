from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from agent.window_reader import iter_jsonl
from eval.channel_eval import evaluate_job
from path_utils import resolve_project_path


MatchKey = Tuple[str, str, Tuple[int, ...], Tuple[str, ...], str]
MODE_RANK = {"none": 0, "watch": 1, "rate_limit": 2, "drop": 3}


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_single_job_eval(job_dir: Path) -> Dict[str, Any]:
    report_path = job_dir / "evaluation_report.json"
    if report_path.exists():
        return _read_json(report_path)
    return evaluate_job(job_dir)


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return list(iter_jsonl(str(path)))


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float | None = None) -> float | None:
    try:
        return float(value)
    except Exception:
        return default


def _normalized_ports(value: Any) -> Tuple[int, ...]:
    ports: List[int] = []
    for item in value or []:
        try:
            ports.append(int(item))
        except Exception:
            continue
    return tuple(sorted(set(ports)))


def _normalized_top_dest_ips(value: Any) -> Tuple[str, ...]:
    ips: List[str] = []
    for item in value or []:
        if isinstance(item, dict):
            ip = str(item.get("dest_ip") or "").strip()
        else:
            ip = str(item or "").strip()
        if ip:
            ips.append(ip)
    return tuple(sorted(set(ips)))


def _top_signature(item: Dict[str, Any]) -> str:
    signatures = item.get("top_signatures") or []
    if signatures and isinstance(signatures[0], dict):
        return str(signatures[0].get("signature") or "")
    evidence = item.get("evidence") or {}
    return str(evidence.get("top_signature") or "")


def _build_match_key_from_window(item: Dict[str, Any]) -> MatchKey:
    flow_uid = str(item.get("flow_uid") or (item.get("csv_features") or {}).get("flow_uid") or "").strip()
    if flow_uid:
        return ("flow_uid", flow_uid, tuple(), tuple(), "")
    return (
        str(item.get("src_ip") or "").strip(),
        str(item.get("window_start_iso") or "").strip(),
        _normalized_ports(item.get("dest_ports") or []),
        _normalized_top_dest_ips(item.get("top_dest_ips") or []),
        _top_signature(item),
    )


def _build_match_key_from_decision(decision: Dict[str, Any]) -> MatchKey:
    evidence = decision.get("evidence") or {}
    flow_uid = str(evidence.get("flow_uid") or "").strip()
    if flow_uid:
        return ("flow_uid", flow_uid, tuple(), tuple(), "")
    return (
        str(evidence.get("src_ip") or "").strip(),
        str(evidence.get("window_start_iso") or "").strip(),
        _normalized_ports(evidence.get("dest_ports") or []),
        _normalized_top_dest_ips(evidence.get("top_dest_ips") or []),
        str(evidence.get("top_signature") or "").strip(),
    )


def _load_job_artifacts(job_dir: str | Path) -> Dict[str, Any]:
    resolved = resolve_project_path(job_dir)
    if not resolved.exists():
        raise ValueError(f"job_dir does not exist: {resolved}")
    summary = _read_json(resolved / "channel_summary.json")
    if not summary:
        raise ValueError(f"channel_summary.json not found: {resolved / 'channel_summary.json'}")
    if str(summary.get("channel") or "") != "replay_online":
        raise ValueError(f"job is not replay_online: {resolved}")

    decisions = _load_jsonl(resolved / "llm_decisions.jsonl")
    if not decisions:
        raise ValueError(f"llm_decisions.jsonl not found or empty: {resolved / 'llm_decisions.jsonl'}")

    alerts_filtered = _load_jsonl(resolved / "alerts_filtered.jsonl")
    inputs_all = _load_jsonl(resolved / "llm_inputs_all.jsonl")
    evaluation = _ensure_single_job_eval(resolved)
    replay_summary = _read_json(resolved / "summary.json")

    return {
        "job_dir": str(resolved),
        "summary": summary,
        "evaluation": evaluation,
        "replay_summary": replay_summary,
        "decisions": decisions,
        "alerts_filtered": alerts_filtered,
        "inputs_all": inputs_all,
    }


def _compatibility_checks(exec_job: Dict[str, Any], baseline_job: Dict[str, Any]) -> Dict[str, Any]:
    exec_summary = exec_job["summary"]
    base_summary = baseline_job["summary"]
    exec_agg = exec_summary.get("aggregation") or {}
    base_agg = base_summary.get("aggregation") or {}
    exec_replay = exec_summary.get("replay") or {}
    base_replay = base_summary.get("replay") or {}

    differences: List[str] = []

    checks = {
        "same_channel": (exec_summary.get("channel") == base_summary.get("channel"), "channel differs"),
        "same_source_path": (exec_summary.get("source_path") == base_summary.get("source_path"), "source_path differs"),
        "same_window_sec": (exec_agg.get("window_sec") == base_agg.get("window_sec"), "window_sec differs"),
        "same_min_hits": (exec_agg.get("min_hits") == base_agg.get("min_hits"), "min_hits differs"),
        "same_topk": (exec_agg.get("topk") == base_agg.get("topk"), "topk differs"),
        "same_suricata_interface": (exec_replay.get("suricata_interface") == base_replay.get("suricata_interface"), "suricata_interface differs"),
        "same_replay_interface": (exec_replay.get("replay_interface") == base_replay.get("replay_interface"), "replay_interface differs"),
        "same_replay_netns": (exec_replay.get("replay_netns") == base_replay.get("replay_netns"), "replay_netns differs"),
        "same_selected_window_count": (exec_agg.get("selected_groups") == base_agg.get("selected_groups"), "selected_groups differs"),
    }

    report: Dict[str, Any] = {}
    for name, (ok, message) in checks.items():
        report[name] = bool(ok)
        if not ok:
            differences.append(message)
    report["compatible"] = len(differences) == 0
    report["differences"] = differences
    return report


def _tool_result(decision: Dict[str, Any]) -> Dict[str, Any]:
    result = decision.get("tool_result")
    return result if isinstance(result, dict) else {}


def _decision_summary(decision: Dict[str, Any]) -> Dict[str, Any]:
    strategy = decision.get("strategy") or {}
    tool_result = _tool_result(decision)
    evidence = decision.get("evidence") or {}
    execution_mode = str(strategy.get("execution_mode") or "none")
    return {
        "match_key": _build_match_key_from_decision(decision),
        "src_ip": evidence.get("src_ip"),
        "window_start_iso": evidence.get("window_start_iso"),
        "action": str(decision.get("action") or ""),
        "execution_mode": execution_mode,
        "ttl_sec": _safe_int(decision.get("ttl_sec"), 0),
        "decision_state": str(decision.get("decision_state") or ""),
        "dry_run": bool(tool_result.get("dry_run")),
        "tool_ok": bool(tool_result.get("ok")),
        "skipped_execution": bool(tool_result.get("skipped_execution")),
        "covered_by_existing_action": bool(tool_result.get("covered_by_existing_action")),
        "strength": MODE_RANK.get(execution_mode, 0),
        "raw": decision,
    }


def _match_decisions(exec_decisions: List[Dict[str, Any]], baseline_decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
    exec_map = {_build_match_key_from_decision(item): item for item in exec_decisions}
    base_map = {_build_match_key_from_decision(item): item for item in baseline_decisions}

    matched_keys = sorted(set(exec_map) & set(base_map))
    exec_only = sorted(set(exec_map) - set(base_map))
    baseline_only = sorted(set(base_map) - set(exec_map))

    matched_pairs = [
        {
            "key": key,
            "exec": _decision_summary(exec_map[key]),
            "baseline": _decision_summary(base_map[key]),
        }
        for key in matched_keys
    ]

    return {
        "matched_pairs": matched_pairs,
        "matched_count": len(matched_pairs),
        "exec_only_keys": exec_only,
        "baseline_only_keys": baseline_only,
        "exec_decision_count": len(exec_decisions),
        "baseline_decision_count": len(baseline_decisions),
        "match_rate_exec": round(len(matched_pairs) / len(exec_decisions), 6) if exec_decisions else None,
        "match_rate_baseline": round(len(matched_pairs) / len(baseline_decisions), 6) if baseline_decisions else None,
    }


def _classify_pair_outcomes(pairs: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = Counter()
    diff_cases: List[Dict[str, Any]] = []

    for pair in pairs:
        exec_item = pair["exec"]
        base_item = pair["baseline"]
        same_action = exec_item["action"] == base_item["action"]
        same_mode = exec_item["execution_mode"] == base_item["execution_mode"]

        if same_action and same_mode:
            counts["same_action_same_mode"] += 1
        elif same_action:
            counts["same_action_different_mode"] += 1
        else:
            counts["different_action"] += 1

        if exec_item["strength"] > base_item["strength"]:
            counts["exec_stronger_than_baseline"] += 1
        elif exec_item["strength"] < base_item["strength"]:
            counts["baseline_stronger_than_exec"] += 1

        if not same_action or not same_mode:
            if len(diff_cases) < 20:
                diff_cases.append(
                    {
                        "src_ip": exec_item["src_ip"],
                        "window_start_iso": exec_item["window_start_iso"],
                        "exec_action": exec_item["action"],
                        "exec_execution_mode": exec_item["execution_mode"],
                        "baseline_action": base_item["action"],
                        "baseline_execution_mode": base_item["execution_mode"],
                        "exec_ttl_sec": exec_item["ttl_sec"],
                        "baseline_ttl_sec": base_item["ttl_sec"],
                    }
                )

    return {**dict(counts), "different_action_cases": diff_cases}


def _effect_pairs(effect_eval: Dict[str, Any]) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    pairs: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for item in effect_eval.get("per_decision", []) or []:
        key = (
            str(item.get("src_ip") or "").strip(),
            str(item.get("decision_window_start_iso") or "").strip(),
            str(item.get("execution_mode") or "").strip(),
        )
        pairs[key] = item
    return pairs


def _compare_execution_effects(exec_job: Dict[str, Any], baseline_job: Dict[str, Any], pairs: List[Dict[str, Any]]) -> Dict[str, Any]:
    exec_effect = _effect_pairs((exec_job.get("evaluation") or {}).get("effect_eval") or {})
    baseline_effect = _effect_pairs((baseline_job.get("evaluation") or {}).get("effect_eval") or {})

    deltas: List[float] = []
    improved = unchanged = worse = 0
    samples: List[Dict[str, Any]] = []

    for pair in pairs:
        exec_item = pair["exec"]
        base_item = pair["baseline"]
        effect_key = (exec_item["src_ip"] or "", exec_item["window_start_iso"] or "", exec_item["execution_mode"] or "")
        exec_effect_item = exec_effect.get(effect_key)
        base_effect_item = baseline_effect.get(effect_key)
        if not exec_effect_item or not base_effect_item:
            continue
        exec_ratio = _safe_float(exec_effect_item.get("suppression_ratio"))
        base_ratio = _safe_float(base_effect_item.get("suppression_ratio"))
        if exec_ratio is None or base_ratio is None:
            continue
        delta = round(exec_ratio - base_ratio, 6)
        deltas.append(delta)
        if delta > 0:
            improved += 1
        elif delta < 0:
            worse += 1
        else:
            unchanged += 1
        if len(samples) < 20 and delta != 0:
            samples.append(
                {
                    "src_ip": exec_item["src_ip"],
                    "window_start_iso": exec_item["window_start_iso"],
                    "execution_mode": exec_item["execution_mode"],
                    "exec_suppression_ratio": exec_ratio,
                    "baseline_suppression_ratio": base_ratio,
                    "delta": delta,
                }
            )

    exec_eval = (exec_job.get("evaluation") or {}).get("effect_eval") or {}
    base_eval = (baseline_job.get("evaluation") or {}).get("effect_eval") or {}

    return {
        "applicable": True,
        "exec_mean_suppression_ratio": exec_eval.get("mean_suppression_ratio"),
        "baseline_mean_suppression_ratio": base_eval.get("mean_suppression_ratio"),
        "delta_mean_suppression_ratio": (
            round(_safe_float(exec_eval.get("mean_suppression_ratio"), 0.0) - _safe_float(base_eval.get("mean_suppression_ratio"), 0.0), 6)
            if exec_eval.get("mean_suppression_ratio") is not None and base_eval.get("mean_suppression_ratio") is not None
            else None
        ),
        "matched_effect_pairs": len(deltas),
        "improved_pairs": improved,
        "unchanged_pairs": unchanged,
        "worse_pairs": worse,
        "sample_improvements": samples,
    }


def _compare_alert_coverage(exec_job: Dict[str, Any], baseline_job: Dict[str, Any]) -> Dict[str, Any]:
    exec_summary = exec_job.get("replay_summary") or {}
    baseline_summary = baseline_job.get("replay_summary") or {}
    exec_filtered = _safe_int(exec_summary.get("alert_count_filtered") or exec_summary.get("stream_alert_count_filtered"), 0)
    baseline_filtered = _safe_int(baseline_summary.get("alert_count_filtered") or baseline_summary.get("stream_alert_count_filtered"), 0)
    delta = exec_filtered - baseline_filtered
    ratio = round(delta / baseline_filtered, 6) if baseline_filtered > 0 else None
    return {
        "exec_filtered_alerts": exec_filtered,
        "baseline_filtered_alerts": baseline_filtered,
        "delta_filtered_alerts": delta,
        "delta_filtered_alert_ratio": ratio,
    }


def _compare_summary_metrics(exec_eval: Dict[str, Any], baseline_eval: Dict[str, Any]) -> Dict[str, Any]:
    exec_execution = exec_eval.get("execution_eval") or {}
    baseline_execution = baseline_eval.get("execution_eval") or {}
    exec_effective = _safe_int(exec_execution.get("effective_enforcement_count", exec_execution.get("new_enforcement_count")), 0)
    baseline_effective = _safe_int(baseline_execution.get("effective_enforcement_count", baseline_execution.get("new_enforcement_count")), 0)
    return {
        "tool_success_count_delta": _safe_int(exec_execution.get("tool_success_count"), 0) - _safe_int(baseline_execution.get("tool_success_count"), 0),
        "effective_enforcement_count_delta": exec_effective - baseline_effective,
        "repeat_enforcement_count_delta": _safe_int(exec_execution.get("repeat_enforcement_count"), 0) - _safe_int(baseline_execution.get("repeat_enforcement_count"), 0),
        "unique_blocked_ip_count_delta": _safe_int(exec_execution.get("unique_blocked_ip_count"), 0) - _safe_int(baseline_execution.get("unique_blocked_ip_count"), 0),
        "mean_suppression_ratio_delta": (
            round(_safe_float((exec_eval.get("effect_eval") or {}).get("mean_suppression_ratio"), 0.0) - _safe_float((baseline_eval.get("effect_eval") or {}).get("mean_suppression_ratio"), 0.0), 6)
            if (exec_eval.get("effect_eval") or {}).get("mean_suppression_ratio") is not None and (baseline_eval.get("effect_eval") or {}).get("mean_suppression_ratio") is not None
            else None
        ),
    }


def _dry_run_fraction(decisions: Iterable[Dict[str, Any]]) -> float | None:
    considered = 0
    dry_run = 0
    for item in decisions:
        result = _tool_result(item)
        if not result:
            continue
        considered += 1
        if result.get("dry_run") is True:
            dry_run += 1
    if considered == 0:
        return None
    return round(dry_run / considered, 6)


def _execution_impact(exec_job: Dict[str, Any], baseline_job: Dict[str, Any], pairs: List[Dict[str, Any]]) -> Dict[str, Any]:
    enforced_pairs = 0
    dry_run_pairs = 0
    covered_pairs = 0
    effect_pairs = 0

    for pair in pairs:
        exec_item = pair["exec"]
        base_item = pair["baseline"]
        if exec_item["tool_ok"] and not exec_item["dry_run"]:
            enforced_pairs += 1
        if base_item["tool_ok"] and base_item["dry_run"]:
            dry_run_pairs += 1
        if exec_item["covered_by_existing_action"] or base_item["covered_by_existing_action"]:
            covered_pairs += 1
        if exec_item["tool_ok"] != base_item["tool_ok"] or exec_item["dry_run"] != base_item["dry_run"]:
            effect_pairs += 1

    return {
        "enforced_pairs": enforced_pairs,
        "dry_run_pairs": dry_run_pairs,
        "exec_non_dry_run_fraction": _dry_run_fraction(exec_job.get("decisions", [])),
        "baseline_dry_run_fraction": _dry_run_fraction(baseline_job.get("decisions", [])),
        "pairs_with_execution_only_effect": effect_pairs,
        "covered_by_existing_action_pairs": covered_pairs,
    }


def evaluate_replay_comparison(exec_job_dir: str | Path, baseline_job_dir: str | Path) -> Dict[str, Any]:
    exec_job = _load_job_artifacts(exec_job_dir)
    baseline_job = _load_job_artifacts(baseline_job_dir)

    compatibility = _compatibility_checks(exec_job, baseline_job)
    matching = _match_decisions(exec_job["decisions"], baseline_job["decisions"])
    pair_outcomes = _classify_pair_outcomes(matching["matched_pairs"])
    suppression = _compare_execution_effects(exec_job, baseline_job, matching["matched_pairs"])
    summary_delta = _compare_summary_metrics(exec_job["evaluation"], baseline_job["evaluation"])
    alert_volume = _compare_alert_coverage(exec_job, baseline_job)
    execution_impact = _execution_impact(exec_job, baseline_job, matching["matched_pairs"])

    report = {
        "report_version": "v1",
        "comparison_meta": {
            "mode": "execution_vs_no_execution",
            "generated_at": int(time.time()),
            "compatible": compatibility["compatible"],
            "warnings": compatibility["differences"],
        },
        "exec_job": {
            "job_id": (exec_job["summary"] or {}).get("job_id"),
            "job_dir": exec_job["job_dir"],
            "channel": (exec_job["summary"] or {}).get("channel"),
            "source_path": (exec_job["summary"] or {}).get("source_path"),
        },
        "baseline_job": {
            "job_id": (baseline_job["summary"] or {}).get("job_id"),
            "job_dir": baseline_job["job_dir"],
            "channel": (baseline_job["summary"] or {}).get("channel"),
            "source_path": (baseline_job["summary"] or {}).get("source_path"),
        },
        "compatibility": compatibility,
        "matching": {
            "exec_decision_count": matching["exec_decision_count"],
            "baseline_decision_count": matching["baseline_decision_count"],
            "matched_pairs": matching["matched_count"],
            "exec_only": len(matching["exec_only_keys"]),
            "baseline_only": len(matching["baseline_only_keys"]),
            "match_rate_exec": matching["match_rate_exec"],
            "match_rate_baseline": matching["match_rate_baseline"],
        },
        "summary_delta": summary_delta,
        "pair_outcomes": {
            key: pair_outcomes.get(key, 0)
            for key in (
                "same_action_same_mode",
                "same_action_different_mode",
                "different_action",
                "exec_stronger_than_baseline",
                "baseline_stronger_than_exec",
            )
        },
        "execution_impact": execution_impact,
        "suppression_comparison": suppression,
        "alert_volume_comparison": alert_volume,
        "samples": {
            "different_action_cases": pair_outcomes.get("different_action_cases", []),
            "matching_failures": [
                {"side": "exec", "match_key": repr(key)} for key in matching["exec_only_keys"][:10]
            ]
            + [
                {"side": "baseline", "match_key": repr(key)} for key in matching["baseline_only_keys"][:10]
            ],
            "suppression_improvement_cases": suppression.get("sample_improvements", []),
        },
    }
    return report
