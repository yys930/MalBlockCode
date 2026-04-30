import json
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from eval.channel_eval import evaluate_job


class ChannelEvalTests(unittest.TestCase):
    def test_csv_eval_matches_inputs_when_decision_omits_flow_uid_and_ports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir)
            (job_dir / "channel_summary.json").write_text(
                json.dumps(
                    {
                        "channel": "csv_flow",
                        "job_id": "job-1",
                        "source_path": "dummy.csv",
                        "csv_flow_input": {
                            "total_rows": 2,
                            "selected_rows": 2,
                            "malicious_rows": 1,
                            "benign_rows": 1,
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            selected_inputs = [
                {
                    "channel": "csv_flow",
                    "flow_uid": "day:1",
                    "src_ip": "10.0.0.1",
                    "window_start_iso": "2026-04-20T12:00:00+00:00",
                    "top_dest_ips": [{"dest_ip": "8.8.8.8"}],
                    "dest_ports": [80],
                    "top_signatures": [{"signature": "CSV_FLOW::Bot", "count": 1}],
                    "csv_features": {
                        "flow_uid": "day:1",
                        "label": "Bot",
                        "label_is_malicious": True,
                        "attack_family": "botnet",
                        "source_day": "day",
                        "src_port": 12345,
                        "dst_ip": "8.8.8.8",
                    },
                },
                {
                    "channel": "csv_flow",
                    "flow_uid": "",
                    "src_ip": "10.0.0.2",
                    "window_start_iso": "2026-04-20T12:01:00+00:00",
                    "top_dest_ips": [{"dest_ip": "1.1.1.1"}],
                    "dest_ports": [53],
                    "top_signatures": [{"signature": "CSV_FLOW::BENIGN", "count": 1}],
                    "csv_features": {
                        "label": "BENIGN",
                        "label_is_malicious": False,
                        "attack_family": "benign",
                        "source_day": "day",
                        "src_port": 54321,
                        "dst_ip": "1.1.1.1",
                    },
                },
            ]
            decisions = [
                {
                    "action": "block",
                    "strategy": {"execution_mode": "drop"},
                    "decision_state": "new_block",
                    "ttl_reason": "runtime_repair_execution",
                    "evidence": {
                        "flow_uid": "day:1",
                        "src_ip": "10.0.0.1",
                        "window_start_iso": "2026-04-20T12:00:00+00:00",
                        "top_signatures": [{"signature": "CSV_FLOW::Bot", "count": 1}],
                        "top_dest_ips": [{"dest_ip": "8.8.8.8"}],
                        "dest_ports": [80],
                        "src_port": 12345,
                        "dst_ip": "8.8.8.8",
                    },
                    "tool_result": {"ok": True, "action": "block_ip", "ip": "10.0.0.1"},
                },
                {
                    "action": "monitor",
                    "strategy": {"execution_mode": "watch"},
                    "evidence": {
                        "src_ip": "10.0.0.2",
                        "window_start_iso": "2026-04-20T12:01:00+00:00",
                        "top_signatures": [{"signature": "CSV_FLOW::BENIGN", "count": 1}],
                        "top_dest_ips": [{"dest_ip": "1.1.1.1"}],
                        "dest_ports": [53],
                    },
                    "tool_result": {
                        "ok": True,
                        "action": "watch_ip",
                        "ip": "10.0.0.2",
                        "covered_by_existing_action": True,
                    },
                },
            ]
            (job_dir / "llm_inputs_selected.jsonl").write_text(
                "\n".join(json.dumps(item, ensure_ascii=False) for item in selected_inputs) + "\n",
                encoding="utf-8",
            )
            (job_dir / "llm_decisions.jsonl").write_text(
                "\n".join(json.dumps(item, ensure_ascii=False) for item in decisions) + "\n",
                encoding="utf-8",
            )

            report = evaluate_job(job_dir)

            self.assertEqual(report["decision_eval"]["csv_metrics"]["matched_decisions"], 2)
            self.assertEqual(report["decision_eval"]["csv_metrics"]["unmatched_decisions"], 0)
            self.assertEqual(report["decision_eval"]["risk_detection_metrics"]["fp"], 1)
            self.assertEqual(report["decision_eval"]["strong_mitigation_metrics"]["tn"], 1)

    def test_execution_eval_uses_new_enforcement_and_unknown_bucket(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir)
            (job_dir / "channel_summary.json").write_text(
                json.dumps(
                    {
                        "channel": "offline",
                        "job_id": "job-2",
                        "source_path": "dummy.pcap",
                        "aggregation": {
                            "surviving_windows": 2,
                            "selected_windows": 2,
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            decisions = [
                {
                    "action": "block",
                    "strategy": {"execution_mode": "drop"},
                    "decision_state": "new_block",
                    "ttl_reason": "policy",
                    "tool_result": {"ok": True, "action": "block_ip", "ip": "10.0.0.1"},
                },
                {
                    "action": "monitor",
                    "strategy": {"execution_mode": "watch"},
                    "tool_result": {
                        "ok": True,
                        "action": "watch_ip",
                        "ip": "10.0.0.2",
                        "already_present": True,
                    },
                },
            ]
            (job_dir / "llm_decisions.jsonl").write_text(
                "\n".join(json.dumps(item, ensure_ascii=False) for item in decisions) + "\n",
                encoding="utf-8",
            )
            (job_dir / "llm_inputs_selected.jsonl").write_text("", encoding="utf-8")
            (job_dir / "llm_inputs_all.jsonl").write_text("", encoding="utf-8")

            report = evaluate_job(job_dir)
            execution_eval = report["execution_eval"]

            self.assertEqual(execution_eval["tool_success_count"], 2)
            self.assertEqual(execution_eval["new_enforcement_count"], 1)
            self.assertEqual(execution_eval["effective_enforcement_count"], 1)
            self.assertEqual(execution_eval["repeat_enforcement_count"], 1)
            self.assertEqual(execution_eval["decision_state_distribution"]["new_block"], 1)
            self.assertEqual(execution_eval["decision_state_distribution"]["unknown"], 1)
            self.assertEqual(execution_eval["ttl_reason_distribution"]["policy"], 1)
            self.assertEqual(execution_eval["ttl_reason_distribution"]["unknown"], 1)
            self.assertEqual(execution_eval["decision_to_execution_consistency"], 1.0)

    def test_execution_consistency_uses_paper_formula(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir)
            (job_dir / "channel_summary.json").write_text(
                json.dumps(
                    {
                        "channel": "offline",
                        "job_id": "job-3",
                        "source_path": "dummy.pcap",
                        "aggregation": {
                            "surviving_windows": 3,
                            "selected_windows": 3,
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            decisions = [
                {
                    "action": "block",
                    "strategy": {"execution_mode": "drop"},
                    "tool_result": {"ok": False, "action": "block_ip", "error": "boom"},
                },
                {
                    "action": "block",
                    "strategy": {"execution_mode": "none"},
                },
                {
                    "action": "monitor",
                    "strategy": {"execution_mode": "watch"},
                    "tool_result": {"ok": True, "action": "watch_ip", "ip": "10.0.0.3"},
                },
            ]
            (job_dir / "llm_decisions.jsonl").write_text(
                "\n".join(json.dumps(item, ensure_ascii=False) for item in decisions) + "\n",
                encoding="utf-8",
            )
            (job_dir / "llm_inputs_selected.jsonl").write_text("", encoding="utf-8")
            (job_dir / "llm_inputs_all.jsonl").write_text("", encoding="utf-8")

            report = evaluate_job(job_dir)
            execution_eval = report["execution_eval"]

            self.assertEqual(execution_eval["tool_success_count"], 1)
            self.assertEqual(execution_eval["tool_failure_count"], 1)
            self.assertEqual(execution_eval["decision_to_execution_consistency"], 0.666667)


if __name__ == "__main__":
    unittest.main()
