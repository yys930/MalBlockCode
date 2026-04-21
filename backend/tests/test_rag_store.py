import json
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agent.rag_store import VectorRAGConfig, append_rag_case, retrieve_evidence


def _build_message() -> dict:
    return {
        "hints": {
            "attack_family": "scan",
            "top_signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
            "dominant_proto": "TCP",
        },
        "window": {
            "src_ip": "10.0.0.9",
            "window_start_epoch": 100,
            "window_end_epoch": 160,
            "window_start_iso": "2026-04-15T12:00:00+00:00",
            "window_end_iso": "2026-04-15T12:01:00+00:00",
            "hits": 12,
            "severity_min": 3,
            "dest_ports": [80, 443],
            "top_signatures": [
                {
                    "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                    "count": 12,
                }
            ],
            "top_dest_ips": [{"dest_ip": "192.168.10.5", "count": 8}],
            "dominant_proto": "TCP",
        },
        "evidence_window": {
            "src_ip": "10.0.0.9",
            "window_start_epoch": 100,
            "window_end_epoch": 160,
            "window_start_iso": "2026-04-15T12:00:00+00:00",
            "window_end_iso": "2026-04-15T12:01:00+00:00",
            "hits": 12,
            "severity_min": 3,
            "dest_ports": [80, 443],
            "top_signatures": [
                {
                    "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                    "count": 12,
                }
            ],
            "top_dest_ips": [{"dest_ip": "192.168.10.5", "count": 8}],
            "dominant_proto": "TCP",
        },
        "meta": {
            "job_id": "job_rag_test",
            "window_key": "10.0.0.9:100-160",
        },
    }


def _build_case(case_id: str, attack_family: str, top_signature: str, feedback_status: str = "evaluated") -> dict:
    return {
        "case_version": 3,
        "case_id": case_id,
        "window_key": case_id,
        "job_id": "historical_job",
        "incident_profile": {
            "hints": {
                "attack_family": attack_family,
                "top_signature": top_signature,
                "hits": 10,
                "severity_min": 3,
                "dominant_proto": "TCP",
            },
            "window": {
                "src_ip": "10.0.0.7",
                "window_start_epoch": 50,
                "window_end_epoch": 110,
                "window_start_iso": "2026-04-15T11:00:00+00:00",
                "window_end_iso": "2026-04-15T11:01:00+00:00",
                "hits": 10,
                "severity_min": 3,
                "dest_ports": [80, 443],
                "top_signatures": [{"signature": top_signature, "count": 10}],
                "top_dest_ips": [{"dest_ip": "192.168.10.5", "count": 6}],
            },
        },
        "historical_strategy": {
            "action": "block",
            "ttl_sec": 1800,
            "confidence": 0.91,
            "risk_score": 78,
            "labels": ["historical"],
            "reasons": ["historical reason"],
            "strategy": {
                "block_scope": "src_ip",
                "duration_tier": "medium",
                "priority": "high",
                "follow_up": "track_recurrence",
                "template_id": "recon_escalation",
                "escalation_level": 1,
            },
        },
        "execution_result": {
            "ok": True,
            "dry_run": True,
            "ip": "10.0.0.7",
            "ttl_sec": 1800,
        },
        "feedback": {
            "status": feedback_status,
            "is_effective": True,
            "false_positive": False,
            "alert_drop_ratio": 0.6,
        },
    }


class RAGStoreTests(unittest.TestCase):
    def test_retrieve_evidence_falls_back_to_archive_matching(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            archive_path = tmp_path / "decision_history.jsonl"
            archive_cases = [
                _build_case(
                    "scan-case",
                    "scan",
                    "ET SCAN Nmap Scripting Engine User-Agent Detected",
                ),
                _build_case(
                    "dos-case",
                    "dos",
                    "ET DOS Inbound GoldenEye Attack",
                ),
            ]
            with archive_path.open("w", encoding="utf-8") as f:
                for case in archive_cases:
                    f.write(json.dumps(case, ensure_ascii=False) + "\n")

            cfg = VectorRAGConfig(
                db_dir=str(tmp_path / "missing_chroma_db"),
                archive_path=str(archive_path),
                enable_archive_fallback=True,
                archive_fallback_min_score=0.2,
                archive_scan_limit=100,
            )

            retrieved = retrieve_evidence(_build_message(), cfg, top_k=2)

            self.assertGreaterEqual(len(retrieved), 1)
            self.assertEqual(retrieved[0]["window_key"], "scan-case")
            self.assertEqual(retrieved[0]["retrieval_method"], "archive_fallback")
            self.assertGreaterEqual(float(retrieved[0]["similarity"]), 0.2)

    def test_retrieve_evidence_keeps_pending_archive_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            archive_path = tmp_path / "decision_history.jsonl"
            archive_cases = [
                _build_case(
                    "pending-scan-case",
                    "scan",
                    "ET SCAN Nmap Scripting Engine User-Agent Detected",
                    feedback_status="pending_evaluation",
                )
            ]
            with archive_path.open("w", encoding="utf-8") as f:
                for case in archive_cases:
                    f.write(json.dumps(case, ensure_ascii=False) + "\n")

            cfg = VectorRAGConfig(
                db_dir=str(tmp_path / "missing_chroma_db"),
                archive_path=str(archive_path),
                enable_archive_fallback=True,
                archive_fallback_min_score=0.2,
                archive_scan_limit=100,
            )

            retrieved = retrieve_evidence(_build_message(), cfg, top_k=1)

            self.assertEqual(len(retrieved), 1)
            self.assertEqual(retrieved[0]["window_key"], "pending-scan-case")
            self.assertEqual(retrieved[0]["strategy_summary"]["status"], "pending_evaluation")

    def test_append_rag_case_keeps_archive_even_if_vector_upsert_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            archive_path = tmp_path / "decision_history.jsonl"
            cfg = VectorRAGConfig(
                db_dir=str(tmp_path / "chroma_db"),
                archive_path=str(archive_path),
                embedding_api_key="",
            )
            decision = {
                "action": "block",
                "ttl_sec": 1800,
                "confidence": 0.9,
                "risk_score": 80,
                "labels": ["executed"],
                "reasons": ["test decision"],
                "strategy": {
                    "block_scope": "src_ip",
                    "duration_tier": "medium",
                    "priority": "high",
                    "follow_up": "track_recurrence",
                    "execution_mode": "drop",
                    "template_id": "recon_escalation",
                    "escalation_level": 1,
                },
                "tool_result": {"ok": True, "dry_run": True},
            }

            result = append_rag_case(cfg, _build_message(), decision)

            self.assertTrue(result["archive_appended"])
            self.assertFalse(result["vector_upserted"])
            self.assertTrue(result["errors"])

            lines = archive_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            stored = json.loads(lines[0])
            self.assertEqual(stored["job_id"], "job_rag_test")
            self.assertEqual(stored["historical_strategy"]["action"], "block")
            self.assertNotIn("feedback", stored)


if __name__ == "__main__":
    unittest.main()
