import sys
import unittest
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agent.message_builder import build_message


class MessageBuilderTests(unittest.TestCase):
    def test_build_message_keeps_csv_label_fields(self) -> None:
        window = {
            "channel": "csv_flow",
            "flow_uid": "day:1",
            "source_day": "day",
            "source_file": "flows.csv",
            "source_row_id": 1,
            "src_ip": "10.0.0.1",
            "window_sec": 1,
            "window_start_epoch": 1,
            "window_end_epoch": 2,
            "window_start_iso": "2026-04-20T12:00:00+00:00",
            "window_end_iso": "2026-04-20T12:00:01+00:00",
            "hits": 1,
            "severity_min": 2,
            "alert_density_per_sec": 10.0,
            "burst_duration_sec": 1,
            "unique_dest_ip_count": 1,
            "unique_dest_port_count": 1,
            "signature_diversity": 1,
            "dominant_proto": "TCP",
            "top_signatures": [{"signature": "CSV_FLOW::Bot", "count": 1}],
            "top_categories": [{"category": "botnet", "count": 1}],
            "dest_ports": [80],
            "top_dest_port_counts": [{"dest_port": 80, "count": 1}],
            "top_dest_ips": [{"dest_ip": "8.8.8.8", "count": 1}],
            "csv_features": {
                "label": "Bot",
                "label_is_malicious": True,
                "attack_family": "botnet",
                "source_day": "day",
                "flow_uid": "day:1",
            },
        }

        message = build_message(window)

        self.assertIn("csv_features", message["evidence_window"])
        self.assertNotIn("label_is_malicious", message["evidence_window"]["csv_features"])
        self.assertEqual(message["evidence_window"]["csv_features"]["label"], "Bot")
        self.assertEqual(message["evidence_window"]["csv_features"]["attack_family"], "botnet")
        self.assertEqual(message["evidence_window"]["flow_uid"], "day:1")
        self.assertEqual(message["evidence_window"]["source_day"], "day")
        self.assertEqual(message["evidence_window"]["source_file"], "flows.csv")
        self.assertEqual(message["evidence_window"]["severity_min"], 2)
        self.assertEqual(message["hints"]["attack_family"], "botnet")
        self.assertEqual(message["hints"]["top_signature"], "CSV_FLOW::Bot")

    def test_build_message_keeps_non_csv_windows_unchanged(self) -> None:
        window = {
            "src_ip": "10.0.0.2",
            "window_sec": 60,
            "window_start_epoch": 10,
            "window_end_epoch": 70,
            "window_start_iso": "2026-04-20T12:01:00+00:00",
            "window_end_iso": "2026-04-20T12:02:00+00:00",
            "hits": 5,
            "severity_min": 2,
            "alert_density_per_sec": 2.5,
            "burst_duration_sec": 60,
            "unique_dest_ip_count": 2,
            "unique_dest_port_count": 2,
            "signature_diversity": 1,
            "dominant_proto": "TCP",
            "top_signatures": [{"signature": "ET SCAN Nmap", "count": 5}],
            "top_categories": [{"category": "scan", "count": 5}],
            "dest_ports": [80, 443],
            "top_dest_port_counts": [{"dest_port": 80, "count": 3}],
            "top_dest_ips": [{"dest_ip": "8.8.8.8", "count": 3}],
        }

        message = build_message(window)

        self.assertEqual(message["evidence_window"]["severity_min"], 2)
        self.assertTrue(message["evidence_window"]["top_signatures"])
        self.assertEqual(message["hints"]["attack_family"], "scan")
        self.assertEqual(message["hints"]["top_signature"], "ET SCAN Nmap")


if __name__ == "__main__":
    unittest.main()
