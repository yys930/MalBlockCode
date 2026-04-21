import csv
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from pipeline.csv_flow_adapter import build_csv_flow_inputs


class CSVFlowAdapterTests(unittest.TestCase):
    def test_topk_zero_keeps_all_malicious_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            csv_path = tmp_path / "flows.csv"
            job_dir = tmp_path / "job"
            job_dir.mkdir()

            with csv_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Label"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "Timestamp": "2026-04-15 12:00:00",
                        "Source IP": "10.0.0.10",
                        "Destination IP": "8.8.8.8",
                        "Source Port": "11111",
                        "Destination Port": "80",
                        "Protocol": "6",
                        "Label": "PortScan",
                    }
                )
                writer.writerow(
                    {
                        "Timestamp": "2026-04-15 12:00:01",
                        "Source IP": "10.0.0.11",
                        "Destination IP": "8.8.4.4",
                        "Source Port": "11112",
                        "Destination Port": "443",
                        "Protocol": "6",
                        "Label": "DoS Hulk",
                    }
                )
                writer.writerow(
                    {
                        "Timestamp": "2026-04-15 12:00:02",
                        "Source IP": "10.0.0.12",
                        "Destination IP": "1.1.1.1",
                        "Source Port": "11113",
                        "Destination Port": "53",
                        "Protocol": "17",
                        "Label": "BENIGN",
                    }
                )

            result = build_csv_flow_inputs(
                csv_path=csv_path,
                job_dir=job_dir,
                include_benign=False,
                topk=0,
                selection_mode="priority",
                seed=42,
            )

            self.assertEqual(result.total_rows, 3)
            self.assertEqual(result.malicious_rows, 2)
            self.assertEqual(result.selected_rows, 2)

    def test_topk_zero_keeps_all_rows_for_random_sampling(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            csv_path = tmp_path / "flows.csv"
            job_dir = tmp_path / "job"
            job_dir.mkdir()

            with csv_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Label"],
                )
                writer.writeheader()
                for idx, label in enumerate(["BENIGN", "PortScan", "DoS Hulk"], start=1):
                    writer.writerow(
                        {
                            "Timestamp": f"2026-04-15 12:00:0{idx}",
                            "Source IP": f"10.0.0.{idx}",
                            "Destination IP": "8.8.8.8",
                            "Source Port": f"1100{idx}",
                            "Destination Port": "80",
                            "Protocol": "6",
                            "Label": label,
                        }
                    )

            result = build_csv_flow_inputs(
                csv_path=csv_path,
                job_dir=job_dir,
                include_benign=True,
                topk=0,
                selection_mode="random",
                seed=42,
            )

            self.assertEqual(result.total_rows, 3)
            self.assertEqual(result.selected_rows, 3)

    def test_stratified_label_balances_benign_and_malicious(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            csv_path = tmp_path / "flows.csv"
            job_dir = tmp_path / "job"
            job_dir.mkdir()

            with csv_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Label"],
                )
                writer.writeheader()
                labels = [
                    "BENIGN",
                    "BENIGN",
                    "BENIGN",
                    "PortScan",
                    "PortScan",
                    "DoS Hulk",
                    "DoS Hulk",
                    "Bot",
                ]
                for idx, label in enumerate(labels, start=1):
                    writer.writerow(
                        {
                            "Timestamp": f"2026-04-15 12:00:{idx:02d}",
                            "Source IP": f"10.0.0.{idx}",
                            "Destination IP": "8.8.8.8",
                            "Source Port": f"1200{idx}",
                            "Destination Port": "80",
                            "Protocol": "6",
                            "Label": label,
                        }
                    )

            result = build_csv_flow_inputs(
                csv_path=csv_path,
                job_dir=job_dir,
                include_benign=True,
                topk=4,
                selection_mode="stratified_label",
                seed=42,
            )

            selected_path = job_dir / "llm_inputs_selected.jsonl"
            selected_lines = [line for line in selected_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            benign_count = sum('"label_is_malicious": false' in line for line in selected_lines)
            malicious_count = sum('"label_is_malicious": true' in line for line in selected_lines)

            self.assertEqual(result.selected_rows, 4)
            self.assertEqual(benign_count, 2)
            self.assertEqual(malicious_count, 2)


if __name__ == "__main__":
    unittest.main()
