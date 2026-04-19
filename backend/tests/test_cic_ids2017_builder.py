import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from dataset.cic_ids2017_builder import build_cic_ids2017_datasets


class CICIDS2017BuilderTests(unittest.TestCase):
    def test_invalid_rows_are_dropped_and_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            input_dir = tmp_path / "input"
            output_dir = tmp_path / "output"
            input_dir.mkdir()

            csv_path = input_dir / "Tuesday-WorkingHours.pcap_ISCX.csv"
            with csv_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Label"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "Timestamp": "2017-07-04 12:15:00",
                        "Source IP": "10.0.0.10",
                        "Destination IP": "8.8.8.8",
                        "Source Port": "12345",
                        "Destination Port": "80",
                        "Protocol": "6",
                        "Label": "DoS Hulk",
                    }
                )
                writer.writerow(
                    {
                        "Timestamp": "2017-07-04 12:16:00",
                        "Source IP": "10.0.0.11",
                        "Destination IP": "8.8.4.4",
                        "Source Port": "12346",
                        "Destination Port": "443",
                        "Protocol": "6",
                        "Label": "",
                    }
                )
                writer.writerow(
                    {
                        "Timestamp": "not-a-timestamp",
                        "Source IP": "10.0.0.12",
                        "Destination IP": "1.1.1.1",
                        "Source Port": "12347",
                        "Destination Port": "53",
                        "Protocol": "17",
                        "Label": "PortScan",
                    }
                )
                writer.writerow(
                    {
                        "Timestamp": "2017-07-04 12:17:00",
                        "Source IP": "10.0.0.13",
                        "Destination IP": "9.9.9.9",
                        "Source Port": "12348",
                        "Destination Port": "53",
                        "Protocol": "17",
                        "Label": "BENIGN",
                    }
                )

            result = build_cic_ids2017_datasets(
                input_dir=input_dir,
                output_dir=output_dir,
                mixed_eval_benign_ratio=1.0,
                mixed_eval_seed=42,
                progress_every=0,
            )

            self.assertEqual(result.total_rows_read, 4)
            self.assertEqual(result.invalid_rows_dropped, 2)
            self.assertEqual(result.malicious_rows_written, 1)
            self.assertEqual(result.benign_candidate_rows_written, 1)
            self.assertEqual(result.mixed_eval_total_rows_written, 2)

            manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
            self.assertEqual(manifest["invalid_reason_counts"]["missing_label"], 1)
            self.assertEqual(manifest["invalid_reason_counts"]["invalid_timestamp"], 1)

            with Path(result.malicious_dataset_path).open("r", encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["label"], "DoS Hulk")
            self.assertEqual(rows[0]["src_ip"], "10.0.0.10")

    def test_missing_source_csvs_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            input_dir = tmp_path / "empty-input"
            output_dir = tmp_path / "output"
            input_dir.mkdir()

            with self.assertRaises(FileNotFoundError):
                build_cic_ids2017_datasets(
                    input_dir=input_dir,
                    output_dir=output_dir,
                    progress_every=0,
                )

    def test_parent_csvs_dir_auto_resolves_trafficlabelling(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            root_input_dir = tmp_path / "CSVs"
            traffic_dir = root_input_dir / "TrafficLabelling"
            output_dir = tmp_path / "output"
            traffic_dir.mkdir(parents=True)

            csv_path = traffic_dir / "Monday-WorkingHours.pcap_ISCX.csv"
            with csv_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Label"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "Timestamp": "03/07/2017 08:55:58",
                        "Source IP": "8.254.250.126",
                        "Destination IP": "192.168.10.5",
                        "Source Port": "80",
                        "Destination Port": "49188",
                        "Protocol": "6",
                        "Label": "BENIGN",
                    }
                )

            result = build_cic_ids2017_datasets(
                input_dir=root_input_dir,
                output_dir=output_dir,
                progress_every=0,
            )
            manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
            self.assertEqual(manifest["requested_input_dir"], str(root_input_dir.resolve()))
            self.assertEqual(manifest["input_dir"], str(traffic_dir.resolve()))
            self.assertEqual(result.benign_candidate_rows_written, 1)
            self.assertEqual(result.malicious_rows_written, 0)


if __name__ == "__main__":
    unittest.main()
