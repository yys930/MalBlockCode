import argparse
import json
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()

from dataset.cic_ids2017_builder import build_cic_ids2017_malicious_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a cleaned malicious-only CIC-IDS-2017 TrafficLabelling dataset.")
    parser.add_argument("--input-dir", required=True, help="TrafficLabelling CSV directory")
    parser.add_argument("--output-dir", required=True, help="Directory for malicious merged/cleaned outputs")
    parser.add_argument("--dedupe-mode", choices=["flow", "exact"], default="flow", help="`flow` removes near-duplicate malicious flows in the same minute; `exact` only removes exact duplicate rows")
    parser.add_argument("--progress-every", type=int, default=200000, help="Print progress every N rows; 0 disables progress logs")
    args = parser.parse_args()

    result = build_cic_ids2017_malicious_dataset(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        dedupe_mode=args.dedupe_mode,
        progress_every=args.progress_every,
    )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
