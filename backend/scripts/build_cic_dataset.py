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

from dataset.cic_ids2017_builder import build_cic_ids2017_datasets


def main() -> None:
    parser = argparse.ArgumentParser(description="Build cleaned CIC-IDS-2017 TrafficLabelling datasets for malicious-only and mixed-eval CSV experiments.")
    parser.add_argument("--input-dir", required=True, help="TrafficLabelling CSV directory")
    parser.add_argument("--output-dir", required=True, help="Directory for malicious-only and mixed-eval outputs")
    parser.add_argument("--dedupe-mode", choices=["flow", "exact"], default="flow", help="`flow` removes near-duplicate malicious flows in the same minute; `exact` only removes exact duplicate rows")
    parser.add_argument("--mixed-eval-benign-ratio", type=float, default=1.0, help="How many benign rows to sample for mixed_eval relative to malicious rows, e.g. 1.0 means roughly 1:1")
    parser.add_argument("--mixed-eval-seed", type=int, default=42, help="Random seed used when sampling benign rows into mixed_eval_cleaned.csv")
    parser.add_argument("--progress-every", type=int, default=200000, help="Print progress every N rows; 0 disables progress logs")
    args = parser.parse_args()

    result = build_cic_ids2017_datasets(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        dedupe_mode=args.dedupe_mode,
        mixed_eval_benign_ratio=args.mixed_eval_benign_ratio,
        mixed_eval_seed=args.mixed_eval_seed,
        progress_every=args.progress_every,
    )
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
