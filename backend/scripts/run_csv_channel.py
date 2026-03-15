import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

load_dotenv()

from pipeline.channel_runner import run_csv_channel


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run CSV flow channel directly from CIC flow records or cleaned datasets such as malicious_merged_cleaned.csv."
    )
    parser.add_argument("--csv", required=True)
    parser.add_argument("--job-id", default="")
    parser.add_argument("--topk", type=int, default=5000)
    parser.add_argument("--exclude-benign", action="store_true")
    parser.add_argument("--selection-mode", choices=["priority", "random", "stratified_label"], default="priority")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--rag-top-k", type=int, default=3)
    args = parser.parse_args()

    summary = run_csv_channel(
        csv_path=args.csv,
        job_id=args.job_id,
        include_benign=not args.exclude_benign,
        topk=args.topk,
        selection_mode=args.selection_mode,
        seed=args.seed,
        rag_top_k=args.rag_top_k,
    )
    print(summary["job_dir"])


if __name__ == "__main__":
    main()
