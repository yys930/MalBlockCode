import argparse
import json
import sys
from pathlib import Path
from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

load_dotenv()

from eval.channel_eval import evaluate_job


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a completed channel job.")
    parser.add_argument("--job-dir", required=True)
    args = parser.parse_args()

    report = evaluate_job(args.job_dir)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
