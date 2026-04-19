from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

load_dotenv()

from eval.replay_compare_eval import evaluate_replay_comparison


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate execution-vs-baseline replay jobs.")
    parser.add_argument("--exec-job-dir", required=True)
    parser.add_argument("--baseline-job-dir", required=True)
    args = parser.parse_args()

    report = evaluate_replay_comparison(args.exec_job_dir, args.baseline_job_dir)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
