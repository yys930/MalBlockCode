import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

load_dotenv()

from pipeline.channel_runner import run_offline_channel


def main() -> None:
    parser = argparse.ArgumentParser(description="Run offline PCAP -> Suricata -> aggregate -> LLM Agent channel.")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--job-id", default="")
    parser.add_argument("--window-sec", type=int, default=60)
    parser.add_argument("--min-hits", type=int, default=3)
    parser.add_argument("--topk", type=int, default=20)
    parser.add_argument("--rag-top-k", type=int, default=3)
    args = parser.parse_args()

    summary = run_offline_channel(
        pcap=args.pcap,
        job_id=args.job_id,
        window_sec=args.window_sec,
        min_hits=args.min_hits,
        topk=args.topk,
        rag_top_k=args.rag_top_k,
    )
    print(summary["job_dir"])


if __name__ == "__main__":
    main()
