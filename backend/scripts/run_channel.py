import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

load_dotenv()

from pipeline.channel_runner import run_csv_channel, run_offline_channel, run_replay_channel


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified channel runner for offline/replay/csv modes.")
    sub = parser.add_subparsers(dest="channel", required=True)

    offline = sub.add_parser("offline", help="Offline PCAP -> Suricata channel")
    offline.add_argument("--pcap", required=True)
    offline.add_argument("--job-id", default="")
    offline.add_argument("--window-sec", type=int, default=60)
    offline.add_argument("--min-hits", type=int, default=3)
    offline.add_argument("--topk", type=int, default=20)
    offline.add_argument("--rag-top-k", type=int, default=3)

    replay = sub.add_parser("replay", help="Replay/online PCAP channel")
    replay.add_argument("--pcap", required=True)
    replay.add_argument("--suricata-interface", required=True)
    replay.add_argument("--replay-interface", required=True)
    replay.add_argument("--job-id", default="")
    replay.add_argument("--suricata-checksum-mode", default="none")
    replay.add_argument("--replay-speed", default="topspeed")
    replay.add_argument("--replay-netns", default="")
    replay.add_argument("--tcpreplay-extra-arg", action="append", default=[])
    replay.add_argument("--capture-wait-sec", type=int, default=2)
    replay.add_argument("--suricata-ready-timeout-sec", type=int, default=180)
    replay.add_argument("--window-sec", type=int, default=60)
    replay.add_argument("--min-hits", type=int, default=3)
    replay.add_argument("--topk", type=int, default=20)
    replay.add_argument("--rag-top-k", type=int, default=3)

    csvp = sub.add_parser("csv", help="CSV flow direct channel")
    csvp.add_argument("--csv", required=True)
    csvp.add_argument("--job-id", default="")
    csvp.add_argument("--topk", type=int, default=5000)
    csvp.add_argument("--exclude-benign", action="store_true")
    csvp.add_argument("--selection-mode", choices=["priority", "random", "stratified_label"], default="priority")
    csvp.add_argument("--seed", type=int, default=42)
    csvp.add_argument("--rag-top-k", type=int, default=3)

    args = parser.parse_args()
    if args.channel == "offline":
        summary = run_offline_channel(
            pcap=args.pcap,
            job_id=args.job_id,
            window_sec=args.window_sec,
            min_hits=args.min_hits,
            topk=args.topk,
            rag_top_k=args.rag_top_k,
        )
    elif args.channel == "replay":
        summary = run_replay_channel(
            pcap=args.pcap,
            suricata_interface=args.suricata_interface,
            replay_interface=args.replay_interface,
            job_id=args.job_id,
            suricata_checksum_mode=args.suricata_checksum_mode,
            replay_speed=args.replay_speed,
            replay_netns=args.replay_netns,
            tcpreplay_extra_args=args.tcpreplay_extra_arg,
            capture_wait_sec=args.capture_wait_sec,
            suricata_ready_timeout_sec=args.suricata_ready_timeout_sec,
            window_sec=args.window_sec,
            min_hits=args.min_hits,
            topk=args.topk,
            rag_top_k=args.rag_top_k,
        )
    else:
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
