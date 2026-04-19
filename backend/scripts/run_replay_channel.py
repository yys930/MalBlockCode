import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

load_dotenv()

from pipeline.channel_runner import DEFAULT_SURICATA_READY_TIMEOUT_SEC, run_replay_channel


def main() -> None:
    parser = argparse.ArgumentParser(description="Run replay/online PCAP channel via Suricata live capture + tcpreplay.")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--suricata-interface", required=True, help="Host interface listened by Suricata")
    parser.add_argument("--replay-interface", required=True, help="Interface used by tcpreplay, possibly inside namespace")
    parser.add_argument("--job-id", default="")
    parser.add_argument("--suricata-checksum-mode", default="none", help="Passed to `suricata -k`; replay labs usually need `none`")
    parser.add_argument("--replay-speed", default="topspeed")
    parser.add_argument("--replay-netns", default="", help="Optional network namespace used for tcpreplay")
    parser.add_argument("--tcpreplay-extra-arg", action="append", default=[], help="Extra arg passed through to tcpreplay")
    parser.add_argument("--capture-wait-sec", type=int, default=2)
    parser.add_argument(
        "--suricata-ready-timeout-sec",
        type=int,
        default=DEFAULT_SURICATA_READY_TIMEOUT_SEC,
        help="How long to wait for Suricata live engine startup",
    )
    parser.add_argument("--window-sec", type=int, default=60)
    parser.add_argument("--min-hits", type=int, default=3)
    parser.add_argument("--topk", type=int, default=20)
    parser.add_argument("--rag-top-k", type=int, default=3)
    args = parser.parse_args()

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
    print(summary["job_dir"])


if __name__ == "__main__":
    main()
