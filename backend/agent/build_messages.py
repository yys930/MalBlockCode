# backend/agent/build_messages.py
import argparse
import json
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agent.window_reader import iter_jsonl
from agent.message_builder import build_message
from agent.rag_store import retrieve_evidence


def build_messages(input_jsonl: str, output_jsonl: str, rag_store_path: str = "", rag_top_k: int = 3) -> int:
    os.makedirs(os.path.dirname(output_jsonl), exist_ok=True)
    n = 0
    with open(output_jsonl, "w", encoding="utf-8") as fout:
        for window in iter_jsonl(input_jsonl):
            msg = build_message(window)
            if rag_store_path:
                msg["retrieved_evidence"] = retrieve_evidence(msg, rag_store_path, top_k=rag_top_k)
            fout.write(json.dumps(msg, ensure_ascii=False) + "\n")
            n += 1
    return n


def main() -> None:
    parser = argparse.ArgumentParser(description="Build LLM messages from aggregated window JSONL.")
    parser.add_argument("--input-jsonl", required=True, help="Path to llm_inputs_selected.jsonl")
    parser.add_argument("--output-jsonl", required=True, help="Path to llm_messages.jsonl")
    parser.add_argument("--rag-store-path", default="", help="Optional historical RAG store JSONL path")
    parser.add_argument("--rag-top-k", type=int, default=3, help="How many historical cases to retrieve")
    args = parser.parse_args()

    inp = os.path.abspath(args.input_jsonl)
    out = os.path.abspath(args.output_jsonl)
    rag_store_path = os.path.abspath(args.rag_store_path) if args.rag_store_path else ""
    total = build_messages(inp, out, rag_store_path=rag_store_path, rag_top_k=args.rag_top_k)
    print(f"built {total} messages -> {out}")


if __name__ == "__main__":
    main()
