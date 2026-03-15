# backend/agent/build_messages.py
import argparse
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

load_dotenv()

from agent.window_reader import iter_jsonl
from agent.message_builder import build_message
from agent.rag_store import VectorRAGConfig, retrieve_evidence
from path_utils import resolve_project_path


def build_messages(
    input_jsonl: str,
    output_jsonl: str,
    rag_db_dir: str = "",
    rag_archive_path: str = "",
    rag_top_k: int = 3,
    rag_collection: str = "historical_decision_cases",
    rag_embed_model: str = "BAAI/bge-m3",
    rag_embed_api_key: str = "",
    rag_embed_base_url: str = "",
) -> int:
    os.makedirs(os.path.dirname(output_jsonl), exist_ok=True)
    rag_cfg = None
    if rag_db_dir:
        rag_cfg = VectorRAGConfig(
            db_dir=rag_db_dir,
            archive_path=rag_archive_path,
            collection_name=rag_collection,
            embedding_model=rag_embed_model,
            embedding_api_key=rag_embed_api_key,
            embedding_base_url=rag_embed_base_url,
        )
    n = 0
    with open(output_jsonl, "w", encoding="utf-8") as fout:
        for window in iter_jsonl(input_jsonl):
            msg = build_message(window)
            if rag_cfg:
                msg["retrieved_evidence"] = retrieve_evidence(msg, rag_cfg, top_k=rag_top_k)
            fout.write(json.dumps(msg, ensure_ascii=False) + "\n")
            n += 1
    return n


def main() -> None:
    parser = argparse.ArgumentParser(description="Build LLM messages from aggregated window JSONL.")
    parser.add_argument("--input-jsonl", required=True, help="Path to llm_inputs_selected.jsonl")
    parser.add_argument("--output-jsonl", required=True, help="Path to llm_messages.jsonl")
    parser.add_argument("--rag-db-dir", default="", help="Vector database directory for RAG retrieval")
    parser.add_argument("--rag-archive-path", default="", help="Historical decision case archive JSONL path")
    parser.add_argument("--rag-collection", default="historical_decision_cases", help="RAG collection name")
    parser.add_argument("--rag-top-k", type=int, default=3, help="How many historical cases to retrieve")
    parser.add_argument("--rag-embed-model", default=os.environ.get("RAG_EMBED_MODEL", "BAAI/bge-m3"))
    parser.add_argument("--rag-embed-api-key", default=os.environ.get("RAG_EMBED_API_KEY", os.environ.get("SILICONFLOW_API_KEY", "")))
    parser.add_argument("--rag-embed-base-url", default=os.environ.get("RAG_EMBED_BASE_URL", os.environ.get("SILICONFLOW_BASE_URL", "https://api.siliconflow.cn/v1")))
    args = parser.parse_args()

    inp = str(resolve_project_path(args.input_jsonl))
    out = str(resolve_project_path(args.output_jsonl))
    rag_db_dir = str(resolve_project_path(args.rag_db_dir)) if args.rag_db_dir else ""
    rag_archive_path = str(resolve_project_path(args.rag_archive_path)) if args.rag_archive_path else ""
    total = build_messages(
        inp,
        out,
        rag_db_dir=rag_db_dir,
        rag_archive_path=rag_archive_path,
        rag_top_k=args.rag_top_k,
        rag_collection=args.rag_collection,
        rag_embed_model=args.rag_embed_model,
        rag_embed_api_key=args.rag_embed_api_key,
        rag_embed_base_url=args.rag_embed_base_url,
    )
    print(f"built {total} messages -> {out}")


if __name__ == "__main__":
    main()
