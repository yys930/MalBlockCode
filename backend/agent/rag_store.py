import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from path_utils import BACKEND_ROOT, resolve_project_path
from agent.window_reader import iter_jsonl


@dataclass
class VectorRAGConfig:
    db_dir: str
    archive_path: str
    collection_name: str = "historical_decision_cases"
    embedding_model: str = "BAAI/bge-m3"
    embedding_api_key: str = ""
    embedding_base_url: str = "https://api.openai.com/v1"
    min_similarity: float = 0.45
    include_pending_feedback: bool = False
    enable_archive_fallback: bool = True
    archive_fallback_min_score: float = 0.2
    archive_scan_limit: int = 2000


def default_rag_config() -> VectorRAGConfig:
    rag_root = BACKEND_ROOT / "rag"
    return VectorRAGConfig(
        db_dir=str(resolve_project_path(os.environ.get("RAG_DB_DIR", str(rag_root / "chroma_db")))),
        archive_path=str(resolve_project_path(os.environ.get("RAG_ARCHIVE_PATH", str(rag_root / "decision_history.jsonl")))),
        collection_name=os.environ.get("RAG_COLLECTION", "historical_decision_cases"),
        embedding_model=os.environ.get("RAG_EMBED_MODEL", "BAAI/bge-m3"),
        embedding_api_key=(
            os.environ.get("RAG_EMBED_API_KEY", "").strip()
            or os.environ.get("SILICONFLOW_API_KEY", "").strip()
            or os.environ.get("OPENAI_API_KEY", "").strip()
        ),
        embedding_base_url=os.environ.get(
            "RAG_EMBED_BASE_URL",
            os.environ.get("SILICONFLOW_BASE_URL", "https://api.siliconflow.cn/v1"),
        ),
        min_similarity=float(os.environ.get("RAG_MIN_SIMILARITY", "0.45")),
        include_pending_feedback=os.environ.get("RAG_INCLUDE_PENDING_FEEDBACK", "0") == "1",
        enable_archive_fallback=os.environ.get("RAG_ENABLE_ARCHIVE_FALLBACK", "1") != "0",
        archive_fallback_min_score=float(os.environ.get("RAG_ARCHIVE_FALLBACK_MIN_SCORE", "0.2")),
        archive_scan_limit=max(1, int(os.environ.get("RAG_ARCHIVE_SCAN_LIMIT", "2000"))),
    )


def _require_chromadb():
    try:
        import chromadb  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "chromadb is not installed. Install it in the active environment, for example: "
            "`pip install chromadb`"
        ) from exc
    return chromadb


def _require_openai():
    try:
        from openai import OpenAI  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "openai is not installed. Install it in the active environment, for example: "
            "`pip install openai`"
        ) from exc
    return OpenAI


def _ensure_parent(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def _warn(message: str) -> None:
    print(f"[rag] {message}", file=sys.stderr)


def _build_feedback_stub(decision: Dict[str, Any]) -> Dict[str, Any]:
    action = decision.get("action")
    tool_result = decision.get("tool_result") or {}

    return {
        "status": "pending_evaluation",
        "is_effective": None,
        "false_positive": None,
        "alert_drop_ratio": None,
        "notes": [],
        "execution_status": (
            "executed"
            if action == "block" and tool_result.get("ok")
            else "not_executed"
        ),
    }


def build_rag_case(message: Dict[str, Any], decision: Dict[str, Any], feedback: Dict[str, Any] | None = None) -> Dict[str, Any]:
    window = message.get("evidence_window", message.get("window", {}))
    hints = message.get("hints", {})
    meta = message.get("meta", {})
    retrieved = message.get("retrieved_evidence", [])
    feedback = feedback or _build_feedback_stub(decision)

    return {
        "case_version": 3,
        "case_id": meta.get("window_key") or f'{window.get("src_ip")}:{window.get("window_start_epoch")}-{window.get("window_end_epoch")}',
        "window_key": meta.get("window_key"),
        "job_id": meta.get("job_id"),
        "incident_profile": {
            "hints": hints,
            "window": {
                "src_ip": window.get("src_ip"),
                "window_start_epoch": window.get("window_start_epoch"),
                "window_end_epoch": window.get("window_end_epoch"),
                "window_start_iso": window.get("window_start_iso"),
                "window_end_iso": window.get("window_end_iso"),
                "hits": window.get("hits"),
                "severity_min": window.get("severity_min"),
                "top_signatures": window.get("top_signatures", []),
                "dest_ports": window.get("dest_ports", []),
                "top_dest_ips": window.get("top_dest_ips", []),
            },
        },
        "historical_strategy": {
            "action": decision.get("action"),
            "ttl_sec": decision.get("ttl_sec"),
            "confidence": decision.get("confidence"),
            "risk_score": decision.get("risk_score"),
            "labels": decision.get("labels", []),
            "reasons": decision.get("reasons", []),
            "strategy": decision.get("strategy", {}),
        },
        "execution_result": decision.get("tool_result"),
        "feedback": feedback,
        "retrieval_context": {
            "used_history_count": len(retrieved),
            "source_window_key": meta.get("window_key"),
        },
    }


def _top_signatures_text(window: Dict[str, Any]) -> str:
    parts = []
    for item in window.get("top_signatures", []):
        sig = item.get("signature")
        count = item.get("count")
        if sig:
            parts.append(f"{sig} ({count})")
    return ", ".join(parts)


def _top_dest_ips_text(window: Dict[str, Any]) -> str:
    parts = []
    for item in window.get("top_dest_ips", []):
        dest_ip = item.get("dest_ip")
        count = item.get("count")
        if dest_ip:
            parts.append(f"{dest_ip} ({count})")
    return ", ".join(parts)


def _case_to_document(case: Dict[str, Any]) -> str:
    profile = case.get("incident_profile", {})
    hints = profile.get("hints", {})
    window = profile.get("window", {})
    strategy = case.get("historical_strategy", {})
    feedback = case.get("feedback", {})
    strategy_meta = strategy.get("strategy", {})

    return "\n".join(
        [
            "Historical malicious traffic mitigation case",
            f"attack_family: {hints.get('attack_family')}",
            f"top_signature: {hints.get('top_signature')}",
            f"hits: {window.get('hits')}",
            f"severity_min: {window.get('severity_min')}",
            f"dest_ports: {window.get('dest_ports', [])}",
            f"top_signatures: {_top_signatures_text(window)}",
            f"top_dest_ips: {_top_dest_ips_text(window)}",
            f"historical_action: {strategy.get('action')}",
            f"historical_ttl_sec: {strategy.get('ttl_sec')}",
            f"historical_priority: {strategy_meta.get('priority')}",
            f"historical_duration_tier: {strategy_meta.get('duration_tier')}",
            f"historical_follow_up: {strategy_meta.get('follow_up')}",
            f"historical_template_id: {strategy_meta.get('template_id')}",
            f"historical_escalation_level: {strategy_meta.get('escalation_level')}",
            f"historical_reasons: {' | '.join(strategy.get('reasons', []))}",
            f"historical_labels: {strategy.get('labels', [])}",
            f"feedback_status: {feedback.get('status')}",
            f"is_effective: {feedback.get('is_effective')}",
            f"false_positive: {feedback.get('false_positive')}",
            f"alert_drop_ratio: {feedback.get('alert_drop_ratio')}",
        ]
    )


def _query_to_text(message: Dict[str, Any]) -> str:
    hints = message.get("hints", {})
    window = message.get("evidence_window", message.get("window", {}))
    return "\n".join(
        [
            "Current malicious traffic decision query",
            f"attack_family: {hints.get('attack_family')}",
            f"top_signature: {hints.get('top_signature')}",
            f"hits: {window.get('hits')}",
            f"severity_min: {window.get('severity_min')}",
            f"dest_ports: {window.get('dest_ports', [])}",
            f"top_signatures: {_top_signatures_text(window)}",
            f"top_dest_ips: {_top_dest_ips_text(window)}",
            "Task: retrieve historical decision cases that can guide mitigation strategy before current LLM decision.",
        ]
    )


def _case_feedback_allowed(case: Dict[str, Any], cfg: VectorRAGConfig) -> bool:
    feedback = case.get("feedback", {})
    if not cfg.include_pending_feedback and feedback.get("status") == "pending_evaluation":
        return False
    return True


def _case_to_retrieved_entry(
    case: Dict[str, Any],
    *,
    similarity: float | None,
    distance: float | None,
    retrieval_method: str,
    fallback_score: float | None = None,
) -> Dict[str, Any]:
    strategy = case.get("historical_strategy", {})
    feedback = case.get("feedback", {})
    strategy_meta = strategy.get("strategy", {})
    return {
        "similarity": similarity,
        "distance": distance,
        "retrieval_method": retrieval_method,
        "fallback_score": fallback_score,
        "job_id": case.get("job_id"),
        "window_key": case.get("window_key"),
        "incident_profile": {
            "hints": {
                "attack_family": case.get("incident_profile", {}).get("hints", {}).get("attack_family"),
                "top_signature": case.get("incident_profile", {}).get("hints", {}).get("top_signature"),
                "hits": case.get("incident_profile", {}).get("hints", {}).get("hits"),
                "severity_min": case.get("incident_profile", {}).get("hints", {}).get("severity_min"),
                "dominant_proto": case.get("incident_profile", {}).get("hints", {}).get("dominant_proto"),
            },
            "window": {
                "window_start_iso": case.get("incident_profile", {}).get("window", {}).get("window_start_iso"),
                "window_end_iso": case.get("incident_profile", {}).get("window", {}).get("window_end_iso"),
                "dest_ports": case.get("incident_profile", {}).get("window", {}).get("dest_ports", []),
                "top_signatures": case.get("incident_profile", {}).get("window", {}).get("top_signatures", [])[:3],
                "top_dest_ips": case.get("incident_profile", {}).get("window", {}).get("top_dest_ips", [])[:2],
            },
        },
        "historical_strategy": {
            "action": strategy.get("action"),
            "ttl_sec": strategy.get("ttl_sec"),
            "confidence": strategy.get("confidence"),
            "risk_score": strategy.get("risk_score"),
            "labels": strategy.get("labels", [])[:4],
            "reasons": strategy.get("reasons", [])[:2],
            "strategy": {
                "block_scope": strategy_meta.get("block_scope"),
                "duration_tier": strategy_meta.get("duration_tier"),
                "priority": strategy_meta.get("priority"),
                "follow_up": strategy_meta.get("follow_up"),
                "template_id": strategy_meta.get("template_id"),
                "escalation_level": strategy_meta.get("escalation_level"),
            },
        },
        "feedback": feedback,
        "execution_result": {
            "ok": (case.get("execution_result") or {}).get("ok"),
            "dry_run": (case.get("execution_result") or {}).get("dry_run"),
            "ip": (case.get("execution_result") or {}).get("ip"),
            "ttl_sec": (case.get("execution_result") or {}).get("ttl_sec"),
        },
        "strategy_summary": {
            "action": strategy.get("action"),
            "ttl_sec": strategy.get("ttl_sec"),
            "priority": strategy_meta.get("priority"),
            "duration_tier": strategy_meta.get("duration_tier"),
            "follow_up": strategy_meta.get("follow_up"),
            "template_id": strategy_meta.get("template_id"),
            "escalation_level": strategy_meta.get("escalation_level"),
            "reason_summary": strategy.get("reasons", [])[:2],
            "status": feedback.get("status"),
            "is_effective": feedback.get("is_effective"),
            "false_positive": feedback.get("false_positive"),
        },
    }


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _normalized_dest_ports(obj: Dict[str, Any]) -> set[int]:
    ports: set[int] = set()
    for port in obj.get("dest_ports", []) or []:
        try:
            ports.add(int(port))
        except Exception:
            continue
    return ports


def _archive_match_score(message: Dict[str, Any], case: Dict[str, Any]) -> float:
    query_hints = message.get("hints", {}) or {}
    query_window = message.get("evidence_window", message.get("window", {})) or {}
    case_hints = case.get("incident_profile", {}).get("hints", {}) or {}
    case_window = case.get("incident_profile", {}).get("window", {}) or {}

    score = 0.0

    if query_hints.get("attack_family") and query_hints.get("attack_family") == case_hints.get("attack_family"):
        score += 0.35
    if query_hints.get("top_signature") and query_hints.get("top_signature") == case_hints.get("top_signature"):
        score += 0.25
    if query_hints.get("dominant_proto") and query_hints.get("dominant_proto") == case_hints.get("dominant_proto"):
        score += 0.1

    query_ports = _normalized_dest_ports(query_window)
    case_ports = _normalized_dest_ports(case_window)
    if query_ports and case_ports:
        overlap = len(query_ports & case_ports) / len(query_ports | case_ports)
        score += 0.15 * overlap

    query_severity = _safe_int(query_window.get("severity_min"), 99)
    case_severity = _safe_int(case_window.get("severity_min"), 99)
    if query_severity < 99 and case_severity < 99:
        severity_gap = min(abs(query_severity - case_severity), 4)
        score += 0.1 * (1.0 - (severity_gap / 4.0))

    query_hits = _safe_int(query_window.get("hits"), 0)
    case_hits = _safe_int(case_window.get("hits"), 0)
    if query_hits > 0 and case_hits > 0:
        hit_gap = min(abs(query_hits - case_hits), max(query_hits, case_hits, 1))
        score += 0.05 * (1.0 - (hit_gap / max(query_hits, case_hits, 1)))

    return round(min(score, 1.0), 6)


def _query_archive_cases(message: Dict[str, Any], cfg: VectorRAGConfig, top_k: int) -> List[Dict[str, Any]]:
    if top_k <= 0 or not cfg.archive_path or not os.path.exists(cfg.archive_path):
        return []

    all_cases = load_rag_cases(cfg.archive_path)
    if cfg.archive_scan_limit > 0:
        all_cases = all_cases[-cfg.archive_scan_limit :]

    ranked: List[Tuple[float, Dict[str, Any]]] = []
    for case in all_cases:
        if not isinstance(case, dict) or not _case_feedback_allowed(case, cfg):
            continue
        score = _archive_match_score(message, case)
        if score < cfg.archive_fallback_min_score:
            continue
        ranked.append((score, case))

    ranked.sort(
        key=lambda item: (
            item[0],
            _safe_int(item[1].get("incident_profile", {}).get("window", {}).get("window_end_epoch"), 0),
        ),
        reverse=True,
    )
    return [
        _case_to_retrieved_entry(
            case,
            similarity=score,
            distance=None,
            retrieval_method="archive_fallback",
            fallback_score=score,
        )
        for score, case in ranked[:top_k]
    ]


class VectorRAGStore:
    def __init__(self, cfg: VectorRAGConfig):
        self.cfg = cfg
        self._client = None
        self._collection = None
        self._embedding_client = None

    def _embedding_api_enabled(self) -> bool:
        return bool(self.cfg.embedding_api_key)

    def _get_embedding_client(self):
        if self._embedding_client is None:
            if not self._embedding_api_enabled():
                raise RuntimeError(
                    "RAG embedding API key is not configured. Set `RAG_EMBED_API_KEY` or reuse "
                    "`SILICONFLOW_API_KEY` / `OPENAI_API_KEY`."
                )
            OpenAI = _require_openai()
            self._embedding_client = OpenAI(
                api_key=self.cfg.embedding_api_key,
                base_url=self.cfg.embedding_base_url,
            )
        return self._embedding_client

    def _embed_texts(self, texts: List[str]) -> List[List[float]]:
        client = self._get_embedding_client()
        response = client.embeddings.create(model=self.cfg.embedding_model, input=texts)
        return [item.embedding for item in response.data]

    def _get_collection(self):
        if self._collection is not None:
            return self._collection

        chromadb = _require_chromadb()
        os.makedirs(self.cfg.db_dir, exist_ok=True)
        self._client = chromadb.PersistentClient(path=self.cfg.db_dir)
        self._collection = self._client.get_or_create_collection(name=self.cfg.collection_name)
        return self._collection

    def upsert_case(self, case: Dict[str, Any]) -> None:
        collection = self._get_collection()
        case_id = case.get("case_id") or case.get("window_key")
        if not case_id:
            raise ValueError("RAG case missing case_id/window_key")

        document = _case_to_document(case)
        embedding = self._embed_texts([document])[0]
        metadata = {
            "case_id": str(case_id),
            "job_id": str(case.get("job_id") or ""),
            "window_key": str(case.get("window_key") or ""),
            "action": str(case.get("historical_strategy", {}).get("action") or ""),
            "attack_family": str(case.get("incident_profile", {}).get("hints", {}).get("attack_family") or ""),
            "case_json": json.dumps(case, ensure_ascii=False),
        }
        collection.upsert(
            ids=[str(case_id)],
            documents=[document],
            embeddings=[embedding],
            metadatas=[metadata],
        )

    def query(self, message: Dict[str, Any], top_k: int = 3) -> List[Dict[str, Any]]:
        collection = self._get_collection()
        query_text = _query_to_text(message)
        query_embedding = self._embed_texts([query_text])[0]
        result = collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            include=["metadatas", "distances"],
        )

        metadatas = (result.get("metadatas") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]
        retrieved: List[Dict[str, Any]] = []

        for idx, meta in enumerate(metadatas):
            if not isinstance(meta, dict):
                continue
            raw_case = meta.get("case_json")
            if not isinstance(raw_case, str):
                continue
            try:
                case = json.loads(raw_case)
            except json.JSONDecodeError:
                continue

            strategy = case.get("historical_strategy", {})
            if not _case_feedback_allowed(case, self.cfg):
                continue
            distance = distances[idx] if idx < len(distances) else None
            similarity = None if distance is None else round(1.0 / (1.0 + float(distance)), 6)
            if similarity is not None and similarity < self.cfg.min_similarity:
                continue
            retrieved.append(
                _case_to_retrieved_entry(
                    case,
                    similarity=similarity,
                    distance=float(distance) if distance is not None else None,
                    retrieval_method="vector",
                )
            )
        return retrieved


def load_rag_cases(archive_path: str) -> List[Dict[str, Any]]:
    if not archive_path or not os.path.exists(archive_path):
        return []
    return list(iter_jsonl(archive_path))


def resolve_rag_config(config_or_path: Optional[Any] = None) -> VectorRAGConfig:
    if isinstance(config_or_path, VectorRAGConfig):
        config_or_path.db_dir = str(resolve_project_path(config_or_path.db_dir))
        config_or_path.archive_path = str(resolve_project_path(config_or_path.archive_path))
        return config_or_path

    cfg = default_rag_config()
    if isinstance(config_or_path, str) and config_or_path:
        if config_or_path.endswith(".jsonl"):
            cfg.archive_path = str(resolve_project_path(config_or_path))
        else:
            cfg.db_dir = str(resolve_project_path(config_or_path))
    return cfg


def retrieve_evidence(message: Dict[str, Any], config_or_path: Optional[Any] = None, top_k: int = 3) -> List[Dict[str, Any]]:
    cfg = resolve_rag_config(config_or_path)
    if top_k <= 0:
        return []

    if os.path.exists(cfg.db_dir):
        try:
            store = VectorRAGStore(cfg)
            retrieved = store.query(message, top_k=top_k)
            if retrieved:
                return retrieved
        except Exception as exc:
            _warn(f"vector retrieval failed, falling back to archive matching: {exc}")

    if cfg.enable_archive_fallback:
        return _query_archive_cases(message, cfg, top_k=top_k)
    return []


def append_rag_case(
    config_or_path: Optional[Any],
    message: Dict[str, Any],
    decision: Dict[str, Any],
    feedback: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    cfg = resolve_rag_config(config_or_path)
    record = build_rag_case(message, decision, feedback=feedback)
    result = {
        "archive_appended": False,
        "vector_upserted": False,
        "errors": [],
    }

    _ensure_parent(cfg.archive_path)
    try:
        with open(cfg.archive_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        result["archive_appended"] = True
    except Exception as exc:
        result["errors"].append(f"archive_append_failed: {exc}")
        _warn(f"archive append failed: {exc}")

    try:
        store = VectorRAGStore(cfg)
        store.upsert_case(record)
        result["vector_upserted"] = True
    except Exception as exc:
        result["errors"].append(f"vector_upsert_failed: {exc}")
        _warn(f"vector upsert failed: {exc}")

    return result
