"""Agent package exports with lazy imports to avoid optional dependency side effects."""

__all__ = [
    "AgentConfig",
    "LLMBlockAgent",
    "build_message",
    "get_constraints",
    "parse_json_only",
    "retrieve_evidence",
    "validate_decision",
]


def __getattr__(name):
    if name in {"LLMBlockAgent", "AgentConfig"}:
        from .llm_agent_sf import AgentConfig, LLMBlockAgent

        return {"LLMBlockAgent": LLMBlockAgent, "AgentConfig": AgentConfig}[name]
    if name == "build_message":
        from .message_builder import build_message

        return build_message
    if name == "retrieve_evidence":
        from .rag_store import retrieve_evidence

        return retrieve_evidence
    if name in {"validate_decision", "parse_json_only"}:
        from .decision_schema import parse_json_only, validate_decision

        return {"validate_decision": validate_decision, "parse_json_only": parse_json_only}[name]
    if name == "get_constraints":
        from .policy import get_constraints

        return get_constraints
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
