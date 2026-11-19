from __future__ import annotations
from typing import Any, TypedDict

class SOCState(TypedDict, total=False):
    alert: dict[str, Any]
    routing_context: dict[str, Any]
    existing_alerts: list[dict[str, Any]]
    selected_agents: list[str]
    routing_decision: dict[str, Any]
    agent_results: dict[str, dict[str, Any]]
    risk_score: int
    risk_level: str
    recommended_actions: list[dict[str, Any]]
    verification_events: list[dict[str, Any]]
    response_execution_confirmed: bool
    verification: dict[str, Any]
    reinvestigation_count: int
    max_reinvestigations: int
    rag_engine: Any
