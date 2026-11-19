from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field

class AgentResult(BaseModel):
    agent_name: str
    findings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: Literal["completed", "skipped", "failed"] = "completed"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sources: list[dict[str, str]] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)

class AnalyzeAlertRequest(BaseModel):
    verification_events: list[dict[str, Any]] = Field(default_factory=list, description="Optional subsequent/simulated events used only for verification.")
    max_reinvestigations: int = Field(default=1, ge=0, le=3)
    simulated_response_executed: bool = Field(default=False, description="Test-only confirmation that the simulated response step was marked executed; no real system action occurs.")

class SOCAnalysisResponse(BaseModel):
    alert_id: str
    selected_agents: list[str]
    agent_results: dict[str, AgentResult]
    risk_score: int
    risk_level: str
    recommended_actions: list[dict[str, Any]]
    verification: dict[str, Any]
    reinvestigation_count: int
    execution_mode: str = "simulation"
