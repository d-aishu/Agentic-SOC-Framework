from __future__ import annotations
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from app.api.deps import get_alert_repo
from app.schemas.soc import AnalyzeAlertRequest, SOCAnalysisResponse
from app.orchestration.adaptive_router import evidence_based_severity
from app.utils.exceptions import AlertNotFoundError

router = APIRouter(prefix="/soc", tags=["Phase 2 - Adaptive SOC"])

@router.post("/analyze/{alert_id}", response_model=SOCAnalysisResponse,
             summary="Run adaptive multi-agent investigation for an existing Phase 1 alert")
def analyze_alert(alert_id: str, request: Request,
                  body: AnalyzeAlertRequest = Body(default=AnalyzeAlertRequest()),
                  repo=Depends(get_alert_repo)):
    alert = repo.get(alert_id)
    if alert is None: raise AlertNotFoundError(f"Alert '{alert_id}' not found.")
    # AI agents receive only the evidence-only view. Severity is used by the router only.
    def safe_agent_view(item):
        view = item.to_agent_view().model_dump(mode="json")
        # An upstream category is usable only for non-dataset alerts; dataset category is ground truth.
        if item.source.value != "dataset":
            view["reported_category"] = item.attack_category
        return view
    agent_view = safe_agent_view(alert)
    _, other_alerts = repo.query(skip=0, limit=1000)
    candidates = [safe_agent_view(a) for a in other_alerts if a.alert_id != alert_id]
    state = {
        "alert": agent_view,
        "routing_context": {
            "severity": evidence_based_severity({**agent_view, "source": alert.source.value, "severity": alert.severity.value}),
            "source": alert.source.value,
            # Dataset category is ground truth and is intentionally not used by agents/router.
            "severity_basis": "observable_evidence" if alert.source.value == "dataset" else "upstream_alert",
            "routing_category": alert.attack_category if alert.source.value != "dataset" else "",
        },
        "existing_alerts": candidates,
        "agent_results": {}, "verification_events": body.verification_events,
        "response_execution_confirmed": body.simulated_response_executed,
        "reinvestigation_count": 0, "max_reinvestigations": body.max_reinvestigations,
    }
    try:
        final_state = request.app.state.soc_graph.invoke(state)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SOC workflow failed: {type(exc).__name__}: {exc}") from exc
    request.app.state.agent_repo.save_run(alert_id, final_state.get("agent_results", {}))
    return SOCAnalysisResponse(alert_id=alert_id,
        selected_agents=final_state.get("selected_agents", []),
        agent_results=final_state.get("agent_results", {}),
        risk_score=final_state.get("risk_score", 0), risk_level=final_state.get("risk_level", "unknown"),
        recommended_actions=final_state.get("recommended_actions", []),
        verification=final_state.get("verification", {"status": "not_run"}),
        reinvestigation_count=final_state.get("reinvestigation_count", 0))

@router.get("/results/{alert_id}", summary="Get stored agent execution results for an alert")
def get_agent_results(alert_id: str, request: Request, repo=Depends(get_alert_repo)):
    if repo.get(alert_id) is None: raise AlertNotFoundError(f"Alert '{alert_id}' not found.")
    return {"alert_id": alert_id, "results": request.app.state.agent_repo.list_for_alert(alert_id)}
