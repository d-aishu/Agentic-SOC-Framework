"""Alert endpoints: generate, list/filter, detail, agent view, statistics, clear."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.alert_generation.generator import AlertGenerator
from app.api.deps import get_alert_repo, get_dataset_store
from app.schemas.alert import (
    AgentAlertView, Alert, AlertListResponse, AlertSource, AlertStats,
    GenerateAlertsRequest, GenerateAlertsResponse, Severity,
)
from app.utils.exceptions import AlertNotFoundError, DatasetNotProcessedError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("/generate", response_model=GenerateAlertsResponse, summary="Generate alerts from the processed dataset")
def generate_alerts(request: GenerateAlertsRequest | None = None,
                    store=Depends(get_dataset_store), repo=Depends(get_alert_repo)):
    request = request or GenerateAlertsRequest()
    if not store.ready:
        raise DatasetNotProcessedError("Process the dataset first: POST /api/v1/dataset/process.")

    start = 1 if request.replace_existing else repo.next_index()
    alerts, truths = AlertGenerator(AlertSource.DATASET).generate(store.df, request, start_index=start)
    if request.replace_existing:
        repo.replace_all(alerts, truths)
    else:
        repo.add_many(alerts, truths)

    by_cat: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for a in alerts:
        by_cat[a.attack_category] = by_cat.get(a.attack_category, 0) + 1
        by_sev[a.severity.value] = by_sev.get(a.severity.value, 0) + 1
    return GenerateAlertsResponse(
        generated=len(alerts), total_alerts_now=repo.count(), by_category=by_cat, by_severity=by_sev,
        benign_included=by_cat.get("Normal", 0),
        message="Alerts generated from dataset annotations (no AI detection performed).",
    )


@router.get("/stats", response_model=AlertStats, summary="Alert statistics")
def alert_stats(repo=Depends(get_alert_repo)):
    return repo.stats()


@router.get("", response_model=AlertListResponse, summary="List alerts (filter by category / severity / source)")
def list_alerts(
    attack_category: Optional[str] = Query(None, description="Case-insensitive, e.g. 'Exploits'"),
    severity: Optional[Severity] = None,
    source: Optional[AlertSource] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    repo=Depends(get_alert_repo),
):
    total, items = repo.query(attack_category, severity.value if severity else None,
                              source.value if source else None, skip, limit)
    return AlertListResponse(total=total, skip=skip, limit=limit, items=items)


@router.delete("", summary="Delete all alerts and their ground truth")
def clear_alerts(repo=Depends(get_alert_repo)):
    return {"deleted": repo.clear()}


@router.get("/{alert_id}", response_model=Alert, summary="One alert (full record)")
def get_alert(alert_id: str, repo=Depends(get_alert_repo)):
    alert = repo.get(alert_id)
    if alert is None:
        raise AlertNotFoundError(f"Alert '{alert_id}' not found.")
    return alert


@router.get("/{alert_id}/agent-view", response_model=AgentAlertView,
            summary="Leak-free view for AI agents (evidence only)")
def get_agent_view(alert_id: str, repo=Depends(get_alert_repo)):
    alert = repo.get(alert_id)
    if alert is None:
        raise AlertNotFoundError(f"Alert '{alert_id}' not found.")
    return alert.to_agent_view()
