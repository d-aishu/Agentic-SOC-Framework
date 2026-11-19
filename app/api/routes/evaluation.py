"""Ground-truth access. Used ONLY by evaluation code, never by agents."""
from fastapi import APIRouter, Depends

from app.api.deps import get_alert_repo
from app.schemas.alert import GroundTruth
from app.utils.exceptions import AlertNotFoundError

router = APIRouter(prefix="/evaluation", tags=["evaluation (ground truth)"])


@router.get("/ground-truth/{alert_id}", response_model=GroundTruth)
def ground_truth(alert_id: str, repo=Depends(get_alert_repo)):
    truth = repo.get_truth(alert_id)
    if truth is None:
        raise AlertNotFoundError(f"No ground truth for alert '{alert_id}'.")
    return truth
