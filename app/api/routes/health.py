from fastapi import APIRouter, Depends

from app.api.deps import get_alert_repo, get_dataset_store, get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health(settings=Depends(get_settings), store=Depends(get_dataset_store), repo=Depends(get_alert_repo)):
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "dataset_processed": store.ready,
        "alerts_in_memory": repo.count(),
    }
