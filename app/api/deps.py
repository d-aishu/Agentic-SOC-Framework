"""FastAPI dependencies: shared objects live on ``app.state`` (created in main.create_app)."""
from fastapi import Request

from app.config.settings import Settings
from app.storage.alert_repository import AlertRepository
from app.storage.dataset_store import DatasetStore


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_dataset_store(request: Request) -> DatasetStore:
    return request.app.state.dataset_store


def get_alert_repo(request: Request) -> AlertRepository:
    return request.app.state.alert_repo
