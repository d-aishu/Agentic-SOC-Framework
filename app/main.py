"""Application factory and entry point:  uvicorn app.main:app --reload"""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.routes import alerts, dataset, evaluation, health, soc
from app.config.settings import Settings, get_settings
from app.storage.alert_repository import AlertRepository
from app.storage.dataset_store import DatasetStore
from app.storage.agent_repository import AgentRepository
from app.rag.rag_engine import RAGEngine
from app.orchestration.graph import create_soc_graph
from app.utils.exceptions import AppError
from app.utils.logging import setup_logging

logger = logging.getLogger("app.main")


def _error(status: int, code: str, message: str, details=None) -> JSONResponse:
    body = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(status_code=status, content=body)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.ensure_directories()
    setup_logging(settings.log_level, settings.log_file)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.dataset_store.load()
        app.state.alert_repo.load()
        logger.info("Phase 2 SOC workflow initialized (LLM enabled=%s)", bool(__import__("os").getenv("OPENAI_API_KEY")))
        logger.info("%s v%s started", settings.app_name, settings.app_version)
        yield

    app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan,
                  description="Phase 1: UNSW-NB15 processing and security alert generation.")
    app.state.settings = settings
    app.state.dataset_store = DatasetStore(settings.processed_data_dir)
    app.state.alert_repo = AlertRepository(settings.processed_data_dir)
    app.state.agent_repo = AgentRepository(settings.processed_data_dir)
    app.state.rag_engine = RAGEngine(settings.soc_chroma_dir)
    app.state.soc_graph = create_soc_graph(app.state.rag_engine)

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        logger.info("%s %s -> %d (%.0f ms)", request.method, request.url.path,
                    response.status_code, (time.perf_counter() - start) * 1000)
        return response

    @app.exception_handler(AppError)
    async def app_error_handler(_: Request, exc: AppError):
        logger.warning("%s: %s", exc.code, exc.message)
        return _error(exc.status_code, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError):
        details = [{"field": ".".join(str(p) for p in e["loc"]), "problem": e["msg"]} for e in exc.errors()]
        return _error(422, "validation_error", "Request validation failed.", details)

    @app.exception_handler(StarletteHTTPException)
    async def http_handler(_: Request, exc: StarletteHTTPException):
        return _error(exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(Exception)
    async def unhandled_handler(_: Request, exc: Exception):
        logger.exception("Unhandled error")
        return _error(500, "internal_error", "Unexpected server error. See logs/soc.log.")

    prefix = settings.api_prefix
    app.include_router(health.router)
    for r in (dataset.router, alerts.router, evaluation.router, soc.router):
        app.include_router(r, prefix=prefix)
    return app


app = create_app()
