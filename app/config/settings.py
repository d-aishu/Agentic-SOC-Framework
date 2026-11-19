"""Application settings (paths, logging, limits).

Values can be overridden with environment variables prefixed by ``SOC_``
or through a ``.env`` file, e.g. ``SOC_LOG_LEVEL=DEBUG``.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "Adaptive Agentic SOC Framework - Phase 1"
    app_version: str = "0.1.0"
    api_prefix: str = "/api/v1"

    raw_data_dir: Path = BASE_DIR / "data" / "raw"
    processed_data_dir: Path = BASE_DIR / "data" / "processed"
    log_dir: Path = BASE_DIR / "logs"
    log_level: str = "INFO"

    max_upload_mb: int = 2048
    default_seed: int = 42

    # Phase 2 settings
    soc_llm_model: str = "gpt-4o-mini"
    soc_chroma_dir: Path = BASE_DIR / "chroma_db"
    soc_simulation_mode: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SOC_", extra="ignore")

    @property
    def log_file(self) -> Path:
        return self.log_dir / "soc.log"

    def ensure_directories(self) -> None:
        for d in (self.raw_data_dir, self.processed_data_dir, self.log_dir, self.soc_chroma_dir):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
