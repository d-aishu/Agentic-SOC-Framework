"""Holds the processed dataset (in memory + parquet on disk).

Phase 1 uses files; PostgreSQL can replace this class later without touching the routes.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Optional

import pandas as pd

from app.schemas.dataset import ProcessingSummary

logger = logging.getLogger(__name__)


class DatasetStore:
    def __init__(self, directory: Path):
        self._parquet = directory / "unsw_clean.parquet"
        self._summary_file = directory / "dataset_summary.json"
        self._lock = threading.Lock()
        self.df: Optional[pd.DataFrame] = None
        self.summary: Optional[ProcessingSummary] = None

    def set(self, df: pd.DataFrame, summary: ProcessingSummary) -> None:
        with self._lock:
            self.df, self.summary = df, summary
            try:
                df.to_parquet(self._parquet, index=False)
                self._summary_file.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
            except Exception:  # persistence is best-effort; the in-memory copy still works
                logger.exception("Could not persist processed dataset")

    def load(self) -> bool:
        if not (self._parquet.exists() and self._summary_file.exists()):
            return False
        try:
            with self._lock:
                self.df = pd.read_parquet(self._parquet)
                self.summary = ProcessingSummary.model_validate_json(self._summary_file.read_text(encoding="utf-8"))
            logger.info("Restored processed dataset (%d rows) from disk", len(self.df))
            return True
        except Exception:
            logger.exception("Stored processed dataset is unreadable; ignoring it")
            return False

    @property
    def ready(self) -> bool:
        return self.df is not None
