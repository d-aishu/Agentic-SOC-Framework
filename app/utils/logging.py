"""Logging setup: console + rotating file."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def setup_logging(level: str, log_file: Path) -> None:
    """Configure the root logger once (idempotent for a given log file)."""
    root = logging.getLogger()
    root.setLevel(level.upper())
    for h in root.handlers:
        if getattr(h, "_soc_handler", False) and getattr(h, "baseFilename", None) == str(log_file):
            return
    for h in [h for h in root.handlers if getattr(h, "_soc_handler", False)]:
        root.removeHandler(h)
        h.close()

    log_file.parent.mkdir(parents=True, exist_ok=True)
    console = logging.StreamHandler()
    file_handler = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    for h in (console, file_handler):
        h.setFormatter(logging.Formatter(_FORMAT))
        h._soc_handler = True  # type: ignore[attr-defined]
        root.addHandler(h)
