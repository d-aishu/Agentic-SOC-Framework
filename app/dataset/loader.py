"""Inspect and read UNSW-NB15 CSV files."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import pandas as pd

from app.dataset.columns import RAW_COLUMNS
from app.utils.exceptions import InvalidDatasetError

logger = logging.getLogger(__name__)

# latin-1 never fails to decode, which makes the loader robust to odd bytes in the raw files.
ENCODING = "latin-1"


class FileKind(str, Enum):
    RAW_NO_HEADER = "raw_no_header"          # UNSW-NB15_1..4.csv (49 cols, no header)
    RAW_WITH_HEADER = "raw_with_header"      # same layout, but a header row was added
    PARTITIONED = "partitioned"              # training-set / testing-set (no IP/port/time)
    METADATA = "metadata"                    # features / LIST_EVENTS / GT files (not processed in Phase 1)
    UNKNOWN = "unknown"


PROCESSABLE_KINDS = {FileKind.RAW_NO_HEADER, FileKind.RAW_WITH_HEADER, FileKind.PARTITIONED}


@dataclass
class FileInspection:
    path: Path
    kind: FileKind
    n_columns: int = 0
    columns: list[str] = field(default_factory=list)

    @property
    def processable(self) -> bool:
        return self.kind in PROCESSABLE_KINDS


def _is_metadata_name(name: str) -> bool:
    n = name.lower()
    return "features" in n or "list_events" in n or n.endswith("_gt.csv") or n == "unsw-nb15_gt.csv"


def inspect_file(path: Path) -> FileInspection:
    """Decide which UNSW-NB15 layout a CSV has by looking at its first row."""
    if _is_metadata_name(path.name):
        return FileInspection(path, FileKind.METADATA)
    try:
        head = pd.read_csv(path, header=None, nrows=1, dtype=str, encoding=ENCODING)
    except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeError) as exc:
        logger.warning("Cannot parse %s: %s", path.name, exc)
        return FileInspection(path, FileKind.UNKNOWN)

    first = [str(v).strip().lower() for v in head.iloc[0].tolist()]
    if "label" in first and "attack_cat" in first:
        kind = FileKind.RAW_WITH_HEADER if "srcip" in first else FileKind.PARTITIONED
        return FileInspection(path, kind, len(first), first)
    if len(first) == len(RAW_COLUMNS):
        return FileInspection(path, FileKind.RAW_NO_HEADER, len(RAW_COLUMNS), list(RAW_COLUMNS))
    return FileInspection(path, FileKind.UNKNOWN, len(first))


def load_csv(inspection: FileInspection, nrows: int | None = None) -> pd.DataFrame:
    """Read one UNSW-NB15 file into a DataFrame (column names are lower-cased)."""
    if not inspection.processable:
        raise InvalidDatasetError(f"{inspection.path.name} is not a processable UNSW-NB15 data file.")
    if inspection.kind == FileKind.RAW_NO_HEADER:
        df = pd.read_csv(
            inspection.path, header=None, names=RAW_COLUMNS,
            nrows=nrows, low_memory=False, encoding=ENCODING,
        )
    else:
        df = pd.read_csv(inspection.path, nrows=nrows, low_memory=False, encoding=ENCODING)
    df.columns = [str(c).strip().lower() for c in df.columns]
    logger.info("Loaded %s (%s): %d rows x %d cols", inspection.path.name, inspection.kind.value, *df.shape)
    return df


def list_csv_files(raw_dir: Path) -> list[FileInspection]:
    return [inspect_file(p) for p in sorted(raw_dir.glob("*.csv"))]
