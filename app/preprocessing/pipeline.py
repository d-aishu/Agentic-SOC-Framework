"""Dataset processing pipeline: pick files -> load -> clean -> merge -> summarise."""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from app.dataset.loader import FileKind, FileInspection, inspect_file, list_csv_files, load_csv
from app.preprocessing.cleaner import _FILLED, clean_dataframe
from app.schemas.dataset import FileSummary, ProcessingSummary
from app.utils.exceptions import DatasetNotFoundError, InvalidDatasetError

logger = logging.getLogger(__name__)


def _select_files(raw_dir: Path, filenames: list[str] | None) -> list[FileInspection]:
    if filenames:
        selected = []
        for name in filenames:
            if Path(name).name != name:
                raise InvalidDatasetError(f"Invalid filename '{name}': subfolders are not allowed.")
            path = raw_dir / name
            if not path.is_file():
                raise DatasetNotFoundError(f"File '{name}' not found in {raw_dir}.")
            selected.append(inspect_file(path))
    else:
        selected = list_csv_files(raw_dir)

    processable = [f for f in selected if f.processable]
    if not processable:
        raise DatasetNotFoundError(
            f"No processable UNSW-NB15 CSV files found in {raw_dir}. "
            "Upload files with POST /api/v1/dataset/upload or copy them into that folder."
        )
    layouts = {"partitioned" if f.kind == FileKind.PARTITIONED else "raw" for f in processable}
    if len(layouts) > 1:
        raise InvalidDatasetError(
            "Raw files (with IPs/timestamps) and partitioned training/testing files (without them) "
            "cannot be mixed. Pass an explicit 'files' list containing only one layout."
        )
    return processable


def process_dataset(
    raw_dir: Path,
    filenames: list[str] | None = None,
    max_rows_per_file: int | None = None,
    drop_duplicates: bool = True,
) -> tuple[pd.DataFrame, ProcessingSummary]:
    files = _select_files(raw_dir, filenames)
    frames, file_summaries, total = [], [], Counter()

    for insp in files:
        raw = load_csv(insp, nrows=max_rows_per_file)
        clean, stats = clean_dataframe(raw, insp.path.name, drop_duplicates=drop_duplicates)
        frames.append(clean)
        total.update(stats)
        file_summaries.append(FileSummary(
            filename=insp.path.name, kind=insp.kind.value,
            rows_read=int(stats["rows_in"]), rows_kept=int(stats["rows_out"]),
        ))

    df = pd.concat(frames, ignore_index=True)
    if df.empty:
        raise InvalidDatasetError("All rows were removed during cleaning; check the input files.")

    # Memory-friendly dtypes for repeated strings.
    for col in ("proto", "state", "service", "attack_cat", "srcip", "dstip", "source_file"):
        if col in df.columns:
            df[col] = df[col].astype("category")

    dataset_kind = "partitioned" if files[0].kind == FileKind.PARTITIONED else "raw"
    has_ips = bool(df["srcip"].notna().any())
    has_ports = bool(df["sport"].notna().any() or df["dsport"].notna().any())
    has_ts = bool(df["timestamp"].notna().any())

    notes = []
    if not has_ips:
        notes.append("No IP addresses in these files: alerts will have null source/destination IPs.")
    if not has_ports:
        notes.append("No port information in these files: alerts will have null ports.")
    if not has_ts:
        notes.append("No timestamps in these files: alerts will have null timestamps.")
    if total["dropped_conflicting_label"]:
        notes.append("Rows whose label and attack category contradicted each other were dropped.")

    summary = ProcessingSummary(
        processed_at=datetime.now(timezone.utc),
        dataset_kind=dataset_kind,
        files=file_summaries,
        rows_in=int(total["rows_in"]),
        rows_out=len(df),
        label_distribution={"normal": int((df["label"] == 0).sum()), "attack": int((df["label"] == 1).sum())},
        category_distribution={str(k): int(v) for k, v in df["attack_cat"].value_counts().items()},
        has_ip_addresses=has_ips,
        has_ports=has_ports,
        has_timestamps=has_ts,
        data_quality={k: int(v) for k, v in total.items()
                      if v and not k.startswith(_FILLED) and k not in ("rows_in", "rows_out")},
        filled_missing_values={k[len(_FILLED):]: int(v) for k, v in total.items() if v and k.startswith(_FILLED)},
        notes=notes,
    )
    logger.info("Processed %d files: %d -> %d rows", len(files), summary.rows_in, summary.rows_out)
    return df, summary
