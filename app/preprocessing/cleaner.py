"""Cleaning of one UNSW-NB15 DataFrame.

Goals: repair or neutralise inconsistent values, never invent evidence, and
PRESERVE the original labels (``label`` and ``attack_cat_raw``) for evaluation.
"""
from __future__ import annotations

import ipaddress
import logging
import math
from collections import Counter
from typing import Callable

import numpy as np
import pandas as pd

from app.dataset.columns import (
    BINARY_COLUMNS, CATEGORICAL_COLUMNS, CATEGORY_ALIASES, IP_COLUMNS,
    NON_NEGATIVE_COLUMNS, NON_NUMERIC_COLUMNS, NORMAL_CATEGORY, PORT_COLUMNS, UNKNOWN_CATEGORY,
)
from app.utils.exceptions import InvalidDatasetError

logger = logging.getLogger(__name__)

_FILLED = "filled_missing."


# --------------------------------------------------------------------------- helpers
def _map_unique(series: pd.Series, fn: Callable) -> pd.Series:
    """Apply ``fn`` once per distinct value (fast for IPs/ports which have few uniques)."""
    mapping = {u: fn(u) for u in series.dropna().unique()}
    return series.map(mapping)


def normalize_ip(value) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def parse_port(value) -> int | None:
    """Parse ints, floats, '80', ' 80 ', hex like '0x000b'; return None for '-', blanks, out-of-range."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    try:
        if isinstance(value, (int, np.integer)):
            number = int(value)
        elif isinstance(value, (float, np.floating)):
            if not float(value).is_integer():
                return None
            number = int(value)
        else:
            text = str(value).strip().lower()
            if text in ("", "-", "nan", "none"):
                return None
            number = int(text, 16) if text.startswith("0x") else int(float(text))
    except (ValueError, OverflowError):
        return None
    return number if 0 <= number <= 65535 else None


def _clean_text(value) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    return None if v in ("", "-", "nan") else v


# --------------------------------------------------------------------------- main entry
def clean_dataframe(df: pd.DataFrame, source_file: str, drop_duplicates: bool = True) -> tuple[pd.DataFrame, Counter]:
    """Return ``(clean_df, stats)``. ``stats`` is a flat Counter of repairs/drops."""
    stats: Counter = Counter()
    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    stats["rows_in"] = len(df)

    if "label" not in df.columns or "attack_cat" not in df.columns:
        raise InvalidDatasetError(f"{source_file}: required columns 'label' and 'attack_cat' are missing.")

    df["source_file"] = source_file
    df["source_row"] = np.arange(1, len(df) + 1)  # 1-based data-row number inside the file

    # Fields that some files do not have are added as empty columns so downstream code
    # never has to guess; "missing" stays "missing" (None/NA/NaT), it is never invented.
    for col in IP_COLUMNS:
        if col not in df.columns:
            df[col] = None
            stats["missing_column." + col] += 1
    for col in PORT_COLUMNS:
        if col not in df.columns:
            df[col] = None
            stats["missing_column." + col] += 1

    # ---- labels (preserved) ---------------------------------------------------------
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    bad_label = ~df["label"].isin([0, 1])
    stats["dropped_invalid_label"] = int(bad_label.sum())
    df = df.loc[~bad_label].copy()
    df["label"] = df["label"].astype("int8")

    original = df["attack_cat"].astype(object)
    df["attack_cat_raw"] = original.where(original.notna(), None)  # exactly as in the CSV

    key = original.map(lambda v: v.strip().lower() if isinstance(v, str) else "")
    category = key.map(CATEGORY_ALIASES)                     # NaN for blank / unrecognised
    blank = key == ""
    unrecognised = (~blank) & category.isna()
    category = category.astype(object)
    category[blank & (df["label"] == 0)] = NORMAL_CATEGORY   # raw files leave Normal blank
    category[blank & (df["label"] == 1)] = UNKNOWN_CATEGORY
    category[unrecognised] = UNKNOWN_CATEGORY
    stats["attack_rows_without_category"] = int(((category == UNKNOWN_CATEGORY) & (df["label"] == 1)).sum())

    conflict = ((df["label"] == 0) & (category != NORMAL_CATEGORY)) | ((df["label"] == 1) & (category == NORMAL_CATEGORY))
    stats["dropped_conflicting_label"] = int(conflict.sum())
    df["attack_cat"] = category
    df = df.loc[~conflict].copy()

    # ---- categorical text -------------------------------------------------------------
    for col in CATEGORICAL_COLUMNS:
        if col in df.columns:
            s = df[col].astype(object).map(_clean_text)
            stats[_FILLED + col] += int(s.isna().sum())
            df[col] = s.fillna("unknown")

    # ---- IPs, ports ---------------------------------------------------------------------
    for col in IP_COLUMNS:
        before = int(df[col].notna().sum())
        df[col] = _map_unique(df[col].astype(object), normalize_ip).astype(object)
        invalid = before - int(df[col].notna().sum())
        if invalid:
            stats["invalid_ip_set_to_missing"] += invalid
    for col in PORT_COLUMNS:
        before = int(df[col].notna().sum())
        mapped = _map_unique(df[col].astype(object), parse_port)
        df[col] = pd.to_numeric(mapped, errors="coerce").astype("Int64")
        invalid = before - int(df[col].notna().sum())
        if invalid:
            stats["invalid_port_set_to_missing"] += invalid

    # ---- timestamps (Unix epoch seconds in the raw files) ------------------------------
    for src, dst in (("stime", "timestamp"), ("ltime", "end_timestamp")):
        if src in df.columns:
            num = pd.to_numeric(df[src], errors="coerce")
            num = num.where((num >= 0) & (num < 4_102_444_800))
            df[dst] = pd.to_datetime(num, unit="s", utc=True, errors="coerce")
            df = df.drop(columns=[src])
        else:
            df[dst] = pd.NaT
    if "stime" not in df.columns:
        stats["missing_timestamps"] = int(df["timestamp"].isna().sum())

    # ---- numeric features -----------------------------------------------------------------
    for col in [c for c in df.columns if c not in NON_NUMERIC_COLUMNS]:
        numeric = pd.to_numeric(df[col], errors="coerce")
        missing = int(numeric.isna().sum())
        if missing:
            stats[_FILLED + col] += missing
        df[col] = numeric.fillna(0)
    for col in NON_NEGATIVE_COLUMNS:
        if col in df.columns:
            neg = df[col] < 0
            if neg.any():
                stats["negative_values_set_to_zero"] += int(neg.sum())
                df.loc[neg, col] = 0
    for col in BINARY_COLUMNS:
        if col in df.columns:
            stats["non_binary_flags_binarized"] += int((df[col] > 1).sum())
            df[col] = (df[col] > 0).astype("int8")

    # ---- duplicates -------------------------------------------------------------------------
    if drop_duplicates:
        subset = [c for c in df.columns if c != "source_row"]
        n_before = len(df)
        df = df.drop_duplicates(subset=subset).copy()
        stats["dropped_duplicates"] = n_before - len(df)

    stats["rows_out"] = len(df)
    logger.info("Cleaned %s: %d -> %d rows", source_file, stats["rows_in"], stats["rows_out"])
    return df.reset_index(drop=True), stats
