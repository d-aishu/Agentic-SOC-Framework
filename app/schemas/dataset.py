"""Dataset-related response/request schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class FileInfo(BaseModel):
    filename: str
    size_mb: float
    kind: str
    processable: bool
    n_columns: int
    columns: list[str]


class FileListResponse(BaseModel):
    raw_data_dir: str
    files: list[FileInfo]


class UploadResponse(BaseModel):
    filename: str
    size_mb: float
    kind: str
    processable: bool
    message: str


class ProcessRequest(BaseModel):
    files: Optional[list[str]] = Field(None, description="Filenames inside data/raw. Default: every processable file.")
    max_rows_per_file: Optional[int] = Field(None, gt=0, description="Read only the first N rows of each file (quick tests).")
    drop_duplicates: bool = True


class FileSummary(BaseModel):
    filename: str
    kind: str
    rows_read: int
    rows_kept: int


class ProcessingSummary(BaseModel):
    processed_at: datetime
    dataset_kind: str
    files: list[FileSummary]
    rows_in: int
    rows_out: int
    label_distribution: dict[str, int]
    category_distribution: dict[str, int]
    has_ip_addresses: bool
    has_ports: bool
    has_timestamps: bool
    data_quality: dict[str, int] = Field(description="Counts of rows dropped / values repaired.")
    filled_missing_values: dict[str, int] = Field(description="Per-column count of missing/invalid numbers set to 0.")
    notes: list[str]
