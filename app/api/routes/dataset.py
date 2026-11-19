"""Dataset endpoints: take (upload/list), process, summary."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, File, UploadFile

from app.api.deps import get_dataset_store, get_settings
from app.dataset.loader import FileKind, inspect_file, list_csv_files
from app.preprocessing.pipeline import process_dataset
from app.schemas.dataset import FileInfo, FileListResponse, ProcessRequest, ProcessingSummary, UploadResponse
from app.utils.exceptions import InvalidDatasetError, InvalidRequestError, PayloadTooLargeError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/dataset", tags=["dataset"])

_CHUNK = 1024 * 1024


def _mb(path: Path) -> float:
    return round(path.stat().st_size / (1024 * 1024), 3)


@router.get("/files", response_model=FileListResponse, summary="List CSV files in data/raw and their detected layout")
def list_files(settings=Depends(get_settings)):
    files = [
        FileInfo(filename=i.path.name, size_mb=_mb(i.path), kind=i.kind.value,
                 processable=i.processable, n_columns=i.n_columns, columns=i.columns)
        for i in list_csv_files(settings.raw_data_dir)
    ]
    return FileListResponse(raw_data_dir=str(settings.raw_data_dir), files=files)


@router.post("/upload", response_model=UploadResponse, status_code=201,
             summary="Take a dataset file (upload a UNSW-NB15 CSV into data/raw)")
def upload_file(file: UploadFile = File(...), settings=Depends(get_settings)):
    name = Path(file.filename or "").name
    if not name.lower().endswith(".csv"):
        raise InvalidRequestError("Only .csv files are accepted.")
    target = settings.raw_data_dir / name
    limit = settings.max_upload_mb * 1024 * 1024
    written = 0
    try:
        with target.open("wb") as out:
            while chunk := file.file.read(_CHUNK):
                written += len(chunk)
                if written > limit:
                    raise PayloadTooLargeError(f"File exceeds the {settings.max_upload_mb} MB upload limit.")
                out.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise

    inspection = inspect_file(target)
    if inspection.kind == FileKind.UNKNOWN:
        target.unlink(missing_ok=True)
        raise InvalidDatasetError(
            f"'{name}' does not look like a UNSW-NB15 file (expected 49 columns without header, "
            "or a header containing 'attack_cat' and 'label')."
        )
    logger.info("Uploaded %s (%s, %.2f MB)", name, inspection.kind.value, written / 1024 / 1024)
    note = "Ready for processing." if inspection.processable else "Stored, but metadata files are not processed in Phase 1."
    return UploadResponse(filename=name, size_mb=round(written / 1024 / 1024, 3),
                          kind=inspection.kind.value, processable=inspection.processable, message=note)


@router.post("/process", response_model=ProcessingSummary, summary="Clean the dataset and keep it ready for alert generation")
def process(request: ProcessRequest | None = None, settings=Depends(get_settings), store=Depends(get_dataset_store)):
    request = request or ProcessRequest()
    df, summary = process_dataset(
        settings.raw_data_dir, request.files, request.max_rows_per_file, request.drop_duplicates)
    store.set(df, summary)
    return summary


@router.get("/summary", response_model=ProcessingSummary, summary="Summary of the last processing run")
def summary(store=Depends(get_dataset_store)):
    from app.utils.exceptions import DatasetNotProcessedError
    if not store.ready or store.summary is None:
        raise DatasetNotProcessedError("No processed dataset yet. Call POST /api/v1/dataset/process first.")
    return store.summary
