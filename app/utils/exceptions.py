"""Application-level exceptions mapped to JSON error responses in main.py."""
from __future__ import annotations


class AppError(Exception):
    status_code = 500
    code = "internal_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class DatasetNotFoundError(AppError):
    status_code = 404
    code = "dataset_not_found"


class InvalidDatasetError(AppError):
    status_code = 422
    code = "invalid_dataset"


class DatasetNotProcessedError(AppError):
    status_code = 409
    code = "dataset_not_processed"


class InvalidRequestError(AppError):
    status_code = 422
    code = "invalid_request"


class AlertNotFoundError(AppError):
    status_code = 404
    code = "alert_not_found"


class PayloadTooLargeError(AppError):
    status_code = 413
    code = "payload_too_large"
