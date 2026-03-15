"""Object storage — MinIO/S3 adapter for raw outputs, screenshots, evidence, reports."""

from src.storage.s3 import (
    download,
    ensure_bucket,
    exists,
    get_presigned_url,
    upload,
)

__all__ = [
    "download",
    "ensure_bucket",
    "exists",
    "get_presigned_url",
    "upload",
]
