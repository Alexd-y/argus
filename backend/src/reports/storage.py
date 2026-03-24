"""S3/MinIO object storage for reports.

Delegates to src.storage.s3 with object_type ``reports`` → dedicated ``MINIO_REPORTS_BUCKET``.
Path structure: {tenant_id}/{scan_id}/reports/{filename}
"""

from src.core.config import settings
from src.storage.s3 import (
    download,
    exists,
    get_presigned_url,
    upload,
)
from src.storage.s3 import ensure_bucket as _ensure_bucket_named

__all__ = [
    "download",
    "ensure_bucket",
    "exists",
    "get_presigned_url",
    "upload",
]


def ensure_bucket() -> bool:
    """Create reports bucket if missing (not the default stage/artifact bucket)."""
    return _ensure_bucket_named(settings.minio_reports_bucket)
