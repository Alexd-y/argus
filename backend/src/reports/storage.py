"""S3/MinIO object storage for reports and artifacts.

Delegates to src.storage.s3. Path structure: {tenant_id}/{scan_id}/{type}/{filename}
Types: reports, screenshots, evidence, raw, attachments.
"""

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
