"""MinIO/S3 storage adapter — raw outputs, screenshots, evidence, reports, attachments.

Path patterns (per backend-architecture.md):
- raw:       {tenant_id}/{scan_id}/raw/{filename}
- screenshots: {tenant_id}/{scan_id}/screenshots/{filename}
- evidence:  {tenant_id}/{scan_id}/evidence/{filename}
- reports:   {tenant_id}/{scan_id}/reports/{filename}
- attachments: {tenant_id}/{scan_id}/attachments/{filename}
"""

import logging
import re
from typing import BinaryIO

from src.core.config import settings

logger = logging.getLogger(__name__)

# Lazy import to avoid boto3 requirement when storage disabled
_client = None

# Path traversal: reject slashes, backslashes, parent dir refs (for path components)
_FORBIDDEN_PATTERN = re.compile(r"[/\\]|\.\.|^\s*$")

# Full object key: reject path traversal, backslashes, leading slash, empty
_FORBIDDEN_KEY_PATTERN = re.compile(r"\.\.|\\|^/|^\s*$")

# Object type constants (path segments)
OBJECT_TYPE_RAW = "raw"
OBJECT_TYPE_SCREENSHOTS = "screenshots"
OBJECT_TYPE_EVIDENCE = "evidence"
OBJECT_TYPE_REPORTS = "reports"
OBJECT_TYPE_ATTACHMENTS = "attachments"


def _validate_object_key(object_key: str) -> bool:
    """Validate object key; reject path traversal. Returns False if invalid."""
    if not isinstance(object_key, str) or not object_key.strip():
        return False
    return not _FORBIDDEN_KEY_PATTERN.search(object_key)


def _sanitize_path_component(value: str, name: str) -> str:
    """Validate path component; reject path traversal. Raises ValueError if invalid."""
    if not isinstance(value, str):
        raise ValueError(f"Invalid {name}: expected string")
    val = value.strip()
    if _FORBIDDEN_PATTERN.search(val):
        raise ValueError(f"Invalid {name}: path traversal or forbidden characters")
    if not val:
        raise ValueError(f"Invalid {name}: empty")
    return val


def _get_client():
    """Lazy-init S3 client. Uses boto3 for S3/MinIO compatibility."""
    global _client
    if _client is None:
        try:
            import boto3
            from botocore.config import Config

            endpoint = settings.minio_endpoint
            if not endpoint.startswith("http"):
                scheme = "https" if settings.minio_secure else "http"
                endpoint = f"{scheme}://{endpoint}"

            _client = boto3.client(
                "s3",
                endpoint_url=endpoint,
                aws_access_key_id=settings.minio_access_key,
                aws_secret_access_key=settings.minio_secret_key,
                config=Config(signature_version="s3v4", retries={"max_attempts": 2}),
                region_name="us-east-1",
            )
        except ImportError as e:
            logger.warning("boto3 not installed; storage disabled", extra={"error": str(e)})
            return None
    return _client


def build_object_key(
    tenant_id: str,
    scan_id: str,
    object_type: str,
    filename: str,
) -> str:
    """
    Build object key: tenant_id/scan_id/object_type/filename.
    Validates all components against path traversal.
    object_type: raw, screenshots, evidence, reports, attachments
    """
    t = _sanitize_path_component(tenant_id, "tenant_id")
    s = _sanitize_path_component(scan_id, "scan_id")
    o = _sanitize_path_component(object_type, "object_type")
    f = _sanitize_path_component(filename, "filename")
    return f"{t}/{s}/{o}/{f}"


def ensure_bucket(bucket_name: str | None = None) -> bool:
    """Create bucket if not exists. Returns True if bucket is available.
    When bucket_name is None, uses settings.minio_bucket."""
    client = _get_client()
    if not client:
        return False
    bucket = bucket_name or settings.minio_bucket
    try:
        client.head_bucket(Bucket=bucket)
        return True
    except client.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "404":
            try:
                client.create_bucket(Bucket=bucket)
                return True
            except Exception:
                logger.warning("Failed to create bucket", extra={"bucket": bucket})
                return False
        return False
    except Exception:
        return False


def upload(
    tenant_id: str,
    scan_id: str,
    object_type: str,
    filename: str,
    data: bytes | BinaryIO,
    content_type: str = "application/octet-stream",
) -> str | None:
    """
    Upload object to storage.
    Returns object key on success, None on failure.
    object_type: raw, screenshots, evidence, reports, attachments
    """
    client = _get_client()
    if not client:
        return None
    key = build_object_key(tenant_id, scan_id, object_type, filename)
    try:
        body = data if isinstance(data, (bytes, bytearray)) else data.read()
        client.put_object(
            Bucket=settings.minio_bucket,
            Key=key,
            Body=body,
            ContentType=content_type,
        )
        return key
    except Exception:
        logger.warning("Upload failed", extra={"key": key})
        return None


def download(tenant_id: str, scan_id: str, object_type: str, filename: str) -> bytes | None:
    """Download object. Returns bytes or None if not found."""
    client = _get_client()
    if not client:
        return None
    key = build_object_key(tenant_id, scan_id, object_type, filename)
    try:
        resp = client.get_object(Bucket=settings.minio_bucket, Key=key)
        return resp["Body"].read()
    except client.exceptions.NoSuchKey:
        return None
    except Exception:
        logger.warning("Download failed", extra={"key": key})
        return None


def download_by_key(object_key: str) -> bytes | None:
    """Download object by full key. Returns bytes or None if not found."""
    if not _validate_object_key(object_key):
        return None
    client = _get_client()
    if not client:
        return None
    try:
        resp = client.get_object(Bucket=settings.minio_bucket, Key=object_key)
        return resp["Body"].read()
    except client.exceptions.NoSuchKey:
        return None
    except Exception:
        logger.warning("Download failed", extra={"key": object_key})
        return None


def exists(tenant_id: str, scan_id: str, object_type: str, filename: str) -> bool:
    """Check if object exists."""
    client = _get_client()
    if not client:
        return False
    key = build_object_key(tenant_id, scan_id, object_type, filename)
    try:
        client.head_object(Bucket=settings.minio_bucket, Key=key)
        return True
    except client.exceptions.ClientError as e:
        resp = getattr(e, "response", e.args[0] if e.args else {})
        if isinstance(resp, dict) and resp.get("Error", {}).get("Code") == "404":
            return False
        raise
    except Exception:
        return False


def get_presigned_url(
    tenant_id: str,
    scan_id: str,
    object_type: str,
    filename: str,
    expires_in: int = 3600,
) -> str | None:
    """Generate presigned download URL. Returns None if client unavailable."""
    client = _get_client()
    if not client:
        return None
    key = build_object_key(tenant_id, scan_id, object_type, filename)
    try:
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": settings.minio_bucket, "Key": key},
            ExpiresIn=expires_in,
        )
    except Exception:
        return None


def get_presigned_url_by_key(object_key: str, expires_in: int = 3600) -> str | None:
    """Generate presigned URL by full object key."""
    if not _validate_object_key(object_key):
        return None
    client = _get_client()
    if not client:
        return None
    try:
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": settings.minio_bucket, "Key": object_key},
            ExpiresIn=expires_in,
        )
    except Exception:
        return None
