"""MinIO/S3 storage adapter — raw outputs, screenshots, evidence, reports, attachments.

Objects with object_type ``reports`` use ``settings.minio_reports_bucket``; other types use ``settings.minio_bucket``.

Path patterns (per backend-architecture.md):
- raw:       {tenant_id}/{scan_id}/raw/{filename}
- raw (phase): {tenant_id}/{scan_id}/{phase}/raw/{timestamp}_{artifact_type}.{ext}
  phase ∈ recon | threat_modeling | vuln_analysis | exploitation | post_exploitation
- recon summary (stable, RECON-009): {tenant_id}/{scan_id}/recon/raw/recon_summary.json
- screenshots: {tenant_id}/{scan_id}/screenshots/{filename}
- evidence:  {tenant_id}/{scan_id}/evidence/{filename}
- reports:   {tenant_id}/{scan_id}/reports/{filename} (legacy flat filename)
- report artifacts (RPT): {tenant_id}/{scan_id}/reports/{tier}/{report_id}.{fmt}
- attachments: {tenant_id}/{scan_id}/attachments/{filename}
- poc (finding PoC JSON, idempotent): {tenant_id}/{scan_id}/poc/{finding_id}.json — primary bucket (``settings.minio_bucket``), same as raw tooling artifacts (not reports bucket).
- poc screenshots (PNG, idempotent): {tenant_id}/{scan_id}/poc/screenshots/{finding_id}.png — same bucket as PoC JSON.
"""

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any, BinaryIO
from urllib.parse import urlparse, urlunparse

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
OBJECT_TYPE_POC = "poc"
# PoC screenshot objects live under .../poc/screenshots/ (not top-level object_type segment)
POC_SCREENSHOTS_DIR = "screenshots"

# Phase-scoped raw artifacts (MinIO key segment after scan_id)
RAW_ARTIFACT_PHASES: frozenset[str] = frozenset(
    {
        "recon",
        "threat_modeling",
        "vuln_analysis",
        "exploitation",
        "post_exploitation",
    }
)

_ARTIFACT_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_EXT_PATTERN = re.compile(r"^[a-zA-Z0-9]{1,16}$")


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


def _bucket_for_object_type(object_type: str) -> str:
    """Resolve bucket for path segment object_type (reports → dedicated bucket)."""
    if object_type == OBJECT_TYPE_REPORTS:
        return settings.minio_reports_bucket
    return settings.minio_bucket


def _bucket_for_object_key(object_key: str) -> str:
    """Infer bucket from key shape tenant/scan/object_type/filename."""
    parts = object_key.split("/")
    if len(parts) >= 4 and parts[2] == OBJECT_TYPE_REPORTS:
        return settings.minio_reports_bucket
    return settings.minio_bucket


def _normalize_raw_ext(ext: str) -> str:
    """Strip leading dot; validate extension (no path chars). Raises ValueError if invalid."""
    if not isinstance(ext, str):
        raise ValueError("Invalid ext: expected string")
    e = ext.strip().lstrip(".")
    if not _EXT_PATTERN.fullmatch(e):
        raise ValueError("Invalid ext: use alphanumeric only, max 16 characters")
    return e


def _content_type_for_raw_ext(ext: str) -> str:
    """Map file extension to Content-Type; default application/octet-stream."""
    low = ext.lower()
    mapping = {
        "json": "application/json",
        "jsonl": "application/x-ndjson",
        "txt": "text/plain; charset=utf-8",
        "log": "text/plain; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "htm": "text/html; charset=utf-8",
        "xml": "application/xml",
        "csv": "text/csv; charset=utf-8",
        "pdf": "application/pdf",
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "webp": "image/webp",
        "bin": "application/octet-stream",
    }
    return mapping.get(low, "application/octet-stream")


def build_raw_phase_object_key(
    tenant_id: str,
    scan_id: str,
    phase: str,
    timestamp: str,
    artifact_type: str,
    ext: str,
) -> str:
    """
    Build phase-scoped raw artifact key:
    ``{tenant_id}/{scan_id}/{phase}/raw/{timestamp}_{artifact_type}.{ext}``
    """
    if phase not in RAW_ARTIFACT_PHASES:
        raise ValueError(f"Invalid phase: must be one of {sorted(RAW_ARTIFACT_PHASES)}")
    t = _sanitize_path_component(tenant_id, "tenant_id")
    s = _sanitize_path_component(scan_id, "scan_id")
    ph = _sanitize_path_component(phase, "phase")
    raw_seg = _sanitize_path_component(OBJECT_TYPE_RAW, "object_type")
    ts = _sanitize_path_component(timestamp, "timestamp")
    if not isinstance(artifact_type, str) or not _ARTIFACT_TYPE_PATTERN.fullmatch(artifact_type.strip()):
        raise ValueError(
            "Invalid artifact_type: use snake_case (lowercase letters, digits, underscores; "
            "start with a letter)"
        )
    at = artifact_type.strip()
    ex = _normalize_raw_ext(ext)
    filename = f"{ts}_{at}.{ex}"
    if _FORBIDDEN_PATTERN.search(filename):
        raise ValueError("Invalid raw artifact filename")
    key = f"{t}/{s}/{ph}/{raw_seg}/{filename}"
    if not _validate_object_key(key):
        raise ValueError("Invalid object key")
    return key


def build_recon_summary_object_key(tenant_id: str, scan_id: str) -> str:
    """
    Stable idempotent key for unified recon summary JSON (RECON-009):
    ``{tenant_id}/{scan_id}/recon/raw/recon_summary.json``
    """
    t = _sanitize_path_component(tenant_id, "tenant_id")
    s = _sanitize_path_component(scan_id, "scan_id")
    ph = _sanitize_path_component("recon", "phase")
    raw_seg = _sanitize_path_component(OBJECT_TYPE_RAW, "object_type")
    filename = "recon_summary.json"
    if _FORBIDDEN_PATTERN.search(filename):
        raise ValueError("Invalid recon summary filename")
    key = f"{t}/{s}/{ph}/{raw_seg}/{filename}"
    if not _validate_object_key(key):
        raise ValueError("Invalid object key")
    return key


def upload_recon_summary_json(tenant_id: str, scan_id: str, obj: Any) -> str | None:
    """Upload recon summary to stable MinIO key; returns key or None on failure."""
    client = _get_client()
    if not client:
        return None
    try:
        key = build_recon_summary_object_key(tenant_id, scan_id)
    except ValueError:
        logger.warning(
            "recon_summary_key_invalid",
            extra={"event": "recon_summary_upload_validation_failed"},
        )
        return None
    try:
        body = json.dumps(obj, default=str, ensure_ascii=False, indent=2).encode("utf-8")
    except (TypeError, ValueError):
        body = str(obj).encode("utf-8", errors="replace")
    bucket = _bucket_for_object_key(key)
    try:
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
        )
        logger.info(
            "recon_summary_uploaded",
            extra={"event": "recon_summary_uploaded", "size_bytes": len(body)},
        )
        return key
    except Exception:
        logger.warning("recon_summary_upload_failed", extra={"event": "recon_summary_upload_failed"})
        return None


def upload_raw_artifact(
    tenant_id: str,
    scan_id: str,
    phase: str,
    timestamp: str,
    artifact_type: str,
    ext: str,
    data: bytes | BinaryIO,
    content_type: str | None = None,
) -> str | None:
    """
    Upload a phase-scoped raw artifact to ``settings.minio_bucket`` (same as non-report objects).
    Returns full object key on success, None if client unavailable, validation fails, or upload errors.
    When ``content_type`` is None, it is inferred from ``ext`` (else ``application/octet-stream``).
    """
    client = _get_client()
    if not client:
        return None
    try:
        key = build_raw_phase_object_key(
            tenant_id, scan_id, phase, timestamp, artifact_type, ext
        )
    except ValueError:
        logger.warning(
            "Invalid raw artifact key parameters",
            extra={
                "event": "raw_artifact_upload_validation_failed",
                "phase": phase if phase in RAW_ARTIFACT_PHASES else "invalid",
            },
        )
        return None
    bucket = _bucket_for_object_key(key)
    ct = content_type if content_type else _content_type_for_raw_ext(_normalize_raw_ext(ext))
    try:
        body = data if isinstance(data, (bytes, bytearray)) else data.read()
        body_len = len(body)
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType=ct,
        )
        logger.info(
            "Raw artifact uploaded",
            extra={
                "event": "raw_artifact_uploaded",
                "phase": phase,
                "artifact_type": artifact_type.strip() if isinstance(artifact_type, str) else "",
                "ext": _normalize_raw_ext(ext),
                "size_bytes": body_len,
            },
        )
        return key
    except Exception:
        logger.warning(
            "Raw artifact upload failed",
            extra={"event": "raw_artifact_upload_failed", "phase": phase},
        )
        return None


def build_report_object_key(
    tenant_id: str,
    scan_id: str,
    tier: str,
    report_id: str,
    fmt: str,
) -> str:
    """
    Report artifact key (5 path segments, single filename component):
    {tenant_id}/{scan_id}/reports/{tier}/{report_id}.{fmt}
    """
    t = _sanitize_path_component(tenant_id, "tenant_id")
    s = _sanitize_path_component(scan_id, "scan_id")
    reports_seg = _sanitize_path_component(OBJECT_TYPE_REPORTS, "object_type")
    tier_c = _sanitize_path_component(tier, "tier")
    rid = _sanitize_path_component(report_id, "report_id")
    ext = _sanitize_path_component(fmt, "fmt")
    filename = f"{rid}.{ext}"
    if _FORBIDDEN_PATTERN.search(filename):
        raise ValueError("Invalid report artifact filename")
    return f"{t}/{s}/{reports_seg}/{tier_c}/{filename}"


def build_finding_poc_object_key(tenant_id: str, scan_id: str, finding_id: str) -> str:
    """Stable key for idempotent PoC JSON: ``{tenant}/{scan}/poc/{finding_id}.json`` (primary MinIO bucket)."""
    fid = _sanitize_path_component(finding_id, "finding_id")
    fname = f"{fid}.json" if not fid.endswith(".json") else fid
    return build_object_key(tenant_id, scan_id, OBJECT_TYPE_POC, fname)


def build_finding_poc_screenshot_object_key(tenant_id: str, scan_id: str, finding_id: str) -> str:
    """
    Stable key for idempotent PoC screenshot PNG (same overwrite semantics as ``upload_finding_poc_json``):
    ``{tenant_id}/{scan_id}/poc/screenshots/{finding_id}.png`` (primary MinIO bucket).
    """
    t = _sanitize_path_component(tenant_id, "tenant_id")
    s = _sanitize_path_component(scan_id, "scan_id")
    poc_seg = _sanitize_path_component(OBJECT_TYPE_POC, "object_type")
    shots_seg = _sanitize_path_component(POC_SCREENSHOTS_DIR, "screenshots")
    fid = _sanitize_path_component(finding_id, "finding_id")
    base = fid[:-4] if fid.lower().endswith(".png") else fid
    if not base:
        raise ValueError("Invalid finding_id for PoC screenshot key")
    fname = f"{base}.png"
    if _FORBIDDEN_PATTERN.search(fname):
        raise ValueError("Invalid PoC screenshot filename")
    key = f"{t}/{s}/{poc_seg}/{shots_seg}/{fname}"
    if not _validate_object_key(key):
        raise ValueError("Invalid object key")
    return key


def _finding_poc_screenshots_prefix(tenant_id: str, scan_id: str) -> str | None:
    """Validated prefix ``{tenant}/{scan}/poc/screenshots/`` for presign access checks."""
    try:
        t = _sanitize_path_component(tenant_id, "tenant_id")
        s = _sanitize_path_component(scan_id, "scan_id")
        poc_seg = _sanitize_path_component(OBJECT_TYPE_POC, "object_type")
        shots_seg = _sanitize_path_component(POC_SCREENSHOTS_DIR, "screenshots")
        return f"{t}/{s}/{poc_seg}/{shots_seg}/"
    except ValueError:
        return None


def get_finding_poc_screenshot_presigned_url(
    object_key: str,
    tenant_id: str,
    scan_id: str,
    *,
    expires_in: int = 3600,
) -> str | None:
    """
    Presigned GET for a PoC screenshot key, only if ``object_key`` is under the given tenant/scan
    ``.../poc/screenshots/*.png``. Reuses bucket resolution from ``get_presigned_url_by_key``.
    """
    if not isinstance(object_key, str) or not object_key.strip():
        return None
    key = object_key.strip()
    if not _validate_object_key(key):
        return None
    prefix = _finding_poc_screenshots_prefix(tenant_id, scan_id)
    if not prefix or not key.startswith(prefix):
        return None
    rest = key[len(prefix) :]
    if not rest or "/" in rest or not rest.lower().endswith(".png"):
        return None
    return get_presigned_url_by_key(key, expires_in=expires_in)


def upload_finding_poc_json(
    tenant_id: str,
    scan_id: str,
    finding_id: str,
    poc_dict: dict[str, Any],
) -> str | None:
    """
    Upload canonical PoC JSON for a finding; overwrites same key (idempotent).
    Uses ``settings.minio_bucket`` (not the reports bucket).
    """
    import json

    client = _get_client()
    if not client:
        return None
    try:
        key = build_finding_poc_object_key(tenant_id, scan_id, finding_id)
    except ValueError:
        logger.warning(
            "Invalid finding PoC key parameters",
            extra={"event": "finding_poc_upload_validation_failed"},
        )
        return None
    try:
        body = json.dumps(poc_dict, ensure_ascii=False, default=str).encode("utf-8")
    except (TypeError, ValueError):
        body = str(poc_dict).encode("utf-8", errors="replace")
    bucket = settings.minio_bucket
    try:
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json; charset=utf-8",
        )
        logger.info(
            "Finding PoC JSON uploaded",
            extra={"event": "finding_poc_uploaded", "size_bytes": len(body)},
        )
        return key
    except Exception:
        logger.warning("Finding PoC upload failed", extra={"event": "finding_poc_upload_failed"})
        return None


def upload_finding_poc_screenshot_png(
    tenant_id: str,
    scan_id: str,
    finding_id: str,
    data: bytes | BinaryIO,
) -> str | None:
    """
    Upload PoC screenshot bytes (PNG). Overwrites the same key as ``upload_finding_poc_json`` (idempotent).
    Uses ``settings.minio_bucket``. Returns object key on success, None on validation or upload failure.
    """
    client = _get_client()
    if not client:
        return None
    try:
        key = build_finding_poc_screenshot_object_key(tenant_id, scan_id, finding_id)
    except ValueError:
        logger.warning(
            "Invalid finding PoC screenshot key parameters",
            extra={"event": "finding_poc_screenshot_upload_validation_failed"},
        )
        return None
    bucket = settings.minio_bucket
    try:
        body = data if isinstance(data, (bytes, bytearray)) else data.read()
        body_len = len(body)
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="image/png",
        )
        logger.info(
            "Finding PoC screenshot uploaded",
            extra={"event": "finding_poc_screenshot_uploaded", "size_bytes": body_len},
        )
        return key
    except Exception:
        logger.warning(
            "Finding PoC screenshot upload failed",
            extra={"event": "finding_poc_screenshot_upload_failed"},
        )
        return None


def upload_report_artifact(
    tenant_id: str,
    scan_id: str,
    tier: str,
    report_id: str,
    fmt: str,
    data: bytes | BinaryIO,
    content_type: str = "application/octet-stream",
) -> str | None:
    """
    Upload one report file to the reports bucket using ``build_report_object_key``.
    Returns full object key on success, None on failure.
    """
    client = _get_client()
    if not client:
        return None
    try:
        key = build_report_object_key(tenant_id, scan_id, tier, report_id, fmt)
    except ValueError:
        logger.warning("Invalid report artifact key parameters", extra={"tenant_id": tenant_id, "scan_id": scan_id})
        return None
    bucket = _bucket_for_object_key(key)
    try:
        body = data if isinstance(data, (bytes, bytearray)) else data.read()
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType=content_type,
        )
        return key
    except Exception:
        logger.warning("Report artifact upload failed", extra={"key": key})
        return None


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
    bucket = _bucket_for_object_type(object_type)
    try:
        body = data if isinstance(data, (bytes, bytearray)) else data.read()
        client.put_object(
            Bucket=bucket,
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
    bucket = _bucket_for_object_type(object_type)
    try:
        resp = client.get_object(Bucket=bucket, Key=key)
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
    bucket = _bucket_for_object_key(object_key)
    try:
        resp = client.get_object(Bucket=bucket, Key=object_key)
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
    bucket = _bucket_for_object_type(object_type)
    try:
        client.head_object(Bucket=bucket, Key=key)
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
    bucket = _bucket_for_object_type(object_type)
    try:
        url = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=expires_in,
        )
        return rewrite_minio_url_for_report(url)
    except Exception:
        return None


def get_presigned_url_by_key(object_key: str, expires_in: int = 3600) -> str | None:
    """Generate presigned URL by full object key."""
    if not _validate_object_key(object_key):
        return None
    client = _get_client()
    if not client:
        return None
    bucket = _bucket_for_object_key(object_key)
    try:
        url = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": object_key},
            ExpiresIn=expires_in,
        )
        return rewrite_minio_url_for_report(url)
    except Exception:
        return None


def rewrite_minio_url_for_report(presigned_url: str) -> str:
    """Replace internal MinIO hostname with public-facing URL for report delivery.

    Falls back to the original URL when ``settings.minio_public_url`` is unset
    (development / same-network access).
    """
    public_base = settings.minio_public_url
    if not public_base:
        return presigned_url
    parsed = urlparse(presigned_url)
    public_parsed = urlparse(public_base)
    rewritten = parsed._replace(
        scheme=public_parsed.scheme,
        netloc=public_parsed.netloc,
    )
    return urlunparse(rewritten)


# Max pages × MaxKeys to cap list cost (DoS mitigation)
_LIST_OBJECTS_MAX_PAGES = 50
_LIST_OBJECTS_PAGE_SIZE = 1000


def _content_type_from_object_key(object_key: str) -> str:
    """Infer Content-Type from filename extension in key (list_objects_v2 has no ContentType)."""
    base = object_key.rsplit("/", 1)[-1]
    if "." in base:
        ext = base.rsplit(".", 1)[-1]
        if _EXT_PATTERN.fullmatch(ext):
            try:
                return _content_type_for_raw_ext(ext)
            except ValueError:
                pass
    return "application/octet-stream"


def _scan_prefix(tenant_id: str, scan_id: str) -> str:
    """Validated ``{tenant_id}/{scan_id}/`` prefix for list operations."""
    t = _sanitize_path_component(tenant_id, "tenant_id")
    s = _sanitize_path_component(scan_id, "scan_id")
    return f"{t}/{s}/"


def _key_is_scan_raw_path(key: str, tenant_id: str, scan_id: str) -> bool:
    """
    True if key is under tenant/scan and is legacy ``raw/`` or ``{phase}/raw/``.
    """
    prefix = _scan_prefix(tenant_id, scan_id)
    if not key.startswith(prefix):
        return False
    rest = key[len(prefix) :]
    if rest.startswith(f"{OBJECT_TYPE_RAW}/"):
        return True
    return any(
        rest.startswith(f"{ph}/{OBJECT_TYPE_RAW}/") for ph in RAW_ARTIFACT_PHASES
    )


def _list_objects_all_pages(client: Any, bucket: str, prefix: str) -> list[dict[str, Any]]:
    """Paginated list_objects_v2; returns raw Contents entries (Key, Size, LastModified)."""
    out: list[dict[str, Any]] = []
    token: str | None = None
    for _ in range(_LIST_OBJECTS_MAX_PAGES):
        kwargs: dict[str, Any] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "MaxKeys": _LIST_OBJECTS_PAGE_SIZE,
        }
        if token:
            kwargs["ContinuationToken"] = token
        resp = client.list_objects_v2(**kwargs)
        out.extend(resp.get("Contents") or [])
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")
        if not token:
            break
    return out


def list_scan_artifacts(
    tenant_id: str,
    scan_id: str,
    *,
    phase: str | None = None,
    raw_only: bool = False,
) -> list[dict[str, Any]] | None:
    """
    List MinIO/S3 objects under tenant/scan prefix (tenant isolation via prefix).

    - ``phase`` set: prefix ``{tenant}/{scan}/{phase}/`` (must be in ``RAW_ARTIFACT_PHASES``).
    - ``raw_only``: restrict to ``.../raw/`` under that scope; without ``phase``, keys must match
      legacy ``.../raw/`` or ``.../{phase}/raw/``.

    Uses ``minio_bucket`` and ``minio_reports_bucket`` when listing the full scan prefix
    (objects may live in either). Phase-scoped lists use ``minio_bucket`` only.

    Returns list of dicts: ``key``, ``size`` (int), ``last_modified`` (datetime), ``content_type`` (str).
    Returns None if S3 client unavailable or listing fails.
    """
    client = _get_client()
    if not client:
        return None
    try:
        base_prefix = _scan_prefix(tenant_id, scan_id)
    except ValueError:
        logger.warning(
            "Invalid tenant or scan id for artifact list",
            extra={"event": "scan_artifacts_list_invalid_prefix"},
        )
        return None

    buckets: tuple[str, ...]
    list_prefix: str

    if phase is not None:
        if phase not in RAW_ARTIFACT_PHASES:
            raise ValueError(f"Invalid phase: must be one of {sorted(RAW_ARTIFACT_PHASES)}")
        ph = _sanitize_path_component(phase, "phase")
        list_prefix = f"{base_prefix}{ph}/"
        if raw_only:
            list_prefix = f"{list_prefix}{OBJECT_TYPE_RAW}/"
        buckets = (settings.minio_bucket,)
    else:
        list_prefix = base_prefix
        if raw_only:
            buckets = (settings.minio_bucket, settings.minio_reports_bucket)
        else:
            buckets = (settings.minio_bucket, settings.minio_reports_bucket)

    try:
        merged: list[dict[str, Any]] = []
        seen: set[str] = set()
        for bucket in buckets:
            for obj in _list_objects_all_pages(client, bucket, list_prefix):
                key = obj.get("Key")
                if not key or key in seen:
                    continue
                if phase is None and raw_only and not _key_is_scan_raw_path(key, tenant_id, scan_id):
                    continue
                seen.add(key)
                lm = obj.get("LastModified")
                if lm is None:
                    lm = datetime.now(UTC)
                elif isinstance(lm, datetime) and lm.tzinfo is None:
                    lm = lm.replace(tzinfo=UTC)
                merged.append(
                    {
                        "key": key,
                        "size": int(obj.get("Size") or 0),
                        "last_modified": lm,
                        "content_type": _content_type_from_object_key(key),
                    }
                )
        merged.sort(key=lambda x: x["key"])
        return merged
    except Exception:
        logger.warning(
            "Scan artifact list failed",
            extra={"event": "scan_artifacts_list_failed"},
        )
        return None
