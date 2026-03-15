"""Recon artifact storage — hierarchical MinIO keys for recon pipeline."""

import hashlib
import logging
from typing import BinaryIO

from src.core.config import settings
from src.storage.s3 import (
    _get_client,
    _sanitize_path_component,
    _validate_object_key,
)

logger = logging.getLogger(__name__)

STAGE_NAMES: dict[int, str] = {
    0: "00_scope",
    1: "01_domains",
    2: "02_subdomains",
    3: "03_dns",
    4: "04_live_hosts",
    5: "05_clustering",
    6: "06_fingerprint",
    7: "07_endpoints",
    8: "08_crawl",
    9: "09_params",
    10: "10_js",
    11: "11_api",
    12: "12_ports",
    13: "13_tls",
    14: "14_content",
    15: "15_osint",
    16: "16_hypothesis",
    17: "17_attack_map",
    18: "18_reporting",
    19: "19_vulnerability_analysis",
}


def get_stage_name(stage: int) -> str:
    """Get folder name for a recon stage number."""
    return STAGE_NAMES.get(stage, f"{stage:02d}_unknown")


def build_recon_object_key(
    engagement_id: str,
    target_id: str,
    job_id: str,
    stage: int,
    filename: str,
) -> str:
    """Build hierarchical MinIO key for recon artifact.

    Pattern: engagements/{engagement_id}/targets/{target_id}/jobs/{job_id}/{stage_name}/{filename}
    All components validated against path traversal.
    """
    e = _sanitize_path_component(engagement_id, "engagement_id")
    t = _sanitize_path_component(target_id, "target_id")
    j = _sanitize_path_component(job_id, "job_id")
    f = _sanitize_path_component(filename, "filename")
    stage_name = get_stage_name(stage)
    return f"engagements/{e}/targets/{t}/jobs/{j}/{stage_name}/{f}"


def _compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def ensure_recon_bucket() -> bool:
    """Create recon artifact bucket if not exists."""
    client = _get_client()
    if not client:
        return False
    bucket = settings.recon_artifact_bucket
    try:
        client.head_bucket(Bucket=bucket)
        return True
    except Exception:
        try:
            client.create_bucket(Bucket=bucket)
            logger.info("Created recon bucket", extra={"bucket": bucket})
            return True
        except Exception:
            logger.warning("Failed to create recon bucket", extra={"bucket": bucket})
            return False


def upload_artifact(
    engagement_id: str,
    target_id: str,
    job_id: str,
    stage: int,
    filename: str,
    data: bytes | BinaryIO,
    content_type: str = "text/plain",
) -> tuple[str | None, str | None, int]:
    """Upload artifact to MinIO recon bucket.

    Returns: (object_key, sha256_checksum, size_bytes) or (None, None, 0) on failure.
    """
    client = _get_client()
    if not client:
        return None, None, 0

    key = build_recon_object_key(engagement_id, target_id, job_id, stage, filename)
    body = data if isinstance(data, (bytes, bytearray)) else data.read()
    checksum = _compute_sha256(body)
    size = len(body)

    try:
        client.put_object(
            Bucket=settings.recon_artifact_bucket,
            Key=key,
            Body=body,
            ContentType=content_type,
        )
        logger.info(
            "Artifact uploaded",
            extra={"key": key, "size": size, "checksum": checksum[:16]},
        )
        return key, checksum, size
    except Exception:
        logger.warning("Artifact upload failed", extra={"key": key})
        return None, None, 0


def download_artifact(object_key: str) -> bytes | None:
    """Download artifact from recon bucket by full key."""
    if not _validate_object_key(object_key):
        return None
    client = _get_client()
    if not client:
        return None
    try:
        resp = client.get_object(Bucket=settings.recon_artifact_bucket, Key=object_key)
        return resp["Body"].read()
    except Exception:
        logger.warning("Artifact download failed", extra={"key": object_key})
        return None


def get_artifact_url(object_key: str, expires_in: int = 3600) -> str | None:
    """Generate presigned download URL for recon artifact."""
    if not _validate_object_key(object_key):
        return None
    client = _get_client()
    if not client:
        return None
    try:
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": settings.recon_artifact_bucket, "Key": object_key},
            ExpiresIn=expires_in,
        )
    except Exception:
        return None


def list_artifacts_by_prefix(prefix: str) -> list[str]:
    """List object keys with given prefix in recon bucket."""
    client = _get_client()
    if not client:
        return []
    try:
        resp = client.list_objects_v2(
            Bucket=settings.recon_artifact_bucket,
            Prefix=prefix,
            MaxKeys=1000,
        )
        return [obj["Key"] for obj in resp.get("Contents", [])]
    except Exception:
        logger.warning("List artifacts failed", extra={"prefix": prefix})
        return []


def delete_artifact(object_key: str) -> bool:
    """Delete artifact from recon bucket."""
    if not _validate_object_key(object_key):
        return False
    client = _get_client()
    if not client:
        return False
    try:
        client.delete_object(Bucket=settings.recon_artifact_bucket, Key=object_key)
        return True
    except Exception:
        logger.warning("Artifact delete failed", extra={"key": object_key})
        return False
