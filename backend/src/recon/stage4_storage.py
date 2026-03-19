"""Stage 4 artifacts storage — MinIO stage4-artifacts bucket.

Upload path: {scan_id}/exploitation_plan.json, stage4_results.json,
shells.json, ai_exploitation_summary.json.
"""

import logging
from datetime import UTC, datetime
from pathlib import Path

from src.core.config import settings
from src.storage.s3 import _get_client, _sanitize_path_component, ensure_bucket

logger = logging.getLogger(__name__)

STAGE4_ROOT_FILES: tuple[str, ...] = (
    "exploitation_plan.json",
    "stage4_results.json",
    "shells.json",
    "ai_exploitation_summary.json",
)


def ensure_stage4_artifacts_bucket() -> bool:
    """Create stage4-artifacts bucket if not exists. Returns True if available."""
    return ensure_bucket(settings.stage4_artifacts_bucket)


def _build_object_key(scan_id: str, relative_path: str) -> str:
    """Build object key: {scan_id}/{relative_path}. Validates scan_id."""
    s = _sanitize_path_component(scan_id, "scan_id")
    if not relative_path or ".." in relative_path or "\\" in relative_path:
        raise ValueError("Invalid relative_path: path traversal forbidden")
    return f"{s}/{relative_path}".replace("\\", "/")


def _content_type_for(path: Path) -> str:
    """Infer content type from file extension."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix in (".txt", ".md", ".csv"):
        return "text/plain"
    return "application/octet-stream"


def upload_stage4_artifacts(
    artifacts_dir: Path,
    scan_id: str,
    run_id: str,
) -> list[str]:
    """Upload Stage 4 artifacts from artifacts_dir to MinIO stage4-artifacts bucket.

    Returns list of uploaded object keys. Skips missing files.
    """
    client = _get_client()
    if not client:
        logger.warning("S3 client unavailable; stage4 artifacts not uploaded")
        return []

    if not ensure_stage4_artifacts_bucket():
        logger.warning("Stage4 artifacts bucket unavailable")
        return []

    artifacts_dir = Path(artifacts_dir)
    if not artifacts_dir.is_dir():
        logger.warning("Artifacts dir not found", extra={"path": str(artifacts_dir)})
        return []

    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = {
        "scan_id": scan_id,
        "run_id": run_id,
        "generated_at": generated_at,
    }

    uploaded: list[str] = []
    bucket = settings.stage4_artifacts_bucket

    for filename in STAGE4_ROOT_FILES:
        filepath = artifacts_dir / filename
        if not filepath.is_file():
            continue
        try:
            key = _build_object_key(scan_id, filename)
            body = filepath.read_bytes()
            client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentType=_content_type_for(filepath),
                Metadata=metadata,
            )
            uploaded.append(key)
        except (ValueError, OSError) as e:
            logger.warning(
                "Failed to upload stage4 artifact",
                extra={"file": filename, "error": str(e)},
            )

    if uploaded:
        logger.info(
            "Stage4 artifacts uploaded",
            extra={"scan_id": scan_id, "count": len(uploaded), "keys": uploaded[:10]},
        )
    return uploaded


def download_stage4_artifact(scan_id: str, filename: str) -> bytes | None:
    """Download a specific Stage 4 artifact from MinIO."""
    client = _get_client()
    if not client:
        return None
    bucket = settings.stage4_artifacts_bucket
    try:
        key = _build_object_key(scan_id, filename)
        resp = client.get_object(Bucket=bucket, Key=key)
        return resp["Body"].read()
    except ValueError:
        raise
    except Exception:
        logger.warning(
            "Failed to download stage4 artifact",
            extra={"scan_id": scan_id, "artifact_name": filename},
        )
        return None
