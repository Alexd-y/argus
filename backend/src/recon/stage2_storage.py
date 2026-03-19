"""Stage 2 artifacts storage — MinIO stage2-artifacts bucket.

Upload path: {scan_id}/threat_model.json, {scan_id}/ai_tm_priority_hypotheses.json,
{scan_id}/ai_tm_application_flows.json, {scan_id}/stage2_inputs.json
"""

import logging
from datetime import UTC, datetime
from pathlib import Path

from src.core.config import settings
from src.storage.s3 import _get_client, _sanitize_path_component, ensure_bucket

logger = logging.getLogger(__name__)

STAGE2_ROOT_FILES = (
    "threat_model.json",
    "ai_tm_priority_hypotheses.json",
    "ai_tm_application_flows.json",
    "stage2_inputs.json",
)


def ensure_stage2_artifacts_bucket() -> bool:
    """Create stage2-artifacts bucket if not exists. Returns True if available."""
    return ensure_bucket(settings.stage2_artifacts_bucket)


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
    if suffix == ".jsonl":
        return "application/x-ndjson"
    if suffix in (".txt", ".md", ".csv"):
        return "text/plain"
    return "application/octet-stream"


def upload_stage2_artifacts(
    artifacts_dir: Path,
    scan_id: str,
    run_id: str,
    job_id: str,
) -> list[str]:
    """Upload Stage 2 artifacts from artifacts_dir to MinIO stage2-artifacts bucket.

    Uploads:
    - {scan_id}/threat_model.json
    - {scan_id}/ai_tm_priority_hypotheses.json
    - {scan_id}/ai_tm_application_flows.json
    - {scan_id}/stage2_inputs.json

    Object metadata: scan_id, run_id, job_id, generated_at.

    Returns list of uploaded object keys. Skips missing files.
    """
    client = _get_client()
    if not client:
        logger.warning("S3 client unavailable; stage2 artifacts not uploaded")
        return []

    if not ensure_stage2_artifacts_bucket():
        logger.warning("Stage2 artifacts bucket unavailable")
        return []

    artifacts_dir = Path(artifacts_dir)
    if not artifacts_dir.is_dir():
        logger.warning("Artifacts dir not found", extra={"path": str(artifacts_dir)})
        return []

    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = {
        "scan_id": scan_id,
        "run_id": run_id,
        "job_id": job_id,
        "generated_at": generated_at,
    }

    uploaded: list[str] = []
    bucket = settings.stage2_artifacts_bucket

    for filename in STAGE2_ROOT_FILES:
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
                "Failed to upload stage2 artifact",
                extra={"file": filename, "error": str(e)},
            )

    if uploaded:
        logger.info(
            "Stage2 artifacts uploaded",
            extra={"scan_id": scan_id, "count": len(uploaded), "keys": uploaded},
        )
    return uploaded
