"""Stage 1 artifacts storage — MinIO stage1-artifacts bucket.

Upload path: {scan_id}/recon_results.json, {scan_id}/mcp_trace.jsonl,
{scan_id}/tech_profile.json, {scan_id}/raw_tool_outputs/*
"""

import logging
from datetime import UTC, datetime
from pathlib import Path

from src.core.config import settings
from src.storage.s3 import _get_client, _sanitize_path_component, ensure_bucket

logger = logging.getLogger(__name__)

STAGE1_ROOT_FILES = (
    "recon_results.json",
    "tech_profile.json",
    "mcp_trace.jsonl",
    "anomalies_structured.json",
)
RAW_TOOL_OUTPUTS_DIR = "raw_tool_outputs"


def ensure_stage1_artifacts_bucket() -> bool:
    """Create stage1-artifacts bucket if not exists. Returns True if available."""
    return ensure_bucket(settings.stage1_artifacts_bucket)


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


def upload_stage1_artifacts(
    artifacts_dir: Path,
    scan_id: str,
    run_id: str,
    job_id: str,
) -> list[str]:
    """Upload Stage 1 artifacts from artifacts_dir to MinIO stage1-artifacts bucket.

    Uploads:
    - {scan_id}/recon_results.json
    - {scan_id}/mcp_trace.jsonl
    - {scan_id}/tech_profile.json
    - {scan_id}/raw_tool_outputs/*

    Object metadata: scan_id, run_id, job_id, generated_at.

    Returns list of uploaded object keys. Skips missing files.
    """
    client = _get_client()
    if not client:
        logger.warning("S3 client unavailable; stage1 artifacts not uploaded")
        return []

    if not ensure_stage1_artifacts_bucket():
        logger.warning("Stage1 artifacts bucket unavailable")
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
    bucket = settings.stage1_artifacts_bucket

    for filename in STAGE1_ROOT_FILES:
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
                "Failed to upload stage1 artifact",
                extra={"file": filename, "error": str(e)},
            )

    raw_dir = artifacts_dir / RAW_TOOL_OUTPUTS_DIR
    if raw_dir.is_dir():
        for filepath in raw_dir.iterdir():
            if not filepath.is_file():
                continue
            try:
                rel = f"{RAW_TOOL_OUTPUTS_DIR}/{filepath.name}"
                key = _build_object_key(scan_id, rel)
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
                    "Failed to upload raw tool output",
                    extra={"file": filepath.name, "error": str(e)},
                )

    if uploaded:
        logger.info(
            "Stage1 artifacts uploaded",
            extra={"scan_id": scan_id, "count": len(uploaded), "keys": uploaded},
        )
    return uploaded
