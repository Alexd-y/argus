"""Stage 1 artifacts storage — MinIO stage1-artifacts bucket.

Upload path: {scan_id}/recon_results.json, {scan_id}/mcp_trace.jsonl,
{scan_id}/tech_profile.json, {scan_id}/raw_tool_outputs/*
"""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.config import settings
from src.recon.stage_object_download import (
    StageObjectFetchError,
    fetch_stage_bucket_object,
)
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


def upload_stage1_json_objects(scan_id: str, objects: dict[str, Any]) -> list[str]:
    """Upload in-memory ``{filename: json-able}`` to ``{scan_id}/{filename}`` in the
    stage1 bucket.

    The live scan pipeline uses this to persist recon_results.json /
    tech_profile.json / anomalies_structured.json so the report data collector can
    read them — the file-tree uploader above is only reachable from the CLI, which
    is why the Target Intelligence / tech-profile / anomalies report sections were
    empty for every scan. Best-effort: never raises (an artifact hiccup must never
    fail the scan). Only the three Stage-1 JSON root files are accepted.
    """
    client = _get_client()
    if not client:
        logger.warning("S3 client unavailable; stage1 json objects not uploaded")
        return []
    if not ensure_stage1_artifacts_bucket():
        logger.warning("Stage1 artifacts bucket unavailable; stage1 json not uploaded")
        return []
    bucket = settings.stage1_artifacts_bucket
    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    uploaded: list[str] = []
    for filename, payload in (objects or {}).items():
        if filename not in STAGE1_ROOT_FILES or payload is None:
            continue
        try:
            key = _build_object_key(scan_id, filename)
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                Metadata={"scan_id": scan_id, "generated_at": generated_at},
            )
            uploaded.append(key)
        except (ValueError, OSError, TypeError) as e:
            logger.warning(
                "Failed to upload stage1 json object",
                extra={"file": filename, "error": str(e)},
            )
    if uploaded:
        logger.info(
            "stage1_json_objects_uploaded",
            extra={"scan_id": scan_id, "count": len(uploaded), "files": uploaded},
        )
    return uploaded


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


def download_stage1_artifact(scan_id: str, filename: str) -> bytes | None:
    """Download a Stage 1 artifact object from MinIO ({scan_id}/{filename}).

    Returns ``None`` only if the object is missing. Raises
    :class:`StageObjectFetchError` if storage is unavailable or ``get_object`` fails.
    """
    client = _get_client()
    if not client:
        raise StageObjectFetchError("storage_error")
    bucket = settings.stage1_artifacts_bucket
    try:
        key = _build_object_key(scan_id, filename)
    except ValueError:
        raise
    return fetch_stage_bucket_object(client, bucket, key, scan_id=scan_id, filename=filename)
