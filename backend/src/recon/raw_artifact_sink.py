"""DRY helpers for phase-scoped raw MinIO artifacts (recon pipelines).

Uses ``upload_raw_artifact``; failures are non-fatal (returns None, logs in storage layer).
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from src.storage.s3 import upload_raw_artifact

_SLUG_RE = re.compile(r"[^a-z0-9]+")

# Align with orchestration RawPhaseSink: avoid huge duplicate blobs in object storage.
_MAX_RAW_TEXT_CHARS = 750_000
_MAX_RAW_JSON_BYTES = 1_500_000


def raw_artifact_timestamp() -> str:
    """UTC timestamp safe for S3 path component (no slashes)."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S_%f")


def slug_for_artifact_type_component(value: str, max_len: int = 48) -> str:
    """Normalize a dynamic segment (tool name, candidate id) for use inside artifact_type."""
    t = _SLUG_RE.sub("_", value.lower().strip()).strip("_")
    if len(t) > max_len:
        t = t[:max_len].rstrip("_")
    if not t:
        t = "unknown"
    if t[0].isdigit():
        t = f"c_{t}"
    return t


def sink_raw_bytes(
    *,
    tenant_id: str | None,
    scan_id: str,
    phase: str,
    artifact_type: str,
    ext: str,
    data: bytes,
    content_type: str | None = None,
) -> str | None:
    """Upload raw bytes; skips when tenant_id missing or scan_id empty."""
    if not tenant_id or not tenant_id.strip():
        return None
    if not scan_id or not scan_id.strip():
        return None
    ts = raw_artifact_timestamp()
    return upload_raw_artifact(
        tenant_id=tenant_id.strip(),
        scan_id=scan_id.strip(),
        phase=phase,
        timestamp=ts,
        artifact_type=artifact_type,
        ext=ext,
        data=data,
        content_type=content_type,
    )


def sink_raw_json(
    *,
    tenant_id: str | None,
    scan_id: str,
    phase: str,
    artifact_type: str,
    payload: Any,
) -> str | None:
    body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    if len(body) > _MAX_RAW_JSON_BYTES:
        marker = b"\n... [json_truncated]"
        body = body[: _MAX_RAW_JSON_BYTES - len(marker)] + marker
    return sink_raw_bytes(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=phase,
        artifact_type=artifact_type,
        ext="json",
        data=body,
    )


def sink_raw_text(
    *,
    tenant_id: str | None,
    scan_id: str,
    phase: str,
    artifact_type: str,
    text: str,
    ext: str = "txt",
) -> str | None:
    if len(text) > _MAX_RAW_TEXT_CHARS:
        text = text[:_MAX_RAW_TEXT_CHARS] + "\n... [truncated]"
    body = text.encode("utf-8", errors="replace")
    return sink_raw_bytes(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=phase,
        artifact_type=artifact_type,
        ext=ext,
        data=body,
    )
