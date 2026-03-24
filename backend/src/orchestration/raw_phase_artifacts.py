"""Helpers for phase-scoped raw MinIO artifacts (recon, post_exploitation, etc.)."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from src.storage.s3 import upload_raw_artifact

_MAX_TOOL_TEXT_CHARS = 750_000


def _artifact_timestamp() -> str:
    return f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}_{uuid.uuid4().hex[:12]}"


class RawPhaseSink:
    """
    Uploads raw bytes/text/json under {tenant}/{scan}/{phase}/raw/ via upload_raw_artifact.
    Each call uses a fresh timestamp so keys do not collide.
    """

    def __init__(self, tenant_id: str, scan_id: str, phase: str) -> None:
        self.tenant_id = tenant_id
        self.scan_id = scan_id
        self.phase = phase

    def upload_bytes(self, artifact_type: str, ext: str, body: bytes) -> None:
        ts = _artifact_timestamp()
        upload_raw_artifact(
            self.tenant_id,
            self.scan_id,
            self.phase,
            ts,
            artifact_type,
            ext,
            body,
        )

    def upload_text(self, artifact_type: str, text: str, ext: str = "txt") -> None:
        if len(text) > _MAX_TOOL_TEXT_CHARS:
            text = text[:_MAX_TOOL_TEXT_CHARS] + "\n... [truncated]"
        try:
            body = text.encode("utf-8", errors="replace")
        except Exception:
            body = b""
        self.upload_bytes(artifact_type, ext, body)

    def upload_json(self, artifact_type: str, obj: Any) -> None:
        try:
            body = json.dumps(obj, default=str, ensure_ascii=False, indent=2).encode("utf-8")
        except (TypeError, ValueError):
            body = str(obj).encode("utf-8", errors="replace")
        self.upload_bytes(artifact_type, "json", body)
