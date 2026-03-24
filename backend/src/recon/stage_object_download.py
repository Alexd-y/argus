"""Shared MinIO get_object for stage *-artifacts buckets.

Returns ``None`` only when the object is missing (S3 not-found semantics).
Raises :class:`StageObjectFetchError` when the client is unavailable or
``get_object`` fails for reasons other than a missing key.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class StageObjectFetchError(Exception):
    """Stage artifact download failed for a reason other than a missing object.

    ``code`` is ``storage_error`` (no client / unusable storage) or
    ``fetch_failed`` (unexpected error from ``get_object``).
    """

    __slots__ = ("code",)

    def __init__(self, code: str = "storage_error") -> None:
        self.code = code
        super().__init__(code)


def _is_object_not_found(exc: BaseException) -> bool:
    if type(exc).__name__ == "NoSuchKey":
        return True
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        err = response.get("Error", {})
        if isinstance(err, dict):
            code = err.get("Code")
            if code in ("NoSuchKey", "404", "NotFound"):
                return True
        meta = response.get("ResponseMetadata")
        if isinstance(meta, dict) and meta.get("HTTPStatusCode") == 404:
            return True
    return False


def fetch_stage_bucket_object(
    client: Any,
    bucket: str,
    key: str,
    *,
    scan_id: str,
    filename: str,
) -> bytes | None:
    """Read object bytes; ``None`` if missing; raises on other failures."""
    try:
        resp = client.get_object(Bucket=bucket, Key=key)
        return resp["Body"].read()
    except Exception as e:
        if _is_object_not_found(e):
            return None
        logger.warning(
            "Failed to download stage artifact",
            extra={"scan_id": scan_id, "artifact_name": filename, "bucket": bucket},
        )
        raise StageObjectFetchError("fetch_failed") from None
