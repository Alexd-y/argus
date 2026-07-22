"""Object backend for spilled HTTP bodies (WB-P2a-2).

Small bodies are stored inline in the DB; medium bodies "spill" to an object
store addressed by a content-derived key; oversized bodies are dropped
(:class:`~src.web_workbench.proxy.transport.BodyPlan` with ``truncated=True``).
This module provides only the *object* backend used for the spill case:

* :class:`BodyObjectStore` — the Protocol the repository depends on;
* :class:`InMemoryBodyObjectStore` — deterministic, for unit tests;
* :class:`S3BodyObjectStore` — thin adapter over :mod:`src.storage.s3` that
  reuses the existing path-validated, tenant-scoped upload/download surface.

Keys are content-addressed (``sha256``) under a tenant/project prefix, so
identical bodies deduplicate and no body content ever appears in a key or a log.
"""

from __future__ import annotations

from typing import Protocol

from src.storage import s3

_OBJECT_TYPE = "attachments"


class BodyStoreError(Exception):
    """Raised when the object backend cannot store or fetch a body."""


def build_body_key(tenant_id: str, project_id: str, sha256: str) -> str:
    """Deterministic, content-addressed object key for a body."""
    return s3.build_object_key(tenant_id, project_id, _OBJECT_TYPE, f"{sha256}.body")


class BodyObjectStore(Protocol):
    """Pluggable object backend for spilled bodies."""

    def put(
        self,
        *,
        tenant_id: str,
        project_id: str,
        sha256: str,
        data: bytes,
        content_type: str | None,
    ) -> str:
        """Persist ``data`` and return its object key. Raises on failure."""
        ...

    def get(self, object_key: str) -> bytes | None:
        """Fetch body bytes by key, or ``None`` if absent."""
        ...


class InMemoryBodyObjectStore:
    """In-memory backend for tests (deterministic, no external I/O)."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def put(
        self,
        *,
        tenant_id: str,
        project_id: str,
        sha256: str,
        data: bytes,
        content_type: str | None,
    ) -> str:
        key = build_body_key(tenant_id, project_id, sha256)
        self._objects[key] = data
        return key

    def get(self, object_key: str) -> bytes | None:
        return self._objects.get(object_key)


class S3BodyObjectStore:
    """MinIO/S3-backed backend over the existing :mod:`src.storage.s3` surface."""

    def put(
        self,
        *,
        tenant_id: str,
        project_id: str,
        sha256: str,
        data: bytes,
        content_type: str | None,
    ) -> str:
        key = s3.upload(
            tenant_id,
            project_id,
            _OBJECT_TYPE,
            f"{sha256}.body",
            data,
            content_type or "application/octet-stream",
        )
        if key is None:
            raise BodyStoreError("failed to store body in object storage")
        return key

    def get(self, object_key: str) -> bytes | None:
        return s3.download_by_key(object_key)


__all__ = [
    "BodyObjectStore",
    "BodyStoreError",
    "InMemoryBodyObjectStore",
    "S3BodyObjectStore",
    "build_body_key",
]
