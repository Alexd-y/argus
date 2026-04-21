"""Shared fixtures for ``tests/unit/evidence``.

Provides:

* :class:`InMemoryUploader` — implements :class:`StorageUploaderProtocol`,
  records every upload for assertion in tests, and supports both happy and
  failure modes.
* :class:`SampleEvidence` — convenience byte payloads (small / large /
  binary) used across redaction and pipeline tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from src.evidence.pipeline import StorageUploaderProtocol


@dataclass
class UploadCall:
    """Captured arguments of an :class:`InMemoryUploader.upload` invocation."""

    tenant_id: str
    scan_id: str
    object_type: str
    filename: str
    data: bytes
    content_type: str


@dataclass
class InMemoryUploader:
    """In-memory stand-in for :mod:`src.storage.s3`."""

    calls: list[UploadCall] = field(default_factory=list)
    return_key: str | None = None
    raise_exception: type[BaseException] | None = None

    def upload(
        self,
        tenant_id: str,
        scan_id: str,
        object_type: str,
        filename: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str | None:
        if self.raise_exception is not None:
            raise self.raise_exception("simulated upload failure")
        self.calls.append(
            UploadCall(
                tenant_id=tenant_id,
                scan_id=scan_id,
                object_type=object_type,
                filename=filename,
                data=bytes(data),
                content_type=content_type,
            )
        )
        if self.return_key is not None:
            return self.return_key
        return f"{tenant_id}/{scan_id}/{object_type}/{filename}"


# Type-check the duck-typed uploader at import time so a regression in the
# protocol breaks the test boot rather than an obscure runtime failure.
def _typecheck_uploader() -> StorageUploaderProtocol:
    return InMemoryUploader()


_typecheck_uploader()


@pytest.fixture
def uploader() -> InMemoryUploader:
    """Fresh in-memory uploader for each test."""
    return InMemoryUploader()
