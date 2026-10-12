"""Evidence persistence pipeline.

Owns the redact → hash → upload → audit flow for every byte that lands in
S3 as evidence for a finding. The actual S3 client and audit logger are
injected via Protocols so unit tests can run without network or DB.

Design highlights
-----------------
* **Redact-then-hash**. The on-disk SHA-256 reflects the *redacted* bytes
  so an integrity check post-upload validates exactly what was persisted.
* **Deterministic filename**. ``f"{kind}-{sha256[:16]}.bin"`` makes
  re-uploads idempotent: the same bytes overwrite the same key.
* **Audit logging is best-effort but loud**. Failures inside the audit
  layer surface as warnings; they MUST NOT abort an evidence upload (the
  upload is the contract; audit is observability).
* **Asyncio-friendly**. The S3 client is sync; we hop into a worker
  thread via :func:`asyncio.to_thread` so callers can ``await`` the
  pipeline without blocking their loop.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Final, Protocol, runtime_checkable
from uuid import UUID, uuid4

from src.evidence.redaction import RedactedContent, Redactor
from src.pipeline.contracts.finding_dto import EvidenceDTO, EvidenceKind
from src.policy.audit import AuditEventType, AuditLogger

_logger = logging.getLogger(__name__)


_FILENAME_HASH_PREFIX: Final[int] = 16
_DEFAULT_CONTENT_TYPE: Final[str] = "application/octet-stream"
_OBJECT_TYPE_EVIDENCE: Final[str] = "evidence"


class EvidencePersistError(RuntimeError):
    """Raised when the evidence upload step fails (storage layer error)."""


@runtime_checkable
class StorageUploaderProtocol(Protocol):
    """Subset of :mod:`src.storage.s3` used by the pipeline."""

    def upload(
        self,
        tenant_id: str,
        scan_id: str,
        object_type: str,
        filename: str,
        data: bytes,
        content_type: str = ...,
    ) -> str | None: ...


class EvidencePipeline:
    """Redact, hash, upload, and audit a single evidence blob."""

    def __init__(
        self,
        *,
        storage_uploader: StorageUploaderProtocol,
        redactor: Redactor,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._storage = storage_uploader
        self._redactor = redactor
        self._audit = audit_logger

    async def persist(
        self,
        *,
        tool_run_id: UUID,
        finding_id: UUID | None = None,
        tenant_id: UUID,
        scan_id: UUID,
        kind: EvidenceKind,
        raw_data: bytes,
        content_type: str = _DEFAULT_CONTENT_TYPE,
        redact: bool = True,
    ) -> EvidenceDTO:
        """Persist a single evidence blob and return its :class:`EvidenceDTO`."""
        redacted, sha256_hex, filename = self._prepare(kind, raw_data, redact=redact)
        try:
            object_key = await asyncio.to_thread(
                self._storage.upload,
                str(tenant_id),
                str(scan_id),
                _OBJECT_TYPE_EVIDENCE,
                filename,
                redacted.content,
                content_type,
            )
        except Exception as exc:
            self._audit_failure(tenant_id, scan_id, kind, sha256_hex, redacted, "storage_upload_exception")
            raise EvidencePersistError(f"evidence upload failed for tool_run {tool_run_id}") from exc
        return self._finish(
            object_key=object_key,
            redacted=redacted,
            sha256_hex=sha256_hex,
            kind=kind,
            tool_run_id=tool_run_id,
            finding_id=finding_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
        )

    def persist_sync(
        self,
        *,
        tool_run_id: UUID,
        finding_id: UUID | None = None,
        tenant_id: UUID,
        scan_id: UUID,
        kind: EvidenceKind,
        raw_data: bytes,
        content_type: str = _DEFAULT_CONTENT_TYPE,
        redact: bool = True,
    ) -> EvidenceDTO:
        """Synchronous twin of :meth:`persist` for sync callers (the tool executor).

        Same redact → hash → upload → audit contract; the storage client is sync
        so there is no event loop to hop into.
        """
        redacted, sha256_hex, filename = self._prepare(kind, raw_data, redact=redact)
        try:
            object_key = self._storage.upload(
                str(tenant_id),
                str(scan_id),
                _OBJECT_TYPE_EVIDENCE,
                filename,
                redacted.content,
                content_type,
            )
        except Exception as exc:
            self._audit_failure(tenant_id, scan_id, kind, sha256_hex, redacted, "storage_upload_exception")
            raise EvidencePersistError(f"evidence upload failed for tool_run {tool_run_id}") from exc
        return self._finish(
            object_key=object_key,
            redacted=redacted,
            sha256_hex=sha256_hex,
            kind=kind,
            tool_run_id=tool_run_id,
            finding_id=finding_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
        )

    def _prepare(
        self, kind: EvidenceKind, raw_data: bytes, *, redact: bool
    ) -> tuple[RedactedContent, str, str]:
        """Redact (optionally), hash the redacted bytes, and name the object."""
        if not isinstance(raw_data, (bytes, bytearray)):
            raise TypeError(f"raw_data must be bytes-like, got {type(raw_data).__name__}")
        if redact:
            redacted = self._redactor.redact(bytes(raw_data))
        else:
            redacted = RedactedContent(content=bytes(raw_data), redactions_applied=0, report=())
        sha256_hex = hashlib.sha256(redacted.content).hexdigest()
        filename = f"{kind.value}-{sha256_hex[:_FILENAME_HASH_PREFIX]}.bin"
        return redacted, sha256_hex, filename

    def _finish(
        self,
        *,
        object_key: str | None,
        redacted: RedactedContent,
        sha256_hex: str,
        kind: EvidenceKind,
        tool_run_id: UUID,
        finding_id: UUID | None,
        tenant_id: UUID,
        scan_id: UUID,
    ) -> EvidenceDTO:
        """Validate the upload result, build the DTO, and emit the success audit."""
        if object_key is None:
            self._audit_failure(tenant_id, scan_id, kind, sha256_hex, redacted, "storage_upload_none")
            raise EvidencePersistError(f"evidence upload returned None for tool_run {tool_run_id}")
        evidence = EvidenceDTO(
            id=uuid4(),
            finding_id=finding_id,
            tool_run_id=tool_run_id,
            kind=kind,
            s3_key=object_key,
            sha256=sha256_hex,
            redactions_applied=min(redacted.redactions_applied, 10_000),
        )
        self._emit_audit(
            tenant_id=tenant_id,
            scan_id=scan_id,
            allowed=True,
            kind=kind,
            sha256_hex=sha256_hex,
            redactions_applied=redacted.redactions_applied,
            failure=None,
        )
        return evidence

    def _audit_failure(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        kind: EvidenceKind,
        sha256_hex: str,
        redacted: RedactedContent,
        failure: str,
    ) -> None:
        self._emit_audit(
            tenant_id=tenant_id,
            scan_id=scan_id,
            allowed=False,
            kind=kind,
            sha256_hex=sha256_hex,
            redactions_applied=redacted.redactions_applied,
            failure=failure,
        )

    def _emit_audit(
        self,
        *,
        tenant_id: UUID,
        scan_id: UUID,
        allowed: bool,
        kind: EvidenceKind,
        sha256_hex: str,
        redactions_applied: int,
        failure: str | None,
    ) -> None:
        """Emit an audit row; never raise (observability is best-effort)."""
        if self._audit is None:
            return
        payload: dict[str, object] = {
            "kind": kind.value,
            "sha256_prefix": sha256_hex[:16],
            "redactions_applied": min(max(redactions_applied, 0), 10_000),
        }
        try:
            self._audit.emit(
                event_type=AuditEventType.POLICY_DECISION,
                tenant_id=tenant_id,
                scan_id=scan_id,
                decision_allowed=allowed,
                failure_summary=failure,
                payload=payload,
            )
        except Exception:
            _logger.warning(
                "evidence.audit_emit_failed",
                extra={
                    "event": "evidence_audit_emit_failed",
                    "tenant_id": str(tenant_id),
                    "scan_id": str(scan_id),
                    "decision_allowed": allowed,
                },
            )


__all__ = [
    "EvidencePersistError",
    "EvidencePipeline",
    "StorageUploaderProtocol",
]
