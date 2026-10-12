"""Process-wide :class:`EvidencePipeline` assembly (wave 2, R-5.3.2).

The pipeline is built once and reused: a storage uploader wrapping
:mod:`src.storage.s3`, a :class:`~src.evidence.redaction.Redactor` with the
default spec set, and an :class:`~src.policy.audit.AuditLogger`. The audit sink
defaults to the in-process :class:`~src.policy.audit.InMemoryAuditSink` and is
swapped for the persistent :class:`DatabaseAuditSink` (wave 2 / stage 6) via
:func:`set_audit_logger`.
"""

from __future__ import annotations

import threading

from src.evidence.pipeline import EvidencePipeline
from src.evidence.redaction import Redactor, default_specs
from src.policy.audit import AuditLogger, InMemoryAuditSink

_DEFAULT_CONTENT_TYPE = "application/octet-stream"


class _S3StorageUploader:
    """Adapt :func:`src.storage.s3.upload` to ``StorageUploaderProtocol``."""

    def upload(
        self,
        tenant_id: str,
        scan_id: str,
        object_type: str,
        filename: str,
        data: bytes,
        content_type: str = _DEFAULT_CONTENT_TYPE,
    ) -> str | None:
        # Imported lazily so building the pipeline never drags the S3 client
        # (boto3) into import-time of unrelated callers.
        from src.storage import s3

        return s3.upload(tenant_id, scan_id, object_type, filename, data, content_type)


_lock = threading.Lock()
_pipeline: EvidencePipeline | None = None
_audit_logger: AuditLogger | None = None


def _default_audit_logger() -> AuditLogger:
    return AuditLogger(InMemoryAuditSink())


def set_audit_logger(logger: AuditLogger) -> None:
    """Install the process-wide audit logger (stage 6 wires DatabaseAuditSink).

    Resets the cached pipeline so the next :func:`get_evidence_pipeline` picks
    up the new logger.
    """
    global _audit_logger, _pipeline
    with _lock:
        _audit_logger = logger
        _pipeline = None


def get_evidence_pipeline() -> EvidencePipeline:
    """Return the shared :class:`EvidencePipeline`, building it on first use."""
    global _pipeline, _audit_logger
    with _lock:
        if _pipeline is None:
            if _audit_logger is None:
                _audit_logger = _default_audit_logger()
            _pipeline = EvidencePipeline(
                storage_uploader=_S3StorageUploader(),
                redactor=Redactor(default_specs()),
                audit_logger=_audit_logger,
            )
        return _pipeline


def reset_evidence_pipeline() -> None:
    """Drop the cached pipeline + audit logger (tests / reconfiguration)."""
    global _pipeline, _audit_logger
    with _lock:
        _pipeline = None
        _audit_logger = None


__all__ = [
    "get_evidence_pipeline",
    "reset_evidence_pipeline",
    "set_audit_logger",
]
