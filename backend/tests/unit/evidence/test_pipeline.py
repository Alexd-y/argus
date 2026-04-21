"""Unit tests for :mod:`src.evidence.pipeline`."""

from __future__ import annotations

import hashlib
from uuid import uuid4

import pytest

from src.evidence.pipeline import (
    EvidencePersistError,
    EvidencePipeline,
    StorageUploaderProtocol,
)
from src.evidence.redaction import Redactor
from src.pipeline.contracts.finding_dto import EvidenceDTO, EvidenceKind
from src.policy.audit import AuditEventType, AuditLogger, InMemoryAuditSink
from tests.unit.evidence.conftest import InMemoryUploader


# ---------------------------------------------------------------------------
# Identifiers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ids() -> dict[str, object]:
    return {
        "finding_id": uuid4(),
        "tool_run_id": uuid4(),
        "tenant_id": uuid4(),
        "scan_id": uuid4(),
    }


@pytest.fixture
def audit_logger() -> AuditLogger:
    return AuditLogger(InMemoryAuditSink())


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_persist_redacts_uploads_and_emits_audit(
    uploader: InMemoryUploader,
    audit_logger: AuditLogger,
    ids: dict[str, object],
) -> None:
    pipeline = EvidencePipeline(
        storage_uploader=uploader,
        redactor=Redactor(),
        audit_logger=audit_logger,
    )
    raw = b"Authorization: Bearer secret.token-1\nbody=ok"
    evidence = await pipeline.persist(
        **ids,  # type: ignore[arg-type]
        kind=EvidenceKind.RAW_OUTPUT,
        raw_data=raw,
        content_type="text/plain",
    )
    assert isinstance(evidence, EvidenceDTO)
    assert evidence.kind is EvidenceKind.RAW_OUTPUT
    assert evidence.redactions_applied == 1
    assert len(uploader.calls) == 1
    upload_call = uploader.calls[0]
    assert upload_call.object_type == "evidence"
    assert upload_call.content_type == "text/plain"
    assert b"[REDACTED:bearer_token]" in upload_call.data
    assert evidence.sha256 == hashlib.sha256(upload_call.data).hexdigest()
    events = list(audit_logger.sink.iter_events(tenant_id=ids["tenant_id"]))
    assert len(events) == 1
    assert events[0].event_type is AuditEventType.POLICY_DECISION
    assert events[0].decision_allowed is True
    assert events[0].payload["redactions_applied"] == 1


async def test_persist_filename_deterministic_for_same_bytes(
    uploader: InMemoryUploader, ids: dict[str, object]
) -> None:
    pipeline = EvidencePipeline(
        storage_uploader=uploader,
        redactor=Redactor(),
    )
    raw = b"static-payload"
    a = await pipeline.persist(
        **ids,  # type: ignore[arg-type]
        kind=EvidenceKind.PARSED,
        raw_data=raw,
    )
    b = await pipeline.persist(
        **ids,  # type: ignore[arg-type]
        kind=EvidenceKind.PARSED,
        raw_data=raw,
    )
    assert uploader.calls[0].filename == uploader.calls[1].filename
    assert uploader.calls[0].data == uploader.calls[1].data
    assert a.sha256 == b.sha256


async def test_persist_filename_format(
    uploader: InMemoryUploader, ids: dict[str, object]
) -> None:
    pipeline = EvidencePipeline(
        storage_uploader=uploader,
        redactor=Redactor(),
    )
    raw = b"some bytes"
    evidence = await pipeline.persist(
        **ids,  # type: ignore[arg-type]
        kind=EvidenceKind.SCREENSHOT,
        raw_data=raw,
    )
    expected_prefix = f"{EvidenceKind.SCREENSHOT.value}-{evidence.sha256[:16]}"
    assert uploader.calls[0].filename.startswith(expected_prefix)
    assert uploader.calls[0].filename.endswith(".bin")


# ---------------------------------------------------------------------------
# Redaction toggling
# ---------------------------------------------------------------------------


async def test_persist_redact_false_skips_redaction(
    uploader: InMemoryUploader, ids: dict[str, object]
) -> None:
    pipeline = EvidencePipeline(
        storage_uploader=uploader,
        redactor=Redactor(),
    )
    raw = b"Authorization: Bearer secret.token-2"
    evidence = await pipeline.persist(
        **ids,  # type: ignore[arg-type]
        kind=EvidenceKind.RAW_OUTPUT,
        raw_data=raw,
        redact=False,
    )
    assert evidence.redactions_applied == 0
    assert uploader.calls[0].data == raw


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


async def test_persist_uploader_returns_none_raises(
    audit_logger: AuditLogger, ids: dict[str, object]
) -> None:
    uploader = InMemoryUploader(return_key=None)
    uploader.return_key = ""

    class NoneUploader(InMemoryUploader):
        def upload(  # type: ignore[override]
            self,
            tenant_id: str,
            scan_id: str,
            object_type: str,
            filename: str,
            data: bytes,
            content_type: str = "application/octet-stream",
        ) -> str | None:
            self.calls.append(
                # Reuse the dataclass for symmetry though we never read it.
                __import__(
                    "tests.unit.evidence.conftest", fromlist=["UploadCall"]
                ).UploadCall(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    object_type=object_type,
                    filename=filename,
                    data=bytes(data),
                    content_type=content_type,
                )
            )
            return None

    none_uploader = NoneUploader()
    pipeline = EvidencePipeline(
        storage_uploader=none_uploader,
        redactor=Redactor(),
        audit_logger=audit_logger,
    )
    with pytest.raises(EvidencePersistError):
        await pipeline.persist(
            **ids,  # type: ignore[arg-type]
            kind=EvidenceKind.RAW_OUTPUT,
            raw_data=b"hello",
        )
    events = list(audit_logger.sink.iter_events(tenant_id=ids["tenant_id"]))
    assert len(events) == 1
    assert events[0].decision_allowed is False
    assert events[0].failure_summary == "storage_upload_none"


async def test_persist_uploader_raises_propagates_as_persist_error(
    audit_logger: AuditLogger, ids: dict[str, object]
) -> None:
    uploader = InMemoryUploader(raise_exception=RuntimeError)
    pipeline = EvidencePipeline(
        storage_uploader=uploader,
        redactor=Redactor(),
        audit_logger=audit_logger,
    )
    with pytest.raises(EvidencePersistError):
        await pipeline.persist(
            **ids,  # type: ignore[arg-type]
            kind=EvidenceKind.RAW_OUTPUT,
            raw_data=b"hello",
        )
    events = list(audit_logger.sink.iter_events(tenant_id=ids["tenant_id"]))
    assert len(events) == 1
    assert events[0].decision_allowed is False
    assert events[0].failure_summary == "storage_upload_exception"


async def test_persist_rejects_non_bytes(
    uploader: InMemoryUploader, ids: dict[str, object]
) -> None:
    pipeline = EvidencePipeline(
        storage_uploader=uploader,
        redactor=Redactor(),
    )
    with pytest.raises(TypeError):
        await pipeline.persist(
            **ids,  # type: ignore[arg-type]
            kind=EvidenceKind.RAW_OUTPUT,
            raw_data="hello",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Optional audit logger
# ---------------------------------------------------------------------------


async def test_persist_without_audit_logger_does_not_crash(
    uploader: InMemoryUploader, ids: dict[str, object]
) -> None:
    pipeline = EvidencePipeline(
        storage_uploader=uploader,
        redactor=Redactor(),
        audit_logger=None,
    )
    evidence = await pipeline.persist(
        **ids,  # type: ignore[arg-type]
        kind=EvidenceKind.HAR,
        raw_data=b"har-content",
    )
    assert isinstance(evidence, EvidenceDTO)


async def test_audit_emit_failure_is_swallowed(
    uploader: InMemoryUploader, ids: dict[str, object]
) -> None:
    class FlakyAudit:
        def emit(self, **kwargs: object) -> object:
            raise RuntimeError("boom")

    pipeline = EvidencePipeline(
        storage_uploader=uploader,
        redactor=Redactor(),
        audit_logger=FlakyAudit(),  # type: ignore[arg-type]
    )
    evidence = await pipeline.persist(
        **ids,  # type: ignore[arg-type]
        kind=EvidenceKind.OAST_CALLBACK,
        raw_data=b"callback",
    )
    assert isinstance(evidence, EvidenceDTO)


def test_storage_uploader_protocol_runtime_check(uploader: InMemoryUploader) -> None:
    assert isinstance(uploader, StorageUploaderProtocol)
