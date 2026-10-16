"""Wave 5 / R-9.1-R-9.3 — redact-then-store for LLM telemetry text.

Pins the security-critical contract: text capture is OFF by default; when on,
the secret is redacted BEFORE storage, the object is hashed over the REDACTED
bytes, and storage failures never propagate.
"""

from __future__ import annotations

import hashlib

import pytest
from src.core.config import settings
from src.llm import telemetry_text_store
from src.llm.telemetry_text_store import store_redacted_text


@pytest.fixture
def _enable_capture(monkeypatch):
    monkeypatch.setattr(settings, "llm_telemetry_store_text", True, raising=False)


def test_disabled_by_default_returns_empty_and_never_uploads(monkeypatch):
    called = {"n": 0}

    def _upload(**kwargs):  # pragma: no cover - must not be called
        called["n"] += 1
        return "k"

    monkeypatch.setattr(settings, "llm_telemetry_store_text", False, raising=False)
    monkeypatch.setattr("src.storage.s3.upload", _upload)
    key = store_redacted_text(tenant_id="t", scan_id="s", kind="prompt", text="hello")
    assert key == ""
    assert called["n"] == 0


def test_missing_tenant_or_scan_returns_empty(_enable_capture):
    assert store_redacted_text(tenant_id="", scan_id="s", kind="prompt", text="x") == ""
    assert store_redacted_text(tenant_id="t", scan_id="", kind="prompt", text="x") == ""
    assert store_redacted_text(tenant_id="t", scan_id="s", kind="prompt", text="") == ""


def test_redacts_before_storage_and_hashes_redacted_bytes(_enable_capture, monkeypatch):
    captured: dict = {}

    def _upload(*, tenant_id, scan_id, object_type, filename, data, content_type):
        captured.update(
            tenant_id=tenant_id,
            scan_id=scan_id,
            object_type=object_type,
            filename=filename,
            data=data,
            content_type=content_type,
        )
        return build_key(tenant_id, scan_id, object_type, filename)

    def build_key(t, s, o, f):
        return f"{t}/{s}/{o}/{f}"

    monkeypatch.setattr("src.storage.s3.upload", _upload)

    secret = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    text = f"please use token {secret} now"
    key = store_redacted_text(tenant_id="tn", scan_id="sc", kind="prompt", text=text)

    # The secret must be gone from what was uploaded (redaction-on-ingest).
    assert secret.encode() not in captured["data"]
    assert b"[REDACTED:github_pat]" in captured["data"]
    # Hash in the filename is over the REDACTED bytes, not the raw text.
    expected_sha = hashlib.sha256(captured["data"]).hexdigest()
    assert captured["filename"] == f"prompt-{expected_sha[:16]}.txt"
    assert captured["object_type"] == telemetry_text_store.LLM_TELEMETRY_OBJECT_TYPE
    assert key == f"tn/sc/{telemetry_text_store.LLM_TELEMETRY_OBJECT_TYPE}/{captured['filename']}"


def test_upload_failure_is_swallowed(_enable_capture, monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("minio down")

    monkeypatch.setattr("src.storage.s3.upload", _boom)
    assert store_redacted_text(tenant_id="t", scan_id="s", kind="response", text="x") == ""


def test_upload_returning_none_yields_empty_key(_enable_capture, monkeypatch):
    monkeypatch.setattr("src.storage.s3.upload", lambda **kw: None)
    assert store_redacted_text(tenant_id="t", scan_id="s", kind="response", text="x") == ""
