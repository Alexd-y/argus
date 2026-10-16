"""Wave 5 / R-9.1-R-9.3 — redact-then-store for LLM telemetry text.

Pins the security-critical contract:

* capture is OFF by default and fail-closed on authorization — it needs BOTH
  the global master switch AND the tenant in the allowlist (R-9.3: governed by
  tenant policy);
* the secret is redacted BEFORE storage, hashed over the REDACTED bytes;
* oversize text and possibly-incomplete redaction are refused (fail-closed);
* storage failures never propagate into the LLM call path.
"""

from __future__ import annotations

import hashlib

import pytest
from src.core.config import settings
from src.llm import telemetry_text_store
from src.llm.telemetry_text_store import store_redacted_text


@pytest.fixture
def _enable_capture(monkeypatch):
    """Authorize capture for every tenant (global switch + wildcard allowlist)."""
    monkeypatch.setattr(settings, "llm_telemetry_store_text", True, raising=False)
    monkeypatch.setattr(settings, "llm_telemetry_text_tenant_allowlist", "*", raising=False)


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


def test_global_on_but_empty_allowlist_is_fail_closed(monkeypatch):
    monkeypatch.setattr(settings, "llm_telemetry_store_text", True, raising=False)
    monkeypatch.setattr(settings, "llm_telemetry_text_tenant_allowlist", "", raising=False)
    monkeypatch.setattr("src.storage.s3.upload", lambda **kw: "k")
    assert store_redacted_text(tenant_id="t", scan_id="s", kind="prompt", text="x") == ""


def test_tenant_allowlist_is_scoped(monkeypatch):
    monkeypatch.setattr(settings, "llm_telemetry_store_text", True, raising=False)
    monkeypatch.setattr(
        settings, "llm_telemetry_text_tenant_allowlist", "tenant-a, tenant-b", raising=False
    )
    monkeypatch.setattr("src.storage.s3.upload", lambda **kw: "stored")
    assert (
        store_redacted_text(tenant_id="tenant-a", scan_id="s", kind="prompt", text="x") == "stored"
    )
    assert store_redacted_text(tenant_id="tenant-c", scan_id="s", kind="prompt", text="x") == ""


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
        return f"{tenant_id}/{scan_id}/{object_type}/{filename}"

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


def test_oversize_text_is_refused(_enable_capture, monkeypatch):
    called = {"n": 0}

    def _upload(**kwargs):  # pragma: no cover - must not be called
        called["n"] += 1
        return "k"

    monkeypatch.setattr("src.storage.s3.upload", _upload)
    huge = "a" * (telemetry_text_store._MAX_TEXT_BYTES + 1)
    assert store_redacted_text(tenant_id="t", scan_id="s", kind="prompt", text=huge) == ""
    assert called["n"] == 0


def test_redaction_cap_reached_is_refused(_enable_capture, monkeypatch):
    class _Redacted:
        content = b"partially redacted"
        redactions_applied = telemetry_text_store._REDACTION_MATCH_CAP

    class _StubRedactor:
        def redact(self, _content):
            return _Redacted()

    called = {"n": 0}

    def _upload(**kwargs):  # pragma: no cover - must not be called
        called["n"] += 1
        return "k"

    monkeypatch.setattr("src.evidence.redaction.Redactor", _StubRedactor)
    monkeypatch.setattr("src.storage.s3.upload", _upload)
    assert store_redacted_text(tenant_id="t", scan_id="s", kind="prompt", text="x") == ""
    assert called["n"] == 0


def test_upload_failure_is_swallowed(_enable_capture, monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("minio down")

    monkeypatch.setattr("src.storage.s3.upload", _boom)
    assert store_redacted_text(tenant_id="t", scan_id="s", kind="response", text="x") == ""


def test_upload_returning_none_yields_empty_key(_enable_capture, monkeypatch):
    monkeypatch.setattr("src.storage.s3.upload", lambda **kw: None)
    assert store_redacted_text(tenant_id="t", scan_id="s", kind="response", text="x") == ""
