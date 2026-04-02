"""VHQ-006 — MinIO presigned URL rewrite for report-facing public base URL."""

from __future__ import annotations

import pytest

from src.core.config import settings
from src.storage.s3 import rewrite_minio_url_for_report

_PRESIGNED_LIKE = (
    "http://minio.internal:9000/argus-reports/t/s/reports/exec/r.pdf"
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
    "&X-Amz-Credential=key%2F20260101%2Fus-east-1%2Fs3%2Faws4_request"
    "&X-Amz-Date=20260101T120000Z&X-Amz-Expires=3600"
    "&X-Amz-SignedHeaders=host&X-Amz-Signature=abcdef0123456789"
)


def test_rewrite_minio_url_no_public_url_returns_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "minio_public_url", None)
    assert rewrite_minio_url_for_report(_PRESIGNED_LIKE) == _PRESIGNED_LIKE


def test_rewrite_minio_url_public_base_replaces_scheme_and_host_preserves_path_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "minio_public_url", "https://storage.example.com")
    out = rewrite_minio_url_for_report(_PRESIGNED_LIKE)
    assert out.startswith("https://storage.example.com/")
    assert "minio.internal" not in out
    assert "/argus-reports/t/s/reports/exec/r.pdf?" in out
    assert "X-Amz-Algorithm=AWS4-HMAC-SHA256" in out
    assert "X-Amz-Signature=abcdef0123456789" in out


@pytest.mark.parametrize(
    ("presigned_scheme", "public_base", "expected_scheme"),
    [
        ("https://internal:9000/bucket/k?x=1", "http://cdn.example", "http"),
        ("http://internal:9000/bucket/k?x=1", "https://cdn.example", "https"),
    ],
)
def test_rewrite_minio_url_scheme_transition(
    monkeypatch: pytest.MonkeyPatch,
    presigned_scheme: str,
    public_base: str,
    expected_scheme: str,
) -> None:
    monkeypatch.setattr(settings, "minio_public_url", public_base)
    out = rewrite_minio_url_for_report(presigned_scheme)
    assert out.startswith(f"{expected_scheme}://cdn.example/")
    assert "internal" not in out
    assert "bucket/k?x=1" in out


def test_rewrite_minio_url_preserves_complex_query(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "minio_public_url", "https://files.public.test")
    q = (
        "response-content-type=application%2Fpdf"
        "&partNumber=1"
        "&uploadId=abc%2Bdef%2F~"
        "&X-Amz-Signature=sig%2Fvalue%3D"
    )
    url = f"http://s3.local/bucket/obj?{q}"
    out = rewrite_minio_url_for_report(url)
    assert out == f"https://files.public.test/bucket/obj?{q}"


def test_rewrite_minio_url_empty_presigned_no_public_url_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "minio_public_url", None)
    assert rewrite_minio_url_for_report("") == ""


def test_rewrite_minio_url_empty_presigned_with_public_url_no_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "minio_public_url", "https://storage.example.com")
    out = rewrite_minio_url_for_report("")
    assert out == "https://storage.example.com"


def test_rewrite_minio_url_public_base_trailing_slash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "minio_public_url", "https://storage.example.com/")
    out = rewrite_minio_url_for_report(_PRESIGNED_LIKE)
    assert out.startswith("https://storage.example.com/")
    assert "X-Amz-Signature=" in out
