"""ARG-024 — Tests for :mod:`src.reports.report_bundle`.

Coverage targets:
    * SHA-256 is computed from ``content`` (immutability check).
    * ``mime_type`` / ``file_extension`` are the canonical values per format.
    * ``ReportBundle`` is frozen / immutable (Pydantic ``frozen=True``).
    * ``filename`` sanitises stems but never leaks path separators.
    * ``verify_sha256`` round-trips for every format.
    * Bytes-only contract: passing ``str`` raises a ``TypeError``.

These are pure unit tests; no I/O, no DB, no FastAPI app.
"""

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from src.reports.report_bundle import (
    ReportBundle,
    ReportFormat,
    ReportTier,
    file_extension_for,
    mime_type_for,
)

_PAYLOAD = b'{"hello":"world"}'
_SHA = hashlib.sha256(_PAYLOAD).hexdigest()


def _make(fmt: ReportFormat = ReportFormat.JSON) -> ReportBundle:
    return ReportBundle.from_content(
        tier=ReportTier.MIDGARD,
        fmt=fmt,
        content=_PAYLOAD,
    )


class TestReportFormatTier:
    def test_tier_values(self) -> None:
        assert ReportTier.MIDGARD.value == "midgard"
        assert ReportTier.ASGARD.value == "asgard"
        assert ReportTier.VALHALLA.value == "valhalla"

    def test_format_values_canonical(self) -> None:
        expected = {"html", "pdf", "json", "csv", "sarif", "junit"}
        assert {f.value for f in ReportFormat} == expected

    def test_mime_type_for_each_format(self) -> None:
        assert mime_type_for(ReportFormat.HTML).startswith("text/html")
        assert mime_type_for(ReportFormat.PDF) == "application/pdf"
        assert mime_type_for(ReportFormat.JSON).startswith("application/json")
        assert mime_type_for(ReportFormat.CSV).startswith("text/csv")
        assert mime_type_for(ReportFormat.SARIF) == "application/sarif+json"
        assert mime_type_for(ReportFormat.JUNIT).startswith("application/xml")

    def test_file_extension_for_each_format(self) -> None:
        assert file_extension_for(ReportFormat.HTML) == "html"
        assert file_extension_for(ReportFormat.PDF) == "pdf"
        assert file_extension_for(ReportFormat.JSON) == "json"
        assert file_extension_for(ReportFormat.CSV) == "csv"
        assert file_extension_for(ReportFormat.SARIF) == "sarif"
        assert file_extension_for(ReportFormat.JUNIT) == "xml"


class TestFromContent:
    def test_sha256_and_size_are_computed(self) -> None:
        bundle = _make()
        assert bundle.sha256 == _SHA
        assert bundle.size_bytes == len(_PAYLOAD)
        assert bundle.content == _PAYLOAD
        assert bundle.tier is ReportTier.MIDGARD
        assert bundle.format is ReportFormat.JSON

    def test_mime_and_extension_match_format(self) -> None:
        bundle = _make(ReportFormat.SARIF)
        assert bundle.mime_type == "application/sarif+json"
        assert bundle.file_extension() == "sarif"

    def test_truncated_default_false_and_settable(self) -> None:
        b1 = _make()
        assert b1.truncated is False
        b2 = ReportBundle.from_content(
            tier=ReportTier.MIDGARD,
            fmt=ReportFormat.JSON,
            content=_PAYLOAD,
            truncated=True,
        )
        assert b2.truncated is True

    def test_presigned_url_optional(self) -> None:
        b = ReportBundle.from_content(
            tier=ReportTier.MIDGARD,
            fmt=ReportFormat.JSON,
            content=_PAYLOAD,
            presigned_url="https://s3.example/r/123?sig=abc",
        )
        assert b.presigned_url == "https://s3.example/r/123?sig=abc"

    def test_str_content_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            ReportBundle.from_content(
                tier=ReportTier.MIDGARD,
                fmt=ReportFormat.JSON,
                content="this is a str, not bytes",  # type: ignore[arg-type]
            )

    def test_empty_content_is_valid(self) -> None:
        b = ReportBundle.from_content(
            tier=ReportTier.MIDGARD,
            fmt=ReportFormat.JSON,
            content=b"",
        )
        assert b.size_bytes == 0
        assert b.sha256 == hashlib.sha256(b"").hexdigest()


class TestReportBundleImmutability:
    def test_bundle_is_frozen(self) -> None:
        bundle = _make()
        with pytest.raises(ValidationError):
            bundle.size_bytes = 999  # type: ignore[misc]

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            ReportBundle(
                tier=ReportTier.MIDGARD,
                format=ReportFormat.JSON,
                content=_PAYLOAD,
                mime_type="application/json",
                sha256=_SHA,
                size_bytes=len(_PAYLOAD),
                rogue_field="oops",  # type: ignore[call-arg]
            )

    def test_sha256_length_must_be_64(self) -> None:
        with pytest.raises(ValidationError):
            ReportBundle(
                tier=ReportTier.MIDGARD,
                format=ReportFormat.JSON,
                content=_PAYLOAD,
                mime_type="application/json",
                sha256="too-short",
                size_bytes=len(_PAYLOAD),
            )


class TestFilename:
    def test_default_filename(self) -> None:
        b = _make()
        assert b.filename() == "report.json"

    def test_filename_with_stem(self) -> None:
        b = _make(ReportFormat.SARIF)
        assert b.filename(stem="argus-cycle3") == "argus-cycle3.sarif"

    def test_filename_sanitises_path_separators(self) -> None:
        b = _make()
        unsafe = "../../etc/passwd"
        result = b.filename(stem=unsafe)
        assert "/" not in result
        assert "\\" not in result
        assert ".." not in result.replace("..", "_")
        assert result.endswith(".json")

    def test_filename_truncates_long_stem(self) -> None:
        b = _make()
        result = b.filename(stem="x" * 1000)
        assert len(result) <= 96 + len(".json")

    def test_filename_falls_back_when_stem_empty(self) -> None:
        b = _make()
        assert b.filename(stem="") == "report.json"
        assert b.filename(stem="@@@@@") == "_____.json"


class TestVerifySha256:
    def test_round_trip(self) -> None:
        b = _make()
        assert b.verify_sha256() is True

    def test_detects_tamper(self) -> None:
        b = ReportBundle(
            tier=ReportTier.MIDGARD,
            format=ReportFormat.JSON,
            content=b"clean",
            mime_type="application/json",
            sha256=hashlib.sha256(b"tampered").hexdigest(),
            size_bytes=5,
        )
        assert b.verify_sha256() is False
