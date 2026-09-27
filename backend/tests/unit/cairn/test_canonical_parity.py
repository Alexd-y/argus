"""Phase 16 — canonical bundle atomic-parity gate (§20.9)."""

from __future__ import annotations

import pytest
from src.reports.canonical_bundle import (
    REQUIRED_CANONICAL_FORMATS,
    CanonicalArtifact,
    assert_canonical_parity,
    bundle_formats,
)


def _artifact(fmt: str, snapshot_hash: str = "h1") -> CanonicalArtifact:
    return CanonicalArtifact(
        format=fmt,
        content=b"x",
        mime_type="application/octet-stream",
        scan_profile="deep",
        snapshot_hash=snapshot_hash,
        generated_at="2026-09-27T00:00:00Z",
        size=1,
        checksum="0" * 64,
    )


def _full_bundle(snapshot_hash: str = "h1") -> list[CanonicalArtifact]:
    return [_artifact(fmt, snapshot_hash) for fmt in REQUIRED_CANONICAL_FORMATS]


def test_parity_ok_when_all_formats_one_snapshot() -> None:
    assert_canonical_parity(_full_bundle())  # no raise
    assert bundle_formats(_full_bundle()) >= set(REQUIRED_CANONICAL_FORMATS)


def test_parity_fails_on_missing_format() -> None:
    bundle = [a for a in _full_bundle() if a.format != "xml"]
    with pytest.raises(ValueError, match="missing required formats.*xml"):
        assert_canonical_parity(bundle)


def test_parity_fails_on_divergent_snapshot() -> None:
    bundle = _full_bundle()
    bundle[-1] = _artifact(bundle[-1].format, snapshot_hash="DIFFERENT")
    with pytest.raises(ValueError, match="disagree on snapshot_hash"):
        assert_canonical_parity(bundle)
