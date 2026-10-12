"""Unit tests for evidence manifest + integrity verification (wave 2 / stage 7)."""

from __future__ import annotations

import hashlib

from src.evidence.manifest import (
    ManifestEntry,
    compute_root_hash,
    detect_overwrite,
    verify_integrity,
)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_root_hash_is_order_independent_and_sensitive() -> None:
    a = [ManifestEntry("k1", "h1"), ManifestEntry("k2", "h2")]
    b = [ManifestEntry("k2", "h2"), ManifestEntry("k1", "h1")]
    assert compute_root_hash(a) == compute_root_hash(b)  # reproducible regardless of order
    assert compute_root_hash(a) != compute_root_hash([ManifestEntry("k1", "h1")])
    assert compute_root_hash(a) != compute_root_hash([ManifestEntry("k1", "h1"), ManifestEntry("k2", "X")])


def test_verify_integrity_clean() -> None:
    store = {"k1": b"alpha", "k2": b"beta"}
    entries = [ManifestEntry("k1", _sha(b"alpha")), ManifestEntry("k2", _sha(b"beta"))]
    report = verify_integrity(
        scan_id="s",
        manifest_root_hash=compute_root_hash(entries),
        entries=entries,
        download=store.get,
    )
    assert report.ok
    assert report.checked == 2
    assert report.discrepancies == ()


def test_verify_integrity_detects_tampered_object() -> None:
    entries = [ManifestEntry("k1", _sha(b"orig"))]
    report = verify_integrity(
        scan_id="s",
        manifest_root_hash=compute_root_hash(entries),
        entries=entries,
        download=lambda _k: b"TAMPERED",
    )
    assert not report.ok
    assert any(d.reason == "checksum_mismatch" for d in report.discrepancies)


def test_verify_integrity_missing_object() -> None:
    entries = [ManifestEntry("k1", _sha(b"x"))]
    report = verify_integrity(
        scan_id="s",
        manifest_root_hash=compute_root_hash(entries),
        entries=entries,
        download=lambda _k: None,
    )
    assert not report.ok
    assert any(d.reason == "missing" for d in report.discrepancies)


def test_verify_integrity_root_hash_mismatch() -> None:
    entries = [ManifestEntry("k1", _sha(b"a"))]
    report = verify_integrity(
        scan_id="s",
        manifest_root_hash="deadbeef",
        entries=entries,
        download=lambda _k: b"a",
    )
    assert any(d.reason == "root_hash_mismatch" for d in report.discrepancies)


def test_detect_overwrite() -> None:
    assert detect_overwrite(existing_sha256="a", new_sha256="b") is True
    assert detect_overwrite(existing_sha256="a", new_sha256="a") is False
    assert detect_overwrite(existing_sha256=None, new_sha256="b") is False
