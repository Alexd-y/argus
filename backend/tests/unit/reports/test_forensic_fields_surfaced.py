"""Wave 4 / Stage 7 — forensic finding data reaches the report (R-6.4).

taint_path, fingerprint_key and the attempted/successful payloads used to stop at the
DB. These prove the snapshot projection surfaces them and that payloads are sanitised
(secrets / real target redacted) before publication.
"""

from __future__ import annotations

from src.reports.snapshot_builder import _map_finding, _sanitize_payload, _taint_path


class _F:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_taint_path_projected() -> None:
    assert _taint_path(_F(taint_path=["req.body", "db.query"])) == ["req.body", "db.query"]
    assert _taint_path(_F(taint_path=None)) == []
    assert _taint_path({"taint_path": ["a", "", "b"]}) == ["a", "b"]


def test_payload_sanitised_redacts_secret() -> None:
    # A password flag value must not survive into the published payload.
    out = _sanitize_payload(["sqlmap", "-u", "http://x", "--password", "s3cr3t"], "http://x")
    assert out is not None
    assert "s3cr3t" not in out
    assert "REDACTED" in out.upper()


def test_payload_empty_is_none() -> None:
    assert _sanitize_payload(None, "t") is None
    assert _sanitize_payload([], "t") is None


def test_map_finding_surfaces_forensic_fields() -> None:
    f = _F(
        finding_id="F-1",
        title="SQLi",
        severity="high",
        fingerprint_key="fp-123",
        taint_path=["input", "sink"],
        payload_attempted=["' OR 1=1-- -"],
        payload_successful=["' OR 1=1-- -"],
    )
    rf = _map_finding(f, 0, target="http://juice-shop:3000")
    assert rf.fingerprint_key == "fp-123"
    assert rf.taint_path == ["input", "sink"]
    assert rf.payload_attempted and "OR 1=1" in rf.payload_attempted
    assert rf.payload_successful is not None
