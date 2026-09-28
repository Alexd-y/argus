"""Part II Phase M — independent verification kit."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime

from src.reports.report_document import (
    ReportEvidenceRef,
    ReportFinding,
    ReportPoC,
    build_report_document,
)
from src.reports.verification_kit import build_verification_kit

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _doc():
    return build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://target.example",
        findings=[
            ReportFinding(
                finding_id="F-1",
                title="SQLi in /search",
                severity="high",
                verification_status="confirmed",
                evidence_ids=["E-1"],
                validator_id="sqlmap",
                poc=ReportPoC(
                    http_request="GET /search?q=' OR 1=1-- HTTP/1.1",
                    negative_control="GET /search?q=x HTTP/1.1 → 200 clean",
                    discriminator="SQL error signature in body",
                ),
            )
        ],
        evidence_references=[ReportEvidenceRef(evidence_id="E-1", kind="http", object_key="k1")],
        generated_at=_TS,
    )


def _unzip(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


def test_kit_contains_expected_layout():
    data, manifest = build_verification_kit(_doc())
    files = _unzip(data)
    assert "manifest.json" in files
    assert "checks.py" in files
    assert "README.md" in files
    assert "repro/F-1.json" in files
    assert "evidence/E-1.json" in files


def test_kit_hashes_match_snapshot_and_files():
    doc = _doc()
    data, manifest = build_verification_kit(doc)
    files = _unzip(data)
    assert manifest["snapshot_hash"] == doc.snapshot_hash
    # Every listed file hash matches the actual content.
    for name, digest in manifest["files"].items():
        assert hashlib.sha256(files[name]).hexdigest() == digest


def test_repro_carries_negative_control_and_discriminator():
    data, _ = build_verification_kit(_doc())
    repro = json.loads(_unzip(data)["repro/F-1.json"])
    assert repro["negative_control"]
    assert repro["discriminator"]
    assert "request" in repro


def test_kit_contains_no_obvious_secret_note():
    data, _ = build_verification_kit(_doc())
    evidence = json.loads(_unzip(data)["evidence/E-1.json"])
    assert "redacted" in evidence["note"].lower()


def test_checks_script_is_non_exploiting():
    data, _ = build_verification_kit(_doc())
    checks = _unzip(data)["checks.py"].decode("utf-8")
    assert "does NOT" in checks or "does not" in checks
    assert "in scope" in checks.lower() or "in-scope" in checks.lower()


def test_kit_snapshot_hash_is_stable():
    a, _ = build_verification_kit(_doc())
    b, _ = build_verification_kit(_doc())
    # Same snapshot → identical file hashes in manifest (kit is deterministic).
    ma = json.loads(_unzip(a)["manifest.json"])
    mb = json.loads(_unzip(b)["manifest.json"])
    assert ma["files"] == mb["files"]
