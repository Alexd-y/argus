"""Unit tests for :mod:`src.sandbox.parsers.wappalyzer_cli_parser` (Backlog §4.4 — ARG-029).

Pinned contracts:

* Canonical artefact ``wappalyzer.json`` overrides stdout.
* Two envelope shapes accepted:

  - modern ``{"urls": {...}, "technologies": [...]}``
  - legacy ``[{"url": "...", "technologies": [...]}, ...]``

* For every detected technology → one INFO finding,
  category :class:`FindingCategory.INFO`, CWE 200,
  confidence :class:`ConfidenceLevel.LIKELY`, severity ``info``.
* Dedup: ``(url, name, version)`` so multiple versions of the same
  vendor stay distinct.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers import wappalyzer_cli_parser as wappalyzer_module
from src.sandbox.parsers.wappalyzer_cli_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_wappalyzer_cli_json,
)


def _tech(
    *,
    name: str = "Nginx",
    version: str = "1.24.0",
    categories: list[Any] | None = None,
    confidence: int = 100,
    slug: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "name": name,
        "version": version,
        "categories": categories or ["Web servers"],
        "confidence": confidence,
    }
    if slug is not None:
        record["slug"] = slug
    return record


def _modern_payload(
    *,
    url: str = "https://example.com",
    techs: list[dict[str, Any]] | None = None,
) -> bytes:
    document = {
        "urls": {url: {"status": 200}},
        "technologies": techs or [_tech()],
    }
    return json.dumps(document).encode("utf-8")


def _legacy_payload(
    *,
    url: str = "https://example.com",
    techs: list[dict[str, Any]] | None = None,
) -> bytes:
    document = [{"url": url, "technologies": techs or [_tech()]}]
    return json.dumps(document).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_wappalyzer_cli_json(b"", b"", tmp_path, "wappalyzer_cli") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "wappalyzer.json"
    canonical.write_bytes(_modern_payload(techs=[_tech(name="Canonical-Tech")]))
    decoy = _modern_payload(techs=[_tech(name="Decoy-Tech")])
    findings = parse_wappalyzer_cli_json(decoy, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "Canonical-Tech" in sidecar
    assert "Decoy-Tech" not in sidecar


def test_finding_category_and_cwe(tmp_path: Path) -> None:
    findings = parse_wappalyzer_cli_json(
        _modern_payload(), b"", tmp_path, "wappalyzer_cli"
    )
    assert findings[0].category is FindingCategory.INFO
    assert 200 in findings[0].cwe
    assert findings[0].confidence is ConfidenceLevel.LIKELY
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_modern_envelope_supported(tmp_path: Path) -> None:
    payload = _modern_payload(
        techs=[_tech(name="Nginx"), _tech(name="React", categories=["JS frameworks"])]
    )
    findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 2


def test_legacy_envelope_supported(tmp_path: Path) -> None:
    payload = _legacy_payload(
        techs=[
            _tech(name="Apache"),
            _tech(name="PHP", categories=["Programming languages"]),
        ]
    )
    findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 2


def test_urls_envelope_per_url_supported(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "urls": {
                "https://a.example": {
                    "status": 200,
                    "technologies": [_tech(name="Nginx")],
                },
                "https://b.example": {
                    "status": 200,
                    "technologies": [_tech(name="Apache")],
                },
            }
        }
    ).encode("utf-8")
    findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 2


def test_dedup_collapses_same_url_name_version(tmp_path: Path) -> None:
    payload = _modern_payload(techs=[_tech(), _tech()])
    findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 1


def test_distinct_versions_emit_distinct_findings(tmp_path: Path) -> None:
    payload = _modern_payload(techs=[_tech(version="1.18.0"), _tech(version="1.24.0")])
    findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 2


def test_categories_as_dict_extracted_to_strings(tmp_path: Path) -> None:
    payload = _modern_payload(
        techs=[
            _tech(
                categories=[{"name": "Web servers"}, {"slug": "cdn"}, "Other"],
            )
        ]
    )
    parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert sorted(blob["categories"]) == sorted(["Web servers", "cdn", "Other"])


def test_unsupported_payload_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "wappalyzer.json"
    canonical.write_bytes(b'"a string is not an envelope"')
    with caplog.at_level("WARNING"):
        findings = parse_wappalyzer_cli_json(b"", b"", tmp_path, "wappalyzer_cli")
    assert findings == []
    assert any(
        "wappalyzer_cli_parser_unsupported_payload"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_tech_name_skipped(tmp_path: Path) -> None:
    payload = _modern_payload(
        techs=[
            {"version": "1.0", "categories": ["x"]},
            _tech(name="Ok"),
        ]
    )
    findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 1


def test_url_persisted_in_sidecar(tmp_path: Path) -> None:
    parse_wappalyzer_cli_json(
        _modern_payload(url="https://important.example/path"),
        b"",
        tmp_path,
        "wappalyzer_cli",
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "https://important.example/path" in sidecar


def test_findings_sorted_deterministically(tmp_path: Path) -> None:
    payload = _modern_payload(
        techs=[
            _tech(name="Zeta"),
            _tech(name="Alpha"),
            _tech(name="Beta"),
        ]
    )
    parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    names = [json.loads(line)["name"] for line in lines]
    assert names == sorted(names)


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(wappalyzer_module, "_MAX_FINDINGS", 2)
    payload = _modern_payload(
        techs=[_tech(name=f"Tech-{i}", version=f"{i}.0") for i in range(5)]
    )
    with caplog.at_level("WARNING"):
        findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 2
    assert any(
        "wappalyzer_cli_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_legacy_array_with_non_dict_entries_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Legacy array with non-object entries: skip with debug, parse the rest."""
    payload = json.dumps(
        ["not-an-object", {"url": "https://example.com", "technologies": [_tech()]}]
    ).encode("utf-8")
    with caplog.at_level("DEBUG", logger=wappalyzer_module._logger.name):
        findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 1
    assert any(
        "wappalyzer_cli_parser_entry_not_object" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_techs_not_a_list_returns_no_findings(tmp_path: Path) -> None:
    """``technologies`` must be a list — otherwise nothing is yielded."""
    payload = json.dumps(
        {"urls": {"https://x": {}}, "technologies": "not-a-list"}
    ).encode("utf-8")
    findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert findings == []


def test_tech_entry_not_dict_skipped(tmp_path: Path) -> None:
    """Non-object tech entries inside the technologies array are skipped."""
    payload = json.dumps(
        {
            "urls": {"https://x": {}},
            "technologies": ["string-not-tech", _tech()],
        }
    ).encode("utf-8")
    findings = parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    assert len(findings) == 1


def _tech_with_confidence(value: object) -> dict[str, Any]:
    raw = _tech()
    raw["confidence"] = value
    return raw


def test_confidence_string_coerced(tmp_path: Path) -> None:
    """``confidence`` may be a string in older builds — coerce to int."""
    payload = json.dumps(
        {"urls": {"https://x": {}}, "technologies": [_tech_with_confidence("85")]}
    ).encode("utf-8")
    parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["confidence"] == 85


def test_confidence_invalid_string_returns_none(tmp_path: Path) -> None:
    """A non-numeric confidence string must collapse to None (omitted)."""
    payload = json.dumps(
        {"urls": {"https://x": {}}, "technologies": [_tech_with_confidence("bogus")]}
    ).encode("utf-8")
    parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "confidence" not in blob


def test_confidence_float_truncated(tmp_path: Path) -> None:
    payload = json.dumps(
        {"urls": {"https://x": {}}, "technologies": [_tech_with_confidence(99.9)]}
    ).encode("utf-8")
    parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["confidence"] == 99


def test_confidence_bool_rejected(tmp_path: Path) -> None:
    payload = json.dumps(
        {"urls": {"https://x": {}}, "technologies": [_tech_with_confidence(True)]}
    ).encode("utf-8")
    parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "confidence" not in blob


def test_envelope_url_from_urls_list(tmp_path: Path) -> None:
    """``urls`` may also arrive as a list of URLs (not just a dict)."""
    payload = json.dumps(
        {
            "urls": ["https://list-shape.example.com"],
            "technologies": [_tech()],
        }
    ).encode("utf-8")
    parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "https://list-shape.example.com" in sidecar


def test_envelope_url_falls_back_to_url_field(tmp_path: Path) -> None:
    """When ``urls`` is missing, fall back to a top-level ``url`` field."""
    payload = json.dumps(
        {
            "url": "https://flat-shape.example.com",
            "technologies": [_tech()],
        }
    ).encode("utf-8")
    parse_wappalyzer_cli_json(payload, b"", tmp_path, "wappalyzer_cli")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "https://flat-shape.example.com" in sidecar
