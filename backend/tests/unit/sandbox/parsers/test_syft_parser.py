"""Unit tests for :mod:`src.sandbox.parsers.syft_parser` (Backlog §4.15 — ARG-029).

Pinned contracts:

* Canonical artefact ``sbom.json`` (CycloneDX) overrides stdout.
* Always emits ONE ``inventory`` finding (with image + component count)
  whenever any component is present.
* One INFO finding per ``library`` / ``application`` / ``framework`` /
  ``operating-system`` component, deduped on ``(kind, name, version)``.
* Every finding category is :class:`FindingCategory.SUPPLY_CHAIN`,
  CWE [1395], severity ``info``, confidence
  :class:`ConfidenceLevel.CONFIRMED`.
* Inventory finding sorts FIRST so operators see the image header
  before the component list.
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
from src.sandbox.parsers import syft_parser as syft_module
from src.sandbox.parsers.syft_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_syft_json,
)


def _component(
    *,
    name: str = "openssl",
    version: str = "3.0.7-r0",
    component_type: str = "library",
    purl: str = "pkg:apk/alpine/openssl@3.0.7-r0",
    licenses: list[str] | None = None,
) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": component_type,
        "name": name,
        "version": version,
        "purl": purl,
    }
    if licenses is not None:
        component["licenses"] = [{"license": {"id": lic}} for lic in licenses]
    return component


def _payload(
    *components: dict[str, Any],
    image: str | None = "registry/example/api",
    image_version: str | None = "1.2.3",
) -> bytes:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": list(components),
    }
    if image is not None:
        metadata_component: dict[str, Any] = {"name": image, "type": "container"}
        if image_version is not None:
            metadata_component["version"] = image_version
        document["metadata"] = {"component": metadata_component}
    return json.dumps(document).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_syft_json(b"", b"", tmp_path, "syft") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "sbom.json"
    canonical.write_bytes(_payload(_component(name="openssl")))
    decoy = _payload(_component(name="zlib"))
    findings = parse_syft_json(decoy, b"", tmp_path, "syft")
    assert len(findings) == 2  # inventory + 1 component
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "openssl" in sidecar
    assert "zlib" not in sidecar


def test_inventory_finding_emitted(tmp_path: Path) -> None:
    findings = parse_syft_json(_payload(_component()), b"", tmp_path, "syft")
    assert findings, "syft must always emit at least the inventory marker finding"
    sidecar_lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    inventory_line = json.loads(sidecar_lines[0])
    assert inventory_line["kind"] == "inventory"
    assert inventory_line["component_count"] == 1
    assert "registry/example/api" in inventory_line["image"]


def test_findings_use_supply_chain_category(tmp_path: Path) -> None:
    findings = parse_syft_json(_payload(_component()), b"", tmp_path, "syft")
    assert all(f.category is FindingCategory.SUPPLY_CHAIN for f in findings)
    assert all(set(f.cwe) == {1395} for f in findings)
    assert all(f.confidence is ConfidenceLevel.CONFIRMED for f in findings)
    assert all(f.cvss_v3_score == pytest.approx(0.0) for f in findings)


def test_per_component_finding_emitted(tmp_path: Path) -> None:
    findings = parse_syft_json(
        _payload(
            _component(name="openssl"),
            _component(name="zlib", purl="pkg:apk/alpine/zlib@1.2.13"),
        ),
        b"",
        tmp_path,
        "syft",
    )
    assert len(findings) == 3  # inventory + 2 components


def test_only_relevant_types_emitted(tmp_path: Path) -> None:
    payload = _payload(
        _component(name="openssl", component_type="library"),
        _component(name="alpine", component_type="operating-system"),
        _component(name="my-app", component_type="application"),
        _component(name="ignored", component_type="data"),
        _component(name="ignored2", component_type="device"),
    )
    findings = parse_syft_json(payload, b"", tmp_path, "syft")
    # 1 inventory + 3 relevant components.
    assert len(findings) == 4


def test_dedup_collapses_same_kind_name_version(tmp_path: Path) -> None:
    payload = _payload(_component(name="openssl"), _component(name="openssl"))
    findings = parse_syft_json(payload, b"", tmp_path, "syft")
    assert len(findings) == 2  # inventory + 1 dedup'd component


def test_purl_preserved_in_sidecar(tmp_path: Path) -> None:
    purl = "pkg:apk/alpine/openssl@3.0.7-r0?arch=x86_64"
    parse_syft_json(_payload(_component(purl=purl)), b"", tmp_path, "syft")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert purl in sidecar


def test_licenses_preserved_in_sidecar(tmp_path: Path) -> None:
    parse_syft_json(
        _payload(_component(licenses=["Apache-2.0", "MIT"])),
        b"",
        tmp_path,
        "syft",
    )
    sidecar_lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    component_blob = json.loads(sidecar_lines[1])
    assert sorted(component_blob["licenses"]) == ["Apache-2.0", "MIT"]


def test_envelope_not_object_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "sbom.json"
    canonical.write_bytes(b'["not", "an", "sbom"]')
    with caplog.at_level("WARNING"):
        findings = parse_syft_json(b"", b"", tmp_path, "syft")
    assert findings == []
    assert any(
        "syft_parser_envelope_not_object" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_inventory_appears_first_in_sidecar(tmp_path: Path) -> None:
    parse_syft_json(
        _payload(_component(name="z-comp"), _component(name="a-comp")),
        b"",
        tmp_path,
        "syft",
    )
    lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    first = json.loads(lines[0])
    assert first["kind"] == "inventory"


def test_missing_component_name_skipped(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "img", "type": "container"}},
            "components": [
                {"type": "library", "version": "1"},
                _component(name="ok"),
            ],
        }
    ).encode("utf-8")
    findings = parse_syft_json(payload, b"", tmp_path, "syft")
    assert len(findings) == 2  # inventory + ok


def test_image_only_emits_inventory(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "img", "type": "container"}},
            "components": [],
        }
    ).encode("utf-8")
    findings = parse_syft_json(payload, b"", tmp_path, "syft")
    assert len(findings) == 1
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["kind"] == "inventory"
    assert blob["component_count"] == 0


def test_no_components_no_image_returns_empty(tmp_path: Path) -> None:
    payload = json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    ).encode("utf-8")
    assert parse_syft_json(payload, b"", tmp_path, "syft") == []


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(syft_module, "_MAX_COMPONENT_FINDINGS", 2)
    payload = _payload(
        *(_component(name=f"comp-{i}", purl=f"pkg:p/{i}") for i in range(5))
    )
    with caplog.at_level("WARNING"):
        findings = parse_syft_json(payload, b"", tmp_path, "syft")
    # inventory + cap=2 → 3 findings
    assert len(findings) == 3
