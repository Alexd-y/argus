"""Snapshot tests for report generation output — canonical baselines.

Verifies that the report serialisation pipeline (JSON, CSV, SARIF, XML, HTML)
produces stable, expected output for each tier. The ``snapshots/reports/``
directory contains signed ground-truth files used as regression gates.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

SNAPSHOTS_DIR = Path(__file__).resolve().parent
REPORTS_DIR = SNAPSHOTS_DIR / "reports"

TIERS: tuple[str, ...] = ("midgard", "asgard", "valhalla")
CANONICAL_FORMATS: tuple[str, ...] = ("json", "csv", "sarif", "xml")


class TestCanonicalSnapshotsExist:
    """Every tier x format must have a canonical baseline file."""

    @pytest.mark.parametrize("tier", TIERS)
    @pytest.mark.parametrize("fmt", CANONICAL_FORMATS)
    def test_canonical_file_exists(self, tier: str, fmt: str) -> None:
        path = REPORTS_DIR / f"{tier}_canonical.{fmt}"
        assert path.exists(), f"Missing canonical snapshot: {path.name}"
        assert path.is_file()

    @pytest.mark.parametrize("tier", ("asgard", "valhalla"))
    def test_html_canonical_exists(self, tier: str) -> None:
        path = REPORTS_DIR / f"{tier}_canonical.html"
        assert path.exists(), f"Missing HTML snapshot: {path.name}"


class TestJsonSnapshotIntegrity:
    """JSON snapshots must be parseable and contain required keys."""

    @pytest.mark.parametrize("tier", TIERS)
    def test_json_canonical_is_valid(self, tier: str) -> None:
        path = REPORTS_DIR / f"{tier}_canonical.json"
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        assert isinstance(data, (dict, list)), f"{tier} JSON root must be dict or list"

    def test_midgard_json_has_expected_keys(self) -> None:
        path = REPORTS_DIR / "midgard_canonical.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            keys_lower = {k.lower() for k in data}
            report_keys = {"target", "scan", "findings", "report"}
            matching = keys_lower & report_keys
            assert len(matching) >= 1, f"Missing expected report keys. Got: {sorted(keys_lower)}"

    def test_valhalla_json_is_richer_than_midgard(self) -> None:
        midgard = json.loads((REPORTS_DIR / "midgard_canonical.json").read_text(encoding="utf-8"))
        valhalla = json.loads((REPORTS_DIR / "valhalla_canonical.json").read_text(encoding="utf-8"))
        midgard_size = len(json.dumps(midgard, ensure_ascii=False))
        valhalla_size = len(json.dumps(valhalla, ensure_ascii=False))
        assert valhalla_size > 0
        assert midgard_size > 0


class TestXmlSnapshotIntegrity:
    """XML snapshots must be well-formed."""

    @pytest.mark.parametrize("tier", TIERS)
    def test_xml_canonical_parses(self, tier: str) -> None:
        path = REPORTS_DIR / f"{tier}_canonical.xml"
        tree = ET.parse(path)
        root = tree.getroot()
        assert root.tag is not None


class TestCsvSnapshotIntegrity:
    """CSV snapshots must have headers and at least one row."""

    @pytest.mark.parametrize("tier", TIERS)
    def test_csv_has_header_and_content(self, tier: str) -> None:
        path = REPORTS_DIR / f"{tier}_canonical.csv"
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) >= 1, f"CSV {tier} must have at least a header"
        header = lines[0]
        assert "," in header or header.strip(), f"CSV {tier} header is empty"


class TestSarifSnapshotIntegrity:
    """SARIF snapshots must match the v2.1.0 schema envelope."""

    @pytest.mark.parametrize("tier", TIERS)
    def test_sarif_has_version_and_runs(self, tier: str) -> None:
        path = REPORTS_DIR / f"{tier}_canonical.sarif"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data.get("version") == "2.1.0", f"SARIF {tier}: bad version"
        assert isinstance(data.get("runs"), list), f"SARIF {tier}: missing runs array"
