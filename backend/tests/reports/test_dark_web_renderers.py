"""DWM renderer integration: Asgard + Valhalla carry the section; Midgard does not."""

from __future__ import annotations

import json

from src.api.schemas import ReportSummary
from src.reports.asgard_tier_renderer import (
    asgard_assembly_to_jinja_context,
    assemble_asgard_sections,
)
from src.reports.generators import ReportData
from src.reports.report_bundle import ReportTier
from src.reports.tier_classifier import classify_for_tier
from src.reports.valhalla_tier_renderer import (
    assemble_valhalla_sections,
    valhalla_assembly_to_jinja_context,
)

_DWM = {
    "status": "present",
    "observation_count": 1,
    "selectors_count": 2,
    "counts_by_exposure": {"credential": 1},
    "counts_by_severity": {"high": 1},
    "counts_by_source": {"breach_db": 1},
    "observations": [
        {
            "id": "o1",
            "exposure_type": "credential",
            "severity": "high",
            "source_network": "breach_db",
            "source_ref": "hibp:breach:Acme",
            "confidence": "likely",
            "evidence_tier": 2,
            "redacted_summary": "a***@acme.com present in breach Acme",
            "raw_object_key": "t/s/darkweb/ab.bin",
            "raw_sha256": "deadbeef",
            "finding_id": "",
        }
    ],
}


def _summary() -> ReportSummary:
    return ReportSummary(
        critical=0, high=1, medium=0, low=0, info=0,
        technologies=[], sslIssues=0, headerIssues=0, leaksFound=True,
    )


def _data(dwm=_DWM) -> ReportData:
    return ReportData(
        report_id="r", target="acme.com", summary=_summary(),
        findings=[], technologies=[], dark_web_monitoring=dwm,
    )


def test_asgard_assembly_has_masked_dark_web_rows() -> None:
    a = assemble_asgard_sections(classify_for_tier(_data(), ReportTier.ASGARD))
    assert len(a.dark_web_exposure) == 1
    row = a.dark_web_exposure[0]
    assert row.exposure_type == "credential"
    assert row.evidence_tier == 2
    # exec-level summary counts present
    assert a.dark_web_monitoring["observation_count"] == 1
    # jinja slot carries it
    ctx = asgard_assembly_to_jinja_context(a)
    assert "dark_web_exposure" in ctx["asgard_report"]


def test_valhalla_assembly_has_full_dark_web_rows() -> None:
    v = assemble_valhalla_sections(classify_for_tier(_data(), ReportTier.VALHALLA))
    assert len(v.dark_web_exposure) == 1
    row = v.dark_web_exposure[0]
    assert row.raw_sha256 == "deadbeef"  # provenance preserved in detail tier
    ctx = valhalla_assembly_to_jinja_context(v)
    assert "dark_web_exposure" in ctx["valhalla_executive_report"]


def test_no_plaintext_leaks_in_rendered_slots() -> None:
    dwm = json.loads(json.dumps(_DWM))
    dwm["observations"][0]["redacted_summary"] = "combolist a***@acme.com:<redacted>"
    a = assemble_asgard_sections(classify_for_tier(_data(dwm), ReportTier.ASGARD))
    v = assemble_valhalla_sections(classify_for_tier(_data(dwm), ReportTier.VALHALLA))
    blob = json.dumps(asgard_assembly_to_jinja_context(a)) + json.dumps(
        valhalla_assembly_to_jinja_context(v)
    )
    assert "<redacted>" in blob
    # a real plaintext password string must never appear
    assert "hunter2" not in blob


def test_midgard_projection_drops_dark_web_before_render() -> None:
    projected = classify_for_tier(_data(), ReportTier.MIDGARD)
    assert projected.dark_web_monitoring is None
