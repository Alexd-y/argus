"""DWM report tiering: None in free Midgard; kept in Asgard + Valhalla.

Lives under ``tests/reports/`` (conftest offline allowlist) so it runs in the
default ``pytest -q``.
"""

from __future__ import annotations

from src.api.schemas import ReportSummary
from src.reports.generators import ReportData
from src.reports.report_bundle import ReportTier
from src.reports.tier_classifier import classify_for_tier

_DWM = {
    "status": "present",
    "observation_count": 2,
    "counts_by_exposure": {"credential": 1, "mention": 1},
    "observations": [{"id": "o1"}, {"id": "o2"}],
}


def _summary() -> ReportSummary:
    return ReportSummary(
        critical=0, high=0, medium=0, low=0, info=0,
        technologies=[], sslIssues=0, headerIssues=0, leaksFound=False,
    )


def _data() -> ReportData:
    return ReportData(
        report_id="r-1",
        target="https://acme.test",
        summary=_summary(),
        findings=[],
        technologies=[],
        dark_web_monitoring=_DWM,
    )


def test_midgard_strips_dark_web_monitoring() -> None:
    out = classify_for_tier(_data(), ReportTier.MIDGARD)
    assert out.dark_web_monitoring is None


def test_asgard_keeps_dark_web_monitoring() -> None:
    out = classify_for_tier(_data(), ReportTier.ASGARD)
    assert out.dark_web_monitoring == _DWM


def test_valhalla_keeps_dark_web_monitoring() -> None:
    out = classify_for_tier(_data(), ReportTier.VALHALLA)
    assert out.dark_web_monitoring == _DWM


def test_projection_does_not_mutate_input() -> None:
    data = _data()
    classify_for_tier(data, ReportTier.MIDGARD)
    assert data.dark_web_monitoring == _DWM  # original untouched
