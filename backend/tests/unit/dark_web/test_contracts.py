"""DWM contract tests: evidence_tier hard cap, status resolution, schema export."""

from __future__ import annotations

import pytest

from src.intel.dark_web.contracts import (
    DWM_EVIDENCE_TIER_CAP,
    JSON_SCHEMA_DARK_WEB_REPORT,
    DarkWebObservation,
    DarkWebReport,
    DarkWebReportStatus,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
    selector_hash,
)


def _obs(**kw: object) -> DarkWebObservation:
    base = dict(selector_kind="email", source_network="breach_db", exposure_type="credential")
    base.update(kw)
    return DarkWebObservation(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize("raw,expected", [(0, 1), (1, 1), (2, 2), (3, 2), (4, 2), (99, 2), ("7", 2), (None, 1)])
def test_evidence_tier_is_clamped(raw: object, expected: int) -> None:
    assert _obs(evidence_tier=raw).evidence_tier == expected
    assert DWM_EVIDENCE_TIER_CAP == 2


def test_selector_autofills_hash() -> None:
    s = DarkWebSelector(kind=SelectorKind.EMAIL, value="Alice@Example.com")
    assert s.value_hash == selector_hash("alice@example.com")
    assert len(s.value_hash) == 64


def test_report_status_not_collected_stays_when_no_sweep() -> None:
    r = DarkWebReport(scan_id="s", target="example.com", status=DarkWebReportStatus.NOT_COLLECTED)
    assert r.resolve_status() == DarkWebReportStatus.NOT_COLLECTED


def test_report_status_present_when_observations() -> None:
    r = DarkWebReport(
        scan_id="s",
        target="example.com",
        status=DarkWebReportStatus.RAN_EMPTY,
        observations=[_obs()],
    )
    assert r.resolve_status() == DarkWebReportStatus.PRESENT


def test_report_status_disabled_is_sticky() -> None:
    r = DarkWebReport(status=DarkWebReportStatus.DISABLED, observations=[_obs()])
    assert r.resolve_status() == DarkWebReportStatus.DISABLED


def test_counts_and_summary_dict() -> None:
    r = DarkWebReport(
        scan_id="s",
        target="example.com",
        selectors_count=3,
        observations=[
            _obs(exposure_type=ExposureType.CREDENTIAL, source_network=SourceNetwork.BREACH_DB),
            _obs(exposure_type=ExposureType.MENTION, source_network=SourceNetwork.CLEARNET_INDEX),
        ],
    )
    d = r.to_summary_dict()
    assert d["status"] == "present"
    assert d["observation_count"] == 2
    assert d["counts_by_exposure"]["credential"] == 1
    assert d["counts_by_source"]["clearnet_index"] == 1
    assert len(d["observations"]) == 2


def test_json_schema_exported() -> None:
    assert JSON_SCHEMA_DARK_WEB_REPORT["type"] == "object"
    assert "properties" in JSON_SCHEMA_DARK_WEB_REPORT
