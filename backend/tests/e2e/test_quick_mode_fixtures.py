"""QUICK-009 e2e fixtures (master §18).

These fixtures document the dedicated Quick lab stand. They do not start
Docker. Acceptance tests in ``test_quick_mode_acceptance.py`` consume them
when the e2e stack is up.

Fixtures:
- ordinary HTTP service
- technology-specific vulnerability
- misconfiguration
- duplicate findings from two sources
- false-positive fixture
- slow endpoint
- unavailable tool
- out-of-scope target
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import pytest

pytestmark = [
    pytest.mark.requires_docker_e2e,
    pytest.mark.requires_docker,
]


@dataclass(frozen=True)
class QuickE2EFixture:
    name: str
    target: str
    in_scope: bool
    expected_signal: str
    notes: str


QUICK_E2E_FIXTURES: Final[tuple[QuickE2EFixture, ...]] = (
    QuickE2EFixture(
        name="http_service",
        target="http://quick-http.lab",
        in_scope=True,
        expected_signal="reachable",
        notes="Ordinary HTTP service used as the in-scope baseline.",
    ),
    QuickE2EFixture(
        name="tech_specific_vuln",
        target="http://quick-nginx.lab",
        in_scope=True,
        expected_signal="high_signal_cve",
        notes="Technology-specific vulnerability (known product/version).",
    ),
    QuickE2EFixture(
        name="misconfig",
        target="http://quick-misconfig.lab",
        in_scope=True,
        expected_signal="misconfiguration",
        notes="Exposed debug / default credential misconfiguration.",
    ),
    QuickE2EFixture(
        name="duplicate_two_sources",
        target="http://quick-dup.lab",
        in_scope=True,
        expected_signal="duplicate_fingerprint",
        notes="Same finding emitted by two tools; correlation must keep both occurrences.",
    ),
    QuickE2EFixture(
        name="false_positive",
        target="http://quick-fp.lab",
        in_scope=True,
        expected_signal="false_positive_candidate",
        notes="Known FP fixture for precision baseline.",
    ),
    QuickE2EFixture(
        name="slow_endpoint",
        target="http://quick-slow.lab",
        in_scope=True,
        expected_signal="deadline_aware",
        notes="Slow endpoint; scheduler must keep verification/report reserve.",
    ),
    QuickE2EFixture(
        name="unavailable_tool",
        target="http://quick-http.lab",
        in_scope=True,
        expected_signal="tool_error_coverage",
        notes="Tool marked unavailable; scan continues with coverage gap.",
    ),
    QuickE2EFixture(
        name="out_of_scope",
        target="http://evil.example",
        in_scope=False,
        expected_signal="zero_network",
        notes="Out-of-scope target: 0 network requests, 0 findings.",
    ),
)


@pytest.fixture(scope="module")
def quick_e2e_fixtures() -> tuple[QuickE2EFixture, ...]:
    return QUICK_E2E_FIXTURES


def test_fixture_catalog_documents_master_section_18(
    quick_e2e_fixtures: tuple[QuickE2EFixture, ...],
) -> None:
    names = {item.name for item in quick_e2e_fixtures}
    assert names == {
        "http_service",
        "tech_specific_vuln",
        "misconfig",
        "duplicate_two_sources",
        "false_positive",
        "slow_endpoint",
        "unavailable_tool",
        "out_of_scope",
    }
    out = next(item for item in quick_e2e_fixtures if item.name == "out_of_scope")
    assert out.in_scope is False
