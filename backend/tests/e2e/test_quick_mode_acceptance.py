"""QUICK-009 — Quick mode e2e acceptance (master §18 / §19).

Default pytest skips this module via ``requires_docker`` / ``requires_docker_e2e``.
When the dedicated Quick lab stack is up, unset the skip by running:

    pytest -m requires_docker_e2e tests/e2e/test_quick_mode_acceptance.py

Juice Shop is too slow for compact 300s — use the fixtures in
``test_quick_mode_fixtures.py``, not a full shop crawl.
"""

from __future__ import annotations

import os

import pytest

pytestmark = [
    pytest.mark.requires_docker_e2e,
    pytest.mark.requires_docker,
]

_STACK_UP = os.environ.get("ARGUS_QUICK_E2E") == "1"
_SECTION_18_FIXTURES = (
    "http_service",
    "tech_specific_vuln",
    "misconfig",
    "duplicate_two_sources",
    "false_positive",
    "slow_endpoint",
    "unavailable_tool",
    "out_of_scope",
)


@pytest.mark.skipif(not _STACK_UP, reason="Quick e2e stack not provisioned (ARGUS_QUICK_E2E!=1)")
def test_quick_scan_completes_near_budget() -> None:
    pytest.fail("live Quick e2e stack not wired in this environment")


@pytest.mark.skipif(not _STACK_UP, reason="Quick e2e stack not provisioned (ARGUS_QUICK_E2E!=1)")
def test_quick_finds_high_signal_fixtures() -> None:
    pytest.fail("live Quick e2e stack not wired in this environment")


@pytest.mark.skipif(not _STACK_UP, reason="Quick e2e stack not provisioned (ARGUS_QUICK_E2E!=1)")
def test_out_of_scope_makes_zero_network_requests() -> None:
    pytest.fail("live Quick e2e stack not wired in this environment")


@pytest.mark.skipif(not _STACK_UP, reason="Quick e2e stack not provisioned (ARGUS_QUICK_E2E!=1)")
def test_quick_does_not_inherit_lab_unrestricted() -> None:
    pytest.fail("live Quick e2e stack not wired in this environment")


@pytest.mark.skipif(not _STACK_UP, reason="Quick e2e stack not provisioned (ARGUS_QUICK_E2E!=1)")
def test_quick_skips_exhaustive_and_destructive() -> None:
    pytest.fail("live Quick e2e stack not wired in this environment")


@pytest.mark.skipif(not _STACK_UP, reason="Quick e2e stack not wired in this environment")
def test_quick_report_includes_coverage_gaps() -> None:
    pytest.fail("live Quick e2e stack not wired in this environment")


@pytest.mark.skipif(not _STACK_UP, reason="Quick e2e stack not provisioned (ARGUS_QUICK_E2E!=1)")
def test_quick_survives_ai_and_rag_failure() -> None:
    pytest.fail("live Quick e2e stack not wired in this environment")


@pytest.mark.skipif(not _STACK_UP, reason="Quick e2e stack not provisioned (ARGUS_QUICK_E2E!=1)")
def test_raw_evidence_is_retained() -> None:
    pytest.fail("live Quick e2e stack not wired in this environment")


@pytest.mark.skipif(not _STACK_UP, reason="Quick e2e stack not provisioned (ARGUS_QUICK_E2E!=1)")
def test_plan_is_reproducible_for_same_input() -> None:
    pytest.fail("live Quick e2e stack not wired in this environment")


def test_acceptance_fixture_contract_is_documented() -> None:
    """Always-collected contract: §18 fixture names are enumerated for the live lane."""
    assert "out_of_scope" in _SECTION_18_FIXTURES
    assert "tech_specific_vuln" in _SECTION_18_FIXTURES
    assert len(_SECTION_18_FIXTURES) == 8
