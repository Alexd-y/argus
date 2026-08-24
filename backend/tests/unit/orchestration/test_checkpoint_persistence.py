"""Durable checkpoint persistence + profile-driven phase skip (R11 wiring)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.orchestration.checkpoint_persistence import (
    init_scan_checkpoint,
    profile_skipped_phases,
    read_checkpoint,
    resolved_profile_from_options,
    update_checkpoint_phase,
)
from src.orchestration.phases import ScanPhase


def _fake_session():
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    return session


def test_resolved_profile_from_scan_profile_option():
    resolved = resolved_profile_from_options({"scan_profile": "deep"})
    assert resolved is not None
    assert resolved.external_profile.value == "deep"
    assert resolved.requires_lab_lease is True


def test_resolved_profile_none_without_profile():
    assert resolved_profile_from_options({}) is None
    assert resolved_profile_from_options(None) is None


def test_profile_skipped_phases_quick():
    skips = profile_skipped_phases({"scan_profile": "quick"})
    assert ScanPhase.EXPLOITATION in skips
    assert ScanPhase.SOURCE_ANALYSIS in skips
    assert ScanPhase.RECON not in skips


def test_profile_skipped_phases_light_excludes_destructive():
    skips = profile_skipped_phases({"scan_profile": "light"})
    assert ScanPhase.EXPLOITATION in skips
    assert ScanPhase.POST_EXPLOITATION in skips
    assert ScanPhase.VULN_ANALYSIS not in skips


def test_profile_skipped_phases_deep_none():
    assert profile_skipped_phases({"scan_profile": "deep"}) == frozenset()


@pytest.mark.asyncio
async def test_init_checkpoint_persists_into_options():
    session = _fake_session()
    options: dict = {"scan_profile": "light"}
    cp = await init_scan_checkpoint(
        session,
        scan_id="s-1",
        tenant_id="t-1",
        options=options,
        current_phase="recon",
    )
    assert cp is not None
    assert "scan_checkpoint_v1" in options
    session.execute.assert_awaited()
    session.commit.assert_awaited()
    # round-trips through read_checkpoint
    restored = read_checkpoint(options)
    assert restored is not None
    assert restored.resolved().external_profile.value == "light"


@pytest.mark.asyncio
async def test_init_checkpoint_noop_without_profile():
    session = _fake_session()
    options: dict = {}
    cp = await init_scan_checkpoint(
        session, scan_id="s", tenant_id="t", options=options, current_phase="recon"
    )
    assert cp is None
    assert "scan_checkpoint_v1" not in options


@pytest.mark.asyncio
async def test_resume_uses_frozen_checkpoint_profile():
    # Even if scan_profile option later disagrees, resume reads the frozen checkpoint.
    session = _fake_session()
    options: dict = {"scan_profile": "deep", "lab_lease_id": "lease-1"}
    await init_scan_checkpoint(
        session, scan_id="s", tenant_id="t", options=options, current_phase="recon"
    )
    options["scan_profile"] = "quick"  # tamper with raw input
    resolved = resolved_profile_from_options(options)
    # Frozen checkpoint wins → still deep.
    assert resolved.external_profile.value == "deep"


@pytest.mark.asyncio
async def test_update_checkpoint_phase_advances():
    session = _fake_session()
    options: dict = {"scan_profile": "light"}
    await init_scan_checkpoint(
        session, scan_id="s", tenant_id="t", options=options, current_phase="recon"
    )
    await update_checkpoint_phase(
        session, scan_id="s", options=options, current_phase="vuln_analysis",
        completed_phase="recon",
    )
    cp = read_checkpoint(options)
    assert cp.current_phase == "vuln_analysis"
    assert "recon" in cp.completed_phases
