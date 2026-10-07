"""Lab-unrestriction — active-scan concurrency is raised for ambient lab_unrestricted
mode (deep authorized runs) via a separate, larger semaphore; production/quick keep
the normal cap."""

from __future__ import annotations

import pytest
from src.core.config import settings
from src.execution_mode.mode import ExecutionMode
from src.recon.vulnerability_analysis.active_scan import mcp_runner as mr

_MODE_FN = "src.execution_mode.runtime_context.get_runtime_execution_mode"


@pytest.mark.asyncio
async def test_production_semaphore_uses_normal_cap(monkeypatch) -> None:
    monkeypatch.setattr(_MODE_FN, lambda: None)
    mr.reset_active_scan_semaphore_for_testing()
    sem = await mr.get_active_scan_semaphore()
    expected = max(
        1,
        min(
            int(settings.active_scan_max_concurrent_jobs),
            int(settings.argus_active_injection_max_concurrency),
        ),
    )
    assert sem._value == expected
    mr.reset_active_scan_semaphore_for_testing()


@pytest.mark.asyncio
async def test_lab_semaphore_uses_lab_cap(monkeypatch) -> None:
    monkeypatch.setattr(_MODE_FN, lambda: ExecutionMode.LAB_UNRESTRICTED)
    monkeypatch.setattr(settings, "active_scan_lab_max_concurrent_jobs", 50, raising=False)
    mr.reset_active_scan_semaphore_for_testing()
    sem = await mr.get_active_scan_semaphore()
    assert sem._value == 50
    mr.reset_active_scan_semaphore_for_testing()


@pytest.mark.asyncio
async def test_lab_and_prod_semaphores_are_distinct(monkeypatch) -> None:
    monkeypatch.setattr(settings, "active_scan_lab_max_concurrent_jobs", 50, raising=False)
    mr.reset_active_scan_semaphore_for_testing()
    monkeypatch.setattr(_MODE_FN, lambda: ExecutionMode.LAB_UNRESTRICTED)
    lab_sem = await mr.get_active_scan_semaphore()
    monkeypatch.setattr(_MODE_FN, lambda: None)
    prod_sem = await mr.get_active_scan_semaphore()
    assert lab_sem is not prod_sem
    assert lab_sem._value > prod_sem._value
    mr.reset_active_scan_semaphore_for_testing()


def test_config_default() -> None:
    assert settings.active_scan_lab_max_concurrent_jobs == 50
