"""RECON-001 — planned recon gather completes when optional steps (asnmap, gowitness, etc.) are mocked."""

from unittest.mock import AsyncMock, patch

import pytest

# Import handlers first so ``src.orchestration`` is initialized before ``src.recon.pipeline``
# (otherwise ``from src.orchestration.raw_phase_artifacts`` runs package __init__ → cycle).
import src.orchestration.handlers  # noqa: F401
from src.recon.pipeline import run_recon_planned_tool_gather
from src.recon.recon_runtime import ReconRuntimeConfig


@pytest.mark.asyncio
async def test_planned_gather_completes_when_plan_includes_registry_deferred_steps() -> None:
    """Optional recon steps are mocked; gather returns the expected shape."""
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=True,
        deep_port_scan=True,
        js_analysis=True,
        screenshots=True,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    tool_ok = {"success": True, "stdout": "", "stderr": "", "return_code": 0, "execution_time": 0.0}

    async def fake_dns_bundle(*_a, **_kw):
        return ({}, None)

    with (
        patch("src.orchestration.handlers._run_nmap", new_callable=AsyncMock, return_value=tool_ok),
        patch("src.orchestration.handlers._run_dig", new_callable=AsyncMock, return_value=tool_ok),
        patch("src.orchestration.handlers._run_whois", new_callable=AsyncMock, return_value=tool_ok),
        patch("src.orchestration.handlers._query_crtsh", new_callable=AsyncMock, return_value={}),
        patch("src.orchestration.handlers._query_shodan", new_callable=AsyncMock, return_value={}),
        patch(
            "src.orchestration.handlers._extract_url_params_and_forms",
            new_callable=AsyncMock,
            return_value=([], []),
        ),
        patch(
            "src.recon.recon_dns_sandbox.run_recon_dns_sandbox_bundle",
            new_callable=AsyncMock,
            side_effect=fake_dns_bundle,
        ),
        patch(
            "src.recon.pipeline.run_passive_subdomain_sandbox_bundle",
            new_callable=AsyncMock,
            return_value=({}, []),
        ),
        patch(
            "src.recon.pipeline.run_recon_dns_depth_bundle",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "src.recon.pipeline.run_recon_http_probe_bundle",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "src.recon.pipeline.run_recon_deep_port_scan_bundle",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "src.recon.pipeline.run_recon_url_history_bundle",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "src.recon.pipeline.run_recon_js_analysis_bundle",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "src.recon.pipeline.run_recon_asnmap_bundle",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "src.recon.pipeline.run_recon_gowitness_bundle",
            new_callable=AsyncMock,
            return_value={},
        ),
    ):
        tool_results, crawl_params, crawl_forms = await run_recon_planned_tool_gather(
            "https://example.com",
            "example.com",
            "80,443",
            {},
            cfg,
            raw_sink=None,
            tenant_id=None,
            scan_id=None,
        )

    assert isinstance(tool_results, dict)
    assert isinstance(crawl_params, list)
    assert isinstance(crawl_forms, list)
