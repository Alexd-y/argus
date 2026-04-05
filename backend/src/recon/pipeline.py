"""Recon tool orchestration: step registry + parallel gather (lazy-imports handlers to avoid cycles)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.orchestration.raw_phase_artifacts import RawPhaseSink
from src.recon.recon_asn_screenshots import run_recon_asnmap_bundle, run_recon_gowitness_bundle
from src.recon.recon_deep_port_scan import run_recon_deep_port_scan_bundle
from src.recon.recon_dns_depth import run_recon_dns_depth_bundle
from src.recon.recon_dns_sandbox import dedupe_subdomain_intel_rows, run_recon_dns_sandbox_bundle
from src.recon.recon_http_headers import collect_security_headers, security_headers_result_to_dict
from src.recon.recon_http_probe import run_recon_http_probe_bundle
from src.recon.recon_js_analysis import run_recon_js_analysis_bundle
from src.recon.recon_runtime import ReconRuntimeConfig
from src.recon.recon_subdomain_inventory import merge_subdomain_hosts_into_tool_results
from src.recon.recon_subdomain_passive import run_passive_subdomain_sandbox_bundle
from src.recon.recon_url_history import run_recon_url_history_bundle
from src.recon.step_registry import STUB_STEPS, ReconStepId, plan_recon_steps

logger = logging.getLogger(__name__)


async def run_recon_planned_tool_gather(
    target: str,
    domain: str,
    ports: str,
    options: dict[str, Any],
    cfg: ReconRuntimeConfig,
    *,
    raw_sink: RawPhaseSink | None,
    tenant_id: str | None,
    scan_id: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Run recon tools according to ``plan_recon_steps(cfg)``.

    Returns (tool_results, crawl_params, crawl_forms) compatible with existing ``run_recon`` merge logic.
    """
    from src.orchestration.handlers import (
        _extract_url_params_and_forms,
        _query_crtsh,
        _query_shodan,
        _run_dig,
        _run_nmap,
        _run_whois,
    )
    steps = plan_recon_steps(cfg)
    planned = [s.value for s in steps]
    logger.info(
        "recon_pipeline_plan",
        extra={
            "event": "recon_pipeline_plan",
            "mode": cfg.mode,
            "steps": planned,
            "rate_limit_rps": cfg.rate_limit_rps,
            "active_depth": cfg.active_depth,
        },
    )

    for step in steps:
        if step in STUB_STEPS:
            logger.info(
                "recon_step_skipped",
                extra={
                    "event": "recon_step_skipped",
                    "step": step.value,
                    "reason": "not_implemented",
                },
            )

    step_set = frozenset(steps)
    names: list[str] = []
    coros: list[Any] = []

    def add(name: str, coro: Any) -> None:
        names.append(name)
        coros.append(coro)

    if ReconStepId.NMAP_PORT_SCAN in step_set:
        add("nmap", _run_nmap(domain, ports, options=options, raw_sink=raw_sink))
    if ReconStepId.DIG in step_set:
        add("dig", _run_dig(domain))
    if ReconStepId.WHOIS in step_set:
        add("whois", _run_whois(domain))
    if ReconStepId.CRTSH in step_set:
        add("crtsh", _query_crtsh(domain, raw_sink=raw_sink))
    if ReconStepId.SHODAN in step_set:
        add("shodan", _query_shodan(domain))

    http_idx: int | None = None
    if ReconStepId.HTTP_SURFACE in step_set:
        http_idx = len(coros)
        add("__http__", _extract_url_params_and_forms(target))

    results = await asyncio.gather(*coros, return_exceptions=True) if coros else []

    crawl_params: list[dict[str, Any]] = []
    crawl_forms: list[dict[str, Any]] = []
    tool_results: dict[str, Any] = {}

    for i, name in enumerate(names):
        if http_idx is not None and i == http_idx:
            res = results[i]
            if isinstance(res, tuple) and len(res) == 2:
                crawl_params, crawl_forms = res
            elif isinstance(res, Exception):
                logger.warning(
                    "recon_http_crawl_failed",
                    extra={"exc_type": type(res).__name__},
                )
            continue

        res = results[i]
        if isinstance(res, Exception):
            errno = getattr(res, "errno", None)
            logger.warning(
                "recon_tool_failed",
                extra={
                    "tool": name,
                    "exc_type": type(res).__name__,
                    "errno": errno,
                },
            )
            tool_results[name] = {"success": False, "stdout": "", "stderr": str(res)}
        else:
            tool_results[name] = res

    if ReconStepId.HTTP_SURFACE in step_set and cfg.mode in ("active", "full"):
        try:
            probe_frag = await run_recon_http_probe_bundle(
                target,
                cfg,
                raw_sink=raw_sink,
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            if probe_frag:
                tool_results.update(probe_frag)
        except Exception as ex:
            logger.warning(
                "recon_http_probe_pipeline_failed",
                extra={"event": "recon_http_probe_pipeline_failed", "exc_type": type(ex).__name__},
                exc_info=True,
            )

    if ReconStepId.SECURITY_HEADERS in step_set:
        try:
            sh_result = await collect_security_headers(target)
            sh_dict = security_headers_result_to_dict(sh_result)
            tool_results["security_headers"] = sh_dict
            if raw_sink is not None:
                try:
                    await asyncio.to_thread(raw_sink.upload_json, "security_headers", sh_dict)
                except Exception:
                    logger.warning(
                        "security_headers_upload_failed",
                        extra={"event": "security_headers_upload_failed"},
                    )
            logger.info(
                "recon_security_headers_done",
                extra={
                    "event": "recon_security_headers_done",
                    "score": sh_result.score,
                    "findings_count": len(sh_result.findings),
                    "error": sh_result.error,
                },
            )
        except Exception as ex:
            logger.warning(
                "recon_security_headers_pipeline_failed",
                extra={"event": "recon_security_headers_pipeline_failed", "exc_type": type(ex).__name__},
                exc_info=True,
            )

    if ReconStepId.DNS_DEPTH in step_set:
        try:
            depth_frag = await run_recon_dns_depth_bundle(target, cfg, raw_sink=raw_sink)
            if depth_frag:
                tool_results.update(depth_frag)
        except Exception as ex:
            logger.warning(
                "recon_dns_depth_pipeline_failed",
                extra={"event": "recon_dns_depth_pipeline_failed", "exc_type": type(ex).__name__},
                exc_info=True,
            )

    merged_intel: list[dict[str, Any]] = []
    if ReconStepId.SUBDOMAIN_PASSIVE in step_set:
        st_tool_results, st_intel = await run_passive_subdomain_sandbox_bundle(
            target,
            options,
            tenant_id=tenant_id,
            scan_id=scan_id,
        )
        if st_tool_results:
            tool_results.update(st_tool_results)
        merged_intel.extend(st_intel)
        if raw_sink is not None:
            for key in ("subfinder", "assetfinder", "findomain", "theharvester"):
                block = st_tool_results.get(key)
                if isinstance(block, dict):
                    stdout = block.get("stdout")
                    if isinstance(stdout, str) and stdout.strip():
                        try:
                            await asyncio.to_thread(raw_sink.upload_text, key, stdout)
                        except Exception:
                            logger.warning(
                                "recon_raw_subdomain_upload_failed",
                                extra={"event": "recon_raw_subdomain_upload_failed", "tool": key},
                            )

    if ReconStepId.KAL_DNS_BUNDLE in step_set:
        dns_tool_results, dns_intel = await run_recon_dns_sandbox_bundle(
            target,
            options,
            tenant_id=tenant_id,
            scan_id=scan_id,
        )
        if dns_tool_results:
            tool_results.update(dns_tool_results)
        merged_intel.extend(dns_intel)

    if merged_intel:
        tool_results["kal_dns_intel"] = dedupe_subdomain_intel_rows(merged_intel)

    merge_subdomain_hosts_into_tool_results(tool_results, domain=domain)

    if ReconStepId.ASN_MAP in step_set:
        try:
            asn_frag = await run_recon_asnmap_bundle(
                domain,
                cfg,
                raw_sink=raw_sink,
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            if asn_frag:
                tool_results.update(asn_frag)
        except Exception as ex:
            logger.warning(
                "recon_asnmap_pipeline_failed",
                extra={"event": "recon_asnmap_pipeline_failed", "exc_type": type(ex).__name__},
                exc_info=True,
            )

    if ReconStepId.CONTENT_DISCOVERY in step_set:
        try:
            uh_frag = await run_recon_url_history_bundle(
                target,
                domain,
                cfg,
                raw_sink=raw_sink,
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            if uh_frag:
                tool_results.update(uh_frag)
        except Exception as ex:
            logger.warning(
                "recon_url_history_pipeline_failed",
                extra={"event": "recon_url_history_pipeline_failed", "exc_type": type(ex).__name__},
                exc_info=True,
            )

    if ReconStepId.JS_ANALYSIS in step_set:
        try:
            js_frag = await run_recon_js_analysis_bundle(
                target,
                domain,
                tool_results,
                cfg,
                raw_sink=raw_sink,
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            if js_frag:
                tool_results.update(js_frag)
        except Exception as ex:
            logger.warning(
                "recon_js_analysis_pipeline_failed",
                extra={"event": "recon_js_analysis_pipeline_failed", "exc_type": type(ex).__name__},
                exc_info=True,
            )

    if ReconStepId.DEEP_PORT_SCAN in step_set:
        try:
            deep_frag = await run_recon_deep_port_scan_bundle(
                target,
                domain,
                ports,
                tool_results,
                cfg,
                raw_sink=raw_sink,
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            if deep_frag:
                tool_results.update(deep_frag)
        except Exception as ex:
            logger.warning(
                "recon_deep_port_scan_pipeline_failed",
                extra={"event": "recon_deep_port_scan_pipeline_failed", "exc_type": type(ex).__name__},
                exc_info=True,
            )

    if ReconStepId.SCREENSHOTS in step_set:
        try:
            gw_frag = await run_recon_gowitness_bundle(
                target,
                tool_results,
                cfg,
                raw_sink=raw_sink,
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            if gw_frag:
                tool_results.update(gw_frag)
        except Exception as ex:
            logger.warning(
                "recon_gowitness_pipeline_failed",
                extra={"event": "recon_gowitness_pipeline_failed", "exc_type": type(ex).__name__},
                exc_info=True,
            )

    return tool_results, crawl_params, crawl_forms
