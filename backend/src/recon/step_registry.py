"""Recon logical steps: mode → planned steps; optional tool_selection filter; deferred steps log via pipeline."""

from __future__ import annotations

from enum import Enum

from src.recon.recon_runtime import ReconRuntimeConfig


class ReconStepId(str, Enum):
    """Logical recon steps (expand as tools land)."""

    NMAP_PORT_SCAN = "nmap_port_scan"
    DIG = "dig"
    DNS_DEPTH = "dns_depth"
    WHOIS = "whois"
    CRTSH = "crtsh"
    SUBDOMAIN_PASSIVE = "subdomain_passive"
    SHODAN = "shodan"
    HTTP_SURFACE = "http_surface"
    KAL_DNS_BUNDLE = "kal_dns_bundle"
    DEPENDENCY_MANIFESTS = "dependency_manifests"
    # RECON-006 — gau / waybackurls / katana (see recon_url_history); alias: tool_selection "url_history"
    CONTENT_DISCOVERY = "content_discovery"
    JS_ANALYSIS = "js_analysis"
    SCREENSHOTS = "screenshots"
    # RECON-008 — ProjectDiscovery asnmap (apex ASN summary)
    ASN_MAP = "asn_map"
    DEEP_PORT_SCAN = "deep_port_scan"


# Registry slice: steps that only emit audit-trail records when planned (empty by default).
STUB_STEPS: frozenset[ReconStepId] = frozenset()


def _base_steps_for_mode(mode: str) -> list[ReconStepId]:
    passive: list[ReconStepId] = [
        ReconStepId.DIG,
        ReconStepId.DNS_DEPTH,
        ReconStepId.WHOIS,
        ReconStepId.CRTSH,
        ReconStepId.SUBDOMAIN_PASSIVE,
        ReconStepId.SHODAN,
        ReconStepId.KAL_DNS_BUNDLE,
    ]
    active: list[ReconStepId] = [
        *passive,
        ReconStepId.NMAP_PORT_SCAN,
        ReconStepId.HTTP_SURFACE,
        ReconStepId.DEPENDENCY_MANIFESTS,
    ]
    if mode == "passive":
        return passive
    if mode == "active":
        return active
    # full
    return list(active)


def _optional_full_steps(cfg: ReconRuntimeConfig) -> list[ReconStepId]:
    if cfg.mode != "full":
        return []
    out: list[ReconStepId] = []
    if cfg.enable_content_discovery:
        out.append(ReconStepId.CONTENT_DISCOVERY)
    if cfg.js_analysis:
        out.append(ReconStepId.JS_ANALYSIS)
    if cfg.asnmap_enabled:
        out.append(ReconStepId.ASN_MAP)
    if cfg.screenshots:
        out.append(ReconStepId.SCREENSHOTS)
    if cfg.deep_port_scan:
        out.append(ReconStepId.DEEP_PORT_SCAN)
    return out


def plan_recon_steps(cfg: ReconRuntimeConfig) -> list[ReconStepId]:
    """Ordered plan: base mode steps + optional full-only extras/flags; then tool_selection filter."""
    steps = _base_steps_for_mode(cfg.mode)
    steps = list(dict.fromkeys(steps))  # stable dedup
    for extra in _optional_full_steps(cfg):
        if extra not in steps:
            steps.append(extra)

    if cfg.tool_selection is not None:
        sel = set(cfg.tool_selection)
        if "url_history" in sel:
            sel.add(ReconStepId.CONTENT_DISCOVERY.value)
        if "js_analysis" in sel:
            sel.add(ReconStepId.JS_ANALYSIS.value)
        if "asnmap" in sel:
            sel.add(ReconStepId.ASN_MAP.value)
        if "screenshots" in sel:
            sel.add(ReconStepId.SCREENSHOTS.value)
        steps = [s for s in steps if s.value in sel]

    return steps
