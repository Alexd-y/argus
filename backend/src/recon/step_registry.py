"""Recon logical steps: mode → planned steps; optional tool_selection filter; deferred steps log via pipeline."""

from __future__ import annotations

from enum import StrEnum

from src.recon.recon_runtime import ReconRuntimeConfig


class ReconStepId(StrEnum):
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
    # ARGUS-002 — HTTP security headers collector
    SECURITY_HEADERS = "security_headers"


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
        ReconStepId.SECURITY_HEADERS,
        ReconStepId.DEPENDENCY_MANIFESTS,
    ]
    if mode == "passive":
        return passive
    if mode == "active":
        return active
    # full
    return list(active)


def _optional_full_steps(cfg: ReconRuntimeConfig) -> list[ReconStepId]:
    """Optional heavy recon steps, added ADDITIVELY by their own flags.

    Each flag only ever ADDS its step — it never subtracts one. Flags are read in
    every mode (not gated on mode="full"): the step plan is not reduced by mode."""
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
    """Ordered plan: the FULL recon surface — nothing is ever cut.

    Policy (operator request): recon runs every step; ``tool_selection``, ``mode``
    and ``passive_only`` never REMOVE a step. The base plan is always the full
    surface (WHOIS / DIG / DNS depth / crt.sh / subdomain / Shodan / kal-DNS /
    nmap / HTTP surface / security headers / dependency manifests); optional heavy
    steps are added additively by their own flags. A step whose tool is missing is
    skipped at run time by the pipeline (logged), not pruned here.
    """
    base = list(dict.fromkeys(_base_steps_for_mode("full")))  # always the full surface
    extras = [e for e in _optional_full_steps(cfg) if e not in base]
    return base + extras
