"""Merge global RECON_* settings with per-scan ``options`` / ``options.recon`` (additive, no API break)."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any, Literal

from src.core.config import Settings, settings as default_settings

ReconModeLiteral = Literal["passive", "active", "full"]


def _parse_tool_selection(raw: str | None) -> frozenset[str] | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    parts = frozenset(p.strip().lower() for p in s.split(",") if p.strip())
    return parts or None


def _coerce_mode(value: Any) -> ReconModeLiteral | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in ("passive", "active", "full"):
        return s  # type: ignore[return-value]
    return None


def _coerce_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(int(value))
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return None


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _coerce_dnsx_extra_flags_frozenset(value: Any) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return frozenset()
        try:
            return frozenset(shlex.split(s, posix=True))
        except ValueError:
            return None
    if isinstance(value, (list, tuple)):
        return frozenset(str(x).strip() for x in value if str(x).strip())
    return None


def _effective_rate_rps(s: Settings) -> int:
    if s.recon_rate_limit is not None:
        return max(1, int(s.recon_rate_limit))
    return max(1, int(s.recon_rate_limit_per_second))


@dataclass(frozen=True)
class ReconRuntimeConfig:
    """Resolved recon pipeline flags for one scan run."""

    mode: ReconModeLiteral
    active_depth: int
    enable_content_discovery: bool
    deep_port_scan: bool
    js_analysis: bool
    screenshots: bool
    tool_selection: frozenset[str] | None
    wordlist_path: str
    rate_limit_rps: int
    # RECON-003 — dnsx depth + optional dig / takeover hints
    dns_depth_enabled: bool = True
    dns_depth_dig_deep: bool = False
    dns_depth_takeover_hints: bool = True
    dnsx_record_types_csv: str = "a,aaaa,cname,mx,txt,ns"
    dnsx_include_resp: bool = False
    dnsx_silent: bool = False
    dns_depth_timeout_sec: int | None = None
    dnsx_extra_flags: frozenset[str] | None = None
    # RECON-004 — nuclei tech-only profile (tags / template list from env or scan options)
    nuclei_tech_tags_csv: str = "tech"
    nuclei_tech_templates_csv: str = ""
    # RECON-005 — deep port scan caps (naabu + nmap -sV)
    deep_naabu_enabled: bool = True
    deep_naabu_top_ports: int = 500
    deep_max_hosts: int = 5
    deep_max_ports_per_host: int = 40
    deep_timeout_sec: int | None = None
    # RECON-008 — asnmap + gowitness (full-mode optional; skipped when passive)
    asnmap_enabled: bool = True
    gowitness_max_urls: int = 25
    gowitness_timeout_sec: int | None = None
    gowitness_concurrency: int = 3


def _nested_recon_dict(scan_options: dict[str, Any]) -> dict[str, Any]:
    nested = scan_options.get("recon")
    if isinstance(nested, dict):
        return dict(nested)
    return {}


def build_recon_runtime_config(
    scan_options: dict[str, Any] | None,
    *,
    app_settings: Settings | None = None,
) -> ReconRuntimeConfig:
    """Defaults from env/settings; overrides from ``scan_options['recon']`` and top-level recon_* keys."""
    s = app_settings or default_settings
    opt = dict(scan_options or {})
    nested = _nested_recon_dict(opt)

    def pick(key: str, nested_keys: tuple[str, ...]) -> Any:
        for nk in nested_keys:
            if nk in nested and nested[nk] is not None:
                return nested[nk]
        if key in opt and opt[key] is not None:
            return opt[key]
        return None

    passive_only = _coerce_bool(pick("recon_passive_only", ("passive_only",)))
    if passive_only is None:
        passive_only = bool(s.recon_passive_only)

    mode = _coerce_mode(pick("recon_mode", ("mode",)))
    if mode is None:
        mode = s.recon_mode  # type: ignore[assignment]
    if passive_only:
        mode = "passive"

    active_depth = _coerce_int(pick("recon_active_depth", ("active_depth",)))
    if active_depth is None:
        active_depth = int(s.recon_active_depth)
    active_depth = max(0, active_depth)

    def pick_bool(setting_attr: str, nested_key: str) -> bool:
        v = _coerce_bool(pick(setting_attr, (nested_key,)))
        if v is not None:
            return v
        return bool(getattr(s, setting_attr))

    enable_cd = pick_bool("recon_enable_content_discovery", "enable_content_discovery")
    deep_ports = pick_bool("recon_deep_port_scan", "deep_port_scan")
    js_a = pick_bool("recon_js_analysis", "js_analysis")
    shots = pick_bool("recon_screenshots", "screenshots")

    ts_raw = pick("recon_tool_selection", ("tool_selection",))
    if ts_raw is None:
        ts_raw = s.recon_tool_selection
    tool_selection = _parse_tool_selection(
        ts_raw if isinstance(ts_raw, str) else ",".join(str(x) for x in ts_raw) if ts_raw else None,
    )

    wl = pick("recon_wordlist_path", ("wordlist_path",))
    wordlist_path = (
        str(wl).strip()
        if wl is not None
        else str(s.recon_wordlist_path or "").strip()
    )

    rl = _coerce_int(pick("recon_rate_limit", ("rate_limit",)))
    rate_rps = _effective_rate_rps(s)
    if rl is not None:
        rate_rps = max(1, rl)

    dns_depth_enabled = pick_bool("recon_dns_depth_enabled", "dns_depth_enabled")
    dns_depth_dig_deep = pick_bool("recon_dns_depth_dig_deep", "dns_depth_dig_deep")
    dns_depth_takeover_hints = pick_bool("recon_dns_depth_takeover_hints", "dns_depth_takeover_hints")

    dnx_types = pick("recon_dnsx_record_types", ("dnsx_record_types",))
    dnsx_record_types_csv = (
        str(dnx_types).strip()
        if dnx_types is not None
        else str(getattr(s, "recon_dnsx_record_types", "") or "").strip()
    )
    if not dnsx_record_types_csv:
        dnsx_record_types_csv = "a,aaaa,cname,mx,txt,ns"

    dnsx_include_resp = pick_bool("recon_dnsx_include_resp", "dnsx_include_resp")
    dnsx_silent = pick_bool("recon_dnsx_silent", "dnsx_silent")

    dd_to = _coerce_int(pick("recon_dns_depth_timeout_sec", ("dns_depth_timeout_sec",)))
    dns_depth_timeout_sec = dd_to if dd_to is not None else getattr(s, "recon_dns_depth_timeout_sec", None)

    xf_pick = pick("recon_dnsx_extra_flags", ("dnsx_extra_flags",))
    dnsx_extra_flags = _coerce_dnsx_extra_flags_frozenset(xf_pick)

    nt_tags = pick("recon_nuclei_tech_tags", ("nuclei_tech_tags",))
    nuclei_tech_tags_csv = (
        str(nt_tags).strip()
        if nt_tags is not None
        else str(getattr(s, "recon_nuclei_tech_tags", "") or "").strip()
    )
    if not nuclei_tech_tags_csv:
        nuclei_tech_tags_csv = "tech"

    nt_tpl = pick("recon_nuclei_tech_templates", ("nuclei_tech_templates",))
    nuclei_tech_templates_csv = (
        str(nt_tpl).strip()
        if nt_tpl is not None
        else str(getattr(s, "recon_nuclei_tech_templates", "") or "").strip()
    )

    deep_naabu_en = pick_bool("recon_deep_naabu_enabled", "deep_naabu_enabled")
    dntp = _coerce_int(pick("recon_deep_naabu_top_ports", ("deep_naabu_top_ports",)))
    deep_naabu_top_ports = (
        max(1, min(65535, int(dntp)))
        if dntp is not None
        else max(1, min(65535, int(getattr(s, "recon_deep_naabu_top_ports", 500) or 500)))
    )
    dmh = _coerce_int(pick("recon_deep_max_hosts", ("deep_max_hosts",)))
    deep_max_hosts = (
        max(1, int(dmh)) if dmh is not None else max(1, int(getattr(s, "recon_deep_max_hosts", 5) or 5))
    )
    dmph = _coerce_int(pick("recon_deep_max_ports_per_host", ("deep_max_ports_per_host",)))
    deep_max_ports_per_host = (
        max(1, min(256, int(dmph)))
        if dmph is not None
        else max(1, min(256, int(getattr(s, "recon_deep_max_ports_per_host", 40) or 40)))
    )
    dts = _coerce_int(pick("recon_deep_timeout_sec", ("deep_timeout_sec",)))
    deep_timeout_sec = dts if dts is not None else getattr(s, "recon_deep_timeout_sec", None)

    asnmap_en = pick_bool("recon_asnmap_enabled", "asnmap_enabled")
    gwm = _coerce_int(pick("recon_gowitness_max_urls", ("gowitness_max_urls",)))
    gowitness_max_urls = (
        max(1, min(500, int(gwm)))
        if gwm is not None
        else max(1, min(500, int(getattr(s, "recon_gowitness_max_urls", 25) or 25)))
    )
    gwt = _coerce_int(pick("recon_gowitness_timeout_sec", ("gowitness_timeout_sec",)))
    gowitness_timeout_sec = gwt if gwt is not None else getattr(s, "recon_gowitness_timeout_sec", None)
    gwc = _coerce_int(pick("recon_gowitness_concurrency", ("gowitness_concurrency",)))
    gowitness_concurrency = (
        max(1, min(8, int(gwc)))
        if gwc is not None
        else max(1, min(8, int(getattr(s, "recon_gowitness_concurrency", 3) or 3)))
    )

    return ReconRuntimeConfig(
        mode=mode,
        active_depth=active_depth,
        enable_content_discovery=enable_cd,
        deep_port_scan=deep_ports,
        js_analysis=js_a,
        screenshots=shots,
        tool_selection=tool_selection,
        wordlist_path=wordlist_path,
        rate_limit_rps=rate_rps,
        dns_depth_enabled=dns_depth_enabled,
        dns_depth_dig_deep=dns_depth_dig_deep,
        dns_depth_takeover_hints=dns_depth_takeover_hints,
        dnsx_record_types_csv=dnsx_record_types_csv,
        dnsx_include_resp=dnsx_include_resp,
        dnsx_silent=dnsx_silent,
        dns_depth_timeout_sec=dns_depth_timeout_sec,
        dnsx_extra_flags=dnsx_extra_flags,
        nuclei_tech_tags_csv=nuclei_tech_tags_csv,
        nuclei_tech_templates_csv=nuclei_tech_templates_csv,
        deep_naabu_enabled=deep_naabu_en,
        deep_naabu_top_ports=deep_naabu_top_ports,
        deep_max_hosts=deep_max_hosts,
        deep_max_ports_per_host=deep_max_ports_per_host,
        deep_timeout_sec=deep_timeout_sec,
        asnmap_enabled=asnmap_en,
        gowitness_max_urls=gowitness_max_urls,
        gowitness_timeout_sec=gowitness_timeout_sec,
        gowitness_concurrency=gowitness_concurrency,
    )
