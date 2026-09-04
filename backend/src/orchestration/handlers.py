"""Phase handlers — production implementation with real tools and data sources."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import re
import shlex
import socket
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from src.core.config import settings
from src.data_sources.crtsh_client import CrtShClient
from src.data_sources.hibp_pwned_passwords import summarize_pwned_passwords_for_report
from src.data_sources.nvd_client import NVDClient
from src.data_sources.shodan_client import ShodanClient
from src.execution_mode.mode import ExecutionMode
from src.llm import facade as llm_facade
from src.llm.task_router import LLMTask
from src.orchestration.adaptive_driver import (
    make_constant_tool_resolver,
    run_adaptive_vuln_analysis_signed,
)
from src.orchestration.ai_prompts import (
    ai_exploitation,
    ai_post_exploitation,
    ai_recon,
    ai_reporting,
    ai_threat_modeling,
    ai_vuln_analysis,
)
from src.orchestration.coverage_phase_sink import (
    attach_phase_coverage,
    signals_for_vuln_analysis,
    signals_from_tool_results,
    snapshot_coverage_dicts,
)
from src.orchestration.cve_platform_mitigations import apply_platform_cve_mitigations
from src.orchestration.execution_mode_context import (
    attach_execution_mode_to_input,
    extract_execution_mode,
    resolve_tool_policy_from_options,
)
from src.orchestration.exploit_verify import verify_exploit_poc_async
from src.orchestration.finding_gate import gate_and_dedupe_findings
from src.orchestration.phases import (
    ExploitationInput,
    ExploitationOutput,
    PostExploitationInput,
    PostExploitationOutput,
    QuickFuzzOutput,
    ReconInput,
    ReconOutput,
    ReportingInput,
    ReportingOutput,
    SourceAnalysisInput,
    SourceAnalysisOutput,
    ThreatModelInput,
    ThreatModelOutput,
    VulnAnalysisInput,
    VulnAnalysisOutput,
)
from src.orchestration.raw_phase_artifacts import RawPhaseSink
from src.owasp_top10_2025 import parse_owasp_category
from src.quick.cancellation import is_scan_cancelled
from src.quick.circuit_breaker import default_circuit_breaker
from src.quick.scheduler import QuickScheduler
from src.quick.schemas import QuickTaskStage
from src.quick.workflow import QuickWorkflow, is_quick_execution, resolve_quick_plan
from src.recon.exploitation.custom_xss_poc import run_custom_xss_poc
from src.recon.pipeline import run_recon_planned_tool_gather
from src.recon.recon_runtime import build_recon_runtime_config
from src.recon.step_registry import ReconStepId, plan_recon_steps
from src.recon.summary_builder import build_recon_summary_document
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    build_input_surface_inventory,
)
from src.recon.vulnerability_analysis.active_scan.spa_api_surface import (
    extract_script_urls_from_html,
    extract_spa_api_surfaces,
)
from src.recon.vulnerability_analysis.active_scan.va_active_scan_phase import (
    run_va_active_scan_phase,
)
from src.recon.vulnerability_analysis.active_scan.web_vuln_heuristics import (
    run_web_vuln_heuristics,
)
from src.recon.vulnerability_analysis.finding_normalizer import (
    normalize_active_scan_intel_findings,
)
from src.recon.vulnerability_analysis.finding_stable_id import assign_stable_finding_ids
from src.recon.vulnerability_analysis.owasp_category_map import resolve_owasp_category
from src.reports.finding_metadata import apply_default_finding_metadata
from src.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.tools.executor import execute_command

logger = logging.getLogger(__name__)


def _attach_phase_execution_mode(
    scan_options: dict[str, Any] | None,
    *,
    tenant_id: str | None = None,
    scan_id: str | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Stamp ``execution_mode_context`` onto scan options at phase start; return options."""
    opts = scan_options if isinstance(scan_options, dict) else {}
    resolved_tenant = tenant_id or (
        str(opts.get("tenant_id")).strip() if opts.get("tenant_id") else None
    )
    eid = engagement_id or (
        str(opts.get("engagement_id")).strip() if opts.get("engagement_id") else None
    )
    if resolved_tenant and not opts.get("tenant_id"):
        opts["tenant_id"] = resolved_tenant
    if eid and not opts.get("engagement_id"):
        opts["engagement_id"] = eid
    attach_execution_mode_to_input(
        opts,
        opts,
        tenant_id=resolved_tenant,
        engagement_id=eid,
        scan_id=scan_id,
    )
    return opts


def _lab_tool_dispatch_allowed(
    tool_name: str,
    scan_options: dict[str, Any] | None,
    *,
    target: str = "",
    tenant_id: str | None = None,
) -> bool:
    """Gate tool dispatch for LAB phases via ``resolve_tool_policy_from_options``.

    Production always returns True (existing downstream gates unchanged).
    LAB + valid lease → True; outside boundary / missing lease → False.
    """
    opts = scan_options if isinstance(scan_options, dict) else {}
    mode = extract_execution_mode(opts)
    if mode is ExecutionMode.PRODUCTION:
        return True
    decision = resolve_tool_policy_from_options(
        tool_name,
        opts,
        target=target,
        tenant_id=tenant_id,
    )
    if decision.allowed and (decision.lab_lease_active or not decision.requires_approval):
        return True
    logger.info(
        "phase_tool_policy_denied",
        extra={
            "event": "phase_tool_policy_denied",
            "tool": tool_name,
            "reason": decision.reason,
            "deny_code": decision.deny_code,
            "lab_lease_active": decision.lab_lease_active,
        },
    )
    return False


_QUICK_RECON_STEPS = (
    "dig,dns_depth,whois,crtsh,nmap_port_scan,http_surface,security_headers"
)
_QUICK_PRIORITY_PORTS = "80,443,8080,8443,8000,3000"
_QUICK_TOOL_TO_RECON_STEP: dict[str, str] = {
    "nmap": "nmap_port_scan",
    "dig": "dig",
    "whois": "whois",
    "crtsh": "crtsh",
    "crt.sh": "crtsh",
    "httpx": "http_surface",
    "whatweb": "http_surface",
    "testssl": "security_headers",
    "shodan": "shodan",
    "subfinder": "subdomain_passive",
}


def _apply_quick_recon_constraints(
    options: dict[str, Any],
    *,
    target: str,
    scan_id: str | None,
) -> dict[str, Any]:
    """Cap recon to Quick discovery/fingerprint tasks instead of the full tool set."""
    opts = dict(options)
    opts["recon_mode"] = "active"
    opts["recon_deep_port_scan"] = False
    opts["recon_enable_content_discovery"] = False
    opts["recon_js_analysis"] = False
    opts["recon_screenshots"] = False
    if opts.get("ports") in (None, "", "1-1000", "1-65535"):
        opts["ports"] = _QUICK_PRIORITY_PORTS
    plan = resolve_quick_plan(scan_id=scan_id or "", target=target, options=opts)
    step_ids: list[str] = []
    breaker = default_circuit_breaker()
    if plan is not None:
        opts["quick_plan"] = plan.model_dump()
        for task in plan.tasks:
            if breaker.is_open(task.tool_id, task.target_ref):
                continue
            mapped = _QUICK_TOOL_TO_RECON_STEP.get(task.tool_id.strip().lower())
            if mapped and mapped not in step_ids:
                step_ids.append(mapped)
    opts["recon_tool_selection"] = ",".join(step_ids) if step_ids else _QUICK_RECON_STEPS
    return opts


_QUICK_VA_STAGES = frozenset(
    {
        QuickTaskStage.TEST.value,
        QuickTaskStage.VERIFY.value,
    }
)
_QUICK_VA_VULN_FLAGS = (
    "xss_enabled",
    "sqli_enabled",
    "ssrf_enabled",
    "lfi_enabled",
    "csrf_enabled",
    "rce_enabled",
    "idor_enabled",
)


def _apply_quick_va_constraints(
    options: dict[str, Any],
    *,
    target: str,
    scan_id: str | None,
) -> dict[str, Any]:
    """Force VA onto the Quick task set instead of the full active-scan stack."""
    opts = dict(options)
    opts["scan_mode"] = "quick"
    opts["execution_mode"] = "quick"
    vulns = dict(opts.get("vulnerabilities") or {}) if isinstance(opts.get("vulnerabilities"), dict) else {}
    for flag in _QUICK_VA_VULN_FLAGS:
        vulns[flag] = False
    opts["vulnerabilities"] = vulns
    plan = resolve_quick_plan(scan_id=scan_id or "", target=target, options=opts)
    if plan is None:
        return opts
    opts["quick_plan"] = plan.model_dump()
    workflow = QuickWorkflow.from_plan(plan)
    scheduler = QuickScheduler(workflow, plan_version=plan.plan_version)
    eligible = scheduler.eligible_tasks(
        scan_id=scan_id or "",
        completed_ids=set(),
        cancelled=bool(scan_id and is_scan_cancelled(scan_id)),
    )
    allowed = [
        task.tool_id
        for task in eligible
        if task.stage.value in _QUICK_VA_STAGES
    ]
    if not allowed:
        breaker = default_circuit_breaker()
        allowed = [
            task.tool_id
            for task in plan.tasks
            if task.stage.value in _QUICK_VA_STAGES
            and not breaker.is_open(task.tool_id, task.target_ref)
        ]
    opts["quick_allowed_tool_ids"] = allowed
    return opts


def _record_quick_circuit_outcomes(
    tool_results: dict[str, Any],
    *,
    target: str,
) -> None:
    breaker = default_circuit_breaker()
    step_to_tool = {step: tool for tool, step in _QUICK_TOOL_TO_RECON_STEP.items()}
    for name, result in tool_results.items():
        if not isinstance(result, dict):
            continue
        tool_id = step_to_tool.get(name, name)
        if result.get("success") is False:
            breaker.record_failure(tool_id, target)
        elif result.get("success") is True:
            breaker.record_success(tool_id, target)


def _stamped_lab_lease_active(scan_options: dict[str, Any] | None) -> bool:
    """Read collaborator stamp — True when attach recorded a usable LAB lease."""
    opts = scan_options if isinstance(scan_options, dict) else {}
    ctx = opts.get("execution_mode_context")
    return isinstance(ctx, dict) and bool(ctx.get("lab_lease_active"))


def _llm_execution_mode(scan_options: dict[str, Any] | None) -> str:
    """Mode string for ``call_llm_unified`` after phase attach (defaults production)."""
    opts = scan_options if isinstance(scan_options, dict) else {}
    ctx = opts.get("execution_mode_context")
    if isinstance(ctx, dict) and ctx.get("mode"):
        return str(ctx["mode"])
    return extract_execution_mode(opts).value


def _resolve_ip(domain: str) -> str | None:
    """Resolve domain to IP for Shodan lookup."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _safe_json(obj: Any, max_len: int = 30000) -> str:
    """Serialize object to JSON string, truncated to max_len."""
    try:
        text = json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(obj)
    if len(text) > max_len:
        text = text[:max_len] + "\n... [truncated]"
    return text


_HTTP_CRAWL_TIMEOUT = 10.0
_HTTP_CRAWL_MAX_REDIRECTS = 3
_HTTP_CRAWL_USER_AGENT = "ARGUS-Scanner/1.0 (recon; +https://github.com/argus)"
_MANIFEST_FETCH_MAX_BYTES = 256_000


def _truncate_query_values_for_log(url: str, max_value_len: int = 80) -> str:
    """Redact long query values in a URL for structured logs (secrets in query strings)."""
    t = (url or "").strip()
    if not t or max_value_len < 8:
        return t[:500]
    parsed = urlparse(t)
    if not parsed.query:
        return t[:500]
    pairs: list[tuple[str, str]] = []
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        if len(v) > max_value_len:
            v = v[: max_value_len - 3] + "..."
        pairs.append((k, v))
    new_query = urlencode(pairs)
    rebuilt = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment),
    )
    return rebuilt[:500]


def _log_va_url_surface_extracted(
    target: str,
    params: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    endpoints: list[dict[str, Any]] | None = None,
    routes: list[dict[str, Any]] | None = None,
) -> None:
    logger.info(
        "va_url_surface_extracted",
        extra={
            "event": "va_url_surface_extracted",
            "extracted_url_params_count": len(params),
            "extracted_forms_count": len(forms),
            "extracted_endpoint_count": len(endpoints or []),
            "extracted_route_count": len(routes or []),
            "target": _truncate_query_values_for_log(target, 80),
        },
    )


class _FormHTMLParser(HTMLParser):
    """Lightweight stdlib parser that extracts <form> elements and their <input> fields."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": (attr_map.get("method", "GET")).upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            input_name = attr_map.get("name", "")
            if input_name:
                self._current_form["inputs"].append({
                    "name": input_name,
                    "type": attr_map.get("type", "text"),
                    "value": attr_map.get("value", ""),
                })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _extract_url_query_params(target: str) -> list[dict[str, Any]]:
    """Extract query parameters from a target URL string (no network call)."""
    parsed = urlparse(target)
    if not parsed.query:
        return []

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else target.split("?")[0]
    params_inventory: list[dict[str, Any]] = []
    for param_name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        params_inventory.append({
            "url": base_url,
            "param": param_name,
            "value": values[0] if values else "",
            "method": "GET",
        })
    return params_inventory


def _live_host_row_for_target(target: str) -> dict[str, str]:
    """Single live_hosts row with normalized hostname (full URL in `host` breaks active-scan scope)."""
    t = (target or "").strip()
    if not t:
        return {"host": ""}
    parsed = urlparse(t)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        return {"host": parsed.hostname.strip().lower()}
    host_part = t.split("/")[0].split("?")[0].strip().lower()
    return {"host": host_part}


def _parse_forms_from_html(html: str, page_url: str) -> list[dict[str, Any]]:
    """Parse HTML string and return forms_inventory rows (one per input)."""
    parser = _FormHTMLParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        logger.debug("html_form_parse_error", extra={"page_url": page_url})
        return []

    forms_inventory: list[dict[str, Any]] = []
    for form in parser.forms:
        action_raw = form.get("action", "")
        action = urljoin(page_url, action_raw) if action_raw else page_url
        method = form.get("method", "GET")
        inputs: list[dict[str, Any]] = form.get("inputs", [])
        if not inputs:
            continue
        for inp in inputs:
            forms_inventory.append({
                "page_url": page_url,
                "action": action,
                "method": method,
                "input_name": inp["name"],
                "input_type": inp.get("type", "text"),
            })
    return forms_inventory


def _auth_profile_from_scan_options(scan_options: dict[str, Any] | None) -> dict[str, Any]:
    """Sanitize optional authenticated scan profile/test credentials for surface planning.

    Secret values are intentionally not returned; only presence and field names are kept.
    """
    if not isinstance(scan_options, dict):
        return {"enabled": False}
    raw = (
        scan_options.get("authenticated_scan_profile")
        or scan_options.get("auth_profile")
        or scan_options.get("auth")
        or scan_options.get("test_credentials")
    )
    if raw is True:
        return {"enabled": True}
    if not isinstance(raw, dict):
        if scan_options.get("authenticated") is True:
            return {"enabled": True}
        return {"enabled": False}
    username_field = str(
        raw.get("username_field")
        or raw.get("user_field")
        or raw.get("login_field")
        or "username"
    ).strip()[:80]
    password_field = str(raw.get("password_field") or "password").strip()[:80]
    headers = raw.get("headers")
    cookies = raw.get("cookies")
    return {
        "enabled": bool(raw.get("enabled", True)),
        "login_url": str(raw.get("login_url") or raw.get("url") or "").strip()[:2048],
        "username_field": username_field or "username",
        "password_field": password_field or "password",
        "username_present": bool(raw.get("username") or raw.get("email")),
        "password_present": bool(raw.get("password")),
        "headers_present": sorted(str(k)[:80] for k in headers) if isinstance(headers, dict) else [],
        "cookies_present": sorted(str(k)[:80] for k in cookies) if isinstance(cookies, dict) else [],
    }


def _add_auth_profile_login_endpoint(
    endpoint_inventory: list[dict[str, Any]],
    *,
    target: str,
    auth_profile: dict[str, Any],
) -> None:
    if not auth_profile.get("enabled"):
        return
    login_url = str(auth_profile.get("login_url") or "").strip()
    if login_url:
        absolute = urljoin(target, login_url)
    else:
        return
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return
    fields = [
        str(auth_profile.get("username_field") or "username").strip() or "username",
        str(auth_profile.get("password_field") or "password").strip() or "password",
    ]
    row = {
        "url": urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, "")),
        "method": "POST",
        "content_type": "application/json",
        "json_fields": list(dict.fromkeys(fields)),
        "query_params": [],
        "path_params": [],
        "source": "authenticated_scan_profile",
        "evidence_ref": "scan_options:authenticated_scan_profile",
        "confidence": "medium",
        "confirmed": bool(auth_profile.get("username_present") and auth_profile.get("password_present")),
        "auth_context": "anonymous",
    }
    key = (row["url"], row["method"], tuple(row["json_fields"]))
    existing = {
        (str(r.get("url") or ""), str(r.get("method") or ""), tuple(r.get("json_fields") or []))
        for r in endpoint_inventory
        if isinstance(r, dict)
    }
    if key not in existing:
        endpoint_inventory.append(row)


def _dedupe_dict_rows(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = tuple(str(row.get(k) or "") for k in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


_RECON_HTTP_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.IGNORECASE)
_RECON_API_PATH_RE = re.compile(
    r"(?P<path>/(?:api|trpc|graphql|rpc|auth|login|signin|admin|user|users|account|"
    r"orders?|products?|search|profile|session|cart|checkout|upload|webhook)"
    r"[A-Za-z0-9_./{}:?=&%+\-]*)",
    re.IGNORECASE,
)
_RECON_JS_KEY_HINTS = (
    "js",
    "javascript",
    "bundle",
    "linkfinder",
    "script",
    "next",
)
_RECON_URL_KEY_HINTS = (
    "url",
    "urls",
    "stdout",
    "endpoint",
    "route",
    "path",
    "katana",
    "gau",
    "wayback",
    "history",
    "crawl",
    "js_analysis",
)


def _normalize_scan_mode_for_va(scan_options: dict[str, Any] | None) -> str:
    """Single depth selector for VA; top-level scan_mode wins over legacy scanType."""
    opts = scan_options or {}
    if is_quick_execution(opts):
        return "quick"
    raw = opts.get("scan_mode") or opts.get("scanType") or "standard"
    mode = str(raw or "standard").strip().lower()
    aliases = {
        "light": "standard",
        "normal": "standard",
        "aggressive": "deep",
        "maximum": "deep",
        "lab": "deep",
    }
    mode = aliases.get(mode, mode)
    return mode if mode in {"quick", "standard", "deep"} else "standard"


def _same_origin_or_path(target: str, candidate: str) -> bool:
    parsed_target = urlparse(target)
    cand = str(candidate or "").strip()
    if not cand:
        return False
    if cand.startswith("/"):
        return True
    parsed = urlparse(cand)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    return parsed.hostname.lower() == (parsed_target.hostname or "").lower()


def _collect_recon_surface_artifacts(
    recon_context: Any,
    *,
    target: str,
    max_urls: int = 1000,
    max_scripts: int = 40,
) -> tuple[list[str], dict[str, str]]:
    """Extract URL/API/script hints from recon tool results for active scan targeting."""
    discovered_urls: list[str] = []
    script_bodies: dict[str, str] = {}
    seen_urls: set[str] = set()

    def add_url(raw: str) -> None:
        if len(discovered_urls) >= max_urls:
            return
        value = str(raw or "").strip().strip(".,;)")
        if not value or not _same_origin_or_path(target, value):
            return
        if value in seen_urls:
            return
        seen_urls.add(value)
        discovered_urls.append(value)

    def add_text(label: str, text: str) -> None:
        if not text:
            return
        key_low = label.lower()
        if not any(h in key_low for h in _RECON_URL_KEY_HINTS + _RECON_JS_KEY_HINTS):
            return
        clipped = text[:1_500_000]
        for m in _RECON_HTTP_URL_RE.finditer(clipped):
            add_url(m.group(0))
        for m in _RECON_API_PATH_RE.finditer(clipped):
            add_url(m.group("path"))
        if (
            len(script_bodies) < max_scripts
            and any(h in key_low for h in _RECON_JS_KEY_HINTS)
            and any(token in clipped for token in ("fetch(", "axios.", "XMLHttpRequest", "/api/", "__NEXT_DATA__"))
        ):
            script_bodies[f"recon:{label[:120]}:{len(script_bodies)}"] = clipped

    def walk(obj: Any, path: str = "recon") -> None:
        if len(discovered_urls) >= max_urls and len(script_bodies) >= max_scripts:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                walk(value, f"{path}.{key}")
            return
        if isinstance(obj, (list, tuple, set)):
            for idx, value in enumerate(list(obj)[:2000]):
                walk(value, f"{path}[{idx}]")
            return
        if isinstance(obj, str):
            add_text(path, obj)

    walk(recon_context)
    return discovered_urls, script_bodies


async def _extract_url_params_forms_and_spa_surfaces(
    target: str,
    scan_options: dict[str, Any] | None = None,
    *,
    discovered_urls: list[str] | None = None,
    recon_script_bodies: dict[str, str] | None = None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Extract URL, form, SPA/API and endpoint inventories for active scan targeting.

    Returns params, forms, endpoint_inventory, route_inventory, api_surface, js_findings.
    """
    legacy_extractor = globals().get("_extract_url_params_and_forms")
    baseline_legacy = globals().get("_LEGACY_URL_PARAMS_FORMS_EXTRACTOR")
    if (
        baseline_legacy is not None
        and legacy_extractor is not None
        and legacy_extractor is not baseline_legacy
    ):
        params, forms = await legacy_extractor(target)  # type: ignore[misc]
        return params, forms, [], [], [], []

    params_inventory = _extract_url_query_params(target)

    forms_inventory: list[dict[str, Any]] = []
    endpoint_inventory: list[dict[str, Any]] = []
    route_inventory: list[dict[str, Any]] = []
    api_surface: list[dict[str, Any]] = []
    js_findings: list[dict[str, Any]] = []
    script_bodies: dict[str, str] = dict(recon_script_bodies or {})
    seed_discovered_urls = [str(u) for u in (discovered_urls or []) if str(u).strip()][:1000]
    auth_profile = _auth_profile_from_scan_options(scan_options)

    parsed = urlparse(target)
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        logger.info("http_crawl_skipped", extra={"reason": "non_http_scheme"})
        _log_va_url_surface_extracted(
            target,
            params_inventory,
            forms_inventory,
            endpoint_inventory,
            route_inventory,
        )
        return params_inventory, forms_inventory, endpoint_inventory, route_inventory, api_surface, js_findings

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(_HTTP_CRAWL_TIMEOUT),
            max_redirects=_HTTP_CRAWL_MAX_REDIRECTS,
            follow_redirects=True,
            verify=False,
        ) as client:
            response = await client.get(
                target,
                headers={"User-Agent": _HTTP_CRAWL_USER_AGENT},
            )
        content_type = response.headers.get("content-type", "")
        if "html" not in content_type.lower():
            logger.info("http_crawl_no_html", extra={"content_type": content_type})
            surfaces = extract_spa_api_surfaces(
                str(response.url),
                html_text="",
                script_bodies=script_bodies,
                discovered_urls=seed_discovered_urls,
                auth_profile=auth_profile,
            )
            endpoint_inventory = list(surfaces.endpoint_inventory)
            _add_auth_profile_login_endpoint(
                endpoint_inventory,
                target=str(response.url),
                auth_profile=auth_profile,
            )
            route_inventory = list(surfaces.route_inventory)
            api_surface = list(surfaces.api_surface)
            js_findings = list(surfaces.js_findings)
            _log_va_url_surface_extracted(
                target,
                params_inventory,
                forms_inventory,
                endpoint_inventory,
                route_inventory,
            )
            return params_inventory, forms_inventory, endpoint_inventory, route_inventory, api_surface, js_findings

        body = response.text[:500_000]
        forms_inventory = _parse_forms_from_html(body, str(response.url))

        script_urls = extract_script_urls_from_html(str(response.url), body, max_scripts=12)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(_HTTP_CRAWL_TIMEOUT),
            max_redirects=_HTTP_CRAWL_MAX_REDIRECTS,
            follow_redirects=True,
            verify=False,
        ) as script_client:
            for script_url in script_urls[:12]:
                try:
                    sr = await script_client.get(
                        script_url,
                        headers={"User-Agent": _HTTP_CRAWL_USER_AGENT},
                    )
                except httpx.HTTPError:
                    continue
                ctype = sr.headers.get("content-type", "").lower()
                if sr.status_code >= 400 or ("javascript" not in ctype and not script_url.lower().endswith(".js")):
                    continue
                script_bodies[script_url] = sr.text[:1_000_000]

        surfaces = extract_spa_api_surfaces(
            str(response.url),
            html_text=body,
            script_bodies=script_bodies,
            discovered_urls=seed_discovered_urls,
            auth_profile=auth_profile,
        )
        endpoint_inventory = list(surfaces.endpoint_inventory)
        _add_auth_profile_login_endpoint(
            endpoint_inventory,
            target=str(response.url),
            auth_profile=auth_profile,
        )
        route_inventory = list(surfaces.route_inventory)
        api_surface = list(surfaces.api_surface)
        js_findings = list(surfaces.js_findings)

        page_params = _extract_url_query_params(str(response.url))
        existing_keys = {(p["url"], p["param"]) for p in params_inventory}
        for pp in page_params:
            if (pp["url"], pp["param"]) not in existing_keys:
                params_inventory.append(pp)

    except httpx.TooManyRedirects:
        logger.warning(
            "http_crawl_too_many_redirects",
            extra={"target": _truncate_query_values_for_log(target, 80)},
        )
    except httpx.TimeoutException:
        logger.warning(
            "http_crawl_timeout",
            extra={"target": _truncate_query_values_for_log(target, 80)},
        )
    except httpx.HTTPError as exc:
        logger.warning(
            "http_crawl_error",
            extra={
                "target": _truncate_query_values_for_log(target, 80),
                "exc_type": type(exc).__name__,
            },
        )
    except Exception:
        logger.warning(
            "http_crawl_unexpected_error",
            extra={"target": _truncate_query_values_for_log(target, 80)},
            exc_info=True,
        )

    if not endpoint_inventory and (script_bodies or seed_discovered_urls):
        surfaces = extract_spa_api_surfaces(
            target,
            html_text="",
            script_bodies=script_bodies,
            discovered_urls=seed_discovered_urls,
            auth_profile=auth_profile,
        )
        endpoint_inventory = list(surfaces.endpoint_inventory)
        _add_auth_profile_login_endpoint(
            endpoint_inventory,
            target=target,
            auth_profile=auth_profile,
        )
        route_inventory = list(surfaces.route_inventory)
        api_surface = list(surfaces.api_surface)
        js_findings = list(surfaces.js_findings)

    logger.info(
        "http_crawl_complete",
        extra={
            "params_count": len(params_inventory),
            "forms_count": len(forms_inventory),
            "endpoint_count": len(endpoint_inventory),
            "route_count": len(route_inventory),
            "js_bundle_count": len(script_bodies),
        },
    )
    _log_va_url_surface_extracted(
        target,
        params_inventory,
        forms_inventory,
        endpoint_inventory,
        route_inventory,
    )
    return (
        params_inventory,
        forms_inventory,
        _dedupe_dict_rows(endpoint_inventory, ("url", "method", "source")),
        _dedupe_dict_rows(route_inventory, ("url", "source")),
        _dedupe_dict_rows(api_surface, ("endpoint", "method", "source")),
        _dedupe_dict_rows(js_findings, ("url", "method", "source")),
    )


async def _extract_url_params_and_forms(
    target: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Backward-compatible helper kept for older tests and callers."""
    params, forms, _endpoints, _routes, _api, _js = await _extract_url_params_forms_and_spa_surfaces(target)
    return params, forms


_LEGACY_URL_PARAMS_FORMS_EXTRACTOR = _extract_url_params_and_forms


async def _try_fetch_and_upload_dependency_manifests(target: str, sink: RawPhaseSink) -> None:
    """Best-effort fetch of /requirements.txt and /package.json into recon raw artifacts (KAL-006 / Trivy)."""
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return
    base_root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
    specs: tuple[tuple[str, str, str], ...] = (
        ("/requirements.txt", "dependency_requirements_txt", "txt"),
        ("/package.json", "dependency_package_json", "json"),
    )
    for path, artifact_type, ext in specs:
        url = urljoin(base_root, path)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(8.0),
                max_redirects=_HTTP_CRAWL_MAX_REDIRECTS,
                follow_redirects=True,
                verify=False,
            ) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": _HTTP_CRAWL_USER_AGENT},
                )
        except Exception:  # noqa: BLE001
            logger.debug(
                "dependency_manifest_fetch_failed",
                extra={"reason": "http_error", "manifest": artifact_type},
            )
            continue
        if response.status_code != 200:
            continue
        body = response.content
        if not body or len(body) > _MANIFEST_FETCH_MAX_BYTES:
            continue
        if path.endswith("package.json"):
            head = body[:12_000]
            if not body.lstrip().startswith(b"{") or (
                b"dependencies" not in head and b'"name"' not in head
            ):
                continue
        else:
            if not any(
                line.strip() and not line.lstrip().startswith(b"#")
                for line in body.splitlines()[:30]
            ):
                continue
        try:
            await asyncio.to_thread(sink.upload_bytes, artifact_type, ext, body)
            logger.info(
                "dependency_manifest_uploaded",
                extra={"artifact_type": artifact_type, "bytes": len(body)},
            )
        except Exception:
            logger.warning(
                "dependency_manifest_upload_failed",
                extra={"artifact_type": artifact_type},
                exc_info=True,
            )


async def _upload_recon_tool_streams(sink: RawPhaseSink, tool_results: dict[str, Any]) -> None:
    """Persist per-tool stdout/stderr as raw recon artifacts (best-effort)."""
    for name, result in tool_results.items():
        if name == "recon_pipeline_summary":
            continue
        if not isinstance(result, dict):
            continue
        stdout = result.get("stdout")
        stderr = result.get("stderr")
        # Persist any captured bytes (including whitespace-only) when the subprocess wrote a stream.
        if isinstance(stdout, str) and len(stdout) > 0:
            await asyncio.to_thread(sink.upload_text, f"tool_{name}_stdout", stdout)
        if isinstance(stderr, str) and len(stderr) > 0:
            await asyncio.to_thread(sink.upload_text, f"tool_{name}_stderr", stderr)


def _format_tool_results(results: dict[str, Any]) -> str:
    """Format tool results dict into a readable string for LLM."""
    parts: list[str] = []
    for tool_name, result in results.items():
        if tool_name == "recon_pipeline_summary":
            continue
        parts.append(f"--- {tool_name.upper()} ---")
        if tool_name == "kal_dns_intel" and isinstance(result, list):
            parts.append(_safe_json({"kal_dns_intel": result}, 12000))
            parts.append("")
            continue
        if tool_name == "http_probe_tech_stack" and isinstance(result, dict):
            parts.append(_safe_json({"http_probe_tech_stack": result}, 12000))
            parts.append("")
            continue
        if tool_name == "security_headers" and isinstance(result, dict):
            parts.append(_safe_json(result, 12000))
            parts.append("")
            continue
        if tool_name == "deep_port_scan" and isinstance(result, dict):
            parts.append(_safe_json(result.get("structured") or {}, 12000))
            parts.append("")
            continue
        if tool_name == "recon_open_ports_merged" and isinstance(result, dict):
            parts.append(str(result.get("stdout") or "")[:8000])
            parts.append("")
            continue
        if isinstance(result, dict):
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            if stdout:
                parts.append(stdout[:15000])
            structured = result.get("structured")
            if tool_name == "nmap" and isinstance(structured, dict) and structured.get("mode") == "sandbox_cycle":
                parts.append(_safe_json(structured, 12000))
            if stderr and not result.get("success", True):
                parts.append(f"[stderr] {stderr[:2000]}")
        elif isinstance(result, str):
            parts.append(result[:15000])
        else:
            parts.append(_safe_json(result, 15000))
        parts.append("")
    return "\n".join(parts)


def _log_recon_tool_done(tool: str, cmd: str, result: dict[str, Any]) -> None:
    """Log tool completion without target or full argv (argv count + exit metadata only)."""
    try:
        argv_count = len(shlex.split(cmd))
    except ValueError:
        argv_count = -1
    logger.info(
        "recon_tool_finished",
        extra={
            "tool": tool,
            "argv_count": argv_count,
            "return_code": result.get("return_code"),
            "success": result.get("success"),
        },
    )


async def _run_nmap(
    target: str,
    ports: str = "1-1000",
    *,
    options: dict | None = None,
    raw_sink: RawPhaseSink | None = None,
) -> dict[str, Any]:
    """Run nmap: multi-phase sandbox cycle (KAL-003) or legacy single -sV -sC scan."""
    from src.recon.nmap_recon_cycle import run_nmap_recon_for_recon

    result = await run_nmap_recon_for_recon(
        target,
        ports_option=ports,
        scan_options=dict(options or {}),
        raw_sink=raw_sink,
        execute_command=execute_command,
    )
    mode = (result.get("structured") or {}).get("mode")
    cmd_log = "nmap_sandbox_cycle" if mode == "sandbox_cycle" else "nmap_legacy_single"
    _log_recon_tool_done("nmap", cmd_log, result)
    return result


async def _run_dig(domain: str) -> dict[str, Any]:
    """Run dig for DNS records."""
    cmd = f"dig {domain} ANY +noall +answer"
    result = execute_command(cmd, use_sandbox=False)
    _log_recon_tool_done("dig", cmd, result)
    return result


async def _run_whois(domain: str) -> dict[str, Any]:
    """Run whois lookup."""
    cmd = f"whois {domain}"
    result = execute_command(cmd, use_sandbox=False)
    _log_recon_tool_done("whois", cmd, result)
    return result


async def _query_crtsh(domain: str, *, raw_sink: RawPhaseSink | None = None) -> dict[str, Any]:
    """Query crt.sh JSON API for certificate transparency hostnames; optional raw JSON to MinIO."""
    try:
        client = CrtShClient()
        timeout_sec = float(max(5, int(getattr(settings, "recon_tools_timeout", 300) or 300)))
        data = await client.query(params={"q": f"%.{domain}"}, timeout_sec=timeout_sec)
        results = data.get("results", [])
        if raw_sink is not None and isinstance(results, list) and results:
            try:
                await asyncio.to_thread(raw_sink.upload_json, "crtsh_api", results)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "crtsh_raw_upload_failed",
                    extra={"event": "crtsh_raw_upload_failed"},
                )
        subdomains: set[str] = set()
        for entry in results if isinstance(results, list) else []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name_value", "")
            for line in str(name).split("\n"):
                line = line.strip().lstrip("*.")
                if line and "." in line:
                    subdomains.add(line)
        cap = max(1, int(getattr(settings, "recon_max_subdomains", 10000)))
        sorted_subs = sorted(subdomains)[:cap]
        return {"success": True, "stdout": json.dumps(sorted_subs)}
    except Exception:  # noqa: BLE001
        logger.warning("crtsh_query_failed", extra={"event": "crtsh_query_failed"})
        return {"success": False, "stdout": "", "stderr": "crt.sh query failed"}


async def _query_shodan(target: str) -> dict[str, Any]:
    """Query Shodan for host information."""
    client = ShodanClient()
    if not client.is_available():
        return {"success": False, "stdout": "", "stderr": "Shodan API key not configured"}

    ip = target if _is_ip(target) else _resolve_ip(target)
    if not ip:
        return {"success": False, "stdout": "", "stderr": f"Cannot resolve {target} to IP"}

    try:
        data = await client.query(endpoint=f"shodan/host/{ip}")
        return {"success": True, "stdout": _safe_json(data, 15000)}
    except Exception:
        logger.exception("Shodan query failed")
        return {"success": False, "stdout": "", "stderr": "Shodan query failed"}


async def run_source_analysis(
    target: str,
    options: dict,
    *,
    tenant_id: str | None = None,
    scan_id: str | None = None,
) -> SourceAnalysisOutput:
    from src.orchestration.source_analysis.analyzer import SourceAnalyzer

    options = _attach_phase_execution_mode(
        options if isinstance(options, dict) else {},
        tenant_id=tenant_id,
        scan_id=scan_id,
    )
    sa_input = SourceAnalysisInput(
        target=target,
        repo_path=options.get("repo_path"),
        repo_url=options.get("repo_url"),
        options=options,
    )
    analyzer = SourceAnalyzer(sa_input)
    try:
        result = await analyzer.analyze()
        return result
    except Exception as exc:  # noqa: BLE001
        logger.warning("source_analysis handler failed: %s", exc)
        return SourceAnalysisOutput(skipped=True, summary=f"Source analysis failed: {exc}")


async def run_recon(
    target: str,
    options: dict,
    *,
    tenant_id: str | None = None,
    scan_id: str | None = None,
    source_analysis: Any | None = None,
) -> ReconOutput:
    """
    Production recon: nmap + dig + whois + crt.sh + Shodan -> LLM analysis.
    Runs tools in parallel, collects results, feeds to LLM for structured output.
    When tenant_id and scan_id are set, raw tool streams and LLM responses are uploaded to MinIO.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    options = _attach_phase_execution_mode(
        options if isinstance(options, dict) else {},
        tenant_id=tenant_id,
        scan_id=scan_id,
    )
    if is_quick_execution(options):
        if scan_id and is_scan_cancelled(scan_id):
            return ReconOutput(assets=[target] if target else [])
        options = _apply_quick_recon_constraints(
            options, target=target, scan_id=scan_id
        )
    ports = options.get("ports", "1-1000")
    recon_cfg = build_recon_runtime_config(options)
    planned_steps = frozenset(plan_recon_steps(recon_cfg))

    raw_sink: RawPhaseSink | None = None
    if tenant_id and scan_id:
        raw_sink = RawPhaseSink(tenant_id, scan_id, "recon")

    tool_results, crawl_params, crawl_forms = await run_recon_planned_tool_gather(
        target,
        domain,
        ports,
        options,
        recon_cfg,
        raw_sink=raw_sink,
        tenant_id=tenant_id,
        scan_id=scan_id,
    )

    if crawl_params or crawl_forms:
        tool_results["http_crawl"] = {
            "success": True,
            "stdout": _safe_json(
                {"params_inventory": crawl_params, "forms_inventory": crawl_forms},
                15000,
            ),
        }

    tool_results["recon_pipeline_summary"] = build_recon_summary_document(tool_results, target=target)

    tool_results_str = _format_tool_results(tool_results)
    logger.info("Recon tool results collected (%d chars), sending to LLM", len(tool_results_str))

    if raw_sink is not None:
        try:
            await asyncio.to_thread(
                raw_sink.upload_recon_summary_stable,
                tool_results.get("recon_pipeline_summary") or {},
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "recon_summary_stable_upload_failed",
                extra={"event": "recon_summary_stable_upload_failed"},
            )
        await _upload_recon_tool_streams(raw_sink, tool_results)
        await asyncio.to_thread(raw_sink.upload_text, "tool_results_llm_context", tool_results_str)
        if ReconStepId.DEPENDENCY_MANIFESTS in planned_steps:
            await _try_fetch_and_upload_dependency_manifests(target, raw_sink)

    inp = ReconInput(target=target, options=options, source_analysis=source_analysis)
    recon_out = await ai_recon(
        inp,
        tool_results=tool_results_str,
        raw_sink=raw_sink,
        scan_id=scan_id,
    )
    recon_out.tool_results = tool_results
    recon_out.crawl_params = crawl_params
    recon_out.crawl_forms = crawl_forms
    if is_quick_execution(options):
        _record_quick_circuit_outcomes(tool_results, target=target)
    recon_out.coverage_results = attach_phase_coverage(
        phase="recon",
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=target,
        signals=signals_from_tool_results(tool_results, phase="recon"),
        scan_options=options,
    )
    return recon_out


async def _query_nvd_for_technologies(assets: list[str]) -> str:
    """Query NVD for CVEs related to technologies found in assets + detected component versions."""
    client = NVDClient()
    all_cves: list[dict[str, Any]] = []
    keywords_seen: set[str] = set()

    for asset in assets[:10]:
        parts = asset.lower().split()
        for keyword in parts:
            if len(keyword) < 3 or keyword in keywords_seen:
                continue
            if keyword in ("tcp", "udp", "open", "port", "http", "https", "the", "and", "for"):
                continue
            keywords_seen.add(keyword)

    tech_keywords = {
        "nginx", "apache", "cloudflare", "wordpress", "joomla", "drupal",
        "bootstrap", "jquery", "react", "vue", "angular", "laravel",
        "django", "flask", "express", "spring", "tomcat", "iis",
        "php", "python", "ruby", "node", "mysql", "postgresql", "mariadb",
        "redis", "mongodb", "elasticsearch", "memcached",
    }
    keyword_priority = sorted(
        tech_keywords & keywords_seen,
        key=lambda k: (1 if k == "wordpress" else 2, k),
    )
    for kw in keyword_priority[:5]:
        if kw not in keywords_seen:
            keywords_seen.add(kw)
            break

    for keyword in list(keywords_seen)[:8]:
        try:
            data = await client.query(
                params={"keywordSearch": keyword, "resultsPerPage": 10}
            )
            vulns = data.get("vulnerabilities", [])
            for v in vulns[:8]:
                cve_item = v.get("cve", {})
                cve_id = cve_item.get("id", "")
                descriptions = cve_item.get("descriptions", [])
                desc = next(
                    (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                    "",
                )
                metrics = cve_item.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])
                base_score = (
                    cvss_data[0].get("cvssData", {}).get("baseScore", 0.0)
                    if cvss_data
                    else 0.0
                )
                all_cves.append({
                    "cve_id": cve_id,
                    "description": desc[:500],
                    "base_score": base_score,
                    "keyword": keyword,
                })
        except Exception:  # noqa: BLE001
            logger.warning("NVD query for '%s' failed", keyword)

    return _safe_json(all_cves, 40000) if all_cves else "No CVE data available"


def _recon_seed_urls(recon_output: dict[str, Any] | None) -> list[str]:
    """Extract http(s) endpoint URLs discovered by recon for quick-fuzz seeding.

    Scans recon output ``assets`` / ``endpoints`` / ``urls`` (whichever are
    present) for http(s) URLs, order-preserving + de-duplicated. Returns [] when
    recon produced nothing usable (the fuzzer still probes ``target``).
    """
    if not isinstance(recon_output, dict):
        return []
    seen: set[str] = set()
    out: list[str] = []

    def _add(value: Any) -> None:
        if isinstance(value, str):
            url = value.strip()
            if url.lower().startswith(("http://", "https://")) and url not in seen:
                seen.add(url)
                out.append(url)
        elif isinstance(value, dict):
            for key in ("url", "endpoint", "location", "target"):
                if key in value:
                    _add(value[key])

    for key in ("assets", "endpoints", "urls", "entry_points", "api_endpoints"):
        items = recon_output.get(key)
        if isinstance(items, (list, tuple)):
            for item in items:
                _add(item)
    return out


async def run_quick_fuzz(
    target: str,
    *,
    recon_output: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
    tenant_id: str | None = None,
    scan_id: str | None = None,
) -> QuickFuzzOutput:
    """Run quick pre-scan fuzzing between RECON and THREAT_MODELING.

    Uses discovered endpoints from recon to send targeted payloads
    and identify quick-win vulnerabilities.  Produces candidate
    endpoint/parameter pairs that feed into VULN_ANALYSIS for deep
    testing with heavy tools.
    """
    options = options or {}
    options = _attach_phase_execution_mode(
        options,
        tenant_id=tenant_id,
        scan_id=scan_id,
    )
    categories = options.get("quick_fuzz_categories")
    custom_wordlist = options.get("quick_fuzz_wordlist_path")
    if "quick_fuzz_delay" in options:
        delay = float(options["quick_fuzz_delay"])
    elif _stamped_lab_lease_active(options):
        delay = 0.0
    else:
        delay = 0.3

    # Feed recon-discovered endpoint URLs into the fuzzer so quick_fuzz probes
    # the discovered attack surface, not just the root target (chain link G1).
    seed_urls = _recon_seed_urls(recon_output)

    try:
        from src.recon.quick_fuzz.quick_fuzzer import run_quick_fuzz as _run_qf
        fuzz_categories = tuple(categories) if categories else None
        result = await _run_qf(
            target,
            categories=fuzz_categories,
            custom_wordlist_path=custom_wordlist,
            delay=delay,
            seed_urls=seed_urls,
        )
    except Exception as qf_exc:  # noqa: BLE001
        logger.warning("quick_fuzz_failed: %s", qf_exc, extra={"scan_id": scan_id})
        result = {"findings": [], "fuzz_results": [], "candidates": []}

    findings = result.get("findings", [])
    fuzz_results = result.get("fuzz_results", [])
    candidates = result.get("candidates", [])

    tech_stack: dict[str, Any] = {}
    baseline_responses: dict[str, Any] = {}
    if recon_output and isinstance(recon_output, dict):
        tech_stack = recon_output.get("tech_stack", recon_output.get("technologies", {}))
        baseline_responses = recon_output.get("baseline_responses", {})

    return QuickFuzzOutput(
        findings=findings,
        fuzz_results=fuzz_results,
        candidates=candidates,
        tech_stack=tech_stack,
        baseline_responses=baseline_responses,
    )


async def run_threat_modeling(
    assets: list[str],
    *,
    subdomains: list[str] | None = None,
    ports: list[int] | None = None,
    target: str = "",
    recon_summary: dict[str, Any] | None = None,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
    source_analysis: Any | None = None,
    quick_fuzz_findings: list[dict[str, Any]] | None = None,
) -> ThreatModelOutput:
    """Production threat modeling: enriched recon context + NVD CVE lookup + LLM STRIDE analysis."""
    from src.orchestration.threat_model_enrichment import (
        build_recon_context,
        format_recon_context_for_prompt,
        merge_threat_model_result_into_output,
        parse_threat_model_result,
    )

    scan_options = _attach_phase_execution_mode(
        scan_options if isinstance(scan_options, dict) else {},
        tenant_id=tenant_id,
        scan_id=scan_id,
    )

    recon_ctx = build_recon_context(
        assets=assets,
        subdomains=subdomains,
        ports=ports,
        target=target,
        recon_summary=recon_summary,
    )
    recon_context_str = format_recon_context_for_prompt(recon_ctx)
    if quick_fuzz_findings:
        try:
            _qf_lines = []
            for _qff in quick_fuzz_findings[:20]:
                _qf_lines.append(
                    f"- [{_qff.get('severity', 'medium').upper()}] {_qff.get('title', 'unknown')}"
                    f" (category: {_qff.get('category', 'unknown')})"
                )
            recon_context_str += (
                "\n\n[Quick Fuzz Pre-Scan Findings]:\n"
                + "\n".join(_qf_lines)
            )
        except Exception:  # noqa: BLE001, S110
            pass
    logger.info(
        "threat_model_recon_context_built",
        extra={
            "event": "threat_model_recon_context_built",
            "technologies_count": len(recon_ctx.get("technologies", [])),
            "ports_count": len(recon_ctx.get("open_ports", [])),
            "endpoints_count": len(recon_ctx.get("endpoints", [])),
            "entry_points_count": len(recon_ctx.get("entry_points", [])),
        },
    )

    nvd_data = await _query_nvd_for_technologies(assets)
    logger.info("NVD data collected (%d chars), sending to LLM for threat modeling", len(nvd_data))

    inp = ThreatModelInput(assets=assets, source_analysis=source_analysis)
    raw_output = await ai_threat_modeling(
        inp,
        nvd_data=nvd_data,
        recon_context=recon_context_str,
        scan_id=scan_id,
        scan_options=scan_options,
    )

    parsed = parse_threat_model_result(raw_output.threat_model)
    if parsed.threats or parsed.attack_surface or parsed.cves:
        merged = merge_threat_model_result_into_output(
            {"threat_model": raw_output.threat_model}, parsed
        )
        raw_output = ThreatModelOutput(threat_model=merged["threat_model"])
        logger.info(
            "threat_model_enriched",
            extra={
                "event": "threat_model_enriched",
                "threats_count": len(parsed.threats),
                "attack_surface_count": len(parsed.attack_surface),
                "cves_count": len(parsed.cves),
                "mitigations_count": len(parsed.mitigations),
            },
        )

    return raw_output


# CVSS v3.1 defaults / floors for confirmed vulnerabilities by type.
_CVSS_DEFAULTS: dict[str, float] = {
    "xss": 7.2,
    "sqli": 9.8,
    "sql_injection": 9.8,
    "rce": 9.8,
    "ssrf": 8.6,
    "lfi": 8.6,
    "rfi": 9.0,
    "open_redirect": 4.7,
}
_MIN_CONFIRMED_XSS_CVSS = 7.0
_MIN_CONFIRMED_ACTIVE_CVSS = 7.0

_CWE_MAP: dict[str, str] = {
    "xss": "CWE-79",
    "sqli": "CWE-89",
    "sql_injection": "CWE-89",
    "rce": "CWE-78",
    "ssrf": "CWE-918",
    "lfi": "CWE-22",
    "rfi": "CWE-98",
    "open_redirect": "CWE-601",
    "csrf": "CWE-352",
    "idor": "CWE-639",
}


def _intel_data_suggests_xss_via_poc(data: dict[str, Any]) -> bool:
    """True when PoC/URL text looks like a classic reflected XSS PoC (payload + alert(1))."""
    poc = str(data.get("poc") or "")
    url = str(data.get("url") or "")
    blob = f"{poc}\n{url}".lower()
    if "alert(1)" not in blob and "alert%281%29" not in blob:
        return False
    markers = (
        "<script",
        "%3cscript",
        "javascript:",
        "onerror=",
        "onload=",
        "<svg",
        "%3csvg",
    )
    return any(m in blob for m in markers)


def _generate_poc(finding_data: dict[str, Any]) -> str:
    """Generate a safe PoC curl command or URL string from finding data."""
    poc = str(finding_data.get("poc") or "").strip()
    url = str(finding_data.get("url") or "").strip()
    param = str(finding_data.get("param") or "").strip()
    target = poc or url
    if not target:
        return ""
    safe_target = target.replace("'", "'\\''")
    cmd = f"curl -v '{safe_target}'"
    if param:
        cmd += f"  # parameter: {param}"
    return cmd


def _normalize_intel_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize an active-scan intel_finding dict to the standard findings format."""
    data = raw.get("data") or {}
    vuln_type = data.get("type") or data.get("template_id") or "unknown"
    vuln_type_lower = str(vuln_type).lower().strip()
    title = data.get("name") or f"{vuln_type} finding"
    if data.get("url"):
        title = f"{title} — {data['url']}"
    severity = (data.get("severity") or "info").lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "info"

    cvss: float | None = None
    raw_cvss = data.get("cvss_score") or data.get("cvss")
    if isinstance(raw_cvss, (int, float)):
        cvss = float(raw_cvss)

    # Include human-readable labels (e.g. dalfox / alf.nu — "Reflected XSS") for CVSS ≥ 7 floor.
    is_xss = vuln_type_lower in (
        "xss",
        "cross-site scripting",
        "reflected_xss",
        "stored_xss",
        "reflected xss",
        "dom xss",
        "dom_xss",
    )
    if not is_xss and _intel_data_suggests_xss_via_poc(data):
        is_xss = True

    if is_xss:
        default_cvss = _CVSS_DEFAULTS.get("xss", 7.2)
        cvss = max(cvss or 0.0, default_cvss)
        cvss = max(cvss, _MIN_CONFIRMED_XSS_CVSS)
    elif cvss is None and vuln_type_lower in _CVSS_DEFAULTS:
        cvss = _CVSS_DEFAULTS[vuln_type_lower]

    cwe = data.get("cwe") or data.get("cwe_id") or ""
    if not cwe and is_xss:
        cwe = "CWE-79"
    elif not cwe:
        cwe = _CWE_MAP.get(vuln_type_lower, "")

    poc_cmd = _generate_poc(data)

    description_parts = [data.get("type", "")]
    if data.get("param"):
        description_parts.append(f"Parameter: {data['param']}")
    if data.get("poc"):
        description_parts.append(f"Payload: {data['poc']}")
    if poc_cmd:
        description_parts.append(f"PoC: {poc_cmd}")
    if data.get("matched_at"):
        description_parts.append(f"Matched: {data['matched_at']}")
    if data.get("poc_curl"):
        description_parts.append(f"PoC (curl): {data['poc_curl']}")
    description = "; ".join(p for p in description_parts if p)
    st_raw = str(raw.get("source_tool") or "").strip() or None
    pre_owasp = raw.get("owasp_category")
    owasp_resolved: str | None = None
    if isinstance(pre_owasp, str) and pre_owasp.strip():
        owasp_resolved = parse_owasp_category(pre_owasp.strip())
    if owasp_resolved is None:
        owasp_resolved = resolve_owasp_category(
            cwe=str(cwe)[:20] if cwe else None,
            finding_type_key=vuln_type_lower or None,
            source_tool=st_raw,
        )

    out: dict[str, Any] = {
        "title": title[:500],
        "severity": severity,
        "description": description[:5000],
        "cwe": str(cwe)[:20] if cwe else None,
        "cvss": cvss,
        "source": "active_scan",
    }
    if st_raw:
        out["source_tool"] = st_raw
    if owasp_resolved:
        out["owasp_category"] = owasp_resolved
    raw_poc = data.get("proof_of_concept")
    poc_m: dict[str, Any] = dict(raw_poc) if isinstance(raw_poc, dict) else {}
    if data.get("url"):
        poc_m.setdefault("url", str(data["url"])[:500])
    if data.get("param"):
        poc_m.setdefault("parameter", str(data["param"])[:256])
    if poc_m:
        out["proof_of_concept"] = poc_m
    vt_key = str(data.get("type") or data.get("template_id") or "").strip().lower()[:128]
    if vt_key:
        out["vuln_type"] = vt_key
    return out


def _build_active_scan_context(findings: list[dict[str, Any]]) -> str:
    """Build a prompt-safe context string from active scan findings for LLM consumption."""
    if not findings:
        return ""
    lines = ["Active scan findings (from automated security tools):\n"]
    for i, f in enumerate(findings[:50], 1):
        parts = [f"  {i}. [{f.get('severity', 'info').upper()}] {f.get('title', 'N/A')}"]
        if f.get("cwe"):
            parts.append(f"CWE: {f['cwe']}")
        if f.get("cvss") is not None:
            parts.append(f"CVSS: {f['cvss']}")
        if f.get("description"):
            parts.append(f"Details: {f['description'][:300]}")
        poc = f.get("proof_of_concept")
        if isinstance(poc, dict):
            curl = poc.get("curl_command")
            if isinstance(curl, str) and curl.strip():
                parts.append(f"PoC curl: {curl.strip()[:400]}")
            js = poc.get("javascript_code")
            if isinstance(js, str) and js.strip():
                parts.append(f"PoC js: {js.strip()[:400]}")
        lines.append(" | ".join(parts))
    lines.append("")
    return "\n".join(lines) + "\n"


def _postprocess_findings_cvss(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Post-process LLM + active-scan findings: assign default CVSS, enforce floors, sort desc."""
    for f in findings:
        title_lower = (f.get("title") or "").lower()
        desc_lower = (f.get("description") or "").lower()
        severity = (f.get("severity") or "").lower()
        cvss = f.get("cvss")

        # Never auto-assign CWE-79/CVSS-7.2 to FUZZ_HIT or COMMAND_INJECTION_CANDIDATE — those are scanner hits, not confirmed XSS
        is_unconfirmed_scanner_hit = "fuzz_hit" in title_lower or "command_injection_candidate" in title_lower

        is_xss = not is_unconfirmed_scanner_hit and any(kw in title_lower or kw in desc_lower for kw in ("xss", "cross-site scripting"))
        is_sqli = any(kw in title_lower or kw in desc_lower for kw in ("sqli", "sql injection"))

        if is_xss:
            if not f.get("cwe"):
                f["cwe"] = "CWE-79"
            if cvss is None or cvss < _MIN_CONFIRMED_XSS_CVSS:
                f["cvss"] = _CVSS_DEFAULTS.get("xss", 7.2)
        elif is_sqli:
            if not f.get("cwe"):
                f["cwe"] = "CWE-89"
            if cvss is None:
                f["cvss"] = _CVSS_DEFAULTS.get("sqli", 9.8)
        elif f.get("source") == "active_scan" and severity in ("critical", "high"):
            if cvss is None or cvss < _MIN_CONFIRMED_ACTIVE_CVSS:
                f["cvss"] = _MIN_CONFIRMED_ACTIVE_CVSS

        raw_oc = f.get("owasp_category")
        oc = parse_owasp_category(raw_oc.strip()) if isinstance(raw_oc, str) and raw_oc.strip() else None
        if oc is None:
            cwe_s = str(f["cwe"]).strip() if f.get("cwe") else None
            st = str(f.get("source_tool") or "").strip() or None
            title_low = (f.get("title") or "").lower()
            desc_low = (f.get("description") or "").lower()
            blob = f"{title_low} {desc_low}".strip() or None
            oc = resolve_owasp_category(
                cwe=cwe_s,
                finding_type_key=blob,
                source_tool=st,
            )
        if oc:
            f["owasp_category"] = oc
        elif "owasp_category" in f:
            del f["owasp_category"]

        apply_default_finding_metadata(f)

    findings.sort(key=lambda f: f.get("cvss") or 0.0, reverse=True)
    return findings


async def _run_sast_scan(
    repo_path: str,
    *,
    scan_id: str | None = None,  # noqa: ARG001
) -> list[dict[str, Any]]:
    """Run SAST + secrets scan on a repository path."""
    findings: list[dict[str, Any]] = []

    try:
        result = execute_command(
            f"semgrep --config=auto --json {repo_path}",
            use_sandbox=False,
        )
        data = json.loads(result["stdout"]) if result["stdout"] else {}
        for r in data.get("results", []):
            findings.append({
                "type": "sast", "tool": "semgrep",
                "rule": r.get("check_id", ""),
                "file": r.get("path", ""),
                "severity": r.get("extra", {}).get("severity", "medium"),
                "description": r.get("extra", {}).get("message", ""),
            })
    except Exception:  # noqa: BLE001, S110
        pass

    try:
        result = execute_command(
            f"gitleaks detect --source {repo_path} --no-git -v --format=json",
            use_sandbox=False,
        )
        if result["stdout"]:
            raw = result["stdout"]
            leaks = json.loads(raw) if isinstance(raw, str) else raw
            for leak in leaks if isinstance(leaks, list) else []:
                findings.append({
                    "type": "secret", "tool": "gitleaks",
                    "rule": leak.get("RuleID", ""),
                    "file": leak.get("File", ""),
                    "severity": "high",
                    "description": f"Secret found: {leak.get('Description', '')}",
                })
    except Exception:  # noqa: BLE001, S110
        pass

    return findings


async def _maybe_adaptive_vuln_analysis(
    bundle: VulnerabilityAnalysisInputBundle,
    *,
    scan_id: str | None,
    tenant_id: str | None,
) -> VulnAnalysisOutput | None:
    """Flag-gated adaptive VA driver (overhaul §6, final integration step).

    When ``ARGUS_ADAPTIVE_LOOP`` is on, drive the plan→execute→verify loop over the
    freshly-discovered input surfaces via the signed control plane and return its
    typed ``VulnAnalysisOutput`` (which the FSM persists exactly like the linear
    one). Returns ``None`` — so the caller falls back to the linear active-scan +
    LLM path — when the flag is off, no injectable surface was discovered, or the
    driver raises. Fully exception-guarded: the adaptive path can never fail a scan.
    """
    if not settings.argus_adaptive_loop:
        return None
    try:
        inventory = build_input_surface_inventory(bundle)
        if not inventory.items:
            logger.info(
                "adaptive_va_driver",
                extra={"event": "skipped_no_surfaces", "scan_id": scan_id},
            )
            return None
        result = await run_adaptive_vuln_analysis_signed(
            inventory=inventory,
            tool_resolver=make_constant_tool_resolver("nuclei"),
            scan_id=scan_id or "",
            tenant_id=tenant_id or "",
        )
        logger.info(
            "adaptive_va_driver",
            extra={
                "event": "drove_vuln_analysis",
                "scan_id": scan_id,
                "surfaces": len(inventory.items),
                "actions_run": result.report.actions_run,
                "findings": len(result.vuln_output.findings),
                "stopped_reason": result.report.stopped_reason,
            },
        )
        return result.vuln_output
    except Exception:
        logger.warning(
            "adaptive_va_driver_failed_fallback_linear",
            extra={"scan_id": scan_id},
            exc_info=True,
        )
        return None


async def run_vuln_analysis(
    threat_model: dict,
    assets: list[str],
    *,
    target: str = "",
    tenant_id: str | None = None,
    scan_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
    recon_context: dict[str, Any] | None = None,
    source_analysis: Any | None = None,
    quick_fuzz_candidates: list[dict[str, Any]] | None = None,
) -> VulnAnalysisOutput:
    """Production vuln analysis: optional active scan + LLM analysis.

    When sandbox is enabled and a target is provided, the VA active-scan pipeline
    (dalfox, nuclei, ffuf, etc.) runs first. Its findings are fed into the LLM
    prompt as additional context and merged into the final output.
    Falls back to LLM-only when sandbox is disabled or active scan fails.
    """
    scan_options = _attach_phase_execution_mode(
        scan_options if isinstance(scan_options, dict) else {},
        tenant_id=tenant_id,
        scan_id=scan_id,
    )
    if scan_id and not scan_options.get("scan_id"):
        scan_options["scan_id"] = scan_id
    if is_quick_execution(scan_options) and scan_id and is_scan_cancelled(scan_id):
        return VulnAnalysisOutput(findings=[])
    if is_quick_execution(scan_options):
        scan_options = _apply_quick_va_constraints(
            scan_options, target=target, scan_id=scan_id
        )
    active_scan_findings: list[dict[str, Any]] = []
    active_scan_context = ""
    active_injection_coverage: dict[str, Any] = {}
    params_inv: list[dict[str, Any]] = []
    forms_inv: list[dict[str, Any]] = []
    endpoint_inv: list[dict[str, Any]] = []
    route_inv: list[dict[str, Any]] = []
    api_surface_inv: list[dict[str, Any]] = []
    js_findings_inv: list[dict[str, Any]] = []

    target_present = bool((target or "").strip())
    va_skip_reason: str | None = None
    va_tool_executed = False
    va_tool_error = False
    if not target_present:
        va_skip_reason = "no_target"
        logger.info(
            "vuln_analysis_active_scan",
            extra={
                "event": "skipped",
                "reason": "no_target",
                "scan_id": scan_id,
                "target_present": False,
            },
        )
    elif not settings.sandbox_enabled:
        va_skip_reason = "sandbox_disabled"
        logger.info(
            "vuln_analysis_active_scan",
            extra={
                "event": "skipped",
                "reason": "sandbox_disabled",
                "scan_id": scan_id,
                "target_present": True,
            },
        )

    _lab_tools_ok = _lab_tool_dispatch_allowed(
        "nuclei",
        scan_options,
        target=target,
        tenant_id=tenant_id,
    )
    if is_quick_execution(scan_options):
        allowed_tools = scan_options.get("quick_allowed_tool_ids") or []
        if not allowed_tools:
            va_skip_reason = va_skip_reason or "circuit_open"
            _lab_tools_ok = False
            logger.info(
                "vuln_analysis_active_scan",
                extra={
                    "event": "skipped",
                    "reason": "circuit_open",
                    "scan_id": scan_id,
                    "target_present": target_present,
                },
            )
    if not _lab_tools_ok and va_skip_reason != "circuit_open":
        va_skip_reason = va_skip_reason or "lab_tool_policy_denied"
        logger.info(
            "vuln_analysis_active_scan",
            extra={
                "event": "skipped",
                "reason": "lab_tool_policy_denied",
                "scan_id": scan_id,
                "target_present": target_present,
            },
        )

    if settings.sandbox_enabled and target and _lab_tools_ok:
        try:
            from src.recon.scan_options_kal import scan_kal_flags

            kal_flags = scan_kal_flags(scan_options)
            recon_urls, recon_scripts = _collect_recon_surface_artifacts(
                recon_context or {},
                target=target,
            )
            (
                params_inv,
                forms_inv,
                endpoint_inv,
                route_inv,
                api_surface_inv,
                js_findings_inv,
            ) = await _extract_url_params_forms_and_spa_surfaces(
                target,
                scan_options,
                discovered_urls=recon_urls,
                recon_script_bodies=recon_scripts,
            )
            bundle = VulnerabilityAnalysisInputBundle(
                engagement_id=scan_id or "unknown",
                target_id=target[:36],
                entry_points=[],
                threat_scenarios=[],
                params_inventory=params_inv,
                forms_inventory=forms_inv,
                endpoint_inventory=endpoint_inv,
                route_inventory=route_inv,
                api_surface=api_surface_inv,
                js_findings=js_findings_inv,
                intel_findings=[],
                live_hosts=[_live_host_row_for_target(target)],
                tech_profile=[],
            )
            # Final adaptive-driver integration (overhaul §6): when the flag is on,
            # the plan→execute→verify loop drives this phase over the discovered
            # surfaces and produces the VulnAnalysisOutput directly. Guarded — any
            # miss/failure returns None and falls through to the linear path below.
            _adaptive_out = await _maybe_adaptive_vuln_analysis(
                bundle, scan_id=scan_id, tenant_id=tenant_id
            )
            if _adaptive_out is not None:
                return _adaptive_out
            logger.info(
                "vuln_analysis_active_scan",
                extra={
                    "event": "triggered",
                    "reason": "",
                    "scan_id": scan_id,
                    "target_present": True,
                    "stage": "pre_va_active_scan_phase",
                },
            )
            _effective_scan_mode = _normalize_scan_mode_for_va(scan_options)
            result_bundle = await run_va_active_scan_phase(
                bundle,
                tenant_id_raw=tenant_id,
                scan_id_raw=scan_id or "",
                va_raw_log=lambda msg: logger.info(
                    "va_active_scan",
                    extra={"va_message": msg, "scan_id": scan_id},
                ),
                password_audit_opt_in=bool(kal_flags["password_audit_opt_in"]),
                va_network_capture_opt_in=bool(kal_flags["va_network_capture_opt_in"]),
                scan_approval_flags=(
                    {
                        str(k).strip().lower(): bool(v)
                        for k, v in scan_options.get("scan_approval_flags", {}).items()
                    }
                    if isinstance(scan_options.get("scan_approval_flags"), dict)
                    else None
                ),
                scan_mode=_effective_scan_mode,
                scan_options=scan_options,
            )
            if isinstance(scan_options, dict) and isinstance(
                scan_options.get("active_injection_coverage"), dict
            ):
                active_injection_coverage = dict(scan_options["active_injection_coverage"])
            raw_intel = list(result_bundle.intel_findings or [])
            raw_intel = normalize_active_scan_intel_findings(raw_intel)
            if settings.va_custom_xss_poc_enabled and not is_quick_execution(scan_options):
                try:
                    _lab_active = _stamped_lab_lease_active(scan_options)
                    custom_rows = await run_custom_xss_poc(
                        target,
                        params_inv,
                        forms_inv,
                        timeout=20.0,
                        max_payloads=(
                            80 if (_lab_active or settings.va_aggressive_scan) else 50
                        ),
                        max_total_requests=0 if _lab_active else 200,
                        aggressive=_lab_active or bool(settings.va_aggressive_scan),
                    )
                    if custom_rows:
                        raw_intel.extend(custom_rows)
                        raw_intel = normalize_active_scan_intel_findings(raw_intel)
                        logger.info(
                            "custom_xss_poc_merged",
                            extra={"scan_id": scan_id, "count": len(custom_rows)},
                        )
                except Exception as e:  # noqa: BLE001
                    logger.warning(
                        "custom_xss_poc_failed",
                        extra={
                            "event": "custom_xss_poc_failed",
                            "scan_id": scan_id,
                            "error_type": type(e).__name__,
                        },
                    )
            active_scan_findings = [_normalize_intel_finding(f) for f in raw_intel]
            active_scan_context = _build_active_scan_context(active_scan_findings)

            if tenant_id and scan_id and active_scan_findings:
                raw_sink = RawPhaseSink(tenant_id, scan_id, "vuln_analysis")
                await asyncio.to_thread(
                    raw_sink.upload_json,
                    "active_scan_findings",
                    {"findings": active_scan_findings, "count": len(active_scan_findings)},
                )

            logger.info(
                "va_active_scan_complete",
                extra={
                    "scan_id": scan_id,
                    "findings_count": len(active_scan_findings),
                },
            )
            logger.info(
                "vuln_analysis_active_scan",
                extra={
                    "event": "triggered",
                    "reason": "",
                    "scan_id": scan_id,
                    "target_present": True,
                    "stage": "post_va_active_scan_phase",
                    "active_scan_findings_count": len(active_scan_findings),
                },
            )
            va_tool_executed = True
            if is_quick_execution(scan_options):
                for tool_id in scan_options.get("quick_allowed_tool_ids") or ("nuclei",):
                    default_circuit_breaker().record_success(str(tool_id), target)

        except Exception:
            va_tool_error = True
            if is_quick_execution(scan_options):
                default_circuit_breaker().record_failure("nuclei", target)
            logger.warning(
                "va_active_scan_failed_fallback_to_llm",
                extra={"scan_id": scan_id},
                exc_info=True,
            )

    if target:
        try:
            if not params_inv and not forms_inv:
                params_inv, forms_inv = await _extract_url_params_and_forms(target)
            heuristic_findings = await run_web_vuln_heuristics(
                target, params_inv, forms_inv,
            )
            if heuristic_findings:
                heuristic_normalized = [
                    _normalize_intel_finding(f) for f in heuristic_findings
                ]
                active_scan_findings.extend(heuristic_normalized)
                active_scan_context = _build_active_scan_context(active_scan_findings)
                logger.info(
                    "web_vuln_heuristics_merged",
                    extra={
                        "scan_id": scan_id,
                        "heuristic_count": len(heuristic_normalized),
                    },
                )
        except Exception:
            logger.warning(
                "web_vuln_heuristics_failed",
                extra={"scan_id": scan_id},
                exc_info=True,
            )

    try:
        from src.recon.kal_searchsploit_intel import run_searchsploit_for_recon_assets

        ssp_rows = await run_searchsploit_for_recon_assets(
            assets, tenant_id=tenant_id, scan_id=scan_id
        )
        for raw_row in ssp_rows:
            active_scan_findings.append(_normalize_intel_finding(raw_row))
        if ssp_rows:
            active_scan_context = _build_active_scan_context(active_scan_findings)
    except Exception:
        logger.warning(
            "searchsploit_intel_failed",
            extra={"scan_id": scan_id},
            exc_info=True,
        )

    if tenant_id and scan_id:
        try:
            from src.recon.trivy_recon_manifest_scan import (
                raw_trivy_vuln_to_intel_row,
                run_trivy_fs_on_recon_manifests,
            )

            trivy_rows = await run_trivy_fs_on_recon_manifests(tenant_id, scan_id)
            for tr in trivy_rows:
                active_scan_findings.append(
                    _normalize_intel_finding(raw_trivy_vuln_to_intel_row(tr))
                )
            if trivy_rows:
                active_scan_context = _build_active_scan_context(active_scan_findings)
        except Exception:
            logger.warning(
                "trivy_recon_manifest_failed",
                extra={"scan_id": scan_id},
                exc_info=True,
            )

    if recon_context and recon_context.get("repo_path"):
        try:
            sast_findings = await _run_sast_scan(
                str(recon_context["repo_path"]),
                scan_id=scan_id,
            )
            active_scan_findings.extend(sast_findings)
            if sast_findings:
                active_scan_context = _build_active_scan_context(active_scan_findings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("sast_scan_failed", extra={"scan_id": scan_id, "error": str(exc)})

    quick_fuzz_section = ""
    if quick_fuzz_candidates:
        try:
            _qf_lines = []
            for _cand in quick_fuzz_candidates[:30]:
                _qf_lines.append(
                    f"- endpoint={_cand.get('url', _cand.get('endpoint', ''))} "
                    f"method={_cand.get('method', 'GET')} "
                    f"params={_cand.get('params', _cand.get('parameters', []))} "
                    f"category={_cand.get('category', '')}"
                )
            quick_fuzz_section = (
                "\n\n[Quick Fuzz Candidates — endpoints flagged for deep testing]:\n"
                + "\n".join(_qf_lines)
            )
        except Exception:  # noqa: BLE001
            quick_fuzz_section = ""

    inp = VulnAnalysisInput(threat_model=threat_model, assets=assets)
    code_aware_section = ""
    if source_analysis is not None:
        try:
            from src.orchestration.code_aware_prompts import (
                build_code_aware_prompt_section,
            )
            code_aware_section = build_code_aware_prompt_section(source_analysis)
        except Exception:  # noqa: BLE001, S110
            pass
    memory_context = ""
    try:
        from src.orchestration.episodic_memory import EpisodicMemory
        _em = EpisodicMemory()
        memory_context = _em.build_context_prompt(f"vuln_analysis {target}", max_entries=3)
    except Exception:  # noqa: BLE001, S110
        pass
    active_scan_combined = active_scan_context
    if quick_fuzz_section:
        active_scan_combined = (active_scan_combined + quick_fuzz_section) if active_scan_combined else quick_fuzz_section

    llm_output = await ai_vuln_analysis(
        inp, active_scan_context=active_scan_combined, scan_id=scan_id,
        code_aware_section=code_aware_section, memory_context=memory_context,
        use_react=scan_options.get("use_react", False),
        scan_options=scan_options,
    )

    if active_scan_findings:
        seen_titles = {f.get("title", "").lower() for f in llm_output.findings}
        for asf in active_scan_findings:
            if asf.get("title", "").lower() not in seen_titles:
                llm_output.findings.append(asf)
                seen_titles.add(asf.get("title", "").lower())

    if quick_fuzz_candidates:
        try:
            for _qc in quick_fuzz_candidates[:20]:
                _sev = _qc.get("severity", "medium")
                if isinstance(_sev, str) and _sev.lower() not in ("info", "informational"):
                    _existing_titles = {f.get("title", "").lower() for f in llm_output.findings}
                    _qtitle = f"Quick-fuzz: {_qc.get('category', 'unknown')} on {_qc.get('url', _qc.get('endpoint', ''))}"
                    if _qtitle.lower() not in _existing_titles:
                        llm_output.findings.append({
                            "title": _qtitle,
                            "severity": _sev,
                            "category": _qc.get("category", "quick_fuzz"),
                            "description": _qc.get("reason", _qc.get("description", "Flagged by quick fuzzer for deep analysis")),
                            "source": "quick_fuzz",
                            "url": _qc.get("url", _qc.get("endpoint", "")),
                        })
        except Exception as _qf_merge_exc:  # noqa: BLE001
            logger.debug("quick_fuzz_merge_failed", extra={"error": str(_qf_merge_exc)})

    llm_output.findings = _postprocess_findings_cvss(llm_output.findings)
    apply_platform_cve_mitigations(
        llm_output.findings,
        assets=assets,
        target=target,
        extra_context_blob=(active_scan_context or "")[:8000],
    )
    assign_stable_finding_ids(llm_output.findings, scan_id=scan_id)

    # R8 defense-in-depth: drop fabricated LLM findings (confirmed/exploitable or
    # CVE claim without any evidence). Opt-in; never touches evidenced findings.
    if settings.typed_intent_compiler_enabled:
        try:
            from src.orchestration.typed_intent_runner import enforce_finding_evidence

            kept, dropped = enforce_finding_evidence(
                llm_output.findings,
                scan_id=scan_id,
                tenant_id=tenant_id,
                phase="vuln_analysis",
            )
            if dropped:
                logger.info(
                    "typed_intent_evidence_gate",
                    extra={
                        "event": "typed_intent_evidence_gate",
                        "scan_id": scan_id,
                        "kept": len(kept),
                        "dropped": len(dropped),
                    },
                )
            llm_output.findings = kept
        except Exception as _tig_exc:  # noqa: BLE001 — gate must never break VA
            logger.debug("typed_intent_gate_failed", extra={"error": str(_tig_exc)})

    if scan_options.get("aiml_scan") or (source_analysis and hasattr(source_analysis, "frameworks") and any("llm" in str(f).lower() or "ai" in str(f).lower() for f in (getattr(source_analysis, "frameworks", None) or []))):
        try:
            from src.orchestration.aiml_security import AIMLSecurityScanner
            _aiml = AIMLSecurityScanner()
            _pi_findings = _aiml.scan_prompt_inputs({"target_url": target, "scan_options": json.dumps(scan_options)})
            for _pif in _pi_findings:
                llm_output.findings.append({
                    "title": f"AI/ML: {_pif.finding_type}",
                    "severity": _pif.severity,
                    "description": _pif.description,
                    "recommendation": _pif.recommendation,
                    "cwe": "prompt-injection",
                    "source": "aiml_scanner",
                })
            _mcp_tool_list = scan_options.get("mcp_tools", [])
            if _mcp_tool_list:
                _mcp_risks = _aiml.scan_mcp_tools(_mcp_tool_list)
                for _mr in _mcp_risks:
                    llm_output.findings.append({
                        "title": f"AI/ML: {_mr.risk_type}",
                        "severity": _mr.severity,
                        "description": _mr.description,
                        "recommendation": f"Review MCP tool '{_mr.tool_name}' for {_mr.risk_type}",
                        "cwe": "supply-chain",
                        "source": "aiml_scanner",
                    })
            _td_findings = _aiml.scan_training_data_leaks(
                [str(f) for f in (llm_output.findings or [])],
            )
            for _td in _td_findings:
                llm_output.findings.append({
                    "title": "AI/ML: Training data leak risk",
                    "severity": "medium",
                    "description": _td,
                    "recommendation": "Review LLM output for sensitive data exposure",
                    "cwe": "information-disclosure",
                    "source": "aiml_scanner",
                })
        except Exception:  # noqa: BLE001, S110
            pass
    llm_output.active_injection_coverage = active_injection_coverage

    try:
        from src.orchestration.vuln_agents import (
            VULN_AGENT_SPECS,
            AgentDomain,
            filter_findings_by_domain,
        )
        agent_findings_map: dict[str, list[dict[str, Any]]] = {}
        for domain in AgentDomain:
            spec = VULN_AGENT_SPECS[domain]
            relevant = filter_findings_by_domain(
                llm_output.findings, domain
            )
            if relevant:
                agent_findings_map[domain.value] = relevant
                logger.debug(
                    "vuln_agent_mapping",
                    extra={
                        "domain": domain.value,
                        "agent": spec.display_name,
                        "relevant_findings": len(relevant),
                        "tools": list(spec.tool_allowlist),
                        "scan_id": scan_id,
                    },
                )

                # Fan-out: run domain-specific LLM analysis for each domain with relevant findings
                if scan_options.get("enable_vuln_agents", True):
                    try:
                        domain_context = "\n".join(
                            f"- [{f.get('severity','?').upper()}] {f.get('title','?')} (CWE {f.get('cwe','?')})"
                            for f in relevant[:10]
                        )
                        domain_prompt = (
                            f"You are the {spec.display_name} — a CWE-specialized vulnerability analyst.\n"
                            f"Focus domains: {', '.join(str(c) for c in spec.cwe_focus)}\n"
                            f"Available tools: {', '.join(spec.tool_allowlist)}\n\n"
                            f"Target: {target}\n\n"
                            f"Findings requiring deeper analysis:\n{domain_context}\n\n"
                            f"For each finding, produce an ExploitHypothesis JSON:\n"
                            f'{{"vuln_type": "...", "location": "...", "method": "...", '
                            f'"parameter": "...", "evidence": "...", "suggested_payload": "...", '
                            f'"confidence": 0.0-1.0}}\n\n'
                            f"Return a JSON array of hypotheses."
                        )
                        domain_analysis = await llm_facade.call_llm_with_escalation(
                            system_prompt=f"You are {spec.display_name}. {spec.description}",
                            user_prompt=domain_prompt,
                            task=LLMTask.VULN_ANALYSIS,
                            scan_id=scan_id,
                            phase=f"vuln_agent_{domain.value}",
                            execution_mode=_llm_execution_mode(scan_options),
                            scan_options=scan_options,
                        )
                        if domain_analysis:
                            import json as _json
                            try:
                                hypotheses = _json.loads(domain_analysis)
                                if isinstance(hypotheses, list):
                                    for h in hypotheses[:20]:
                                        h["source_domain"] = domain.value
                                        h["source_agent"] = spec.display_name
                                    llm_output.hypotheses.extend(hypotheses)
                            except (_json.JSONDecodeError, TypeError):
                                for line in domain_analysis.splitlines():
                                    if line.strip().startswith("{"):
                                        try:
                                            h = _json.loads(line.strip())
                                            h["source_domain"] = domain.value
                                            h["source_agent"] = spec.display_name
                                            llm_output.hypotheses.append(h)
                                        except (_json.JSONDecodeError, TypeError):
                                            pass
                    except Exception as _agent_llm_exc:  # noqa: BLE001
                        logger.debug(
                            "vuln_agent_llm_failed",
                            extra={"domain": domain.value, "error": str(_agent_llm_exc)},
                        )

        if agent_findings_map:
            # Build typed ExploitationQueue objects (one per domain) so the field
            # matches its declared ``dict[str, ExploitationQueue]`` type. Assigning
            # raw ``list[dict]`` here triggered a Pydantic serialization warning
            # (PydanticSerializationUnexpectedValue) on every VulnAnalysisOutput dump.
            from src.orchestration.exploitation_queue import ExploitationQueue

            typed_queues: dict[str, ExploitationQueue] = {}
            for _domain_key, _domain_findings in agent_findings_map.items():
                try:
                    typed_queues[_domain_key] = ExploitationQueue.from_vuln_analysis_output(
                        target=target or "unknown",
                        findings=_domain_findings,
                        scan_id=scan_id or "",
                    )
                except Exception as _queue_exc:  # noqa: BLE001
                    logger.debug(
                        "exploitation_queue_build_failed",
                        extra={"domain": _domain_key, "error": str(_queue_exc)},
                    )
            if typed_queues:
                llm_output.exploitation_queues = typed_queues
    except Exception as va_exc:  # noqa: BLE001
        logger.debug("vuln_agents mapping failed (non-fatal): %s", va_exc)

    if scan_options.get("fuzzing_enabled") and source_analysis is not None:
        try:
            from src.orchestration.fuzzing import (
                FuzzingRequest,
                run_fuzzing_campaign,
                select_engine,
            )
            _fuzz_targets = []
            _sa_dict = source_analysis.model_dump() if hasattr(source_analysis, "model_dump") else {}
            _code_files = _sa_dict.get("code_files", [])
            for _cf in (_code_files or [])[:3]:
                _lang = str(_cf.get("language", "c")).lower() if isinstance(_cf, dict) else "c"
                _engine = select_engine(_lang)
                _fuzz_targets.append({"file": str(_cf), "engine": _engine, "language": _lang})
            if _fuzz_targets:
                logger.info("fuzzing_campaign_starting", extra={"scan_id": scan_id, "targets": len(_fuzz_targets)})
                for _ft in _fuzz_targets:
                    try:
                        _freq = FuzzingRequest(
                            target_binary=_ft["file"],
                            language=_ft["language"],
                            engine=_ft["engine"],
                            scan_id=scan_id or "",
                            timeout_seconds=min(int(scan_options.get("fuzz_timeout", 300)), 600),
                        )
                        _fresult = await run_fuzzing_campaign(_freq, use_sandbox=bool(settings.sandbox_enabled))
                        if _fresult.crashes:
                            for _fc in _fresult.crashes:
                                llm_output.findings.append({
                                    "title": f"Fuzz: {_fc.crash_type} in {_ft['file']}",
                                    "severity": "high" if _fc.crash_type == "crash" else "medium",
                                    "description": f"Fuzzer ({_ft['engine']}) found {_fc.crash_type}: {_fc.stack_trace[:500]}",
                                    "source": "fuzzing",
                                    "cwe": "CWE-20",
                                    "evidence_tier": 3,
                                })
                            logger.info("fuzzing_crashes_found", extra={"scan_id": scan_id, "target": _ft["file"], "crashes": len(_fresult.crashes)})
                        else:
                            logger.info("fuzzing_campaign_clean", extra={"scan_id": scan_id, "target": _ft["file"], "runs": _fresult.total_runs})
                    except Exception as _fuzz_exc:  # noqa: BLE001
                        logger.debug("fuzzing_target_failed", extra={"target": _ft["file"], "error": str(_fuzz_exc)})
        except Exception as _fuzz_outer:  # noqa: BLE001
            logger.debug("fuzzing_campaign_failed: %s", _fuzz_outer)

    if scan_options.get("binary_analysis_enabled", True) and source_analysis is not None:
        try:
            from src.orchestration.binary_analysis import (
                BinaryAnalysisRequest,
                detect_binary_type,
                run_binary_analysis,
            )
            _sa_dict_ba = source_analysis.model_dump() if hasattr(source_analysis, "model_dump") else {}
            _code_files_ba = _sa_dict_ba.get("code_files", []) or []
            for _cf_ba in _code_files_ba[:3]:
                _path_ba = str(_cf_ba.get("path", _cf_ba)) if isinstance(_cf_ba, dict) else str(_cf_ba)
                _btype_ba = detect_binary_type(_path_ba)
                if _btype_ba != "unknown":
                    try:
                        _ba_req = BinaryAnalysisRequest(
                            binary_path=_path_ba,
                            analysis_type="full",
                            architecture=_btype_ba,
                            scan_id=scan_id or "",
                        )
                        _ba_result = await run_binary_analysis(_ba_req, use_sandbox=bool(settings.sandbox_enabled))
                        if _ba_result and _ba_result.vulnerabilities:
                            for _bv in _ba_result.vulnerabilities:
                                llm_output.findings.append({
                                    "title": f"Binary: {_bv.vuln_type} in {_path_ba}",
                                    "severity": _bv.severity,
                                    "description": _bv.description,
                                    "source": "binary_analysis",
                                    "cwe": getattr(_bv, "cwe", ""),
                                    "evidence_tier": 2,
                                    "code_location": _path_ba,
                                })
                            logger.info("binary_analysis_vulns_found", extra={"scan_id": scan_id, "file": _path_ba, "vulns": len(_ba_result.vulnerabilities)})
                    except Exception as _ba_exc:  # noqa: BLE001
                        logger.debug("binary_analysis_target_failed", extra={"scan_id": scan_id, "file": _path_ba, "error": str(_ba_exc)})
        except Exception as _ba_outer:  # noqa: BLE001
            logger.debug("binary_analysis_campaign_failed: %s", _ba_outer)

    if agent_findings_map:
        try:
            from src.orchestration.sub_agent_spawner import (
                SubAgentSpawner,
                SubAgentTask,
            )
            _spawner = SubAgentSpawner(max_depth=2)
            _spawned = 0
            for _domain, _finds in agent_findings_map.items():
                _task = SubAgentTask(task_description=f"Analyze {_domain} findings", depth=0)
                if _spawner.can_spawn(_task):
                    async def _sub_agent_executor(desc: str, _d=_domain, _f=_finds) -> dict:  # noqa: ARG001
                        try:
                            _d_inp = VulnAnalysisInput(
                                threat_model={"domain": _d, "findings_summary": json.dumps(_f[:5], default=str)[:2000]},
                                assets=assets,
                            )
                            _d_out = await ai_vuln_analysis(
                                _d_inp, scan_id=scan_id, scan_options=scan_options,
                            )
                            return {"findings_count": len(_d_out.findings)}
                        except Exception:  # noqa: BLE001
                            return {}
                    _result = await _spawner.aspawn(_task, executor=_sub_agent_executor)
                    _spawned += 1
            if _spawned:
                logger.info("sub_agents_spawned", extra={"scan_id": scan_id, "count": _spawned})
        except Exception as _sa_exc:  # noqa: BLE001
            logger.debug("sub_agent_spawn_failed: %s", _sa_exc)

    if agent_findings_map:
        try:
            import asyncio as _asyncio

            from src.orchestration.vuln_agents import VULN_AGENT_SPECS, AgentDomain

            async def _fanout_domain(_fo_domain: AgentDomain) -> list[dict[str, Any]]:
                if _fo_domain.value not in agent_findings_map:
                    return []
                _fo_spec = VULN_AGENT_SPECS[_fo_domain]
                _fo_relevant = agent_findings_map[_fo_domain.value]
                _fo_domain_inp = VulnAnalysisInput(
                    threat_model={
                        "domain": _fo_domain.value,
                        "focus": _fo_spec.cwe_focus[:5],
                        "prompt_key": _fo_spec.prompt_key,
                        "tools": list(_fo_spec.tool_allowlist),
                    },
                    assets=assets,
                )
                try:
                    _fo_domain_out = await ai_vuln_analysis(
                        _fo_domain_inp,
                        active_scan_context=_build_active_scan_context(_fo_relevant),
                        scan_id=scan_id,
                        code_aware_section=code_aware_section,
                        scan_options=scan_options,
                    )
                    for _fo_df in _fo_domain_out.findings:
                        _fo_df["source_domain"] = _fo_domain.value
                    return _fo_domain_out.findings
                except Exception as _fo_dexc:  # noqa: BLE001
                    logger.debug("fanout_va_domain_failed", extra={"domain": _fo_domain.value, "error": str(_fo_dexc)})
                    return []

            _fanout_coros = [_fanout_domain(d) for d in AgentDomain]
            _fanout_results = await _asyncio.gather(*_fanout_coros, return_exceptions=True)
            _fanout_findings: list[dict[str, Any]] = []
            for _result in _fanout_results:
                if isinstance(_result, list):
                    _fanout_findings.extend(_result)
            if _fanout_findings:
                _fo_seen = {f.get("title", "").lower() for f in llm_output.findings}
                for _fo_ff in _fanout_findings:
                    if _fo_ff.get("title", "").lower() not in _fo_seen:
                        llm_output.findings.append(_fo_ff)
                        _fo_seen.add(_fo_ff.get("title", "").lower())
                logger.info("fanout_va_merged", extra={"scan_id": scan_id, "new_findings": len(_fanout_findings)})
        except Exception as _fo_exc:  # noqa: BLE001
            logger.debug("fanout_va_failed (non-fatal): %s", _fo_exc)

    # Evidence gate (Block 1.2) + deduplication (Block 1.3). Drops evidence-less
    # placeholder records ("unknown finding", fingerprint-only WhatWeb hits) and
    # collapses exact duplicates (e.g. two TLS_PROBE, two rate-limiting) before
    # ids are assigned, so the report is built from a clean, non-inflated set.
    # Guarded by settings.finding_evidence_gate_enabled (default True) per the
    # "never remove behavior silently" rule; every drop/merge is logged.
    llm_output.findings = gate_and_dedupe_findings(
        llm_output.findings,
        scan_id=scan_id,
        enabled=bool(getattr(settings, "finding_evidence_gate_enabled", True)),
    )

    # Re-assign stable finding ids after ALL late appends (aiml/fuzzing/binary/
    # sub-agent/fanout). The first pass at line ~1830 runs before these appends,
    # so without this, late findings reach exploitation/verification without a
    # finding_id and get dropped ("Exploit candidate missing finding_id").
    # Idempotent: recomputation yields identical ids for already-tagged findings.
    assign_stable_finding_ids(llm_output.findings, scan_id=scan_id)

    # Optional reviewer/judge pass (config-gated via phase routing). Advisory only:
    # annotates output metadata, never mutates/drops findings (idempotent).
    await _maybe_run_phase_reviewer(
        "vuln_analysis", llm_output, scan_id=scan_id, scan_options=scan_options
    )

    llm_output.coverage_results = attach_phase_coverage(
        phase="vuln_analysis",
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=target or (assets[0] if assets else "unknown"),
        signals=signals_for_vuln_analysis(
            skipped=va_skip_reason is not None and not va_tool_executed,
            skip_reason=va_skip_reason,
            tool_executed=va_tool_executed,
            tool_error=va_tool_error,
            findings=llm_output.findings,
            scan_id=scan_id or "unknown",
        ),
        scan_options=scan_options,
    )
    return llm_output


async def _maybe_run_phase_reviewer(
    phase: str,
    output: VulnAnalysisOutput,
    *,
    scan_id: str | None,
    scan_options: dict[str, Any] | None = None,
) -> None:
    """Run an idempotent reviewer/judge pass when the phase route defines one.

    Reuses the existing adversarial critic. Gated by ARGUS_PHASE_ROUTING_ENABLED and
    a ``reviewer_alias`` in phase_routing.yaml for *phase*. Advisory: stores a compact
    summary under ``output.active_injection_coverage['phase_review']`` and never raises.
    """
    try:
        from src.llm.phase_routing import get_phase_route

        route = get_phase_route(phase)
        if route is None or not route.reviewer_alias:
            return
        findings = list(output.findings or [])
        if not findings:
            return

        from src.orchestration.adversarial_critic import run_adversarial_critic

        _review_mode = _llm_execution_mode(scan_options)

        async def _executor(system_prompt: str, user_prompt: str) -> dict[str, str]:
            text = await llm_facade.call_llm_unified(
                system_prompt,
                user_prompt,
                task=LLMTask.VALIDATION_ONESHOT,
                scan_id=scan_id,
                phase=f"{phase}_review",
                execution_mode=_review_mode,
            )
            return {"content": text or ""}

        result = await run_adversarial_critic(findings, llm_executor=_executor)
        if not isinstance(output.active_injection_coverage, dict):
            return
        output.active_injection_coverage["phase_review"] = {
            "reviewer_alias": route.reviewer_alias,
            "findings_reviewed": getattr(result, "findings_reviewed", 0),
            "critiques": len(getattr(result, "critiques", []) or []),
            "blind_spots": (getattr(result, "blind_spots", []) or [])[:10],
            "overall_assessment": str(getattr(result, "overall_assessment", ""))[:500],
        }
        logger.info(
            "phase_reviewer_completed",
            extra={
                "event": "phase_reviewer_completed",
                "phase": phase,
                "reviewer_alias": route.reviewer_alias,
                "findings_reviewed": getattr(result, "findings_reviewed", 0),
            },
        )
    except Exception as _rev_exc:  # never break the phase  # noqa: BLE001
        logger.debug("phase_reviewer_failed", extra={"phase": phase, "error": str(_rev_exc)})


async def run_exploit_attempt(
    findings: list[dict],
    *,
    scan_id: str | None = None,
    target: str = "",
    tenant_id: str = "",
    auth_config: dict[str, Any] | None = None,
    execution_mode: str | None = None,
    scan_options: dict[str, Any] | None = None,
) -> ExploitationOutput:
    """Exploitation: generates payloads via PayloadBuilder, executes tools in sandbox,
    verifies exploitability via WRB analysis. Falls back to LLM-only if sandbox unavailable.

    When auth_config is provided, attempts browser-based login via PlaywrightAdapter
    before exploitation to establish authenticated sessions.
    """
    opts = dict(scan_options) if isinstance(scan_options, dict) else {}
    if execution_mode and "execution_mode" not in opts:
        opts["execution_mode"] = execution_mode
    if is_quick_execution(opts):
        logger.info(
            "exploitation_skipped_quick_profile",
            extra={
                "event": "exploitation_skipped_quick_profile",
                "scan_id": scan_id,
                "coverage_reason": "not_scheduled_by_quick_profile",
            },
        )
        return ExploitationOutput(exploits=[], evidence=[])

    from src.orchestration.exploitation_executor import execute_exploitation

    if not findings:
        return ExploitationOutput(exploits=[], evidence=[])

    if tenant_id and "tenant_id" not in opts:
        opts["tenant_id"] = tenant_id
    if scan_id and "scan_id" not in opts:
        opts["scan_id"] = scan_id
    opts = _attach_phase_execution_mode(
        opts,
        tenant_id=tenant_id or None,
        scan_id=scan_id,
    )
    effective_mode = extract_execution_mode(opts).value

    # LAB without usable lease / outside boundary: skip sandbox tool dispatch
    # (LLM theoretical fallback below still runs). Production is unchanged.
    _sandbox_tools_allowed = _lab_tool_dispatch_allowed(
        "sqlmap",
        opts,
        target=target,
        tenant_id=tenant_id or None,
    )
    if not _sandbox_tools_allowed:
        logger.info(
            "exploitation_tool_dispatch_denied",
            extra={
                "event": "exploitation_tool_dispatch_denied",
                "scan_id": scan_id,
                "reason": "lab_tool_policy_denied",
            },
        )

    # G-1 fix: establish an authenticated session via Playwright, persist it in a
    # SessionStore (isolated per principal), and propagate the owner session's
    # cookies/headers into execute_exploitation so tools run authenticated.
    _auth_context: dict[str, Any] | None = None
    if auth_config and _sandbox_tools_allowed:
        try:
            from src.auth.session_store import SessionStore
            from src.orchestration.auth_config import PrincipalRole, TargetConfig
            from src.sandbox.playwright_adapter import (
                PlaywrightAdapter,
                export_auth_context,
            )

            tc = TargetConfig.from_json(auth_config) if isinstance(auth_config, dict) else None
            principals = tc.resolved_principals() if tc else []
            owner = next(
                (p for p in principals if p.role == PrincipalRole.OWNER),
                principals[0] if principals else None,
            )
            if owner is not None and owner.login is not None:
                login = owner.resolve_placeholders().login
                pa = PlaywrightAdapter()
                await pa._start_session()
                login_steps = [
                    {
                        "instruction": step.instruction,
                        "selector": step.selector or "",
                        "value": step.value or "",
                    }
                    for step in (login.login_flow or [])
                ]
                success_condition = (
                    {"type": login.success_condition.type, "value": login.success_condition.value}
                    if login.success_condition
                    else None
                )
                login_resp = await pa.login_flow(
                    url=login.login_url or target,
                    steps=login_steps,
                    success_condition=success_condition,
                )
                if login_resp.success:
                    store = SessionStore()
                    session = store.create_session(
                        principal_id=owner.principal_id,
                        role=owner.role,
                        tenant_id=owner.tenant_id or (tenant_id or None),
                    )
                    ctx = export_auth_context(login_resp)
                    session.set_cookies_from_playwright(ctx.get("cookies") or [])
                    if ctx.get("storage_state"):
                        session.storage_state = ctx["storage_state"]
                    # Execution-layer export: cookies/headers for tool argv (never logged).
                    _auth_context = session.as_exploitation_auth()
                    logger.info(
                        "playwright_login_ok",
                        extra={"scan_id": scan_id, "principal_id": owner.principal_id},
                    )
                else:
                    logger.debug("playwright_login_failed", extra={"scan_id": scan_id})
        except Exception as pa_exc:  # noqa: BLE001
            logger.debug(
                "playwright_auth_failed_non_fatal",
                extra={"scan_id": scan_id, "error": str(pa_exc)},
            )

    try:
        if _sandbox_tools_allowed:
            exploits, evidence = await execute_exploitation(
                findings,
                target=target,
                tenant_id=tenant_id,
                scan_id=scan_id,
                auth_context=_auth_context,
                execution_mode=effective_mode,
                scan_options=opts,
            )
            if exploits:
                return ExploitationOutput(exploits=exploits, evidence=evidence)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "exploitation_executor_failed",
            extra={"scan_id": scan_id, "error": str(exc)},
        )

    # Fallback: LLM theoretical exploitation
    inp = ExploitationInput(findings=findings)
    _use_react = auth_config is not None and isinstance(auth_config, dict) and auth_config.get("use_react")
    exploit_out = await ai_exploitation(
        inp,
        scan_id=scan_id,
        use_react=bool(_use_react),
        scan_options=opts,
        execution_mode=effective_mode,
    )

    if not exploit_out.exploits and findings:
        try:
            from src.orchestration.react_agent import ReActAgent
            _react = ReActAgent(task="Find exploitable paths for reported vulnerabilities")
            for _finding in findings[:5]:
                _react.add_observation(f"Finding: {json.dumps(_finding, default=str)[:500]}")
            logger.info("ReAct exploitation fallback used", extra={"scan_id": scan_id})
        except Exception:  # noqa: BLE001, S110
            pass

    for _exploit in (exploit_out.exploits or []):
        _sev = str(_exploit.get("severity", "")).lower()
        if _sev in ("critical", "high"):
            try:
                from src.orchestration.symbolic_execution import (
                    SymbolicExecutionRequest,
                    run_symbolic_execution,
                )
                _ser = SymbolicExecutionRequest(
                    binary_path=str(_exploit.get("target_url", target)),
                    source_function=str(_exploit.get("parameter", "input")),
                    sink_function=str(_exploit.get("vuln_type", "unknown")),
                    scan_id=scan_id or "",
                    timeout_seconds=300,
                )
                _sym_result = await run_symbolic_execution(_ser, use_sandbox=bool(settings.sandbox_enabled))
                if _sym_result.vulnerable:
                    _exploit["symbolic_execution_proven"] = True
                    _exploit["symbolic_input_values"] = json.dumps(_sym_result.input_values, default=str)[:1000]
                _exploit["symbolic_execution_prompt"] = _sym_result.angr_script[:500] if _sym_result.angr_script else ""
                logger.info("symbolic_execution_result", extra={"scan_id": scan_id, "proven": _sym_result.proven, "error": _sym_result.error[:200] if _sym_result.error else ""})
            except Exception as _sym_exc:  # noqa: BLE001
                logger.debug("symbolic_execution_failed", extra={"scan_id": scan_id, "error": str(_sym_exc)})

    # Playwright screenshot evidence for browser-verifiable exploits (XSS, auth bypass)
    _xss_vuln_types = {"xss", "cross-site scripting", "reflected xss", "stored xss", "dom xss"}
    _browser_vuln_types = {"xss", "cross-site scripting", "auth", "authentication", "csrf", "open-redirect"}
    for _exploit in (exploit_out.exploits or []):
        _vtype = str(_exploit.get("vuln_type", "")).lower()
        _is_browser_verifiable = any(_bt in _vtype for _bt in _browser_vuln_types)
        if _is_browser_verifiable and _exploit.get("poc_url") or _exploit.get("poc_curl"):
            try:
                from src.sandbox.playwright_adapter import (
                    PlaywrightAdapter,
                )
                _pa = PlaywrightAdapter()
                await _pa._start_session()
                _poc_url = _exploit.get("poc_url", target)
                _nav_resp = await _pa.navigate(_poc_url)
                if _nav_resp.success:
                    _shot_resp = await _pa.screenshot()
                    if _shot_resp.success and (_shot_resp.screenshot_base64 or _shot_resp.screenshot_path):
                        if _shot_resp.screenshot_base64:
                            _exploit["screenshot_base64"] = _shot_resp.screenshot_base64
                        if _shot_resp.screenshot_path:
                            _exploit["screenshot_path"] = _shot_resp.screenshot_path
                        _exploit["browser_evidence"] = {
                            "url": _nav_resp.url,
                            "title": _nav_resp.title,
                            "body_snippet": (_nav_resp.body_text or "")[:500],
                        }
                        logger.info("Playwright screenshot captured", extra={"scan_id": scan_id, "url": _poc_url})
                _pa._session.stop()
            except Exception as _pw_exc:  # noqa: BLE001
                logger.debug("Playwright screenshot failed (non-fatal): %s", _pw_exc)

    # R8/R6 defense-in-depth: LLM-derived exploits inherently claim exploitability,
    # so drop any without PoC/evidence. Opt-in; the sandbox executor path (which
    # returns earlier with real evidence) is never reached here.
    if settings.typed_intent_compiler_enabled and exploit_out.exploits:
        try:
            from src.orchestration.typed_intent_runner import enforce_finding_evidence

            kept, dropped = enforce_finding_evidence(
                exploit_out.exploits,
                scan_id=scan_id,
                tenant_id=tenant_id,
                phase="exploitation",
                treat_as_provable=True,
                extra_evidence_keys=(
                    "poc_url",
                    "poc_curl",
                    "browser_evidence",
                    "screenshot_base64",
                    "screenshot_path",
                    "symbolic_execution_proven",
                    "evidence",
                ),
            )
            if dropped:
                logger.info(
                    "typed_intent_exploit_gate",
                    extra={
                        "event": "typed_intent_exploit_gate",
                        "scan_id": scan_id,
                        "kept": len(kept),
                        "dropped": len(dropped),
                    },
                )
            exploit_out.exploits = kept
        except Exception as _eg_exc:  # noqa: BLE001 — gate must never break exploitation
            logger.debug("typed_intent_exploit_gate_failed", extra={"error": str(_eg_exc)})

    return exploit_out


async def run_exploit_verify(candidates_output: ExploitationOutput) -> ExploitationOutput:
    """
    EXPLOIT_VERIFY sub-phase: PoC verification of exploit candidates.
    Only candidates that pass verification are returned as verified exploits.
    """
    verified_exploits: list[dict] = []
    verified_finding_ids: set[str] = set()

    for candidate in candidates_output.exploits:
        if await verify_exploit_poc_async(candidate):
            verified = {**candidate, "status": "verified"}
            verified_exploits.append(verified)
            verified_finding_ids.add(str(candidate.get("finding_id", "")))

    verified_evidence = [
        ev
        for ev in candidates_output.evidence
        if not ev.get("finding_id") or str(ev.get("finding_id", "")) in verified_finding_ids
    ]

    return ExploitationOutput(
        exploits=verified_exploits,
        evidence=verified_evidence,
    )


async def run_exploitation(
    findings: list[dict], *, scan_id: str | None = None
) -> ExploitationOutput:
    """
    Exploitation: input(findings) -> output(exploits, evidence).
    Runs EXPLOIT_ATTEMPT then EXPLOIT_VERIFY; only verified exploits are returned.
    """
    attempt_out = await run_exploit_attempt(findings, scan_id=scan_id)
    return await run_exploit_verify(attempt_out)


async def run_post_exploitation(
    exploits: list[dict],
    *,
    evidence: list[dict[str, Any]] | None = None,
    evidence_tiers: dict[str, int] | None = None,
    tenant_id: str | None = None,
    scan_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
) -> PostExploitationOutput:
    """Post exploitation: LLM analyzes lateral movement and persistence.

    When there are verified exploits, also attempts basic post-exploitation checks:
    - Internal network reachability
    - Service discovery on compromised host
    - Persistence mechanism feasibility assessment

    ``evidence`` / ``evidence_tiers`` are the exploitation-phase artifacts threaded
    from the pipeline (state machine ``_build_phase_input``). They ground the
    analysis so post-exploitation only builds on exploits that carry real
    evidence — no lateral/persistence claim is invented without a proven exploit.
    """
    evidence = list(evidence or [])
    evidence_tiers = dict(evidence_tiers or {})
    # Set of finding ids that carry exploitation evidence (tier >= CONFIRMED=3),
    # used to keep post-exploitation grounded in proven exploits only.
    _evidenced_finding_ids = {
        fid for fid, tier in evidence_tiers.items() if isinstance(tier, int) and tier >= 3
    }
    scan_opts = dict(scan_options) if isinstance(scan_options, dict) else {}
    if tenant_id and "tenant_id" not in scan_opts:
        scan_opts["tenant_id"] = tenant_id
    if scan_id and "scan_id" not in scan_opts:
        scan_opts["scan_id"] = scan_id
    scan_opts = _attach_phase_execution_mode(
        scan_opts,
        tenant_id=tenant_id,
        scan_id=scan_id,
    )
    raw_sink: RawPhaseSink | None = None
    if tenant_id and scan_id:
        raw_sink = RawPhaseSink(tenant_id, scan_id, "post_exploitation")

    def _has_exploit_evidence(exploit: dict[str, Any]) -> bool:
        # Grounded when the exploit itself carries evidence, or its finding id is
        # in the confirmed-evidence set threaded from the exploitation phase.
        if int(exploit.get("evidence_tier", 0) or 0) >= 3:
            return True
        fid = str(exploit.get("finding_id", "") or "")
        if fid and fid in _evidenced_finding_ids:
            return True
        return any(exploit.get(k) for k in ("poc_url", "poc_curl", "browser_evidence", "screenshot_base64"))

    verified = [e for e in exploits if e.get("status") == "verified"]
    # When the pipeline threads exploitation evidence, keep post-exploitation
    # grounded in exploits that actually carry evidence (R6: no invented lateral
    # movement / persistence without a proven exploit). Legacy callers that omit
    # evidence_tiers keep the prior behaviour.
    if evidence_tiers and verified:
        grounded = [e for e in verified if _has_exploit_evidence(e)]
        verified = grounded
    target = verified[0].get("target") or verified[0].get("url") if verified else ""

    # Basic post-exploitation checks if we have verified exploits
    post_lateral: list[dict[str, Any]] = []
    post_persistence: list[dict[str, Any]] = []

    if verified and target:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname

            # Check internal network — try common internal services
            internal_checks = [
                ("metadata_service", "http://169.254.169.254/latest/meta-data/"),
                ("internal_dns", f"http://{host}:53/"),
                ("internal_api", f"http://{host}:8080/"),
                ("internal_admin", f"http://{host}:3000/"),
            ]

            import httpx
            async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
                for service_name, service_url in internal_checks:
                    try:
                        resp = await client.get(service_url)
                        if 200 <= resp.status_code < 500:
                            post_lateral.append({
                                "technique": f"Internal {service_name} reachable",
                                "description": f"Discovered {service_name} at {service_url} (HTTP {resp.status_code})",
                                "from_exploit": verified[0].get("finding_id", ""),
                            })
                    except Exception:  # noqa: BLE001, S110
                        pass

            # Check common persistence paths
            if post_lateral:
                post_persistence.append({
                    "type": "internal_service_access",
                    "description": "Access to internal services enables potential lateral movement. Review network segmentation.",
                    "risk_level": "medium",
                })

            # AD/SMB enumeration if targets appear to be Windows/AD
            if any(svc.get("technique", "").startswith("Internal") for svc in post_lateral):
                try:
                    ad_target = host if host else target
                    if _lab_tool_dispatch_allowed(
                        "enum4linux-ng",
                        scan_opts,
                        target=str(ad_target or ""),
                        tenant_id=tenant_id,
                    ):
                        enum_result = execute_command(
                            f"enum4linux-ng -A {ad_target}",
                            use_sandbox=True,
                        )
                        if enum_result["success"] and enum_result["stdout"]:
                            post_lateral.append({
                                "technique": "SMB Enumeration via enum4linux",
                                "description": enum_result["stdout"][:500],
                                "from_exploit": verified[0].get("finding_id", ""),
                                "tool": "enum4linux_ng",
                            })
                except Exception as e:  # noqa: BLE001
                    logger.debug("ad_enum_skipped", extra={"error": str(e)})
        except Exception as exc:  # noqa: BLE001
            logger.warning("post_exploitation_checks_failed", extra={"error": str(exc)})

    # Combine with LLM analysis
    inp = PostExploitationInput(exploits=exploits)
    ai_result = await ai_post_exploitation(
        inp, raw_sink=raw_sink, scan_id=scan_id, scan_options=scan_opts,
    )

    # Merge real checks with AI results
    ai_result.lateral = post_lateral + ai_result.lateral
    ai_result.persistence = post_persistence + ai_result.persistence

    return ai_result


async def run_reporting(
    target: str,
    recon: ReconOutput | None,
    threat_model: ThreatModelOutput | None,
    vuln_analysis: VulnAnalysisOutput | None,
    exploitation: ExploitationOutput | None,
    post_exploitation: PostExploitationOutput | None,
    *,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
    scope_config: dict[str, Any] | None = None,
    source_analysis: Any | None = None,
    quick_fuzz: QuickFuzzOutput | None = None,
) -> ReportingOutput:
    """Reporting: aggregates all real data and generates comprehensive report via LLM."""
    scan_options = _attach_phase_execution_mode(
        scan_options if isinstance(scan_options, dict) else {},
        tenant_id=tenant_id,
        scan_id=scan_id,
    )
    report_context: dict[str, Any] = {}
    if exploitation is not None:
        hibp_summary = await summarize_pwned_passwords_for_report(
            exploitation.model_dump(),
            max_checks=5,
        )
        if hibp_summary:
            report_context["hibp_pwned_password_summary"] = hibp_summary

    _critic_insights: list[dict[str, Any]] = []
    if vuln_analysis and vuln_analysis.findings:
        try:
            from src.orchestration.adversarial_critic import run_adversarial_critic

            _report_mode = _llm_execution_mode(scan_options)

            async def _critic_executor(sys_prompt: str, user_prompt: str):
                return await llm_facade.call_llm_unified(
                    sys_prompt, user_prompt, task=LLMTask.REPORT_SECTION,
                    scan_id=scan_id, phase="adversarial_critic",
                    execution_mode=_report_mode,
                )

            _critic_result = await run_adversarial_critic(
                vuln_analysis.findings[:30], llm_executor=_critic_executor,
            )
            for _bs in (_critic_result.blind_spots or [])[:5]:
                _critic_insights.append({"type": "blind_spot", "detail": _bs})
            for _c in (_critic_result.critiques or [])[:5]:
                _critic_insights.append({"type": "critique", "finding_id": _c.finding_id, "detail": _c.description})
        except Exception:  # noqa: BLE001, S110
            pass

    if quick_fuzz is not None:
        with contextlib.suppress(Exception):
            report_context["quick_fuzz_summary"] = {
                "findings_count": len(quick_fuzz.findings),
                "candidates_count": len(quick_fuzz.candidates),
                "categories": list({f.get("category", "unknown") for f in quick_fuzz.findings}),
            }

    inp = ReportingInput(
        target=target,
        recon=recon,
        threat_model=threat_model,
        vuln_analysis=vuln_analysis,
        exploitation=exploitation,
        post_exploitation=post_exploitation,
        report_context=report_context,
        scope_config=scope_config,
        source_analysis=source_analysis.model_dump() if hasattr(source_analysis, "model_dump") else source_analysis,
    )
    report_out = await ai_reporting(inp, scan_id=scan_id, scan_options=scan_options)
    report_out.coverage_results = snapshot_coverage_dicts(scan_id)
    if report_out.coverage_results:
        report_out.report["coverage_results"] = report_out.coverage_results

    if _critic_insights:
        try:
            _existing = report_out.report.get("ai_insights", [])
            _existing.extend(_critic_insights)
            report_out.report["ai_insights"] = _existing
        except Exception:  # noqa: BLE001, S110
            pass

        try:
            from src.orchestration.detection_engineering import (
                run_detection_engineering,
            )

            async def _de_executor(sys_prompt: str, user_prompt: str):
                return await llm_facade.call_llm_unified(
                    sys_prompt, user_prompt, task=LLMTask.REPORT_SECTION,
                    scan_id=scan_id, phase="detection_engineering",
                    execution_mode=_llm_execution_mode(scan_options),
                )

            _de_result = await run_detection_engineering(
                vuln_analysis.findings[:20], llm_executor=_de_executor,
            )
            if _de_result.rules:
                _existing = report_out.report.get("detection_rules", [])
                for _r in _de_result.rules:
                    _existing.append({"rule_type": _r.rule_type, "title": _r.title, "content": _r.rule_content})
                report_out.report["detection_rules"] = _existing
        except Exception:  # noqa: BLE001, S110
            pass

        if scan_options and scan_options.get("auto_patch_enabled"):
            try:
                from src.orchestration.auto_patch import (
                    build_autopatch_prompt,
                    create_patch_pr,
                    parse_patch_response,
                )
                _patches = []
                _pr_urls = []
                _patch_mode = _llm_execution_mode(scan_options)
                for _hf in vuln_analysis.findings[:10]:
                    _sev = str(_hf.get("severity", "")).lower()
                    if _sev in ("critical", "high") and _hf.get("code_location"):
                        _ps, _pu = build_autopatch_prompt(
                            cwe=str(_hf.get("cwe", "")),
                            description=str(_hf.get("description", "")),
                            file_path=str(_hf.get("code_location", "")),
                            severity=_sev,
                            vulnerable_code=str(_hf.get("vulnerable_code", "")),
                        )
                        _presp = await llm_facade.call_llm_unified(
                            _ps, _pu, task=LLMTask.EXPLOIT_GENERATION,
                            scan_id=scan_id, phase="auto_patch",
                            execution_mode=_patch_mode,
                        )
                        if _presp:
                            _pc = parse_patch_response(str(_hf.get("finding_id", "")), str(_hf.get("code_location", "")), _presp)
                            _patches.append({"finding_id": _pc.finding_id, "file": _pc.file_path, "diff": _pc.patch_diff[:2000]})
                            if scan_options.get("auto_patch_create_pr") and scan_options.get("repo_provider") and scan_options.get("repo_token"):
                                _pr_result = await create_patch_pr(
                                    _pc,
                                    owner=str(scan_options.get("repo_owner", "")),
                                    name=str(scan_options.get("repo_name", "")),
                                    provider=str(scan_options.get("repo_provider", "github")),
                                    token=str(scan_options.get("repo_token", "")),
                                    base_url=str(scan_options.get("repo_base_url", "")),
                                    scan_id=scan_id or "",
                                    tenant_id=str(scan_options.get("tenant_id", "")),
                                )
                                if _pr_result.pr_url:
                                    _pr_urls.append({"finding_id": _pc.finding_id, "pr_url": _pr_result.pr_url})
                                    _patches[-1]["pr_url"] = _pr_result.pr_url
                if _patches:
                    report_out.report.setdefault("auto_patches", []).extend(_patches)
                if _pr_urls:
                    report_out.report.setdefault("patch_prs", []).extend(_pr_urls)
            except Exception:  # noqa: BLE001, S110
                pass

    return report_out
