"""Stage 1 enrichment builder for authorized safe recon outputs.

This module expands Stage 1 reporting with:
- Route/page discovery
- JavaScript analysis (safe static hints only)
- Params/input inventory
- API surface mapping
- AI task templates (input schema, prompt, output schema, validation)
- Raw + normalized persistence with evidence references
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx
from app.schemas.ai.common import ReconAiTask, build_task_metadata
from app.schemas.ai.schema_export import (
    RECON_AI_TASKS,
    get_recon_ai_task_definitions,
    validate_recon_ai_payload,
)
from app.schemas.recon.stage3_readiness import (
    CoverageScores,
    ROUTE_CLASSIFICATION_CSV_COLUMNS,
    Stage3ReadinessResult,
)

from src.recon.mcp.client import fetch_url_mcp
from src.recon.parsers.http_probe_parser import parse_http_probe

logger = logging.getLogger(__name__)

_ROUTE_CANDIDATE_PATHS = [
    "/",
    "/login",
    "/signin",
    "/reset-password",
    "/forgot-password",
    "/contact",
    "/portal",
    "/admin",
    "/account",
    "/user",
]

_MAX_PAGES = 120
_MAX_SCRIPTS = 50
_MAX_JS_BYTES = 150_000
_MAX_BODY_BYTES = 200_000

_API_HINT_RE = re.compile(r"(?P<path>/api/[a-zA-Z0-9_\-./]+|/graphql\b|/[a-zA-Z0-9_\-./]+\.json\b)")
_CLIENT_ROUTE_RE = re.compile(r"(?P<route>/[a-zA-Z0-9_\-]{2,}(?:/[a-zA-Z0-9_\-]{1,}){0,4})")
_FEATURE_FLAG_RE = re.compile(r"(feature[_-]?flag|enable[_-]beta|is[_-]enabled)", re.IGNORECASE)
_AUTH_HINT_RE = re.compile(
    r"(login|signin|logout|refresh[_-]?token|auth[_-]?token|forgot[_-]?password|reset[_-]?password)",
    re.IGNORECASE,
)
_CONFIG_HINT_RE = re.compile(
    r"(public[_-]?config|window\.__|process\.env|NEXT_PUBLIC_|VITE_|REACT_APP_)",
    re.IGNORECASE,
)
_THIRD_PARTY_RE = re.compile(
    r"(googleapis|googletagmanager|sentry|segment|mixpanel|stripe|recaptcha|datadog|intercom|cdnjs|cloudflare|jsdelivr|unpkg|bootstrapcdn)",
    re.IGNORECASE,
)
# Fetch/XHR URL patterns for inline script extraction
_FETCH_URL_RE = re.compile(
    r"(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    re.IGNORECASE,
)
_XHR_OPEN_URL_RE = re.compile(
    r"\.open\s*\(\s*['\"]?(?:GET|POST|PUT|DELETE|PATCH)['\"]?\s*,\s*['\"`]([^'\"`]+)['\"`]",
    re.IGNORECASE,
)
_AJAX_URL_RE = re.compile(
    r"(?:url|URL)\s*:\s*['\"`]([^'\"`]+)['\"`]",
    re.IGNORECASE,
)
_ID_PATH_RE = re.compile(
    r"/(?:user|users|account|accounts|order|orders|invoice|session|token|project|projects)/[^/?#]+",
    re.IGNORECASE,
)
_SUSPICIOUS_HOST_PREFIXES = (
    "cpanel.",
    "mail.",
    "webmail.",
    "autodiscover.",
    "autoconfig.",
    "smtp.",
    "imap.",
)
_SENSITIVE_PARAM_KEYWORDS = (
    "token",
    "code",
    "session",
    "password",
    "passwd",
    "secret",
    "key",
    "auth",
    "authorization",
    "cookie",
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._\-+/=]{8,}|"
    r"(token|password|passwd|secret|api[_-]?key|session|auth|code|authorization|cookie)\s*[:=]\s*[^,\s;&]+)"
)


@dataclass(slots=True)
class _FetchedPage:
    url: str
    status: int
    content_type: str
    body: str
    fetch_backend: str
    evidence_ref: str


class _HtmlEvidenceParser(HTMLParser):
    """Safe HTML extractor for links/forms/scripts/title/inline scripts."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form_stack: dict[str, Any] | None = None
        self._capture_title = False
        self._capture_inline_script = False
        self._current_inline = ""
        self.title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {k.lower(): (v or "").strip() for k, v in attrs}
        tag_lower = tag.lower()

        if tag_lower == "a":
            href = attrs_map.get("href", "")
            if href:
                self.links.append(href)
            return

        if tag_lower == "script":
            src = attrs_map.get("src", "")
            if src:
                self.scripts.append(src)
            else:
                self._capture_inline_script = True
                self._current_inline = ""
            return

        if tag_lower == "form":
            self._form_stack = {
                "action": attrs_map.get("action", ""),
                "method": (attrs_map.get("method") or "GET").upper(),
                "inputs": [],
            }
            return

        if tag_lower in {"input", "select", "textarea"} and self._form_stack is not None:
            self._form_stack["inputs"].append(
                {
                    "name": attrs_map.get("name", ""),
                    "type": attrs_map.get("type", "text" if tag_lower != "select" else "select"),
                    "required": "required" in attrs_map,
                }
            )
            return

        if tag_lower == "title":
            self._capture_title = True

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower == "form" and self._form_stack is not None:
            self.forms.append(self._form_stack)
            self._form_stack = None
        if tag_lower == "title":
            self._capture_title = False
        if tag_lower == "script" and self._capture_inline_script:
            if self._current_inline.strip():
                self.inline_scripts.append(self._current_inline.strip())
            self._capture_inline_script = False
            self._current_inline = ""

    def handle_data(self, data: str) -> None:
        if self._capture_title:
            self.title += data.strip()
        if self._capture_inline_script:
            self._current_inline += data


def _extract_from_inline_script(
    content: str,
    page_url: str,
    evidence_ref: str,
) -> dict[str, list[dict[str, str]]]:
    """Extract API/route/config hints from inline script content.

    Returns dict with keys: routes, api_refs, third_party, config_hints,
    feature_flags, auth_hints, hidden_hints.
    """
    result: dict[str, list[dict[str, str]]] = {
        "routes": [],
        "api_refs": [],
        "third_party": [],
        "config_hints": [],
        "feature_flags": [],
        "auth_hints": [],
        "hidden_hints": [],
    }
    seen_routes: set[str] = set()
    seen_api: set[str] = set()
    seen_third_party: set[str] = set()
    seen_config: set[str] = set()

    for match in _CLIENT_ROUTE_RE.finditer(content):
        value = match.group("route")
        if value.count("/") < 1 or len(value) > 120 or value in seen_routes:
            continue
        seen_routes.add(value)
        result["routes"].append({"value": value, "evidence_ref": evidence_ref})

    for match in _API_HINT_RE.finditer(content):
        path = match.group("path")
        full_url = urljoin(page_url, path)
        safe_full_url = _sanitize_url_for_artifact(full_url)
        if safe_full_url not in seen_api:
            seen_api.add(safe_full_url)
            result["api_refs"].append({"value": safe_full_url, "evidence_ref": evidence_ref})

    for pattern in (_FETCH_URL_RE, _XHR_OPEN_URL_RE, _AJAX_URL_RE):
        for match in pattern.finditer(content):
            url = match.group(1).strip()
            if not url or len(url) > 500:
                continue
            if url.startswith("/"):
                full_url = urljoin(page_url, url)
            else:
                full_url = url
            safe_full_url = _sanitize_url_for_artifact(full_url)
            if safe_full_url not in seen_api:
                seen_api.add(safe_full_url)
                result["api_refs"].append({"value": safe_full_url, "evidence_ref": evidence_ref})

    for match in _THIRD_PARTY_RE.finditer(content):
        value = match.group(0)
        if value.lower() not in seen_third_party:
            seen_third_party.add(value.lower())
            result["third_party"].append({"value": value, "evidence_ref": evidence_ref})

    for match in _CONFIG_HINT_RE.finditer(content):
        value = match.group(0)
        if value not in seen_config:
            seen_config.add(value)
            result["config_hints"].append({"value": value, "evidence_ref": evidence_ref})

    if _FEATURE_FLAG_RE.search(content):
        result["feature_flags"].append({"value": "inline_script", "evidence_ref": evidence_ref})
    if _AUTH_HINT_RE.search(content):
        result["auth_hints"].append({"value": "inline_script", "evidence_ref": evidence_ref})
    if "hidden" in content.lower() or "internal" in content.lower():
        result["hidden_hints"].append({"value": "inline_script", "evidence_ref": evidence_ref})

    return result


def _as_csv(rows: list[dict[str, Any]], columns: list[str]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row.get(col, "") for col in columns])
    return out.getvalue()


def _is_html_like(content_type: str, body: str) -> bool:
    ctype = (content_type or "").lower()
    if "text/html" in ctype or "application/xhtml+xml" in ctype:
        return True
    stripped = body.lstrip()
    return stripped.startswith("<!doctype html") or stripped.startswith("<html")


def _is_js_like(url: str, content_type: str, body: str) -> bool:
    u = url.lower()
    ctype = (content_type or "").lower()
    if u.endswith(".js") or "javascript" in ctype:
        return True
    body_head = body[:500].lower()
    return "function(" in body_head or "const " in body_head or "import " in body_head


def _normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized


def _is_sensitive_param_name(name: str) -> bool:
    lowered = (name or "").strip().lower()
    return any(marker in lowered for marker in _SENSITIVE_PARAM_KEYWORDS)


def _sanitize_preview_value(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if _SENSITIVE_VALUE_RE.search(raw):
        return "[REDACTED]"
    if len(raw) > 120:
        return f"{raw[:120]}...[TRUNCATED]"
    return raw


def _sanitize_example_value(param_name: str, value: str) -> str:
    if _is_sensitive_param_name(param_name):
        return "[REDACTED]"
    return _sanitize_preview_value(value)


def _sanitize_url_for_artifact(url: str) -> str:
    parsed = urlparse((url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    if not parsed.query:
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"

    safe_pairs: list[tuple[str, str]] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_sensitive_param_name(key) or _SENSITIVE_VALUE_RE.search(value):
            safe_pairs.append((key, "[REDACTED]"))
        else:
            safe_pairs.append((key, _sanitize_preview_value(value)))
    safe_query = urlencode(safe_pairs, doseq=True)
    return urlunparse(parsed._replace(query=safe_query))


def _build_evidence_ref(prefix: str, url: str, *, suffix: str = "") -> str:
    """Build evidence reference using a query-redacted URL."""
    safe_url = _sanitize_url_for_artifact(url)
    if not safe_url:
        safe_url = (url or "").strip()
    return f"{prefix}:{safe_url}{suffix}"


def _host_from_url(url: str) -> str:
    return urlparse(url).netloc.lower()


def _is_valid_redirect_target(redirect_target: str) -> bool:
    parsed = urlparse((redirect_target or "").strip())
    return bool(parsed.scheme and parsed.netloc)


def _is_fetch_empty(fetched: _FetchedPage) -> bool:
    """True if fetch returned no usable content (status 0 or empty body)."""
    return fetched.status == 0 or not (fetched.body or "").strip()


def _build_fetcher(
    fetch_func: Any | None,
    use_mcp: bool,
    timeout: float,
) -> Any:
    """Return callable(url) -> _FetchedPage with explicit backend marker.

    When use_mcp=True and primary fetch (httpx or custom) returns empty,
    falls back to MCP fetch for safe read-only HTML/JS retrieval.
    MCP fetch is used only for safe reads — no payload generation.
    """

    def _safe_httpx(url: str) -> _FetchedPage:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(url)
            content_type = resp.headers.get("content-type", "").split(";")[0].strip()
            body = (resp.text or "")[:_MAX_BODY_BYTES]
            return _FetchedPage(
                url=str(resp.url),
                status=resp.status_code,
                content_type=content_type,
                body=body,
                fetch_backend="httpx",
                evidence_ref=_build_evidence_ref("httpx", url),
            )
        except Exception:
            logger.info(
                "stage1_enrichment_fetch_httpx_failed",
                extra={"url": _sanitize_url_for_artifact(url), "error_code": "httpx_fetch_failed"},
            )
            return _FetchedPage(
                url=url,
                status=0,
                content_type="",
                body="",
                fetch_backend="httpx",
                evidence_ref=_build_evidence_ref("httpx", url),
            )

    def _safe_custom(url: str) -> _FetchedPage:
        try:
            data = fetch_func(url)  # type: ignore[misc]
        except Exception:
            logger.info(
                "stage1_enrichment_fetch_custom_failed",
                extra={"url": _sanitize_url_for_artifact(url), "error_code": "custom_fetch_failed"},
            )
            data = {}
        status = int(data.get("status", 0) or 0)
        content_type = str(data.get("content_type", "") or "")
        body = str(data.get("body", "") or "")[:_MAX_BODY_BYTES]
        return _FetchedPage(
            url=url,
            status=status,
            content_type=content_type,
            body=body,
            fetch_backend="custom_fetch",
            evidence_ref=_build_evidence_ref("custom_fetch", url),
        )

    def _safe_mcp(url: str) -> _FetchedPage:
        try:
            data = fetch_url_mcp(url, timeout=timeout, operation="route_endpoint_extraction")
        except Exception:
            logger.info(
                "stage1_enrichment_fetch_mcp_failed",
                extra={"url": _sanitize_url_for_artifact(url), "error_code": "mcp_fetch_failed"},
            )
            return _FetchedPage(
                url=url,
                status=0,
                content_type="",
                body="",
                fetch_backend="mcp_fetch",
                evidence_ref=_build_evidence_ref("mcp_fetch", url),
            )
        status = int(data.get("status", 0) or 0)
        content_type = str(data.get("content_type", "") or "")
        body = str(data.get("body", "") or "")[:_MAX_BODY_BYTES]
        return _FetchedPage(
            url=url,
            status=status,
            content_type=content_type,
            body=body,
            fetch_backend="mcp_fetch",
            evidence_ref=_build_evidence_ref("mcp_fetch", url),
        )

    def _with_mcp_fallback(primary_fetcher: Any, primary_name: str) -> Any:
        """Wrap primary fetcher: on empty result and use_mcp, retry with MCP."""

        def _fetch(url: str) -> _FetchedPage:
            result = primary_fetcher(url)
            if not _is_fetch_empty(result) or not use_mcp:
                return result
            mcp_result = _safe_mcp(url)
            if not _is_fetch_empty(mcp_result):
                logger.info(
                    "stage1_enrichment_mcp_fallback_succeeded",
                    extra={
                        "url": _sanitize_url_for_artifact(url),
                        "primary": primary_name,
                        "error_code": "mcp_fallback_used",
                    },
                )
                return mcp_result
            return result

        return _fetch

    if fetch_func is not None:
        return _with_mcp_fallback(_safe_custom, "custom_fetch")
    return _with_mcp_fallback(_safe_httpx, "httpx")


def _route_classification(path_or_url: str) -> str:
    lowered = path_or_url.lower()
    for marker, cls in [
        ("login", "login_flow"),
        ("signin", "login_flow"),
        ("reset", "password_reset_flow"),
        ("forgot", "password_reset_flow"),
        ("contact", "contact_flow"),
        ("portal", "portal_flow"),
        ("admin", "admin_flow"),
        ("account", "account_flow"),
        ("user", "user_flow"),
    ]:
        if marker in lowered:
            return cls
    return "public_page"


def _param_category(name: str) -> str:
    lowered = name.lower()
    if any(x in lowered for x in ("search", "q", "query")):
        return "search"
    if any(x in lowered for x in ("filter", "sort", "order")):
        return "filter"
    if any(x in lowered for x in ("file", "upload", "attachment")):
        return "file"
    if any(x in lowered for x in ("callback", "cb", "hook")):
        return "callback"
    if any(x in lowered for x in ("redirect", "return", "next", "continue")):
        return "redirect"
    if any(x in lowered for x in ("id", "uuid", "token", "session", "state")):
        return "id_state"
    return "general"


def _build_stage3_readiness(
    *,
    route_classification_rows: list[dict[str, Any]],
    params_rows: list[dict[str, Any]],
    api_rows: list[dict[str, Any]],
    content_cluster_rows: list[dict[str, Any]],
    redirect_cluster_rows: list[dict[str, Any]],
    frontend_backend_boundaries_md: str,
) -> Stage3ReadinessResult:
    """Build Stage3ReadinessResult from recon artifacts for stage3_preparation_summary input."""
    route_count = len(route_classification_rows)
    params_count = len(params_rows)
    api_count = len(api_rows)
    content_count = len(content_cluster_rows)
    redirect_count = len(redirect_cluster_rows)
    has_boundaries = bool(frontend_backend_boundaries_md and frontend_backend_boundaries_md.strip())

    route_score = min(1.0, route_count / 20.0) if route_count else 0.0
    input_score = min(1.0, params_count / 15.0) if params_count else 0.0
    api_score = min(1.0, api_count / 10.0) if api_count else 0.0
    content_score = min(1.0, (content_count + redirect_count) / 10.0) if (content_count or redirect_count) else 0.0
    boundary_score = 1.0 if has_boundaries else 0.0

    coverage_scores = CoverageScores(
        route=round(route_score, 2),
        input_surface=round(input_score, 2),
        api_surface=round(api_score, 2),
        content_anomaly=round(content_score, 2),
        boundary_mapping=round(boundary_score, 2),
    )

    avg_score = (
        route_score + input_score + api_score + content_score + boundary_score
    ) / 5.0
    if avg_score >= 0.7:
        status: str = "ready_for_stage3"
    elif avg_score >= 0.3:
        status = "partially_ready_for_stage3"
    else:
        status = "not_ready_for_stage3"

    missing_evidence: list[str] = []
    if route_count == 0:
        missing_evidence.append("route_classification.csv")
    if params_count == 0:
        missing_evidence.append("params_inventory.csv")
    if api_count == 0:
        missing_evidence.append("api_surface.csv")
    if not content_count and not redirect_count:
        missing_evidence.append("content_clusters.csv or redirect_clusters.csv")
    if not has_boundaries:
        missing_evidence.append("frontend_backend_boundaries.md")

    recommended_follow_up: list[str] = []
    if route_score < 0.5:
        recommended_follow_up.append("Expand route discovery for critical flows (login, admin, API).")
    if input_score < 0.5:
        recommended_follow_up.append("Map additional input surfaces (forms, query params).")
    if api_score < 0.5:
        recommended_follow_up.append("Discover and classify API endpoints.")

    return Stage3ReadinessResult(
        status=status,
        missing_evidence=missing_evidence[:100],
        unknowns=[],
        recommended_follow_up=recommended_follow_up[:50],
        coverage_scores=coverage_scores,
    )


def _build_stage3_readiness_md(
    *,
    run_id: str,
    job_id: str,
    trace_id: str,
    result: Stage3ReadinessResult,
) -> str:
    """Build stage3_readiness.md from Stage3ReadinessResult."""
    lines = [
        "# Stage 3 Readiness",
        "",
        f"- Run ID: `{run_id}`",
        f"- Job ID: `{job_id}`",
        f"- Trace ID: `{trace_id}`",
        "",
        f"- **Status**: `{result.status}`",
        "",
        "## Coverage Scores",
        "",
        f"- Route discovery: {result.coverage_scores.route:.2f}",
        f"- Input surface: {result.coverage_scores.input_surface:.2f}",
        f"- API surface: {result.coverage_scores.api_surface:.2f}",
        f"- Content/anomaly: {result.coverage_scores.content_anomaly:.2f}",
        f"- Boundary mapping: {result.coverage_scores.boundary_mapping:.2f}",
        "",
    ]
    if result.missing_evidence:
        lines.extend(["## Missing Evidence", ""] + [f"- {e}" for e in result.missing_evidence[:20]] + [""])
    if result.recommended_follow_up:
        lines.extend(
            ["## Recommended Follow-up", ""]
            + [f"- {r}" for r in result.recommended_follow_up[:15]]
            + [""]
        )
    return "\n".join(lines)


def _normalize_body_fingerprint(body: str) -> str:
    normalized = re.sub(r"\s+", " ", body.lower())
    normalized = re.sub(r"\b\d{2,}\b", "#", normalized)
    normalized = normalized.strip()
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _root_domain(host: str) -> str:
    parts = [p for p in host.lower().split(".") if p]
    if len(parts) < 2:
        return host.lower()
    return ".".join(parts[-2:])


def _is_suspicious_host(host: str) -> bool:
    host_lower = host.lower()
    return any(host_lower.startswith(prefix) for prefix in _SUSPICIOUS_HOST_PREFIXES)


def _build_content_clusters(
    *,
    run_id: str,
    job_id: str,
    public_page_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in public_page_rows:
        content_hash = str(row.get("content_hash", "") or "")
        status = str(row.get("status", "") or "")
        title = str(row.get("title", "") or "")[:120]
        key = (content_hash, status, title)
        grouped.setdefault(key, []).append(row)

    root_keys: dict[str, tuple[str, str, str]] = {}
    for row in public_page_rows:
        host = str(row.get("host", "") or "")
        if not host:
            continue
        if host == _root_domain(host):
            key = (
                str(row.get("content_hash", "") or ""),
                str(row.get("status", "") or ""),
                str(row.get("title", "") or "")[:120],
            )
            root_keys[_root_domain(host)] = key

    clusters: list[dict[str, Any]] = []
    for cluster_idx, (key, rows) in enumerate(
        sorted(grouped.items(), key=lambda item: len(item[1]), reverse=True), start=1
    ):
        content_hash, status, title = key
        cluster_id = f"content_cluster_{cluster_idx}"
        cluster_size = len(rows)
        template_hint = "generic_template"
        if status == "404" and cluster_size > 1:
            template_hint = "shared_404_template"
        elif cluster_size > 2:
            template_hint = "shared_platform_template"

        for row in rows:
            host = str(row.get("host", "") or "")
            root_key = root_keys.get(_root_domain(host))
            similar_to_root = "yes" if root_key == key and bool(root_key) else "no"
            suspicious_host = "yes" if _is_suspicious_host(host) else "no"
            catch_all_hint = "yes" if suspicious_host == "yes" and similar_to_root == "yes" else "no"
            clusters.append(
                {
                    "run_id": run_id,
                    "job_id": job_id,
                    "cluster_id": cluster_id,
                    "cluster_type": "content_fingerprint",
                    "host": host,
                    "url": row.get("url", ""),
                    "status": status,
                    "title": title,
                    "content_hash": content_hash,
                    "cluster_size": cluster_size,
                    "template_hint": template_hint,
                    "suspicious_host": suspicious_host,
                    "similar_to_root": similar_to_root,
                    "catch_all_hint": catch_all_hint,
                    "evidence_ref": row.get("evidence_ref", ""),
                }
            )
    return clusters


def _build_redirect_clusters(
    *,
    run_id: str,
    job_id: str,
    http_probe_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    root_redirects: dict[str, str] = {}
    for row in http_probe_rows:
        host = str(row.get("host", "") or "")
        source_url = str(row.get("url", "") or "")
        redirect_target = str(row.get("redirect", "") or "")
        if not host or not source_url:
            continue
        if not _is_valid_redirect_target(redirect_target):
            continue
        redirect_path = urlparse(redirect_target).path or "/"
        key = (redirect_target, redirect_path)
        groups.setdefault(key, []).append(row)
        if host == _root_domain(host):
            root_redirects[_root_domain(host)] = redirect_target

    rows_out: list[dict[str, Any]] = []
    for cluster_idx, (key, rows) in enumerate(
        sorted(groups.items(), key=lambda item: len(item[1]), reverse=True), start=1
    ):
        redirect_target, redirect_path = key
        cluster_id = f"redirect_cluster_{cluster_idx}"
        for row in rows:
            host = str(row.get("host", "") or "")
            status = str(row.get("status", "") or "")
            source_url = str(row.get("url", "") or "")
            root_target = root_redirects.get(_root_domain(host), "")
            shared_with_root = "yes" if root_target and root_target == redirect_target else "no"
            suspicious = "yes" if _is_suspicious_host(host) else "no"
            cluster_type = "redirect_to_root" if redirect_path in {"", "/"} else "redirect_custom"
            rows_out.append(
                {
                    "run_id": run_id,
                    "job_id": job_id,
                    "redirect_cluster_id": cluster_id,
                    "cluster_type": cluster_type,
                    "host": host,
                    "source_url": source_url,
                    "status": status,
                    "redirect_target": redirect_target,
                    "redirect_target_host": urlparse(redirect_target).netloc if redirect_target else "",
                    "redirect_path": redirect_path,
                    "cluster_size": len(rows),
                    "shared_with_root": shared_with_root,
                    "suspicious_host": suspicious,
                    "evidence_ref": _build_evidence_ref("http_probe", source_url),
                }
            )
    return rows_out


def _build_response_similarity_from_redirect(
    *,
    run_id: str,
    job_id: str,
    trace_id: str,
    redirect_clusters: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build response_similarity rows from redirect_clusters when content_clusters is empty."""
    rows_out: list[dict[str, Any]] = []
    for row in redirect_clusters:
        host = str(row.get("host", "") or "")
        if not host:
            continue
        rows_out.append(
            {
                "run_id": run_id,
                "job_id": job_id,
                "trace_id": trace_id,
                "cluster_id": str(row.get("redirect_cluster_id", "")),
                "host": host,
                "url": str(row.get("source_url", "") or ""),
                "similarity_score": "1.00",
                "template_hint": str(row.get("cluster_type", "redirect")),
                "evidence_ref": str(row.get("evidence_ref", "") or ""),
                "similarity_type": "redirect",
                "shared_redirect_target": str(row.get("redirect_target", "") or ""),
            }
        )
    return rows_out


def _build_anomaly_validation_rows(
    *,
    run_id: str,
    job_id: str,
    trace_id: str,
    content_clusters: list[dict[str, Any]],
    redirect_clusters: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build anomaly_validation.csv rows from content_clusters and redirect_clusters.

    When content_clusters is empty, derives validation from redirect_clusters
    (hosts with shared_with_root, suspicious_host).
    """
    rows_out: list[dict[str, Any]] = []
    hosts_seen: set[str] = set()

    for row in content_clusters:
        host = str(row.get("host", "") or "")
        if not host:
            continue
        anomaly_type, confidence, recommendation = _classify_anomaly(
            suspicious_host=str(row.get("suspicious_host", "no")) == "yes",
            catch_all_hint=str(row.get("catch_all_hint", "no")) == "yes",
            status=str(row.get("status", "") or ""),
            shared_with_root=str(row.get("similar_to_root", "no")) == "yes",
        )
        rows_out.append(
            {
                "run_id": run_id,
                "job_id": job_id,
                "trace_id": trace_id,
                "host": host,
                "classification": anomaly_type,
                "confidence": f"{confidence:.2f}",
                "recommendation": recommendation,
                "evidence_refs": "|".join([str(row.get("evidence_ref", "")), "content_clusters.csv"]),
            }
        )
        hosts_seen.add(host)

    for row in redirect_clusters:
        host = str(row.get("host", "") or "")
        if not host or host in hosts_seen:
            continue
        anomaly_type, confidence, recommendation = _classify_anomaly(
            suspicious_host=str(row.get("suspicious_host", "no")) == "yes",
            catch_all_hint=False,
            status=str(row.get("status", "") or ""),
            shared_with_root=str(row.get("shared_with_root", "no")) == "yes",
        )
        rows_out.append(
            {
                "run_id": run_id,
                "job_id": job_id,
                "trace_id": trace_id,
                "host": host,
                "classification": anomaly_type,
                "confidence": f"{confidence:.2f}",
                "recommendation": recommendation,
                "evidence_refs": "|".join([str(row.get("evidence_ref", "")), "redirect_clusters.csv"]),
            }
        )
        hosts_seen.add(host)

    return rows_out


def _classify_anomaly(
    *,
    suspicious_host: bool,
    catch_all_hint: bool,
    status: str,
    shared_with_root: bool,
) -> tuple[str, float, str]:
    if suspicious_host and catch_all_hint:
        return ("catch_all", 0.86, "Validate wildcard/catch-all routing at edge and app layer.")
    if suspicious_host and status == "404":
        return ("forgotten_infra", 0.74, "Check DNS/CNAME ownership and decommissioned services.")
    if shared_with_root:
        return ("platform_alias", 0.78, "Confirm aliasing is intended and has explicit access controls.")
    if suspicious_host:
        return ("legacy_naming", 0.61, "Validate naming consistency and ownership of legacy labels.")
    return ("intentional_placeholder", 0.55, "Review business intent and exposure surface.")


def _build_anomaly_validation_md(
    *,
    run_id: str,
    job_id: str,
    content_clusters: list[dict[str, Any]],
    redirect_clusters: list[dict[str, Any]],
) -> str:
    lines = [
        "# Anomaly Validation",
        "",
        f"- Run ID: `{run_id}`",
        f"- Job ID: `{job_id}`",
        "- [Evidence] Source artifacts: `content_clusters.csv`, `redirect_clusters.csv`, `public_pages.csv`, `04_live_hosts/http_probe.csv`",
        "",
        "## Classified Anomalies",
        "",
    ]
    by_host: dict[str, dict[str, Any]] = {}
    for row in content_clusters:
        host = str(row.get("host", "") or "")
        if not host:
            continue
        by_host.setdefault(host, {}).update(
            {
                "status": str(row.get("status", "") or ""),
                "suspicious_host": str(row.get("suspicious_host", "no")) == "yes",
                "catch_all_hint": str(row.get("catch_all_hint", "no")) == "yes",
                "evidence_ref": str(row.get("evidence_ref", "") or ""),
            }
        )
    for row in redirect_clusters:
        host = str(row.get("host", "") or "")
        if not host:
            continue
        by_host.setdefault(host, {}).update(
            {
                "shared_with_root": str(row.get("shared_with_root", "no")) == "yes",
                "redirect_evidence_ref": str(row.get("evidence_ref", "") or ""),
            }
        )

    if not by_host:
        lines.extend(
            [
                "- [Observation] No anomalies were classified from current Stage 1 evidence.",
                "",
            ]
        )
    else:
        for host, item in sorted(by_host.items()):
            anomaly_type, confidence, follow_up = _classify_anomaly(
                suspicious_host=bool(item.get("suspicious_host")),
                catch_all_hint=bool(item.get("catch_all_hint")),
                status=str(item.get("status", "")),
                shared_with_root=bool(item.get("shared_with_root")),
            )
            lines.extend(
                [
                    f"### {host}",
                    "",
                    f"- [Observation] classification: `{anomaly_type}`",
                    f"- [Inference] confidence: `{confidence:.2f}`",
                    f"- [Hypothesis] follow-up: {follow_up}",
                    f"- [Evidence] refs: `{item.get('evidence_ref', '')}`, `{item.get('redirect_evidence_ref', '')}`",
                    "",
                ]
            )

    lines.extend(
        [
            "## Recommended Follow-up Queue",
            "",
            "- [Hypothesis] Priority 1: validate `catch_all` and `platform_alias` hosts against expected ownership and auth controls.",
            "- [Hypothesis] Priority 2: validate `forgotten_infra` for dangling CNAME/decommission risk.",
            "- [Hypothesis] Priority 3: confirm `intentional_placeholder` and `legacy_naming` records with asset owners.",
            "",
            "---",
            "",
            "*Generated by ARGUS Stage 1 enrichment (authorized safe recon only).*",
        ]
    )
    return "\n".join(lines)


def _validate_schema(data: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Very small schema validator for object/array/string/number/boolean."""
    if not isinstance(schema, dict):
        return [f"{path}: malformed schema (expected object)"]

    errors: list[str] = []
    expected_type = schema.get("type")
    if expected_type not in {"object", "array", "string", "number", "boolean"}:
        return [f"{path}: malformed schema type '{expected_type}'"]

    if expected_type == "object":
        if not isinstance(data, dict):
            return [f"{path}: expected object"]
        required_keys = schema.get("required", [])
        if not isinstance(required_keys, list):
            return [f"{path}: malformed schema (required must be list)"]
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            return [f"{path}: malformed schema (properties must be object)"]
        for req in required_keys:
            if req not in data:
                errors.append(f"{path}: missing required key '{req}'")
        for key, value in data.items():
            if key in props:
                key_schema = props[key]
                errors.extend(_validate_schema(value, key_schema, f"{path}.{key}"))
        return errors

    if expected_type == "array":
        if not isinstance(data, list):
            return [f"{path}: expected array"]
        item_schema = schema.get("items")
        if item_schema:
            if not isinstance(item_schema, dict):
                return [f"{path}: malformed schema (items must be object)"]
            for idx, item in enumerate(data):
                errors.extend(_validate_schema(item, item_schema, f"{path}[{idx}]"))
        return errors

    if expected_type == "string" and not isinstance(data, str):
        return [f"{path}: expected string"]
    if expected_type == "number" and (
        not isinstance(data, (int, float)) or isinstance(data, bool)
    ):
        return [f"{path}: expected number"]
    if expected_type == "boolean" and not isinstance(data, bool):
        return [f"{path}: expected boolean"]
    return errors


_AI_TEMPLATES: dict[str, dict[str, Any]] = get_recon_ai_task_definitions()


def _persist_ai_task(
    *,
    task_name: str,
    run_id: str,
    job_id: str,
    trace_id: str,
    input_payload: dict[str, Any],
    normalized_output: dict[str, Any],
    source_artifacts: list[str],
    evidence_refs: list[str],
) -> dict[str, str]:
    template = _AI_TEMPLATES[task_name]
    validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=input_payload,
        output_payload=normalized_output,
    )
    run_link = f"recon://runs/{run_id}"
    job_link = f"recon://jobs/{job_id}"
    persistence = template["persistence_mapping"]
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    task_trace_id = f"{trace_id}:{task_name}"

    source_refs = sorted({str(ref) for ref in evidence_refs if str(ref).strip()})
    source_artifact_refs = sorted(
        {
            str(ref).split(":", 1)[0]
            for ref in source_refs
            if "." in str(ref).split(":", 1)[0]
        }
    )
    mcp_trace_refs = sorted(
        {
            "mcp_invocation_audit_meta.json",
            "mcp_invocation_audit.jsonl",
            "mcp_trace.jsonl",
            *(
                "mcp_invocation_audit.jsonl"
                for ref in source_refs
                if ref.startswith("mcp_fetch:") or ref.startswith("mcp:")
            ),
        }
    )

    linkage = {
        "run_id": run_id,
        "job_id": job_id,
        "run_link": run_link,
        "job_link": job_link,
        "trace_id": task_trace_id,
    }
    rendered_prompt = (
        f"Task: {task_name}\n"
        f"Trace ID: {task_trace_id}\n"
        f"Run Link: {run_link}\n"
        f"Job Link: {job_link}\n\n"
        "Prompt Template:\n"
        f"{template['prompt_template']}\n\n"
        "Input Bundle (JSON):\n"
        f"{json.dumps(input_payload, indent=2, ensure_ascii=False)}"
    )

    input_bundle = {
        "task": task_name,
        "generated_at": timestamp,
        **linkage,
        "prompt_template": template["prompt_template"],
        "input_schema": template["input_schema"],
        "input_payload": input_payload,
        "source_artifacts": sorted(set(source_artifacts) | set(source_artifact_refs)),
        "evidence_refs": source_refs,
        "mcp_trace_refs": mcp_trace_refs,
    }
    raw = {
        "task": task_name,
        "generated_at": timestamp,
        **linkage,
        "raw_output": normalized_output,
        "report_section_mapping": template["report_section_mapping"],
        "persistence_mapping": template["persistence_mapping"],
        "evidence_trace": {
            "source_artifacts": sorted(set(source_artifacts) | set(source_artifact_refs)),
            "evidence_refs": source_refs,
            "mcp_trace_refs": mcp_trace_refs,
        },
        "validation": {
            "is_valid": validation["input"]["is_valid"],
            "errors": validation["input"]["errors"],
        },
    }
    normalized = {
        "task": task_name,
        "generated_at": timestamp,
        **linkage,
        "expected_output_schema": template["expected_output_schema"],
        "output": normalized_output,
        "validation_result": {
            "is_valid": validation["output"]["is_valid"],
            "errors": validation["output"]["errors"],
        },
        "report_section_mapping": template["report_section_mapping"],
        "persistence_mapping": template["persistence_mapping"],
        "evidence_trace": {
            "source_artifacts": sorted(set(source_artifacts) | set(source_artifact_refs)),
            "evidence_refs": source_refs,
            "mcp_trace_refs": mcp_trace_refs,
        },
        "validation": {
            "is_valid": validation["output"]["is_valid"],
            "errors": validation["output"]["errors"],
        },
    }
    validation_result = {
        "task": task_name,
        "generated_at": timestamp,
        **linkage,
        "input": validation["input"],
        "output": validation["output"],
    }
    raw_name = persistence["raw"]
    normalized_name = persistence["normalized"]
    input_bundle_name = persistence.get("input_bundle", f"ai_{task_name}_input_bundle.json")
    validation_name = persistence.get("validation", f"ai_{task_name}_validation.json")
    prompt_name = persistence.get("rendered_prompt", f"ai_{task_name}_rendered_prompt.md")
    return {
        raw_name: json.dumps(raw, indent=2, ensure_ascii=False),
        normalized_name: json.dumps(normalized, indent=2, ensure_ascii=False),
        input_bundle_name: json.dumps(input_bundle, indent=2, ensure_ascii=False),
        validation_name: json.dumps(validation_result, indent=2, ensure_ascii=False),
        prompt_name: rendered_prompt,
    }


def _render_js_findings_md(
    *,
    run_id: str,
    job_id: str,
    public_pages_count: int,
    js_bundle_rows: list[dict[str, Any]],
    client_routes: list[dict[str, Any]],
    api_refs: list[dict[str, Any]],
    hidden_hints: list[dict[str, Any]],
    third_party: list[dict[str, Any]],
    feature_flags: list[dict[str, Any]],
    auth_hints: list[dict[str, Any]],
    config_hints: list[dict[str, Any]],
    frontend_markers: list[dict[str, Any]],
) -> str:
    bundles_count = len(js_bundle_rows)
    has_inline_fallback = bundles_count == 0 and (
        client_routes or api_refs or third_party or config_hints
    )
    lines = [
        "# JavaScript Findings",
        "",
        f"- Run ID: `{run_id}`",
        f"- Job ID: `{job_id}`",
        f"- Public pages analyzed: `{public_pages_count}`",
        f"- JS bundles discovered: `{bundles_count}`",
        "",
    ]
    if has_inline_fallback:
        lines.extend(
            [
                "*No external JS bundles fetched (all out-of-scope or none). Findings below extracted from inline scripts in HTML.*",
                "",
            ]
        )
    lines.append("## Client Routes")
    lines.extend(
        [f"- `{x['value']}` (evidence: `{x['evidence_ref']}`)" for x in client_routes[:25]]
        or ["- No evidence found."]
    )
    lines.extend(["", "## API References"])
    lines.extend(
        [f"- `{x['value']}` (evidence: `{x['evidence_ref']}`)" for x in api_refs[:25]]
        or ["- No evidence found."]
    )
    lines.extend(["", "## Hidden Endpoint Hints"])
    lines.extend(
        [f"- `{x['value']}` (evidence: `{x['evidence_ref']}`)" for x in hidden_hints[:25]]
        or ["- No evidence found."]
    )
    lines.extend(["", "## Third-Party Integrations"])
    lines.extend(
        [f"- `{x['value']}` (evidence: `{x['evidence_ref']}`)" for x in third_party[:25]]
        or ["- No evidence found."]
    )
    lines.extend(["", "## Feature Flags"])
    lines.extend(
        [f"- `{x['value']}` (evidence: `{x['evidence_ref']}`)" for x in feature_flags[:25]]
        or ["- No evidence found."]
    )
    lines.extend(["", "## Auth Flow Hints"])
    lines.extend(
        [f"- `{x['value']}` (evidence: `{x['evidence_ref']}`)" for x in auth_hints[:25]]
        or ["- No evidence found."]
    )
    lines.extend(["", "## Public Config Hints"])
    lines.extend(
        [f"- `{x['value']}` (evidence: `{x['evidence_ref']}`)" for x in config_hints[:25]]
        or ["- No evidence found."]
    )
    lines.extend(["", "## Frontend Markers"])
    lines.extend(
        [f"- `{x['value']}` (evidence: `{x['evidence_ref']}`)" for x in frontend_markers[:25]]
        or ["- No evidence found."]
    )
    lines.extend(
        [
            "",
            "---",
            "",
            "*Generated by ARGUS Stage 1 enrichment (authorized safe recon only).*",
        ]
    )
    return "\n".join(lines)


def build_stage1_enrichment_artifacts(
    recon_dir: str | Path,
    live_hosts: list[str],
    endpoint_inventory_path: str | Path | None = None,
    fetch_func: Any | None = None,
    use_mcp: bool = True,
    timeout: float = 10.0,
    trace_id: str | None = None,
) -> dict[str, str]:
    """Build Stage 1 enrichment artifacts and AI task raw/normalized outputs."""
    base = Path(recon_dir)
    run_id = base.name
    job_id = f"{run_id}-stage1"
    trace_token = trace_id or f"{run_id}-{job_id}-enrichment"
    fetch_page = _build_fetcher(fetch_func=fetch_func, use_mcp=use_mcp, timeout=timeout)

    http_probe_rows = parse_http_probe(base / "04_live_hosts" / "http_probe.csv")
    endpoint_rows: list[dict[str, Any]] = []
    if endpoint_inventory_path:
        ep_path = Path(endpoint_inventory_path)
        if ep_path.exists():
            with ep_path.open(encoding="utf-8", errors="replace", newline="") as f:
                endpoint_rows = list(csv.DictReader(f))
    if not endpoint_rows:
        ep_path = base / "endpoint_inventory.csv"
        if ep_path.exists():
            try:
                with ep_path.open(encoding="utf-8", errors="replace", newline="") as f:
                    endpoint_rows = list(csv.DictReader(f))
            except (OSError, csv.Error):
                endpoint_rows = []

    crawl_targets: list[str] = []
    seen_targets: set[str] = set()

    def _add_target(url: str) -> None:
        n = _normalize_url(url)
        if n and n not in seen_targets:
            seen_targets.add(n)
            crawl_targets.append(n)

    for row in http_probe_rows:
        _add_target(row.get("url", ""))
    for row in endpoint_rows:
        if str(row.get("exists", "")).lower() == "yes":
            _add_target(str(row.get("url", "")))
    if not http_probe_rows and endpoint_rows:
        for row in endpoint_rows:
            _add_target(str(row.get("url", "") or ""))
    for base_url in live_hosts:
        for path in _ROUTE_CANDIDATE_PATHS:
            _add_target(f"{base_url.rstrip('/')}{path}")

    crawl_targets = crawl_targets[:_MAX_PAGES]
    in_scope_hosts: set[str] = {_host_from_url(url) for url in live_hosts if _host_from_url(url)}
    in_scope_hosts.update(str(row.get("host", "") or "").lower() for row in http_probe_rows if row.get("host"))
    in_scope_hosts.update(
        _host_from_url(str(row.get("url", "") or ""))
        for row in http_probe_rows
        if _host_from_url(str(row.get("url", "") or ""))
    )
    if not in_scope_hosts:
        in_scope_hosts.update(_host_from_url(url) for url in crawl_targets if _host_from_url(url))

    route_rows: list[dict[str, Any]] = []
    public_page_rows: list[dict[str, Any]] = []
    forms_rows: list[dict[str, Any]] = []
    params_rows: list[dict[str, Any]] = []
    js_bundle_rows: list[dict[str, Any]] = []
    api_rows: list[dict[str, Any]] = []

    js_client_routes: list[dict[str, Any]] = []
    js_api_refs: list[dict[str, Any]] = []
    js_hidden_hints: list[dict[str, Any]] = []
    js_third_party: list[dict[str, Any]] = []
    js_feature_flags: list[dict[str, Any]] = []
    js_auth_hints: list[dict[str, Any]] = []
    js_config_hints: list[dict[str, Any]] = []
    js_frontend_markers: list[dict[str, Any]] = []

    seen_forms: set[tuple[str, str, str, str]] = set()
    seen_params: set[tuple[str, str, str]] = set()
    seen_api: set[tuple[str, str]] = set()
    seen_routes: set[tuple[str, str, str]] = set()
    seen_js_bundle: set[tuple[str, str]] = set()
    js_bundle_index: dict[tuple[str, str], dict[str, Any]] = {}
    script_targets: list[tuple[str, str, str]] = []
    seen_script_targets: set[tuple[str, str]] = set()

    def _append_route(
        *,
        source: str,
        url: str,
        status: int,
        content_type: str,
        evidence_ref: str,
        fetch_backend: str,
        skipped_reason: str = "",
    ) -> None:
        safe_url = _sanitize_url_for_artifact(url)
        parsed = urlparse(url)
        route_path = parsed.path or "/"
        key = (safe_url, source, evidence_ref)
        if key in seen_routes:
            return
        seen_routes.add(key)
        route_rows.append(
            {
                "run_id": run_id,
                "job_id": job_id,
                "host": parsed.netloc,
                "url": safe_url,
                "route_path": route_path,
                "discovery_source": source,
                "classification": _route_classification(url),
                "status": status,
                "content_type": content_type,
                "fetch_backend": fetch_backend,
                "evidence_ref": evidence_ref,
                "skipped_reason": skipped_reason,
            }
        )

        for param_name, value in parse_qsl(parsed.query, keep_blank_values=True):
            pkey = (safe_url, param_name, "query")
            if pkey in seen_params:
                continue
            seen_params.add(pkey)
            params_rows.append(
                {
                    "run_id": run_id,
                    "job_id": job_id,
                    "param_name": param_name,
                    "param_source": "query",
                    "param_category": _param_category(param_name),
                    "example_value": _sanitize_example_value(param_name, value),
                    "context_url": safe_url,
                    "pattern_hint": "",
                    "evidence_ref": evidence_ref,
                }
            )

        if _ID_PATH_RE.search(route_path) or re.search(r"/\d{2,}", route_path):
            pkey = (safe_url, "id_path_pattern", "id_state")
            if pkey not in seen_params:
                seen_params.add(pkey)
                params_rows.append(
                    {
                        "run_id": run_id,
                        "job_id": job_id,
                        "param_name": "id_path_pattern",
                        "param_source": "path",
                        "param_category": "id_state",
                        "example_value": _sanitize_preview_value(route_path),
                        "context_url": safe_url,
                        "pattern_hint": "state_transition_or_identifier",
                        "evidence_ref": evidence_ref,
                    }
                )

    def _get_or_create_js_bundle_row(
        *,
        page_url: str,
        script_url: str,
        fetch_backend: str,
        evidence_ref: str,
        is_third_party: bool,
    ) -> dict[str, Any]:
        safe_page_url = _sanitize_url_for_artifact(page_url)
        safe_script_url = _sanitize_url_for_artifact(script_url)
        key = (safe_page_url, safe_script_url)
        existing = js_bundle_index.get(key)
        if existing is not None:
            return existing

        row = {
            "run_id": run_id,
            "job_id": job_id,
            "page_url": safe_page_url,
            "script_url": safe_script_url,
            "origin": "external" if is_third_party else "same_origin",
            "type": "script_src",
            "is_third_party": "yes" if is_third_party else "no",
            "fetch_status": 0,
            "fetch_backend": fetch_backend,
            "evidence_ref": evidence_ref,
            "skipped_reason": "",
        }
        js_bundle_rows.append(row)
        js_bundle_index[key] = row
        return row

    for target_url in crawl_targets:
        target_host = _host_from_url(target_url)
        if not target_host or target_host not in in_scope_hosts:
            _append_route(
                source="public_crawl",
                url=target_url,
                status=0,
                content_type="",
                evidence_ref=_build_evidence_ref("scope_filter", target_url),
                fetch_backend="scope_filter",
                skipped_reason="out_of_scope",
            )
            continue
        fetched = fetch_page(target_url)
        _append_route(
            source="public_crawl",
            url=fetched.url or target_url,
            status=fetched.status,
            content_type=fetched.content_type,
            evidence_ref=fetched.evidence_ref,
            fetch_backend=fetched.fetch_backend,
        )

        if fetched.status < 400 and _is_html_like(fetched.content_type, fetched.body):
            parser = _HtmlEvidenceParser()
            try:
                parser.feed(fetched.body[:_MAX_BODY_BYTES])
            except Exception:
                logger.info(
                    "stage1_enrichment_html_parse_failed",
                    extra={"url": _sanitize_url_for_artifact(fetched.url), "run_id": run_id},
                )
            public_page_rows.append(
                {
                    "run_id": run_id,
                    "job_id": job_id,
                    "host": urlparse(fetched.url).netloc,
                    "url": _sanitize_url_for_artifact(fetched.url),
                    "title": parser.title[:180],
                    "status": fetched.status,
                    "form_count": len(parser.forms),
                    "link_count": len(parser.links),
                    "classification": _route_classification(fetched.url),
                    "content_hash": _normalize_body_fingerprint(fetched.body[:_MAX_BODY_BYTES]),
                    "fetch_backend": fetched.fetch_backend,
                    "evidence_ref": fetched.evidence_ref,
                }
            )

            for href in parser.links[:120]:
                linked = _normalize_url(urljoin(fetched.url, href))
                if not linked:
                    continue
                _append_route(
                    source="internal_link",
                    url=linked,
                    status=0,
                    content_type="",
                    evidence_ref=_build_evidence_ref("html_link", fetched.url),
                    fetch_backend=fetched.fetch_backend,
                )

            for form_idx, form in enumerate(parser.forms, 1):
                action = _normalize_url(urljoin(fetched.url, form.get("action", ""))) or fetched.url
                safe_action = _sanitize_url_for_artifact(action)
                safe_page_url = _sanitize_url_for_artifact(fetched.url)
                method = str(form.get("method", "GET")).upper()
                _append_route(
                    source="form_action",
                    url=action,
                    status=0,
                    content_type="",
                    evidence_ref=_build_evidence_ref("html_form", fetched.url, suffix=f"#{form_idx}"),
                    fetch_backend=fetched.fetch_backend,
                )
                for input_meta in form.get("inputs", []):
                    input_name = str(input_meta.get("name", "")).strip()
                    input_type = str(input_meta.get("type", "text")).strip() or "text"
                    row_key = (safe_page_url, safe_action, input_name, input_type)
                    if row_key in seen_forms:
                        continue
                    seen_forms.add(row_key)
                    forms_rows.append(
                        {
                            "run_id": run_id,
                            "job_id": job_id,
                            "page_url": safe_page_url,
                            "form_index": form_idx,
                            "method": method,
                            "action": safe_action,
                            "input_name": input_name,
                            "input_type": input_type,
                            "required": "yes" if bool(input_meta.get("required")) else "no",
                            "classification": _param_category(input_name or input_type),
                            "evidence_ref": _build_evidence_ref(
                                "html_form",
                                fetched.url,
                                suffix=f"#{form_idx}",
                            ),
                        }
                    )
                    if input_name:
                        pkey = (safe_page_url, input_name, "form_input")
                        if pkey not in seen_params:
                            seen_params.add(pkey)
                            params_rows.append(
                                {
                                    "run_id": run_id,
                                    "job_id": job_id,
                                    "param_name": input_name,
                                    "param_source": "form_input",
                                    "param_category": _param_category(input_name),
                                    "example_value": "",
                                    "context_url": safe_page_url,
                                    "pattern_hint": f"type:{input_type}",
                                    "evidence_ref": _build_evidence_ref(
                                        "html_form",
                                        fetched.url,
                                        suffix=f"#{form_idx}",
                                    ),
                                }
                            )

                if _API_HINT_RE.search(action):
                    api_key = (urlparse(action).netloc, urlparse(action).path)
                    if api_key not in seen_api:
                        seen_api.add(api_key)
                        api_rows.append(
                            {
                                "run_id": run_id,
                                "job_id": job_id,
                                "host": urlparse(action).netloc,
                                "path": urlparse(action).path or "/",
                                "full_url": safe_action,
                                "source": "form_action",
                                "api_type": "rest_like",
                                "method_hint": method,
                                "schema_hint": "unknown",
                                "auth_boundary_hint": (
                                    "auth_related" if _AUTH_HINT_RE.search(action) else "unknown"
                                ),
                                "fetch_backend": fetched.fetch_backend,
                                "evidence_ref": _build_evidence_ref(
                                    "html_form",
                                    fetched.url,
                                    suffix=f"#{form_idx}",
                                ),
                            }
                        )

            for inline_content in parser.inline_scripts[:20]:
                inline_evidence = _build_evidence_ref("html_inline_script", fetched.url)
                extracted = _extract_from_inline_script(
                    content=inline_content[:_MAX_JS_BYTES],
                    page_url=fetched.url,
                    evidence_ref=inline_evidence,
                )
                for item in extracted["routes"]:
                    js_client_routes.append(item)
                    _append_route(
                        source="js_route_hint",
                        url=urljoin(fetched.url, item["value"]),
                        status=0,
                        content_type="",
                        evidence_ref=item["evidence_ref"],
                        fetch_backend=fetched.fetch_backend,
                    )
                for item in extracted["api_refs"]:
                    js_api_refs.append(item)
                    full_url = item["value"]
                    parsed_api = urlparse(full_url)
                    api_key = (parsed_api.netloc, parsed_api.path or "/")
                    if api_key not in seen_api:
                        seen_api.add(api_key)
                        api_rows.append(
                            {
                                "run_id": run_id,
                                "job_id": job_id,
                                "host": parsed_api.netloc,
                                "path": parsed_api.path or "/",
                                "full_url": full_url,
                                "source": "js_api_ref",
                                "api_type": "graphql" if "graphql" in (parsed_api.path or "").lower() else "rest_like",
                                "method_hint": "unknown",
                                "schema_hint": "unknown",
                                "auth_boundary_hint": (
                                    "auth_related" if _AUTH_HINT_RE.search(full_url) else "frontend_to_backend"
                                ),
                                "fetch_backend": fetched.fetch_backend,
                                "evidence_ref": item["evidence_ref"],
                            }
                        )
                for item in extracted["third_party"]:
                    js_third_party.append(item)
                for item in extracted["config_hints"]:
                    js_config_hints.append(item)
                for item in extracted["feature_flags"]:
                    js_feature_flags.append(item)
                for item in extracted["auth_hints"]:
                    js_auth_hints.append(item)
                for item in extracted["hidden_hints"]:
                    js_hidden_hints.append(item)

            for script_src in parser.scripts[:80]:
                script_url = _normalize_url(urljoin(fetched.url, script_src))
                if not script_url:
                    continue
                safe_page_url = _sanitize_url_for_artifact(fetched.url)
                safe_script_url = _sanitize_url_for_artifact(script_url)
                bundle_key = (safe_page_url, safe_script_url)
                if bundle_key not in seen_js_bundle:
                    seen_js_bundle.add(bundle_key)
                    is_third_party = (
                        urlparse(script_url).netloc
                        and urlparse(script_url).netloc != urlparse(fetched.url).netloc
                    )
                    _get_or_create_js_bundle_row(
                        page_url=fetched.url,
                        script_url=script_url,
                        fetch_backend=fetched.fetch_backend,
                        evidence_ref=_build_evidence_ref("html_script", fetched.url),
                        is_third_party=is_third_party,
                    )
                page_host = _host_from_url(fetched.url)
                script_host = _host_from_url(script_url)
                same_origin_in_scope = (
                    bool(page_host)
                    and page_host == script_host
                    and page_host in in_scope_hosts
                )
                if not same_origin_in_scope:
                    row = js_bundle_index.get((safe_page_url, safe_script_url))
                    if row is not None:
                        row["skipped_reason"] = "out_of_scope"
                    continue
                script_target_key = (safe_page_url, safe_script_url)
                if len(script_targets) < _MAX_SCRIPTS and script_target_key not in seen_script_targets:
                    seen_script_targets.add(script_target_key)
                    script_targets.append((fetched.url, script_url, fetched.fetch_backend))

    for page_url, script_url, page_fetch_backend in script_targets:
        fetched_script = fetch_page(script_url)
        body = fetched_script.body[:_MAX_JS_BYTES]
        if not _is_js_like(script_url, fetched_script.content_type, body):
            continue

        js_row = js_bundle_index.get(
            (_sanitize_url_for_artifact(page_url), _sanitize_url_for_artifact(script_url))
        )
        if js_row is not None:
            js_row["fetch_status"] = fetched_script.status
            js_row["fetch_backend"] = fetched_script.fetch_backend or page_fetch_backend

        for match in _CLIENT_ROUTE_RE.finditer(body):
            value = match.group("route")
            if value.count("/") < 1 or len(value) > 120:
                continue
            js_client_routes.append({"value": value, "evidence_ref": _build_evidence_ref("js", script_url)})
            _append_route(
                source="js_route_hint",
                url=urljoin(page_url, value),
                status=0,
                content_type="",
                evidence_ref=_build_evidence_ref("js", script_url),
                fetch_backend=fetched_script.fetch_backend,
            )

        for match in _API_HINT_RE.finditer(body):
            path = match.group("path")
            full_url = urljoin(page_url, path)
            safe_full_url = _sanitize_url_for_artifact(full_url)
            js_api_refs.append({"value": safe_full_url, "evidence_ref": _build_evidence_ref("js", script_url)})
            api_key = (urlparse(full_url).netloc, urlparse(full_url).path)
            if api_key not in seen_api:
                seen_api.add(api_key)
                api_rows.append(
                    {
                        "run_id": run_id,
                        "job_id": job_id,
                        "host": urlparse(full_url).netloc,
                        "path": urlparse(full_url).path or "/",
                        "full_url": safe_full_url,
                        "source": "js_api_ref",
                        "api_type": "graphql" if "graphql" in path.lower() else "rest_like",
                        "method_hint": "unknown",
                        "schema_hint": "unknown",
                        "auth_boundary_hint": (
                            "auth_related" if _AUTH_HINT_RE.search(full_url) else "frontend_to_backend"
                        ),
                        "fetch_backend": fetched_script.fetch_backend,
                        "evidence_ref": _build_evidence_ref("js", script_url),
                    }
                )

        if "hidden" in body.lower() or "internal" in body.lower():
            js_hidden_hints.append({"value": script_url, "evidence_ref": _build_evidence_ref("js", script_url)})
        if _THIRD_PARTY_RE.search(script_url):
            js_third_party.append({"value": script_url, "evidence_ref": _build_evidence_ref("js", script_url)})
        if _FEATURE_FLAG_RE.search(body):
            js_feature_flags.append({"value": script_url, "evidence_ref": _build_evidence_ref("js", script_url)})
        if _AUTH_HINT_RE.search(body):
            js_auth_hints.append({"value": script_url, "evidence_ref": _build_evidence_ref("js", script_url)})
        if _CONFIG_HINT_RE.search(body):
            js_config_hints.append({"value": script_url, "evidence_ref": _build_evidence_ref("js", script_url)})

        markers = []
        lowered = body.lower()
        for marker in ("react", "next", "vue", "nuxt", "angular", "svelte"):
            if marker in lowered:
                markers.append(marker)
        for marker in markers:
            js_frontend_markers.append(
                {
                    "value": f"{marker} marker in {script_url}",
                    "evidence_ref": _build_evidence_ref("js", script_url),
                }
            )

    for row_idx, ep_row in enumerate(endpoint_rows, start=1):
        if str(ep_row.get("exists", "")).lower() != "yes":
            continue
        url = str(ep_row.get("url", "") or "").strip()
        if not url:
            continue
        parsed = urlparse(url)
        path = parsed.path or "/"
        content_type = str(ep_row.get("content_type", "") or "").lower()
        is_json_ct = "application/json" in content_type or "json" in content_type
        is_api_path = (
            _API_HINT_RE.search(path)
            or "/api/" in path.lower()
            or "graphql" in path.lower()
            or is_json_ct
        )
        if not is_api_path:
            continue
        api_key = (parsed.netloc, path)
        if api_key in seen_api:
            continue
        seen_api.add(api_key)
        schema_hint = "json" if is_json_ct else "unknown"
        api_rows.append(
            {
                "run_id": run_id,
                "job_id": job_id,
                "host": parsed.netloc,
                "path": path,
                "full_url": _sanitize_url_for_artifact(url),
                "source": "endpoint_inventory",
                "api_type": "graphql" if "graphql" in path.lower() else "rest_like",
                "method_hint": "GET",
                "schema_hint": schema_hint,
                "auth_boundary_hint": (
                    "auth_related" if _AUTH_HINT_RE.search(url) else "unknown"
                ),
                "fetch_backend": "endpoint_inventory",
                "evidence_ref": f"endpoint_inventory.csv:{row_idx}",
            }
        )

    for route in route_rows:
        url = str(route.get("url", ""))
        if not url:
            continue
        parsed = urlparse(url)
        path = parsed.path or "/"
        if _API_HINT_RE.search(path):
            api_key = (parsed.netloc, path)
            if api_key not in seen_api:
                seen_api.add(api_key)
                api_rows.append(
                    {
                        "run_id": run_id,
                        "job_id": job_id,
                        "host": parsed.netloc,
                        "path": path,
                        "full_url": _sanitize_url_for_artifact(url),
                        "source": "route_inventory",
                        "api_type": "graphql" if "graphql" in path.lower() else "rest_like",
                        "method_hint": "GET",
                        "schema_hint": "unknown",
                        "auth_boundary_hint": (
                            "auth_related" if _AUTH_HINT_RE.search(url) else "unknown"
                        ),
                        "fetch_backend": route.get("fetch_backend", ""),
                        "evidence_ref": route.get("evidence_ref", ""),
                    }
                )

    for row in http_probe_rows:
        source_url = str(row.get("url", "") or "").strip()
        if not source_url or "?" not in source_url:
            continue
        parsed = urlparse(source_url)
        if not parsed.query:
            continue
        safe_url = _sanitize_url_for_artifact(source_url)
        for param_name, value in parse_qsl(parsed.query, keep_blank_values=True):
            param_name = (param_name or "").strip()
            if not param_name:
                continue
            pkey = (safe_url, param_name, "query")
            if pkey in seen_params:
                continue
            seen_params.add(pkey)
            params_rows.append(
                {
                    "run_id": run_id,
                    "job_id": job_id,
                    "param_name": param_name,
                    "param_source": "http_probe_url",
                    "param_category": _param_category(param_name),
                    "example_value": _sanitize_example_value(param_name, value),
                    "context_url": safe_url,
                    "pattern_hint": "",
                    "evidence_ref": _build_evidence_ref("http_probe", source_url),
                }
            )

    route_columns = [
        "run_id",
        "job_id",
        "host",
        "url",
        "route_path",
        "discovery_source",
        "classification",
        "status",
        "content_type",
        "fetch_backend",
        "evidence_ref",
        "skipped_reason",
    ]

    route_classification_rows: list[dict[str, Any]] = []
    for row in route_rows:
        route_path = str(row.get("route_path", "") or "").strip()
        if not route_path:
            continue
        host = str(row.get("host", "") or "").strip()
        if not host:
            continue
        classification = str(row.get("classification", "") or "").strip()
        if not classification:
            classification = _route_classification(row.get("url", "") or route_path)
        discovery_source = str(row.get("discovery_source", "") or "").strip()
        if not discovery_source:
            discovery_source = "unknown"
        evidence_ref = str(row.get("evidence_ref", "") or "").strip()
        route_classification_rows.append(
            {
                "route": route_path,
                "host": host,
                "classification": classification,
                "discovery_source": discovery_source,
                "evidence_ref": evidence_ref,
            }
        )
    public_columns = [
        "run_id",
        "job_id",
        "host",
        "url",
        "title",
        "status",
        "form_count",
        "link_count",
        "classification",
        "content_hash",
        "fetch_backend",
        "evidence_ref",
    ]
    forms_columns = [
        "run_id",
        "job_id",
        "page_url",
        "form_index",
        "method",
        "action",
        "input_name",
        "input_type",
        "required",
        "classification",
        "evidence_ref",
    ]
    params_columns = [
        "run_id",
        "job_id",
        "param_name",
        "param_source",
        "param_category",
        "example_value",
        "context_url",
        "pattern_hint",
        "evidence_ref",
    ]
    js_bundle_columns = [
        "run_id",
        "job_id",
        "page_url",
        "script_url",
        "origin",
        "type",
        "is_third_party",
        "fetch_status",
        "fetch_backend",
        "evidence_ref",
        "skipped_reason",
    ]
    api_columns = [
        "run_id",
        "job_id",
        "host",
        "path",
        "full_url",
        "source",
        "api_type",
        "method_hint",
        "schema_hint",
        "auth_boundary_hint",
        "fetch_backend",
        "evidence_ref",
    ]
    content_cluster_rows = _build_content_clusters(
        run_id=run_id,
        job_id=job_id,
        public_page_rows=public_page_rows,
    )
    redirect_cluster_rows = _build_redirect_clusters(
        run_id=run_id,
        job_id=job_id,
        http_probe_rows=http_probe_rows,
    )
    anomaly_validation_md = _build_anomaly_validation_md(
        run_id=run_id,
        job_id=job_id,
        content_clusters=content_cluster_rows,
        redirect_clusters=redirect_cluster_rows,
    )
    content_cluster_columns = [
        "run_id",
        "job_id",
        "cluster_id",
        "cluster_type",
        "host",
        "url",
        "status",
        "title",
        "content_hash",
        "cluster_size",
        "template_hint",
        "suspicious_host",
        "similar_to_root",
        "catch_all_hint",
        "evidence_ref",
    ]
    redirect_cluster_columns = [
        "run_id",
        "job_id",
        "redirect_cluster_id",
        "cluster_type",
        "host",
        "source_url",
        "status",
        "redirect_target",
        "redirect_target_host",
        "redirect_path",
        "cluster_size",
        "shared_with_root",
        "suspicious_host",
        "evidence_ref",
    ]

    js_findings_md = _render_js_findings_md(
        run_id=run_id,
        job_id=job_id,
        public_pages_count=len(public_page_rows),
        js_bundle_rows=js_bundle_rows,
        client_routes=js_client_routes,
        api_refs=js_api_refs,
        hidden_hints=js_hidden_hints,
        third_party=js_third_party,
        feature_flags=js_feature_flags,
        auth_hints=js_auth_hints,
        config_hints=js_config_hints,
        frontend_markers=js_frontend_markers,
    )

    headers_rows: list[dict[str, str]] = []
    headers_path = base / "headers_detailed.csv"
    if headers_path.exists():
        try:
            with headers_path.open(encoding="utf-8", errors="replace", newline="") as f:
                headers_rows = list(csv.DictReader(f))
        except (OSError, csv.Error):
            headers_rows = []
    tls_summary_text = ""
    tls_summary_path = base / "tls_summary.md"
    if tls_summary_path.exists():
        try:
            tls_summary_text = tls_summary_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            tls_summary_text = ""

    js_routes_rows = [
        {
            "run_id": run_id,
            "job_id": job_id,
            "trace_id": trace_token,
            "route_hint": row["value"],
            "evidence_ref": row["evidence_ref"],
        }
        for row in js_client_routes
    ]
    js_api_ref_rows = [
        {
            "run_id": run_id,
            "job_id": job_id,
            "trace_id": trace_token,
            "api_ref": row["value"],
            "evidence_ref": row["evidence_ref"],
        }
        for row in js_api_refs
    ]
    js_integration_rows = [
        {
            "run_id": run_id,
            "job_id": job_id,
            "trace_id": trace_token,
            "integration_hint": row["value"],
            "integration_type": "third_party_script",
            "evidence_ref": row["evidence_ref"],
        }
        for row in js_third_party
    ]
    js_config_hint_rows = [
        {
            "run_id": run_id,
            "job_id": job_id,
            "trace_id": trace_token,
            "config_hint": row["value"],
            "evidence_ref": row["evidence_ref"],
        }
        for row in js_config_hints
    ]
    input_surfaces_rows: list[dict[str, Any]] = []
    seen_input_surfaces: set[tuple[str, str, str]] = set()
    for row in params_rows:
        surface_name = str(row.get("param_name", "") or "").strip()
        if not surface_name:
            continue
        surface_type = str(row.get("param_source", "") or "").strip() or "query"
        context_url = str(row.get("context_url", "") or "").strip()
        key = (surface_type, surface_name, context_url)
        if key in seen_input_surfaces:
            continue
        seen_input_surfaces.add(key)
        input_surfaces_rows.append(
            {
                "run_id": run_id,
                "job_id": job_id,
                "trace_id": trace_token,
                "surface_type": surface_type,
                "surface_name": surface_name,
                "context_url": context_url,
                "classification": row.get("param_category", ""),
                "evidence_ref": row.get("evidence_ref", ""),
            }
        )
    for row in forms_rows:
        surface_name = str(row.get("input_name", "") or "").strip()
        if not surface_name:
            continue
        context_url = str(row.get("page_url", "") or "").strip()
        key = ("form_input", surface_name, context_url)
        if key in seen_input_surfaces:
            continue
        seen_input_surfaces.add(key)
        input_surfaces_rows.append(
            {
                "run_id": run_id,
                "job_id": job_id,
                "trace_id": trace_token,
                "surface_type": "form_input",
                "surface_name": surface_name,
                "context_url": context_url,
                "classification": row.get("classification", ""),
                "evidence_ref": row.get("evidence_ref", ""),
            }
        )

    route_param_map_rows: list[dict[str, Any]] = []
    by_context: dict[str, list[dict[str, Any]]] = {}
    for row in params_rows:
        ctx = str(row.get("context_url", "") or "").strip()
        if not ctx:
            continue
        by_context.setdefault(ctx, []).append(row)
    for context_url, grouped in by_context.items():
        param_names = sorted({str(item.get("param_name", "")).strip() for item in grouped if str(item.get("param_name", "")).strip()})
        if not param_names:
            continue
        route_param_map_rows.append(
            {
                "run_id": run_id,
                "job_id": job_id,
                "trace_id": trace_token,
                "context_url": context_url,
                "route_path": urlparse(context_url).path or "/",
                "param_names": "|".join(param_names),
                "sources": "|".join(sorted({str(item.get("param_source", "")) for item in grouped if item.get("param_source")})),
                "evidence_refs": "|".join(sorted({str(item.get("evidence_ref", "")) for item in grouped if item.get("evidence_ref")})),
            }
        )

    _AUTH_ROUTE_COMMON_PARAMS: dict[str, list[str]] = {
        "/login": ["redirect", "next", "return_url", "callback", "continue"],
        "/signin": ["redirect", "next", "return_url", "callback", "continue"],
        "/reset-password": ["token", "email", "redirect"],
        "/forgot-password": ["email", "redirect"],
        "/account": ["tab", "redirect"],
        "/admin": ["redirect", "next"],
    }
    route_params_map_seen: set[tuple[str, str]] = set()
    for row in route_param_map_rows:
        route_params_map_seen.add((str(row.get("context_url", "")), str(row.get("route_path", ""))))
    for row in route_rows:
        url = str(row.get("url", "") or "").strip()
        if not url:
            continue
        parsed = urlparse(url)
        path = parsed.path or "/"
        base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        if not base_url:
            continue
        context_url = f"{base_url.rstrip('/')}{path}"
        if (context_url, path) in route_params_map_seen:
            continue
        common_params = _AUTH_ROUTE_COMMON_PARAMS.get(path)
        if not common_params:
            continue
        route_params_map_seen.add((context_url, path))
        route_param_map_rows.append(
            {
                "run_id": run_id,
                "job_id": job_id,
                "trace_id": trace_token,
                "context_url": context_url,
                "route_path": path,
                "param_names": "|".join(common_params),
                "sources": "route_candidate_hint",
                "evidence_refs": str(row.get("evidence_ref", "") or ""),
            }
        )

    graphql_candidates_rows = [
        {
            "run_id": run_id,
            "job_id": job_id,
            "trace_id": trace_token,
            "host": row.get("host", ""),
            "path": row.get("path", ""),
            "full_url": row.get("full_url", ""),
            "source": row.get("source", ""),
            "evidence_ref": row.get("evidence_ref", ""),
        }
        for row in api_rows
        if str(row.get("api_type", "")).lower() == "graphql" or "graphql" in str(row.get("path", "")).lower()
    ]
    json_endpoint_candidates_rows = [
        {
            "run_id": run_id,
            "job_id": job_id,
            "trace_id": trace_token,
            "host": row.get("host", ""),
            "path": row.get("path", ""),
            "full_url": row.get("full_url", ""),
            "source": row.get("source", ""),
            "evidence_ref": row.get("evidence_ref", ""),
        }
        for row in api_rows
        if (
            ".json" in str(row.get("path", "")).lower()
            or ".json" in str(row.get("full_url", "")).lower()
            or str(row.get("schema_hint", "")).lower() == "json"
        )
    ]

    frontend_backend_boundaries_md_lines = [
        "# Frontend / Backend Boundaries",
        "",
        f"- Run ID: `{run_id}`",
        f"- Job ID: `{job_id}`",
        f"- Trace ID: `{trace_token}`",
        "",
        "## Boundary Candidates",
        "",
    ]
    boundary_candidates = [
        row
        for row in api_rows
        if row.get("source") in {"js_api_ref", "form_action", "route_inventory", "endpoint_inventory"}
    ]
    if not boundary_candidates:
        frontend_backend_boundaries_md_lines.append("- [Observation] No boundary candidates discovered from Stage 1 evidence.")
    else:
        for row in boundary_candidates[:120]:
            ev_ref = row.get("evidence_ref", "")
            frontend_backend_boundaries_md_lines.extend(
                [
                    f"- [Evidence] `{row.get('full_url', '')}` from `{row.get('source', '')}` (ref: `{ev_ref}`)",
                    f"- [Inference] boundary hint: `{row.get('auth_boundary_hint', 'unknown')}`",
                ]
            )
    evidence_artifacts = [
        "api_surface.csv",
        "js_api_refs.csv",
        "forms_inventory.csv",
        "endpoint_inventory.csv",
        "route_inventory.csv",
        "graphql_candidates.csv",
        "json_endpoint_candidates.csv",
    ]
    frontend_backend_boundaries_md_lines.extend(
        [
            "",
            "## Traceability",
            "",
            f"- [Evidence] Source artifacts: `{', '.join(evidence_artifacts)}`",
            "- [Evidence] Each boundary candidate links to source via `evidence_ref` (e.g. `api_surface.csv:row_N`, `endpoint_inventory.csv:row_M`, `route_inventory.csv` URL ref).",
            "- [Evidence] MCP traces: `mcp_invocation_audit_meta.json`, `mcp_invocation_audit.jsonl`, `mcp_trace.jsonl`",
        ]
    )
    frontend_backend_boundaries_md = "\n".join(frontend_backend_boundaries_md_lines)

    app_flow_hints_lines = [
        "# App Flow Hints",
        "",
        f"- Run ID: `{run_id}`",
        f"- Job ID: `{job_id}`",
        f"- Trace ID: `{trace_token}`",
        "",
        "## Route Classification Summary",
        "",
    ]
    if not route_classification_rows:
        app_flow_hints_lines.append("- [Observation] No route classification data available.")
    else:
        by_classification: dict[str, list[dict[str, Any]]] = {}
        for row in route_classification_rows:
            cls = str(row.get("classification", "") or "unknown").strip() or "unknown"
            by_classification.setdefault(cls, []).append(row)
        summary_parts = [f"`{cls}`: {len(rows)}" for cls, rows in sorted(by_classification.items())]
        app_flow_hints_lines.append(f"- [Observation] Route counts by classification: {', '.join(summary_parts)}")
        app_flow_hints_lines.append("")
        app_flow_hints_lines.append("## Routes by Classification")
        app_flow_hints_lines.append("")
        for cls in sorted(by_classification.keys()):
            app_flow_hints_lines.append(f"### {cls}")
            app_flow_hints_lines.append("")
            for row in by_classification[cls][:50]:
                route = row.get("route", "")
                host = row.get("host", "")
                discovery_source = row.get("discovery_source", "")
                evidence_ref = row.get("evidence_ref", "")
                app_flow_hints_lines.append(
                    f"- [Evidence] `{route}` on `{host}` via `{discovery_source}` (`{evidence_ref}`)"
                )
            if len(by_classification[cls]) > 50:
                app_flow_hints_lines.append(f"- [Observation] ... and {len(by_classification[cls]) - 50} more")
            app_flow_hints_lines.append("")
        app_flow_hints_lines.append("## Form Flow Indicators")
        app_flow_hints_lines.append("")
    if not forms_rows:
        app_flow_hints_lines.append("- [Observation] No form hints available.")
    else:
        for row in forms_rows[:80]:
            app_flow_hints_lines.append(
                f"- [Observation] form `{row.get('method', 'GET')}` -> `{row.get('action', '')}` input `{row.get('input_name', '')}`"
            )
    app_flow_hints_lines.extend(
        [
            "",
            "- [Hypothesis] Prioritize auth-related flows and redirect chains in Stage 2 validation.",
        ]
    )
    app_flow_hints_md = "\n".join(app_flow_hints_lines)

    host_security_posture_rows = [
        {
            "run_id": run_id,
            "job_id": job_id,
            "trace_id": trace_token,
            "host": row.get("host_url", ""),
            "security_header_score": row.get("security_header_score", "0"),
            "cookie_count": row.get("cookie_count", "0"),
            "cookies_secure": row.get("cookies_secure", "0"),
            "cookies_httponly": row.get("cookies_httponly", "0"),
            "cookies_samesite": row.get("cookies_samesite", "0"),
            "evidence_ref": f"headers_detailed.csv:{row.get('host_url', '')}",
        }
        for row in headers_rows
        if row.get("host_url")
    ]

    control_inconsistencies_lines = [
        "# Control Inconsistencies",
        "",
        f"- Run ID: `{run_id}`",
        f"- Job ID: `{job_id}`",
        f"- Trace ID: `{trace_token}`",
        "",
    ]
    inconsistent_count = 0
    for row in host_security_posture_rows:
        score = int(str(row.get("security_header_score", "0")) or 0)
        cookie_count = int(str(row.get("cookie_count", "0")) or 0)
        secure_count = int(str(row.get("cookies_secure", "0")) or 0)
        if score < 3 or (cookie_count > 0 and secure_count < cookie_count):
            inconsistent_count += 1
            control_inconsistencies_lines.extend(
                [
                    f"- [Evidence] host `{row.get('host', '')}` score={score}, secure_cookies={secure_count}/{cookie_count}",
                    f"- [Inference] posture inconsistency candidate (ref: `{row.get('evidence_ref', '')}`)",
                ]
            )
    if inconsistent_count == 0:
        control_inconsistencies_lines.append("- [Observation] No control inconsistencies inferred from current header/tls evidence.")
    control_inconsistencies_md = "\n".join(control_inconsistencies_lines)

    response_similarity_rows: list[dict[str, Any]] = []
    cluster_groups: dict[str, list[dict[str, Any]]] = {}
    for row in content_cluster_rows:
        cluster_groups.setdefault(str(row.get("cluster_id", "")), []).append(row)
    for cluster_id, rows in cluster_groups.items():
        for row in rows:
            response_similarity_rows.append(
                {
                    "run_id": run_id,
                    "job_id": job_id,
                    "trace_id": trace_token,
                    "cluster_id": cluster_id,
                    "host": row.get("host", ""),
                    "url": row.get("url", ""),
                    "similarity_score": "1.00",
                    "template_hint": row.get("template_hint", ""),
                    "evidence_ref": row.get("evidence_ref", ""),
                    "similarity_type": "content",
                    "shared_redirect_target": "",
                }
            )
    if not response_similarity_rows and redirect_cluster_rows:
        response_similarity_rows = _build_response_similarity_from_redirect(
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_token,
            redirect_clusters=redirect_cluster_rows,
        )

    catch_all_evidence_lines = [
        "# Catch-all Evidence",
        "",
        f"- Run ID: `{run_id}`",
        f"- Job ID: `{job_id}`",
        f"- Trace ID: `{trace_token}`",
        "",
    ]
    catch_all_rows = [row for row in content_cluster_rows if str(row.get("catch_all_hint", "no")) == "yes"]
    if not catch_all_rows:
        catch_all_evidence_lines.append("- [Observation] No catch-all indicators detected.")
    for row in catch_all_rows:
        catch_all_evidence_lines.extend(
            [
                f"- [Evidence] `{row.get('host', '')}` matched root-like content fingerprint (`{row.get('evidence_ref', '')}`)",
                "- [Hypothesis] Validate wildcard routing and host ownership in Stage 2.",
            ]
        )
    catch_all_evidence_md = "\n".join(catch_all_evidence_lines)

    anomaly_validation_rows = _build_anomaly_validation_rows(
        run_id=run_id,
        job_id=job_id,
        trace_id=trace_token,
        content_clusters=content_cluster_rows,
        redirect_clusters=redirect_cluster_rows,
    )

    content_cluster_hosts: dict[str, set[str]] = {}
    for row in content_cluster_rows:
        cid = str(row.get("cluster_id", "") or "")
        host = str(row.get("host", "") or "")
        if cid and host:
            content_cluster_hosts.setdefault(cid, set()).add(host)
    redirect_cluster_hosts: dict[str, set[str]] = {}
    for row in redirect_cluster_rows:
        rid = str(row.get("redirect_cluster_id", "") or "")
        host = str(row.get("host", "") or "")
        if rid and host:
            redirect_cluster_hosts.setdefault(rid, set()).add(host)

    host_matrix: dict[str, dict[str, Any]] = {}
    for row in content_cluster_rows:
        host = str(row.get("host", "") or "")
        if not host:
            continue
        cid = str(row.get("cluster_id", "") or "")
        related = set(content_cluster_hosts.get(cid, set())) - {host}
        host_matrix.setdefault(
            host,
            {
                "run_id": run_id,
                "job_id": job_id,
                "trace_id": trace_token,
                "host": host,
                "content_cluster": cid,
                "template_hint": row.get("template_hint", ""),
                "catch_all_hint": row.get("catch_all_hint", "no"),
                "redirect_cluster": "",
                "shared_with_root": "no",
                "suspicious_host": row.get("suspicious_host", "no"),
                "evidence_refs": {str(row.get("evidence_ref", ""))},
                "behavior_type": "content",
                "related_hosts": related,
            },
        )
    for row in redirect_cluster_rows:
        host = str(row.get("host", "") or "")
        if not host:
            continue
        rid = str(row.get("redirect_cluster_id", "") or "")
        related = set(redirect_cluster_hosts.get(rid, set())) - {host}
        item = host_matrix.get(host)
        if item is None:
            host_matrix[host] = {
                "run_id": run_id,
                "job_id": job_id,
                "trace_id": trace_token,
                "host": host,
                "content_cluster": "",
                "template_hint": "",
                "catch_all_hint": "no",
                "redirect_cluster": rid,
                "shared_with_root": row.get("shared_with_root", "no"),
                "suspicious_host": row.get("suspicious_host", "no"),
                "evidence_refs": {str(row.get("evidence_ref", ""))},
                "behavior_type": "redirect",
                "related_hosts": related,
            }
        else:
            item["redirect_cluster"] = rid
            item["shared_with_root"] = row.get("shared_with_root", "no")
            item["evidence_refs"].add(str(row.get("evidence_ref", "")))
            item["related_hosts"] = item["related_hosts"] | related
            item["behavior_type"] = "content+redirect" if item.get("content_cluster") else "redirect"
    hostname_behavior_matrix_rows = [
        {
            **{k: v for k, v in item.items() if k not in ("evidence_refs", "related_hosts")},
            "evidence_refs": "|".join(sorted([ref for ref in item["evidence_refs"] if ref])),
            "related_hosts": "|".join(sorted(item.get("related_hosts", set()))),
        }
        for item in host_matrix.values()
    ]

    stage2_preparation_md = ""

    stage3_readiness_result = _build_stage3_readiness(
        route_classification_rows=route_classification_rows,
        params_rows=params_rows,
        api_rows=api_rows,
        content_cluster_rows=content_cluster_rows,
        redirect_cluster_rows=redirect_cluster_rows,
        frontend_backend_boundaries_md=frontend_backend_boundaries_md,
    )
    stage3_readiness_json = json.dumps(
        stage3_readiness_result.model_dump(mode="json"),
        indent=2,
        ensure_ascii=False,
    )
    stage3_readiness_md = _build_stage3_readiness_md(
        run_id=run_id,
        job_id=job_id,
        trace_id=trace_token,
        result=stage3_readiness_result,
    )

    output_files: dict[str, str] = {
        "route_inventory.csv": _as_csv(route_rows, route_columns),
        "route_classification.csv": _as_csv(route_classification_rows, list(ROUTE_CLASSIFICATION_CSV_COLUMNS)),
        "public_pages.csv": _as_csv(public_page_rows, public_columns),
        "forms_inventory.csv": _as_csv(forms_rows, forms_columns),
        "params_inventory.csv": _as_csv(params_rows, params_columns),
        "js_bundle_inventory.csv": _as_csv(js_bundle_rows, js_bundle_columns),
        "js_routes.csv": _as_csv(js_routes_rows, ["run_id", "job_id", "trace_id", "route_hint", "evidence_ref"]),
        "js_api_refs.csv": _as_csv(js_api_ref_rows, ["run_id", "job_id", "trace_id", "api_ref", "evidence_ref"]),
        "js_integrations.csv": _as_csv(
            js_integration_rows,
            ["run_id", "job_id", "trace_id", "integration_hint", "integration_type", "evidence_ref"],
        ),
        "js_config_hints.csv": _as_csv(
            js_config_hint_rows,
            ["run_id", "job_id", "trace_id", "config_hint", "evidence_ref"],
        ),
        "js_findings.md": js_findings_md,
        "api_surface.csv": _as_csv(api_rows, api_columns),
        "input_surfaces.csv": _as_csv(
            input_surfaces_rows,
            ["run_id", "job_id", "trace_id", "surface_type", "surface_name", "context_url", "classification", "evidence_ref"],
        ),
        "route_params_map.csv": _as_csv(
            route_param_map_rows,
            ["run_id", "job_id", "trace_id", "context_url", "route_path", "param_names", "sources", "evidence_refs"],
        ),
        "graphql_candidates.csv": _as_csv(
            graphql_candidates_rows,
            ["run_id", "job_id", "trace_id", "host", "path", "full_url", "source", "evidence_ref"],
        ),
        "json_endpoint_candidates.csv": _as_csv(
            json_endpoint_candidates_rows,
            ["run_id", "job_id", "trace_id", "host", "path", "full_url", "source", "evidence_ref"],
        ),
        "frontend_backend_boundaries.md": frontend_backend_boundaries_md,
        "app_flow_hints.md": app_flow_hints_md,
        "host_security_posture.csv": _as_csv(
            host_security_posture_rows,
            [
                "run_id",
                "job_id",
                "trace_id",
                "host",
                "security_header_score",
                "cookie_count",
                "cookies_secure",
                "cookies_httponly",
                "cookies_samesite",
                "evidence_ref",
            ],
        ),
        "control_inconsistencies.md": control_inconsistencies_md,
        "response_similarity.csv": _as_csv(
            response_similarity_rows,
            [
                "run_id",
                "job_id",
                "trace_id",
                "cluster_id",
                "host",
                "url",
                "similarity_score",
                "template_hint",
                "evidence_ref",
                "similarity_type",
                "shared_redirect_target",
            ],
        ),
        "catch_all_evidence.md": catch_all_evidence_md,
        "content_clusters.csv": _as_csv(content_cluster_rows, content_cluster_columns),
        "redirect_clusters.csv": _as_csv(redirect_cluster_rows, redirect_cluster_columns),
        "anomaly_validation.md": anomaly_validation_md,
        "anomaly_validation.csv": _as_csv(
            anomaly_validation_rows,
            ["run_id", "job_id", "trace_id", "host", "classification", "confidence", "recommendation", "evidence_refs"],
        ),
        "hostname_behavior_matrix.csv": _as_csv(
            hostname_behavior_matrix_rows,
            [
                "run_id",
                "job_id",
                "trace_id",
                "host",
                "behavior_type",
                "related_hosts",
                "content_cluster",
                "template_hint",
                "catch_all_hint",
                "redirect_cluster",
                "shared_with_root",
                "suspicious_host",
                "evidence_refs",
            ],
        ),
        "stage2_preparation.md": stage2_preparation_md,
        "stage3_readiness.json": stage3_readiness_json,
        "stage3_readiness.md": stage3_readiness_md,
    }

    if set(_AI_TEMPLATES.keys()) != set(RECON_AI_TASKS):
        raise RuntimeError("Recon AI task registry mismatch: expected exactly 8 normalized tasks")

    def _meta(task: ReconAiTask) -> dict[str, Any]:
        return build_task_metadata(
            task=task,
            run_id=run_id,
            job_id=job_id,
            trace_id=f"{trace_token}:{task.value}",
        ).model_dump(mode="json")

    js_input = {
        "meta": _meta(ReconAiTask.JS_FINDINGS_ANALYSIS),
        "script_findings": [
            {"category": "client_route", "value": x["value"], "evidence_refs": [x["evidence_ref"]]}
            for x in js_client_routes[:100]
        ]
        + [
            {"category": "api_ref", "value": x["value"], "evidence_refs": [x["evidence_ref"]]}
            for x in js_api_refs[:100]
        ]
        + [
            {"category": "frontend_marker", "value": x["value"], "evidence_refs": [x["evidence_ref"]]}
            for x in js_frontend_markers[:100]
        ]
        + [
            {"category": "hidden_hint", "value": x["value"], "evidence_refs": [x["evidence_ref"]]}
            for x in js_hidden_hints[:100]
        ],
    }
    js_output = {
        "summary": "Static JS hints extracted from discovered script assets.",
        "findings": [
            {
                "statement_type": "observation",
                "category": "client_route",
                "value": x["value"],
                "confidence": 0.71,
                "evidence_refs": [x["evidence_ref"]],
            }
            for x in js_client_routes[:100]
        ]
        + [
            {
                "statement_type": "observation",
                "category": "api_ref",
                "value": x["value"],
                "confidence": 0.74,
                "evidence_refs": [x["evidence_ref"]],
            }
            for x in js_api_refs[:100]
        ]
        + [
            {
                "statement_type": "observation",
                "category": "frontend_marker",
                "value": x["value"],
                "confidence": 0.66,
                "evidence_refs": [x["evidence_ref"]],
            }
            for x in js_frontend_markers[:100]
        ],
    }
    output_files.update(
        _persist_ai_task(
            task_name=ReconAiTask.JS_FINDINGS_ANALYSIS.value,
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_token,
            input_payload=js_input,
            normalized_output=js_output,
            source_artifacts=[
                "js_routes.csv",
                "js_api_refs.csv",
                "js_integrations.csv",
                "js_config_hints.csv",
                "js_findings.md",
                "mcp_invocation_audit_meta.json",
                "mcp_invocation_audit.jsonl",
                "mcp_trace.jsonl",
            ],
            evidence_refs=[
                *[x["evidence_ref"] for x in js_client_routes[:100]],
                *[x["evidence_ref"] for x in js_api_refs[:100]],
                *[x["evidence_ref"] for x in js_frontend_markers[:100]],
            ],
        )
    )

    params_input = {
        "meta": _meta(ReconAiTask.PARAMETER_INPUT_ANALYSIS),
        "params": [
            {
                "name": p["param_name"],
                "source": p["param_source"],
                "context_url": p["context_url"],
                "evidence_refs": [p["evidence_ref"]],
            }
            for p in params_rows[:300]
        ],
    }
    params_output = {
        "params": [
            {
                "statement_type": "observation",
                "name": p["param_name"],
                "category": p["param_category"],
                "context_url": p["context_url"],
                "confidence": 0.7,
                "evidence_refs": [p["evidence_ref"]],
            }
            for p in params_rows[:300]
        ],
    }
    output_files.update(
        _persist_ai_task(
            task_name=ReconAiTask.PARAMETER_INPUT_ANALYSIS.value,
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_token,
            input_payload=params_input,
            normalized_output=params_output,
            source_artifacts=[
                "params_inventory.csv",
                "input_surfaces.csv",
                "route_params_map.csv",
                "forms_inventory.csv",
                "mcp_invocation_audit_meta.json",
                "mcp_invocation_audit.jsonl",
                "mcp_trace.jsonl",
            ],
            evidence_refs=[p["evidence_ref"] for p in params_rows[:300] if p.get("evidence_ref")],
        )
    )

    api_input = {
        "meta": _meta(ReconAiTask.API_SURFACE_INFERENCE),
        "api_candidates": [
            {
                "path": a["path"],
                "source": a["source"],
                "method_hint": a["method_hint"],
                "evidence_refs": [a["evidence_ref"]],
            }
            for a in api_rows[:300]
        ],
    }
    api_output = {
        "api_surface": [
            {
                "statement_type": "inference",
                "path": a["path"],
                "api_type": a["api_type"],
                "auth_boundary_hint": a["auth_boundary_hint"],
                "confidence": 0.72,
                "evidence_refs": [a["evidence_ref"]],
            }
            for a in api_rows[:300]
        ],
    }
    output_files.update(
        _persist_ai_task(
            task_name=ReconAiTask.API_SURFACE_INFERENCE.value,
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_token,
            input_payload=api_input,
            normalized_output=api_output,
            source_artifacts=[
                "api_surface.csv",
                "graphql_candidates.csv",
                "json_endpoint_candidates.csv",
                "frontend_backend_boundaries.md",
                "mcp_invocation_audit_meta.json",
                "mcp_invocation_audit.jsonl",
                "mcp_trace.jsonl",
            ],
            evidence_refs=[a["evidence_ref"] for a in api_rows[:300] if a.get("evidence_ref")],
        )
    )

    headers_tls_input = {
        "meta": _meta(ReconAiTask.HEADERS_TLS_SUMMARY),
        "hosts": [
            {
                "host": row.get("host_url", ""),
                "header_score": row.get("security_header_score", "0"),
                "cookie_count": row.get("cookie_count", "0"),
                "cookie_secure": row.get("cookies_secure", "0"),
                "evidence_refs": [f"headers_detailed.csv:{row.get('host_url', '')}"],
            }
            for row in headers_rows[:200]
            if row.get("host_url")
        ],
    }
    headers_tls_output = {
        "summary": "Headers/cookies/TLS posture summarized from Stage 1 artifacts.",
        "controls": [
            {
                "statement_type": "observation",
                "host": row.get("host_url", ""),
                "posture": (
                    "strong"
                    if int(row.get("security_header_score", "0") or 0) >= 5
                    else "moderate"
                    if int(row.get("security_header_score", "0") or 0) >= 3
                    else "weak"
                ),
                "confidence": 0.76,
                "evidence_refs": [
                    f"headers_detailed.csv:{row.get('host_url', '')}",
                    f"tls_summary.md:{row.get('host_url', '')}",
                ],
            }
            for row in headers_rows[:200]
        ],
    }
    output_files.update(
        _persist_ai_task(
            task_name=ReconAiTask.HEADERS_TLS_SUMMARY.value,
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_token,
            input_payload=headers_tls_input,
            normalized_output=headers_tls_output,
            source_artifacts=[
                "headers_summary.md",
                "headers_detailed.csv",
                "tls_summary.md",
                "host_security_posture.csv",
                "control_inconsistencies.md",
            ],
            evidence_refs=[
                ref
                for row in headers_tls_output["controls"]
                for ref in row.get("evidence_refs", [])
                if ref
            ],
        )
    )

    content_similarity_input = {
        "meta": _meta(ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION),
        "content_clusters": [
            {
                "cluster_id": str(row.get("cluster_id", "")),
                "host": str(row.get("host", "")),
                "cluster_size": int(row.get("cluster_size", 0) or 0),
                "template_hint": str(row.get("template_hint", "")),
                "evidence_ref": str(row.get("evidence_ref", "")),
            }
            for row in content_cluster_rows[:300]
            if row.get("cluster_id")
        ],
        "redirect_clusters": [
            {
                "redirect_cluster_id": str(row.get("redirect_cluster_id", "")),
                "host": str(row.get("host", "")),
                "redirect_target": str(row.get("redirect_target", "")),
                "evidence_ref": str(row.get("evidence_ref", "")),
            }
            for row in redirect_cluster_rows[:300]
            if row.get("redirect_cluster_id")
        ],
    }
    content_similarity_output = {
        "summary": "Shared templates and redirect behavior interpreted from clustering artifacts.",
        "clusters": [
            {
                "statement_type": "inference",
                "cluster_id": row.get("cluster_id", ""),
                "interpretation": (
                    "shared_404_or_platform_template"
                    if row.get("template_hint") in {"shared_404_template", "shared_platform_template"}
                    else "unique_or_small_cluster"
                ),
                "confidence": 0.73 if int(row.get("cluster_size", 0) or 0) > 1 else 0.58,
                "evidence_refs": [str(row.get("evidence_ref", "")), "content_clusters.csv"],
            }
            for row in content_cluster_rows[:300]
        ],
    }
    output_files.update(
        _persist_ai_task(
            task_name="content_similarity_interpretation",
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_token,
            input_payload=content_similarity_input,
            normalized_output=content_similarity_output,
            source_artifacts=[
                "content_clusters.csv",
                "redirect_clusters.csv",
                "response_similarity.csv",
                "hostname_behavior_matrix.csv",
            ],
            evidence_refs=[
                *[str(row.get("evidence_ref", "")) for row in content_cluster_rows[:300]],
                *[str(row.get("evidence_ref", "")) for row in redirect_cluster_rows[:300]],
            ],
        )
    )

    anomaly_candidates = [
        {
            "host": r["host"],
            "classification": r["classification"],
            "confidence": float(r["confidence"]),
            "recommendation": r["recommendation"],
            "evidence_refs": [x for x in r["evidence_refs"].split("|") if x],
        }
        for r in anomaly_validation_rows
    ]

    anomaly_input = {
        "meta": _meta(ReconAiTask.ANOMALY_INTERPRETATION),
        "anomalies": [
            {
                "host": str(row.get("host", "")),
                "status": str(row.get("status", "") or "0"),
                "suspicious_host": str(row.get("suspicious_host", "no")) == "yes",
                "catch_all_hint": str(row.get("catch_all_hint", "no")) == "yes",
                "shared_with_root": str(row.get("similar_to_root", "no")) == "yes",
                "evidence_refs": [str(row.get("evidence_ref", "")), "content_clusters.csv"],
            }
            for row in content_cluster_rows[:300]
            if row.get("host")
        ],
    }
    anomaly_output = {
        "anomalies": [
            {
                "statement_type": "hypothesis",
                "host": item["host"],
                "classification": item["classification"],
                "confidence": item["confidence"],
                "recommendation": item["recommendation"],
                "evidence_refs": item["evidence_refs"],
            }
            for item in anomaly_candidates[:300]
        ],
    }
    output_files.update(
        _persist_ai_task(
            task_name="anomaly_interpretation",
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_token,
            input_payload=anomaly_input,
            normalized_output=anomaly_output,
            source_artifacts=[
                "anomaly_validation.md",
                "anomaly_validation.csv",
                "catch_all_evidence.md",
                "hostname_behavior_matrix.csv",
            ],
            evidence_refs=[
                ref
                for item in anomaly_candidates[:300]
                for ref in item.get("evidence_refs", [])
                if ref
            ],
        )
    )

    focus_hosts = [str(item.get("host", "")) for item in anomaly_candidates[:20] if item.get("host")]
    stage2_input = {
        "meta": _meta(ReconAiTask.STAGE2_PREPARATION_SUMMARY),
        "focus_hosts": focus_hosts,
        "risk_hypotheses": [str(item.get("classification", "")) for item in anomaly_candidates[:20]],
    }
    stage2_output = {
        "summary": "Stage 2 preparation synthesized from validated anomalies and cluster behavior.",
        "next_steps": [
            {
                "statement_type": "hypothesis",
                "step": "Validate suspicious host ownership and wildcard routing behavior.",
                "priority": "high",
                "confidence": 0.78,
                "evidence_refs": ["anomaly_validation.md", "content_clusters.csv"],
            },
            {
                "statement_type": "hypothesis",
                "step": "Review redirect clusters for shared platform aliasing and routing controls.",
                "priority": "medium",
                "confidence": 0.69,
                "evidence_refs": ["redirect_clusters.csv", "04_live_hosts/http_probe.csv"],
            },
            {
                "statement_type": "hypothesis",
                "step": "Prioritize hypothesis-driven checks for hosts with weak header posture.",
                "priority": "medium",
                "confidence": 0.67,
                "evidence_refs": ["headers_detailed.csv", "tls_summary.md", "anomaly_validation.md"],
            },
        ],
    }
    stage2_source_artifacts = [
        "stage2_preparation.md",
        "frontend_backend_boundaries.md",
        "app_flow_hints.md",
        "anomaly_validation.md",
        "anomaly_validation.csv",
    ]
    if (base / "stage2_inputs.md").exists():
        stage2_source_artifacts.insert(1, "stage2_inputs.md")

    output_files.update(
        _persist_ai_task(
            task_name="stage2_preparation_summary",
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_token,
            input_payload=stage2_input,
            normalized_output=stage2_output,
            source_artifacts=stage2_source_artifacts,
            evidence_refs=[
                ref
                for step in stage2_output["next_steps"]
                for ref in step.get("evidence_refs", [])
                if ref
            ],
        )
    )

    stage3_input = {
        "meta": _meta(ReconAiTask.STAGE3_PREPARATION_SUMMARY),
        "focus_hosts": focus_hosts,
        "risk_hypotheses": [str(item.get("classification", "")) for item in anomaly_candidates[:20]],
        "stage3_readiness": stage3_readiness_result.model_dump(mode="json"),
    }
    stage3_output = {
        "summary": (
            f"Stage 3 readiness: {stage3_readiness_result.status}. "
            "Prioritize missing evidence and recommended follow-up before penetration testing."
        ),
        "next_steps": [
            {
                "statement_type": "hypothesis",
                "step": "Address missing evidence gaps before Stage 3 testing.",
                "priority": "high",
                "confidence": 0.75,
                "evidence_refs": ["stage3_readiness.json", "stage3_readiness.md"],
            },
            {
                "statement_type": "hypothesis",
                "step": "Validate route classification coverage for auth and admin flows.",
                "priority": "medium",
                "confidence": 0.7,
                "evidence_refs": ["route_classification.csv", "stage3_readiness.json"],
            },
            {
                "statement_type": "hypothesis",
                "step": "Complete API surface mapping for penetration test scope.",
                "priority": "medium",
                "confidence": 0.68,
                "evidence_refs": ["api_surface.csv", "stage3_readiness.json"],
            },
        ],
    }
    stage3_source_artifacts = [
        "stage3_readiness.json",
        "stage3_readiness.md",
        "route_classification.csv",
        "stage2_preparation.md",
        "api_surface.csv",
    ]
    output_files.update(
        _persist_ai_task(
            task_name="stage3_preparation_summary",
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_token,
            input_payload=stage3_input,
            normalized_output=stage3_output,
            source_artifacts=stage3_source_artifacts,
            evidence_refs=[
                ref
                for step in stage3_output["next_steps"]
                for ref in step.get("evidence_refs", [])
                if ref
            ],
        )
    )

    stage2_preparation_md_lines = [
        "# Stage 2 Preparation",
        "",
        f"- Run ID: `{run_id}`",
        f"- Job ID: `{job_id}`",
        f"- Trace ID: `{trace_token}`",
        "",
        f"- [Observation] {stage2_output['summary']}",
        "",
        "## Prioritized Next Steps",
        "",
    ]
    for step in stage2_output["next_steps"]:
        stage2_preparation_md_lines.extend(
            [
                f"- [Hypothesis] ({step['priority']}) {step['step']}",
                f"- [Evidence] refs: {', '.join(f'`{ref}`' for ref in step['evidence_refs'])}",
                f"- [Inference] confidence: `{step['confidence']:.2f}`",
            ]
        )
    output_files["stage2_preparation.md"] = "\n".join(stage2_preparation_md_lines)

    ai_artifacts = sorted(name for name in output_files if name.startswith("ai_"))
    output_files["ai_persistence_manifest.json"] = json.dumps(
        {
            "run_id": run_id,
            "job_id": job_id,
            "run_link": f"recon://runs/{run_id}",
            "job_link": f"recon://jobs/{job_id}",
            "trace_id": trace_token,
            "ai_artifacts": ai_artifacts,
            "linkage_required_fields": [
                "run_id",
                "job_id",
                "run_link",
                "job_link",
                "trace_id",
            ],
            "mcp_trace_refs": sorted(
                [
                    "mcp_invocation_audit_meta.json",
                    "mcp_invocation_audit.jsonl",
                    "mcp_trace.jsonl",
                ]
            ),
        },
        indent=2,
        ensure_ascii=False,
    )

    logger.info(
        "stage1_enrichment_artifacts_built",
        extra={
            "run_id": run_id,
            "job_id": job_id,
            "trace_id": trace_token,
            "routes": len(route_rows),
            "public_pages": len(public_page_rows),
            "forms": len(forms_rows),
            "params": len(params_rows),
            "js_bundles": len(js_bundle_rows),
            "api_candidates": len(api_rows),
            "content_clusters": len(content_cluster_rows),
            "redirect_clusters": len(redirect_cluster_rows),
            "anomaly_candidates": len(anomaly_candidates),
            "tls_summary_available": bool(tls_summary_text),
        },
    )
    return output_files
