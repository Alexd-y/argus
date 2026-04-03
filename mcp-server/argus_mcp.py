#!/usr/bin/env python3
"""
ARGUS MCP Server — FastMCP, stdio or HTTP transport.

SSE-MCP-007: Tools call backend API. Typed schemas, auth placeholder, tenant awareness.
MCP-002: 150+ Kali pentest tools via backend /api/v1/tools/* endpoints.
MCP-002: HTTP transport for Docker; stdio for local Cursor spawn.
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import shlex
import sys
import time
from typing import Any, Literal, Optional
from urllib.parse import urlparse

import httpx
from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tools.kali_registry import KALI_TOOL_REGISTRY, ToolDefinition
from tools.va_sandbox_tools import build_enqueue_payload

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[ARGUS MCP] %(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Typed Schemas (SSEEventPayload-compatible, API contracts)
# ---------------------------------------------------------------------------

# Mirror backend ``src/api/schemas.py`` — ScanCreateRequest / ScanSmartCreateRequest / ScanOptions.
TARGET_PATTERN = r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?(/.*)?$"


class MCPScanOptionsAuth(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    type: str = "basic"
    username: str = ""
    password: str = ""
    token: str = ""


class MCPScanOptionsScope(BaseModel):
    model_config = ConfigDict(extra="ignore")

    maxDepth: int = Field(default=3, ge=1, le=10)
    includeSubs: bool = False
    excludePatterns: str = ""


class MCPScanOptionsAdvanced(BaseModel):
    model_config = ConfigDict(extra="ignore")

    timeout: int = Field(default=30, ge=5, le=120)
    userAgent: str = "chrome"
    proxy: str = ""
    customHeaders: str = ""


class MCPScanOptionsVulnerabilities(BaseModel):
    model_config = ConfigDict(extra="ignore")

    xss: bool = True
    sqli: bool = True
    csrf: bool = True
    ssrf: bool = False
    lfi: bool = False
    rce: bool = False


class MCPScanOptionsKal(BaseModel):
    model_config = ConfigDict(extra="ignore")

    password_audit_opt_in: bool = False
    recon_dns_enumeration_opt_in: bool = False
    va_network_capture_opt_in: bool = False


class MCPScanOptions(BaseModel):
    """Aligned with backend ``ScanOptions``."""

    model_config = ConfigDict(extra="ignore")

    scanType: str = "quick"
    reportFormat: str = "pdf"
    rateLimit: str = "normal"
    ports: str = "80,443,8080,8443"
    followRedirects: bool = True
    vulnerabilities: MCPScanOptionsVulnerabilities = Field(default_factory=MCPScanOptionsVulnerabilities)
    authentication: MCPScanOptionsAuth = Field(default_factory=MCPScanOptionsAuth)
    scope: MCPScanOptionsScope = Field(default_factory=MCPScanOptionsScope)
    advanced: MCPScanOptionsAdvanced = Field(default_factory=MCPScanOptionsAdvanced)
    kal: MCPScanOptionsKal = Field(default_factory=MCPScanOptionsKal)


class MCPScanCreateRequest(BaseModel):
    """Aligned with backend ``ScanCreateRequest`` (POST /api/v1/scans)."""

    model_config = ConfigDict(extra="ignore")

    target: str = Field(
        min_length=1,
        max_length=512,
        pattern=TARGET_PATTERN,
        description="URL or domain to scan",
    )
    email: str
    options: MCPScanOptions = Field(default_factory=MCPScanOptions)
    scan_mode: Literal["quick", "standard", "deep"] = Field(
        default="standard",
        description="Scan depth: quick | standard | deep",
    )


class MCPScanSmartCreateRequest(BaseModel):
    """Aligned with backend ``ScanSmartCreateRequest`` (POST /api/v1/scans/smart)."""

    model_config = ConfigDict(extra="ignore")

    target: str = Field(min_length=1, max_length=512, pattern=TARGET_PATTERN)
    objective: str = Field(default="", max_length=2048)
    max_phases: int = Field(default=5, ge=1, le=20)
    tenant_id: str | None = Field(default=None, max_length=36)


class CreateScanResponse(BaseModel):
    """POST /scans response schema."""

    scan_id: str
    status: str
    message: Optional[str] = None


class ScanStatusResponse(BaseModel):
    """GET /scans/:id response schema."""

    id: str
    status: str
    progress: int
    phase: str
    target: str
    created_at: str


class FindingSchema(BaseModel):
    """Finding schema per api-contracts."""

    severity: str
    title: str
    description: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    confidence: str = "likely"
    evidence_type: Optional[str] = None
    evidence_refs: list[str] = Field(default_factory=list)
    reproducible_steps: Optional[str] = None
    applicability_notes: Optional[str] = None


class ReportSchema(BaseModel):
    """Report schema per api-contracts."""

    report_id: str
    target: str
    summary: dict[str, Any]
    findings: list[FindingSchema] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    created_at: Optional[str] = None
    scan_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_SERVER_URL = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT = 300
MAX_RETRIES = 3


def _get_auth_headers() -> dict[str, str]:
    """Auth placeholder: return headers when ARGUS_API_KEY is set."""
    api_key = os.environ.get("ARGUS_API_KEY")
    if api_key:
        return {"Authorization": f"Bearer {api_key}"}
    return {}


def _get_tenant_headers(tenant_id: Optional[str]) -> dict[str, str]:
    """Tenant awareness: X-Tenant-ID header for scan/report filtering."""
    tid = tenant_id or os.environ.get("ARGUS_TENANT_ID")
    if tid:
        return {"X-Tenant-ID": tid}
    return {}


def _get_admin_headers() -> dict[str, str]:
    """Internal VA enqueue: X-Admin-Key when ARGUS_ADMIN_KEY is set (matches backend require_admin)."""
    key = (os.environ.get("ARGUS_ADMIN_KEY") or "").strip()
    if key:
        return {"X-Admin-Key": key}
    return {}


# Defaults aligned with backend ``ScanOptions`` (``src/api/schemas.py``); keep in sync on schema changes.
_DEFAULT_SCAN_OPTIONS: dict[str, Any] = {
    "scanType": "quick",
    "reportFormat": "pdf",
    "rateLimit": "normal",
    "ports": "80,443,8080,8443",
    "followRedirects": True,
    "vulnerabilities": {
        "xss": True,
        "sqli": True,
        "csrf": True,
        "ssrf": False,
        "lfi": False,
        "rce": False,
    },
    "authentication": {
        "enabled": False,
        "type": "basic",
        "username": "",
        "password": "",
        "token": "",
    },
    "scope": {"maxDepth": 3, "includeSubs": False, "excludePatterns": ""},
    "advanced": {"timeout": 30, "userAgent": "chrome", "proxy": "", "customHeaders": ""},
    "kal": {
        "password_audit_opt_in": False,
        "recon_dns_enumeration_opt_in": False,
        "va_network_capture_opt_in": False,
    },
}


def _deep_merge_option_dict(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in overrides.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge_option_dict(out[k], v)
        else:
            out[k] = v
    return out


def _normalize_scan_mode(raw: str) -> str:
    s = (raw or "standard").strip().lower()
    if s in ("quick", "standard", "deep"):
        return s
    if s in ("light", "normal"):
        return "standard"
    return "standard"


def _build_scan_request(
    target: str,
    email: str,
    scan_mode: str,
    *,
    options_overrides: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build and validate JSON body for ``ScanCreateRequest`` (backend ``src/api/schemas.py``)."""
    sm = _normalize_scan_mode(scan_mode)
    ov = options_overrides or {}
    merged = _deep_merge_option_dict(_DEFAULT_SCAN_OPTIONS, ov)
    if "scanType" not in ov:
        merged["scanType"] = sm
    raw = {
        "target": (target or "").strip(),
        "email": (email or "mcp@argus.local").strip(),
        "scan_mode": sm,
        "options": merged,
    }
    validated = MCPScanCreateRequest.model_validate(raw)
    return validated.model_dump(mode="json")


def _build_smart_scan_request(
    target: str,
    objective: str = "",
    max_phases: int = 5,
    tenant_id: Optional[str] = None,
) -> dict[str, Any]:
    """Build and validate JSON body for ``ScanSmartCreateRequest``."""
    try:
        mp = int(max_phases)
    except (TypeError, ValueError):
        mp = 5
    mp = max(1, min(20, mp))
    body: dict[str, Any] = {
        "target": (target or "").strip(),
        "objective": (objective or "").strip()[:2048],
        "max_phases": mp,
    }
    tid = (tenant_id or "").strip() or None
    if tid:
        body["tenant_id"] = tid
    validated = MCPScanSmartCreateRequest.model_validate(body)
    return validated.model_dump(mode="json", exclude_none=True)


# ---------------------------------------------------------------------------
# ArgusClient — backend API
# ---------------------------------------------------------------------------


class ArgusClient:
    """HTTP client for ARGUS backend API (httpx). Tenant filtering, auth placeholder."""

    def __init__(
        self,
        server_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        tenant_id: Optional[str] = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.tenant_id = tenant_id or os.environ.get("ARGUS_TENANT_ID")
        self._client = httpx.Client(
            base_url=self.server_url,
            timeout=httpx.Timeout(float(timeout)),
        )
        self._connect()

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json"}
        h.update(_get_auth_headers())
        h.update(_get_tenant_headers(self.tenant_id))
        return h

    def _headers_with_admin(self) -> dict[str, str]:
        return {**self._headers(), **_get_admin_headers()}

    def _err_response(self, r: httpx.Response) -> dict[str, Any]:
        try:
            data = r.json()
            if isinstance(data, dict):
                out: dict[str, Any] = {"error": f"HTTP {r.status_code}"}
                out.update(data)
                return out
        except Exception:
            pass
        return {"error": f"HTTP {r.status_code}", "detail": (r.text or "")[:500]}

    def _get_json(
        self,
        path: str,
        params: Optional[Any] = None,
        *,
        admin: bool = False,
    ) -> Any:
        """
        Idempotent GET: retry up to 3 attempts with exponential backoff (1s, 2s) only for
        connection errors and 5xx responses. Do not retry 4xx.
        """
        hdrs = self._headers_with_admin() if admin else self._headers()
        last_exc: Optional[BaseException] = None
        for attempt in range(3):
            try:
                r = self._client.get(path, params=params, headers=hdrs)
                if r.status_code < 400:
                    if not (r.content or b"").strip():
                        return {}
                    ct = (r.headers.get("content-type") or "").lower()
                    if "application/json" in ct:
                        return r.json()
                    return {
                        "note": "non_json_ok",
                        "content_type": r.headers.get("content-type"),
                        "text_preview": (r.text or "")[:8192],
                    }
                transient = r.status_code in (408, 429, 500, 502, 503, 504)
                if r.status_code < 500 or not transient:
                    return self._err_response(r)
                if attempt < 2:
                    time.sleep(2**attempt)
                    continue
                return self._err_response(r)
            except httpx.RequestError as e:
                last_exc = e
                logger.warning("GET %s attempt %s failed: %s", path, attempt + 1, e)
                if attempt < 2:
                    time.sleep(2**attempt)
                    continue
        return {"error": str(last_exc) if last_exc else "request_failed"}

    def _post_json(
        self,
        path: str,
        json_body: Optional[dict[str, Any]] = None,
        *,
        admin: bool = False,
    ) -> Any:
        try:
            hdrs = self._headers_with_admin() if admin else self._headers()
            r = self._client.post(path, json=json_body or {}, headers=hdrs)
            if r.status_code < 400:
                if not (r.content or b"").strip():
                    return {}
                ct = (r.headers.get("content-type") or "").lower()
                if "application/json" in ct:
                    return r.json()
                return {"note": "non_json_ok", "text_preview": (r.text or "")[:8192]}
            return self._err_response(r)
        except httpx.RequestError as e:
            logger.error("POST %s failed: %s", path, e)
            return {"error": str(e)}

    def _delete_json(
        self,
        path: str,
        json_body: Optional[dict[str, Any]] = None,
        *,
        admin: bool = False,
    ) -> Any:
        try:
            hdrs = self._headers_with_admin() if admin else self._headers()
            r = self._client.request("DELETE", path, json=json_body or {}, headers=hdrs)
            if r.status_code < 400:
                if not (r.content or b"").strip():
                    return {}
                ct = (r.headers.get("content-type") or "").lower()
                if "application/json" in ct:
                    return r.json()
                return {"note": "non_json_ok", "text_preview": (r.text or "")[:8192]}
            return self._err_response(r)
        except httpx.RequestError as e:
            logger.error("DELETE %s failed: %s", path, e)
            return {"error": str(e)}

    def _connect(self) -> None:
        for i in range(MAX_RETRIES):
            try:
                r = self._client.get("/api/v1/health", headers=self._headers(), timeout=5.0)
                if r.status_code < 400:
                    logger.info("Connected to ARGUS backend at %s", self.server_url)
                    return
            except httpx.RequestError as e:
                logger.warning("Connection attempt %d/%d failed: %s", i + 1, MAX_RETRIES, e)
            if i < MAX_RETRIES - 1:
                time.sleep(2)
        logger.warning("Could not connect to ARGUS backend; tools may fail")

    def create_scan(
        self,
        target: str,
        email: str = "mcp@argus.local",
        scan_mode: str = "standard",
        options: Optional[dict] = None,
    ) -> dict[str, Any]:
        """POST /api/v1/scans — nested ``options`` + ``scan_mode`` (quick | standard | deep)."""
        try:
            payload = _build_scan_request(target, email, scan_mode, options_overrides=options)
        except ValidationError as e:
            return {
                "error": "validation_failed",
                "scan_id": "",
                "status": "error",
                "details": e.errors(),
            }
        data = self._post_json("/api/v1/scans", payload)
        if isinstance(data, dict) and "error" in data:
            data.setdefault("scan_id", "")
            data.setdefault("status", "error")
        return data if isinstance(data, dict) else {"error": "unexpected_response"}

    def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        data = self._get_json(f"/api/v1/scans/{scan_id}")
        if isinstance(data, dict) and data.get("error"):
            data.setdefault("id", scan_id)
            data.setdefault("status", "error")
        return data if isinstance(data, dict) else {"error": "unexpected_response", "id": scan_id}

    def list_scans(self, status: str = "", limit: int = 50) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if status.strip():
            params["status"] = status.strip()
        data = self._get_json("/api/v1/scans", params)
        if isinstance(data, dict) and data.get("error"):
            return {**data, "scans": [], "count": 0}
        if isinstance(data, list):
            return {"scans": data, "count": len(data)}
        return {"error": "unexpected_response", "scans": [], "count": 0}

    def cancel_scan(self, scan_id: str) -> dict[str, Any]:
        data = self._post_json(f"/api/v1/scans/{scan_id}/cancel", {})
        return data if isinstance(data, dict) else {"error": "unexpected_response"}

    def list_findings(
        self,
        scan_id: str,
        severity: str = "",
        validated_only: bool = False,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if severity.strip():
            params["severity"] = severity.strip()
        if validated_only:
            params["validated_only"] = True
        data = self._get_json(f"/api/v1/scans/{scan_id}/findings", params)
        if isinstance(data, dict) and data.get("error"):
            return {**data, "scan_id": scan_id, "findings": [], "count": 0}
        if isinstance(data, list):
            return {"scan_id": scan_id, "findings": data, "count": len(data)}
        return {"error": "unexpected_response", "scan_id": scan_id, "findings": [], "count": 0}

    def list_reports(self, target: Optional[str] = None) -> dict[str, Any]:
        params: dict[str, Any] = {} if not target else {"target": target}
        data = self._get_json("/api/v1/reports", params)
        if isinstance(data, dict) and data.get("error"):
            return {**data, "reports": [], "count": 0}
        if isinstance(data, list):
            return {"reports": data, "count": len(data)}
        return {"error": "unexpected_response", "reports": [], "count": 0}

    def get_report(self, report_id: str) -> dict[str, Any]:
        data = self._get_json(f"/api/v1/reports/{report_id}")
        if isinstance(data, dict) and data.get("error"):
            data.setdefault("report_id", report_id)
        return data if isinstance(data, dict) else {"error": "unexpected_response", "report_id": report_id}

    def get_finding_detail(self, finding_id: str) -> dict[str, Any]:
        return self._get_json(f"/api/v1/findings/{finding_id}")

    def get_adversarial_top(self, scan_id: str, top_n: int = 5) -> dict[str, Any]:
        data = self._get_json(f"/api/v1/scans/{scan_id}/findings/top", {"limit": top_n})
        if isinstance(data, list):
            return {"scan_id": scan_id, "findings": data, "count": len(data)}
        if isinstance(data, dict):
            return data
        return {"error": "unexpected_response"}

    def get_poc_code(self, finding_id: str) -> dict[str, Any]:
        return self._get_json(f"/api/v1/findings/{finding_id}/poc")

    def get_scan_report_v4(self, scan_id: str, report_format: str = "html", tier: str = "valhalla") -> dict[str, Any]:
        try:
            r = self._client.get(
                f"/api/v1/scans/{scan_id}/report",
                params={"format": report_format, "tier": tier},
                headers=self._headers(),
            )
            if r.status_code >= 400:
                return self._err_response(r)
            ct = (r.headers.get("content-type") or "").lower()
            if "application/json" in ct:
                return r.json()
            return {
                "scan_id": scan_id,
                "format": report_format,
                "tier": tier,
                "content_type": r.headers.get("content-type"),
                "text_preview": (r.text or "")[:8192],
                "note": "non_json_or_binary_report_body_truncated",
            }
        except httpx.RequestError as e:
            return {"error": str(e)}

    def get_scan_cost(self, scan_id: str) -> dict[str, Any]:
        return self._get_json(f"/api/v1/scans/{scan_id}/cost")

    def analyze_target_intelligence(self, target: str, analysis_type: str = "comprehensive") -> dict[str, Any]:
        return self._post_json(
            "/api/v1/intelligence/analyze-target",
            {"target": target, "analysis_type": analysis_type},
        )

    def get_cve_intelligence(self, cve_id: str, product: str = "") -> dict[str, Any]:
        body: dict[str, Any] = {"cve_id": cve_id}
        if product.strip():
            body["product"] = product.strip()
        return self._post_json("/api/v1/intelligence/cve", body)

    def osint_domain(self, domain: str) -> dict[str, Any]:
        return self._post_json("/api/v1/intelligence/osint-domain", {"domain": domain})

    def get_shodan_intel(self, target_ip: str) -> dict[str, Any]:
        return self._get_json("/api/v1/intelligence/shodan", {"ip": target_ip})

    def intelligent_smart_scan(
        self,
        target: str,
        objective: str = "comprehensive",
        max_phases: int = 5,
    ) -> dict[str, Any]:
        tid = (self.tenant_id or "").strip() or None
        try:
            body = _build_smart_scan_request(
                target, objective=objective, max_phases=max_phases, tenant_id=tid
            )
        except ValidationError as e:
            return {"error": "validation_failed", "details": e.errors()}
        return self._post_json("/api/v1/scans/smart", body)

    def get_cache_stats(self) -> dict[str, Any]:
        return self._get_json("/api/v1/cache/stats", admin=True)

    def get_cache_health(self) -> dict[str, Any]:
        return self._get_json("/api/v1/cache/health", admin=True)

    def warm_tool_cache(self) -> dict[str, Any]:
        """POST /api/v1/cache/warm — preload ScanKnowledgeBase keys (requires ARGUS_ADMIN_KEY)."""
        return self._post_json("/api/v1/cache/warm", {}, admin=True)

    def flush_tool_cache(self, patterns: list[str], confirm: bool = True) -> dict[str, Any]:
        """DELETE /api/v1/cache — patterns must start with ``argus:``; confirm must be true."""
        body = {"patterns": list(patterns), "confirm": bool(confirm)}
        return self._delete_json("/api/v1/cache", body, admin=True)

    def get_knowledge_strategy(
        self,
        owasp_ids: Optional[list[str]] = None,
        cwe_ids: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        pairs: list[tuple[str, str]] = []
        for o in owasp_ids or []:
            s = str(o).strip()
            if s:
                pairs.append(("owasp_ids", s))
        for c in cwe_ids or []:
            s = str(c).strip()
            if s:
                pairs.append(("cwe_ids", s))
        data = self._get_json("/api/v1/knowledge/strategy", pairs if pairs else None)
        return data if isinstance(data, dict) else {"error": "unexpected_response"}

    def run_skill_scan(self, target: str, skill: str) -> dict[str, Any]:
        tid = (self.tenant_id or "").strip() or None
        body: dict[str, Any] = {"target": target, "skill": skill}
        if tid:
            body["tenant_id"] = tid
        return self._post_json("/api/v1/scans/skill", body)

    def execute_security_tool(
        self,
        tool: str,
        target: str,
        args_json: str = "{}",
        timeout_sec: Optional[int] = None,
    ) -> dict[str, Any]:
        try:
            extra = json.loads(args_json) if args_json.strip() else {}
        except json.JSONDecodeError as e:
            return {"error": f"invalid args_json: {e}"}
        if not isinstance(extra, dict):
            return {"error": "args_json must decode to a JSON object"}
        cmd = _tool_to_shell_command(tool, target, extra)
        if not cmd:
            return {
                "error": f"cannot build sandbox command for tool {tool!r} (allowlist / target)",
                "success": False,
            }
        body: dict[str, Any] = {"command": cmd, "use_sandbox": False}
        if timeout_sec is not None:
            body["timeout_sec"] = timeout_sec
        return self._post_json("/api/v1/sandbox/execute", body)

    def execute_python_in_sandbox(self, script: str, timeout: int = 60) -> dict[str, Any]:
        to = min(120, max(5, int(timeout)))
        return self._post_json("/api/v1/sandbox/python", {"code": script, "timeout_sec": to})

    def validate_finding(self, finding_id: str) -> dict[str, Any]:
        return self._post_json(f"/api/v1/findings/{finding_id}/validate", {})

    def generate_poc(self, finding_id: str) -> dict[str, Any]:
        return self._post_json(f"/api/v1/findings/{finding_id}/poc/generate", {})

    def get_available_skills(self) -> dict[str, Any]:
        return self._get_json("/api/v1/skills")

    def get_scan_memory_summary(self, scan_id: str) -> dict[str, Any]:
        return self._get_json(f"/api/v1/scans/{scan_id}/memory-summary")

    def get_scan_timeline(self, scan_id: str) -> dict[str, Any]:
        return self._get_json(f"/api/v1/scans/{scan_id}/timeline")

    def get_findings_statistics(self, scan_id: str) -> dict[str, Any]:
        return self._get_json(f"/api/v1/scans/{scan_id}/findings/statistics")

    def mark_finding_false_positive(self, finding_id: str, reason: str) -> dict[str, Any]:
        body = {"reason": (reason or "").strip()}
        if not body["reason"]:
            return {"error": "reason_required", "finding_id": finding_id}
        return self._post_json(f"/api/v1/findings/{finding_id}/false-positive", body)

    def get_finding_remediation(self, finding_id: str, use_llm: bool = False) -> dict[str, Any]:
        params: dict[str, Any] | None = {"use_llm": True} if use_llm else None
        return self._get_json(f"/api/v1/findings/{finding_id}/remediation", params)

    def get_process_list(self) -> dict[str, Any]:
        return self._get_json("/api/v1/sandbox/processes")

    def kill_process(self, pid: int) -> dict[str, Any]:
        return self._post_json(f"/api/v1/sandbox/processes/{int(pid)}/kill", {})

    def run_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """
        Execute a Kali tool via backend. Uses dedicated /tools/{name} when available,
        otherwise POST /tools/execute with constructed command.
        """
        endpoint = tool_name.lower()
        path = f"/api/v1/tools/{endpoint}"

        dedicated = {
            "nmap", "nuclei", "gobuster", "nikto", "sqlmap", "dirb", "ffuf",
            "subfinder", "hydra", "wpscan", "httpx", "amass", "feroxbuster",
            "dirsearch", "wfuzz", "rustscan", "masscan", "trivy",
        }

        if endpoint in dedicated:
            return self._post_dedicated_tool(path, endpoint, args)

        cmd = _build_command_for_tool(tool_name, args)
        if not cmd:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Tool {tool_name}: no command builder. Use backend /api/v1/tools/execute directly.",
                "return_code": -1,
                "execution_time": 0.0,
            }
        return self._post_execute(cmd)

    def _post_dedicated_tool(self, path: str, endpoint: str, args: dict[str, Any]) -> dict[str, Any]:
        payload = _normalize_payload_for_endpoint(endpoint, args)
        data = self._post_json(path, payload)
        if isinstance(data, dict) and data.get("error"):
            return {
                **data,
                "success": False,
                "stdout": "",
                "stderr": str(data.get("error", "")),
                "return_code": -1,
            }
        return data if isinstance(data, dict) else {"error": "unexpected_response"}

    def _post_execute(self, command: str) -> dict[str, Any]:
        data = self._post_json("/api/v1/tools/execute", {"command": command, "use_cache": False})
        if isinstance(data, dict) and data.get("error"):
            return {
                **data,
                "success": False,
                "stdout": "",
                "stderr": str(data.get("error", "")),
                "return_code": -1,
            }
        return data if isinstance(data, dict) else {"error": "unexpected_response"}

    def enqueue_va_sandbox_tool(
        self,
        tool_name: str,
        tenant_id: str,
        scan_id: str,
        target: str,
        args_json: str = "",
    ) -> dict[str, Any]:
        payload, err = build_enqueue_payload(tool_name, tenant_id, scan_id, target, args_json)
        if err or not payload:
            return {"success": False, "error": err or "invalid_payload", "task_id": ""}
        hdrs = {**self._headers(), **_get_admin_headers()}
        try:
            r = self._client.post(
                "/api/v1/internal/va-tools/enqueue",
                json=payload,
                headers=hdrs,
                timeout=60.0,
            )
            if r.status_code < 400:
                data = r.json() if r.content else {}
                return {"success": True, **(data if isinstance(data, dict) else {})}
            err_body = self._err_response(r)
            return {
                "success": False,
                "error": str(err_body.get("error", "request_failed")),
                "task_id": "",
            }
        except httpx.RequestError as e:
            logger.error("enqueue_va_sandbox_tool failed: %s", e)
            return {"success": False, "error": str(e), "task_id": ""}

    def kal_run(
        self,
        category: str,
        argv: list[str],
        target: str,
        tenant_id: str = "",
        scan_id: str = "",
        password_audit_opt_in: bool = False,
    ) -> dict[str, Any]:
        tid = tenant_id.strip() or (self.tenant_id or "")
        payload: dict[str, Any] = {
            "category": category.strip().lower().replace("-", "_"),
            "argv": argv,
            "target": target.strip(),
            "tenant_id": tid,
            "scan_id": scan_id.strip(),
            "password_audit_opt_in": password_audit_opt_in,
        }
        data = self._post_json("/api/v1/tools/kal/run", payload)
        if isinstance(data, dict) and data.get("error"):
            return {
                "success": False,
                "stdout": "",
                "stderr": str(data.get("error", "")),
                "return_code": -1,
                "execution_time": 0.0,
                "policy_reason": "request_failed",
                "minio_keys": [],
            }
        return data if isinstance(data, dict) else {"error": "unexpected_response"}


def _tool_to_shell_command(tool: str, target: str, args: dict[str, Any]) -> Optional[str]:
    """Build a single shell command string for POST /api/v1/sandbox/execute allowlist."""
    t = tool.strip().lower()
    a = dict(args)
    if target:
        a.setdefault("target", target)
        a.setdefault("url", target)
        a.setdefault("domain", target)
        a.setdefault("targets", target)
    direct = _build_command_for_tool(t, a)
    if direct:
        return direct
    if t == "nuclei":
        d = _normalize_payload_for_endpoint("nuclei", a)
        u = str(d.get("target") or "").strip()
        if not u:
            return None
        parts = ["nuclei", "-u", u]
        if d.get("additional_args"):
            parts.extend(shlex.split(str(d["additional_args"])))
        return shlex.join(parts)
    if t == "nmap":
        d = _normalize_payload_for_endpoint("nmap", a)
        parts = ["nmap", str(d.get("scan_type") or "-sV")]
        if d.get("ports"):
            parts.extend(["-p", str(d["ports"])])
        parts.append(str(d.get("target") or ""))
        if d.get("additional_args"):
            parts.extend(shlex.split(str(d["additional_args"])))
        return shlex.join(parts)
    if t == "gobuster":
        d = _normalize_payload_for_endpoint("gobuster", a)
        u = str(d.get("url") or "").strip()
        if not u:
            return None
        parts = [
            "gobuster",
            "dir",
            "-u",
            u,
            "-w",
            str(d.get("wordlist") or "/usr/share/wordlists/dirb/common.txt"),
        ]
        if d.get("additional_args"):
            parts.extend(shlex.split(str(d["additional_args"])))
        return shlex.join(parts)
    if t == "nikto":
        d = _normalize_payload_for_endpoint("nikto", a)
        tg = str(d.get("target") or "").strip()
        if not tg:
            return None
        parts = ["nikto", "-h", tg]
        if d.get("additional_args"):
            parts.extend(shlex.split(str(d["additional_args"])))
        return shlex.join(parts)
    if t == "sqlmap":
        d = _normalize_payload_for_endpoint("sqlmap", a)
        u = str(d.get("url") or "").strip()
        if not u:
            return None
        parts = ["sqlmap", "-u", u, "--batch"]
        if d.get("additional_args"):
            parts.extend(shlex.split(str(d["additional_args"])))
        return shlex.join(parts)
    return None


def _normalize_payload_for_endpoint(endpoint: str, args: dict[str, Any]) -> dict[str, Any]:
    """Map generic args to backend schema per endpoint."""
    a = args
    defaults: dict[str, dict[str, Any]] = {
        "nmap": {"target": "", "scan_type": "-sV", "ports": "", "additional_args": "-T4 -Pn"},
        "nuclei": {"target": "", "severity": "", "tags": "", "template": "", "additional_args": ""},
        "gobuster": {"url": "", "mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt", "additional_args": ""},
        "nikto": {"target": "", "additional_args": ""},
        "sqlmap": {"url": "", "data": "", "additional_args": ""},
        "dirb": {"url": "", "wordlist": "/usr/share/wordlists/dirb/common.txt", "additional_args": ""},
        "ffuf": {"url": "", "wordlist": "/usr/share/wordlists/dirb/common.txt", "additional_args": ""},
        "subfinder": {"domain": "", "additional_args": ""},
        "hydra": {"target": "", "service": "", "username": "", "password": "", "username_file": "", "password_file": "", "additional_args": ""},
        "wpscan": {"url": "", "additional_args": ""},
        "httpx": {"targets": "", "additional_args": ""},
        "amass": {"domain": "", "additional_args": ""},
        "feroxbuster": {"url": "", "wordlist": "/usr/share/wordlists/dirb/common.txt", "additional_args": ""},
        "dirsearch": {"url": "", "wordlist": "/usr/share/wordlists/dirb/common.txt", "additional_args": ""},
        "wfuzz": {"url": "", "wordlist": "/usr/share/wordlists/dirb/common.txt", "additional_args": ""},
        "rustscan": {"target": "", "ports": "", "additional_args": ""},
        "masscan": {"target": "", "ports": "1-65535", "rate": "1000", "additional_args": ""},
        "trivy": {"scan_type": "image", "target": "", "additional_args": ""},
    }
    base = defaults.get(endpoint, {})
    out: dict[str, Any] = {}
    for k, default in base.items():
        val = a.get(k) or a.get(_arg_alias(k, endpoint)) or default
        out[k] = val if val is not None else default
    # Map generic "target" to endpoint-specific primary arg
    if "target" in a and a["target"] and endpoint in ("nmap", "nikto", "rustscan", "masscan"):
        out.setdefault("target", a["target"])
    if "domain" in a and a["domain"] and endpoint in ("subfinder", "amass"):
        out["domain"] = a["domain"]
    if "url" in a and a["url"] and endpoint in ("gobuster", "sqlmap", "dirb", "ffuf", "wpscan", "feroxbuster", "dirsearch"):
        out["url"] = a["url"]
    if "targets" in a and a["targets"] and endpoint == "httpx":
        out["targets"] = a["targets"]
    return out


def _arg_alias(key: str, endpoint: str) -> str:
    """Map generic 'target' to endpoint-specific key."""
    if key == "target":
        return "target"
    if key in ("domain", "url", "targets"):
        return key
    return key


def _build_command_for_tool(tool_name: str, args: dict[str, Any]) -> str:
    """Build CLI command for tools using /execute. Returns empty string if no builder."""
    a = args
    target = a.get("target") or a.get("domain") or a.get("url") or a.get("targets") or ""
    extra = (a.get("additional_args") or "").strip()

    builders: dict[str, str] = {
        "dig": f"dig {_q(target)}" if target else "",
        "whois": f"whois {_q(target)}" if target else "",
        "host": f"host {_q(target)}" if target else "",
        "curl": f"curl {_q(target)}" if target else "",
        "whatweb": f"whatweb {_q(target)}" if target else "",
        "dnsx": f"dnsx -d {_q(target)}" if target else "",
        "naabu": f"naabu -host {_q(target)}" if target else "",
        "theharvester": f"theHarvester -d {_q(target)}" if target else "",
        "dnsrecon": f"dnsrecon -d {_q(target)}" if target else "",
        "fierce": f"fierce --domain {_q(target)}" if target else "",
        "assetfinder": f"assetfinder {_q(target)}" if target else "",
        "findomain": f"findomain -d {_q(target)}" if target else "",
        "gau": f"gau {_q(target)}" if target else "",
        "waybackurls": f"waybackurls {_q(target)}" if target else "",
        "sublist3r": f"sublist3r -d {_q(target)}" if target else "",
        "gitleaks": "gitleaks detect" + (f" --source {_q(target)}" if target else ""),
        "semgrep": f"semgrep scan --config auto {_q(target)}" if target else "semgrep scan --config auto .",
        "trufflehog": f"trufflehog filesystem {_q(target)}" if target else "trufflehog filesystem .",
        "prowler": "prowler" + (f" -p {_q(target)}" if target else ""),
        "checkov": f"checkov -d {_q(target)}" if target else "checkov -d .",
        "terrascan": f"terrascan scan -d {_q(target)}" if target else "terrascan scan -d .",
    }
    cmd = builders.get(tool_name.lower(), "")
    if cmd and extra:
        cmd = f"{cmd} {extra}"
    return cmd


def _q(s: str) -> str:
    """Quote for shell safety."""
    return shlex.quote(s) if s else ""


def _scan_mode_from_alias(scan_type: str) -> str:
    """Map legacy scan_type labels to backend scan_mode (quick|standard|deep)."""
    s = (scan_type or "standard").strip().lower()
    if s in ("quick", "standard", "deep"):
        return s
    if s in ("light", "normal"):
        return "standard"
    return "standard"


# ---------------------------------------------------------------------------
# MCP Server Setup
# ---------------------------------------------------------------------------


def setup_mcp_server(client: ArgusClient) -> FastMCP:
    """Register MCP tools. No legacy naming."""
    mcp = FastMCP("argus-mcp")

    @mcp.tool()
    def create_scan(
        target: str,
        email: str = "mcp@argus.local",
        scan_mode: str = "standard",
        options_json: str = "{}",
    ) -> dict[str, Any]:
        """
        Create a new security scan against a target.

        Args:
            target: URL or domain to scan (e.g. https://example.com)
            email: Contact email for the scan
            scan_mode: quick | standard | deep (aliases: light, normal → standard)
            options_json: JSON object merged into ScanOptions (scanType, reportFormat,
                vulnerabilities, scope, advanced, kal, …) — matches backend ScanCreateRequest.options

        Returns:
            scan_id, status, message
        """
        try:
            extra = json.loads(options_json) if options_json.strip() else {}
        except json.JSONDecodeError as e:
            return {"error": f"invalid options_json: {e}", "scan_id": "", "status": "error"}
        if not isinstance(extra, dict):
            return {"error": "options_json must be a JSON object", "scan_id": "", "status": "error"}
        sm = _scan_mode_from_alias(scan_mode)
        return client.create_scan(target=target, email=email, scan_mode=sm, options=extra)

    @mcp.tool()
    def get_scan_status(scan_id: str) -> dict[str, Any]:
        """Get scan status: id, status, progress, phase, target, created_at."""
        return client.get_scan_status(scan_id)

    @mcp.tool()
    def list_scans(status: str = "", limit: int = 50) -> dict[str, Any]:
        """List scans for the current tenant; optional status filter."""
        return client.list_scans(status=status, limit=limit)

    @mcp.tool()
    def cancel_scan(scan_id: str) -> dict[str, Any]:
        """Request cancellation of a scan."""
        return client.cancel_scan(scan_id)

    @mcp.tool()
    def list_findings(
        scan_id: str,
        severity: str = "",
        validated_only: bool = False,
    ) -> dict[str, Any]:
        """List findings for a scan; optional severity filter and validated_only."""
        return client.list_findings(scan_id, severity=severity, validated_only=validated_only)

    @mcp.tool()
    def get_finding_detail(finding_id: str) -> dict[str, Any]:
        """Finding detail including adversarial score and validation-related fields."""
        return client.get_finding_detail(finding_id)

    @mcp.tool()
    def get_adversarial_top(scan_id: str, top_n: int = 5) -> dict[str, Any]:
        """Top findings ordered by adversarial_score for a scan."""
        return client.get_adversarial_top(scan_id, top_n=top_n)

    @mcp.tool()
    def get_poc_code(finding_id: str) -> dict[str, Any]:
        """Stored PoC payload for a finding (if available)."""
        return client.get_poc_code(finding_id)

    @mcp.tool()
    def get_report(
        scan_id: Optional[str] = None,
        report_id: Optional[str] = None,
        target: Optional[str] = None,
        report_format: str = "html",
        tier: str = "valhalla",
    ) -> dict[str, Any]:
        """
        Report by scan (download preview), by report UUID, or list reports when only target is set.
        report_format: html | json | pdf | csv (backend-dependent).
        tier: midgard | asgard | valhalla
        """
        if scan_id:
            return client.get_scan_report_v4(scan_id, report_format=report_format, tier=tier)
        if report_id:
            return client.get_report(report_id)
        return client.list_reports(target=target)

    @mcp.tool()
    def get_scan_cost(scan_id: str) -> dict[str, Any]:
        """LLM / scan cost summary."""
        return client.get_scan_cost(scan_id)

    @mcp.tool()
    def analyze_target_intelligence(target: str, analysis_type: str = "comprehensive") -> dict[str, Any]:
        """LLM target analysis: attack surface, stack, recommended tools."""
        return client.analyze_target_intelligence(target, analysis_type=analysis_type)

    @mcp.tool()
    def get_cve_intelligence(cve_id: str, product: str = "") -> dict[str, Any]:
        """CVE enrichment (Perplexity-backed when configured)."""
        return client.get_cve_intelligence(cve_id, product=product)

    @mcp.tool()
    def osint_domain(domain: str) -> dict[str, Any]:
        """Domain OSINT summary (Perplexity + optional Shodan)."""
        return client.osint_domain(domain)

    @mcp.tool()
    def get_shodan_intel(target_ip: str) -> dict[str, Any]:
        """Shodan summary for an IPv4 address."""
        return client.get_shodan_intel(target_ip)

    @mcp.tool()
    def intelligent_smart_scan(
        target: str,
        objective: str = "comprehensive",
        max_phases: int = 5,
    ) -> dict[str, Any]:
        """Enqueue smart scan from objective + phase budget."""
        return client.intelligent_smart_scan(target, objective=objective, max_phases=max_phases)

    @mcp.tool()
    def run_skill_scan(target: str, skill: str) -> dict[str, Any]:
        """Enqueue scan focused on a named skill."""
        return client.run_skill_scan(target, skill=skill)

    @mcp.tool()
    def execute_security_tool(
        tool: str,
        target: str,
        args_json: str = "{}",
        timeout_sec: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Run allowlisted CLI tool via POST /api/v1/sandbox/execute.
        args_json: JSON object merged into tool args (e.g. additional_args, ports).
        """
        return client.execute_security_tool(tool, target, args_json=args_json, timeout_sec=timeout_sec)

    @mcp.tool()
    def execute_python_in_sandbox(script: str, timeout: int = 60) -> dict[str, Any]:
        """Run constrained Python snippet when ARGUS_SANDBOX_PYTHON_ENABLED is true."""
        return client.execute_python_in_sandbox(script, timeout=timeout)

    @mcp.tool()
    def validate_finding(finding_id: str) -> dict[str, Any]:
        """Run exploitability validation pipeline for a finding."""
        return client.validate_finding(finding_id)

    @mcp.tool()
    def generate_poc(finding_id: str) -> dict[str, Any]:
        """Generate PoC payload for a finding (LLM-backed when available)."""
        return client.generate_poc(finding_id)

    @mcp.tool()
    def get_available_skills() -> dict[str, Any]:
        """List packaged skill markdown ids by category."""
        return client.get_available_skills()

    @mcp.tool()
    def get_cache_stats() -> dict[str, Any]:
        """Redis/tool-cache stats (requires ARGUS_ADMIN_KEY)."""
        return client.get_cache_stats()

    @mcp.tool()
    def get_cache_health() -> dict[str, Any]:
        """Redis connectivity and memory summary (requires ARGUS_ADMIN_KEY)."""
        return client.get_cache_health()

    @mcp.tool()
    def warm_cache() -> dict[str, Any]:
        """Warm ScanKnowledgeBase Redis keys via POST /api/v1/cache/warm (requires ARGUS_ADMIN_KEY)."""
        return client.warm_tool_cache()

    @mcp.tool()
    def flush_cache(patterns_json: str, confirm: bool = False) -> dict[str, Any]:
        """
        Flush cache keys matching patterns (DELETE /api/v1/cache). Each pattern must start with argus:.
        patterns_json: JSON array of strings, e.g. [\"argus:tool:*\"]. confirm must be true.
        """
        try:
            raw = json.loads(patterns_json) if patterns_json.strip() else []
        except json.JSONDecodeError as e:
            return {"error": f"invalid patterns_json: {e}"}
        if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
            return {"error": "patterns_json must be a JSON array of strings"}
        return client.flush_tool_cache(raw, confirm=confirm)

    @mcp.tool()
    def get_knowledge_strategy(
        owasp_ids_json: str = "[]",
        cwe_ids_json: str = "[]",
    ) -> dict[str, Any]:
        """
        GET /api/v1/knowledge/strategy — skills/tools/priority from OWASP ids (e.g. A01) and CWE ids.
        Pass JSON arrays, e.g. owasp_ids_json: [\"A01\",\"A05\"], cwe_ids_json: [\"CWE-79\"].
        """
        try:
            o = json.loads(owasp_ids_json) if owasp_ids_json.strip() else []
            c = json.loads(cwe_ids_json) if cwe_ids_json.strip() else []
        except json.JSONDecodeError as e:
            return {"error": f"invalid JSON: {e}"}
        if not isinstance(o, list):
            return {"error": "owasp_ids_json must be a JSON array"}
        if not isinstance(c, list):
            return {"error": "cwe_ids_json must be a JSON array"}
        o_list = [str(x) for x in o]
        c_list = [str(x) for x in c]
        return client.get_knowledge_strategy(owasp_ids=o_list, cwe_ids=c_list)

    @mcp.tool()
    def get_scan_memory_summary(scan_id: str) -> dict[str, Any]:
        """Compressed scan context: findings summary, technologies, phases, costs."""
        return client.get_scan_memory_summary(scan_id)

    @mcp.tool()
    def get_scan_timeline(scan_id: str) -> dict[str, Any]:
        """Chronological ScanEvent list with gap_from_previous_sec and total_duration_sec."""
        return client.get_scan_timeline(scan_id)

    @mcp.tool()
    def get_findings_statistics(scan_id: str) -> dict[str, Any]:
        """Per-scan aggregates: severity, OWASP, confidence, CWEs, validated, false positives, risk_score."""
        return client.get_findings_statistics(scan_id)

    @mcp.tool()
    def mark_finding_false_positive(finding_id: str, reason: str) -> dict[str, Any]:
        """Mark a finding as false positive with operator reason (same auth as other finding APIs)."""
        return client.mark_finding_false_positive(finding_id, reason)

    @mcp.tool()
    def get_finding_remediation(finding_id: str, use_llm: bool = False) -> dict[str, Any]:
        """Remediation excerpts from ScanKnowledgeBase-mapped skills; optional short LLM summary."""
        return client.get_finding_remediation(finding_id, use_llm=use_llm)

    @mcp.tool()
    def get_process_list() -> dict[str, Any]:
        """List running processes in the sandbox container."""
        return client.get_process_list()

    @mcp.tool()
    def kill_process(pid: int) -> dict[str, Any]:
        """Terminate a process in the sandbox container by PID."""
        return client.kill_process(pid)

    _register_kali_tools(mcp, client)
    _register_va_sandbox_enqueue_tools(mcp, client)
    _register_kal_mcp_tools(mcp, client)

    return mcp


def _register_kal_mcp_tools(mcp: FastMCP, client: ArgusClient) -> None:
    """KAL-002 — category-gated argv tools (hydra only password_audit + server + client opt-in)."""

    @mcp.tool()
    def run_network_scan(
        tenant_id: str,
        scan_id: str,
        target: str,
        tool: str = "nmap",
        extra_args: str = "-sV -Pn -T4",
    ) -> dict[str, Any]:
        """
        Run an allowlisted network scanner (nmap, rustscan, masscan). Policy category: network_scanning.
        extra_args: additional CLI tokens (shell-style split). target is used for guardrails and appended for nmap/rustscan.
        """
        t = tool.strip().lower()
        extras = shlex.split(extra_args.strip()) if extra_args.strip() else []
        if t == "nmap":
            argv = ["nmap", *extras, target]
        elif t == "rustscan":
            argv = ["rustscan", "-a", target, *extras]
        elif t == "masscan":
            argv = ["masscan", target, *extras] if extras else ["masscan", target, "-p", "1-1000", "--rate", "1000"]
        else:
            return {
                "success": False,
                "stdout": "",
                "stderr": "tool must be nmap, rustscan, or masscan",
                "return_code": -1,
                "execution_time": 0.0,
                "policy_reason": "invalid_tool",
                "minio_keys": [],
            }
        return client.kal_run("network_scanning", argv, target, tenant_id, scan_id, False)

    @mcp.tool()
    def run_web_scan(
        tenant_id: str,
        scan_id: str,
        target: str,
        tool: str = "httpx",
        extra_args: str = "-silent",
    ) -> dict[str, Any]:
        """
        Web fingerprint / probe (httpx, whatweb, wpscan, nikto). category: web_fingerprinting.
        target: URL or host. For httpx, -u is set to target automatically when tool is httpx.
        """
        t = tool.strip().lower()
        extras = shlex.split(extra_args.strip()) if extra_args.strip() else []
        if t == "httpx":
            base = ["httpx", "-u", target]
            argv = [*base, *extras] if extras else [*base, "-silent"]
        elif t == "whatweb":
            argv = ["whatweb", target, *extras]
        elif t == "wpscan":
            argv = ["wpscan", "--url", target, *extras]
        elif t == "nikto":
            argv = ["nikto", "-h", target, *extras]
        else:
            return {
                "success": False,
                "stdout": "",
                "stderr": "tool must be httpx, whatweb, wpscan, or nikto",
                "return_code": -1,
                "execution_time": 0.0,
                "policy_reason": "invalid_tool",
                "minio_keys": [],
            }
        return client.kal_run("web_fingerprinting", argv, target, tenant_id, scan_id, False)

    @mcp.tool()
    def run_ssl_test(
        tenant_id: str,
        scan_id: str,
        target: str,
        extra_args: str = "",
    ) -> dict[str, Any]:
        """
        TLS probe via openssl s_client. category: ssl_analysis. target: host:port or https URL (host inferred).
        """
        host = target.strip()
        port = "443"
        if "://" in host:
            p = urlparse(host if host.startswith("http") else f"https://{host}")
            host = (p.hostname or "").strip()
            if p.port:
                port = str(p.port)
        elif ":" in host:
            host_part, _, p = host.rpartition(":")
            host = host_part.strip() or host
            if p.isdigit():
                port = p
        if not host:
            return {
                "success": False,
                "stdout": "",
                "stderr": "invalid target host",
                "return_code": -1,
                "execution_time": 0.0,
                "policy_reason": "invalid_target",
                "minio_keys": [],
            }
        connect = f"{host}:{port}"
        extras = shlex.split(extra_args.strip()) if extra_args.strip() else []
        argv = ["openssl", "s_client", "-connect", connect, "-servername", host, *extras]
        return client.kal_run("ssl_analysis", argv, target, tenant_id, scan_id, False)

    @mcp.tool()
    def run_dns_enum(
        tenant_id: str,
        scan_id: str,
        target: str,
        tool: str = "dig",
        extra_args: str = "",
    ) -> dict[str, Any]:
        """DNS enumeration (dig, subfinder, amass, dnsx, host, nslookup). category: dns_enumeration."""
        t = tool.strip().lower()
        extras = shlex.split(extra_args.strip()) if extra_args.strip() else []
        if t == "dig":
            argv = ["dig", "+short", target, *extras]
        elif t == "subfinder":
            argv = ["subfinder", "-d", target, *extras]
        elif t == "amass":
            argv = ["amass", "enum", "-d", target, *extras]
        elif t == "dnsx":
            argv = ["dnsx", "-d", target, *extras]
        elif t == "host":
            argv = ["host", target, *extras]
        elif t == "nslookup":
            argv = ["nslookup", target, *extras]
        else:
            return {
                "success": False,
                "stdout": "",
                "stderr": "tool must be dig, subfinder, amass, dnsx, host, or nslookup",
                "return_code": -1,
                "execution_time": 0.0,
                "policy_reason": "invalid_tool",
                "minio_keys": [],
            }
        return client.kal_run("dns_enumeration", argv, target, tenant_id, scan_id, False)

    @mcp.tool()
    def run_bruteforce(
        tenant_id: str,
        scan_id: str,
        target: str,
        tool: str = "gobuster",
        extra_args: str = "",
    ) -> dict[str, Any]:
        """
        Content discovery / web bruteforce tools only (gobuster, ffuf, etc.). category: bruteforce_testing.
        Hydra is denied here — use password_audit flow if enabled server-side.
        """
        t = tool.strip().lower()
        extras = shlex.split(extra_args.strip()) if extra_args.strip() else []
        if t == "gobuster":
            argv = ["gobuster", "dir", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", *extras]
        elif t == "feroxbuster":
            argv = ["feroxbuster", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", *extras]
        elif t == "dirsearch":
            argv = ["dirsearch", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", *extras]
        elif t == "ffuf":
            argv = ["ffuf", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", *extras]
        elif t == "wfuzz":
            argv = ["wfuzz", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", *extras]
        elif t == "dirb":
            argv = ["dirb", target, "/usr/share/wordlists/dirb/common.txt", *extras]
        else:
            return {
                "success": False,
                "stdout": "",
                "stderr": "tool must be gobuster, feroxbuster, dirsearch, ffuf, wfuzz, or dirb",
                "return_code": -1,
                "execution_time": 0.0,
                "policy_reason": "invalid_tool",
                "minio_keys": [],
            }
        return client.kal_run("bruteforce_testing", argv, target, tenant_id, scan_id, False)

    @mcp.tool()
    def run_tool(
        category: str,
        tenant_id: str,
        scan_id: str,
        target: str,
        argv_json: str,
        password_audit_opt_in: bool = False,
    ) -> dict[str, Any]:
        """
        Generic KAL MCP runner: argv_json is a JSON array of CLI strings; category must match policy mapping.
        For hydra/medusa use category=password_audit and set password_audit_opt_in=true (requires server KAL_ALLOW_PASSWORD_AUDIT).
        """
        try:
            raw = json.loads(argv_json)
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"invalid argv_json: {e}",
                "return_code": -1,
                "execution_time": 0.0,
                "policy_reason": "invalid_argv_json",
                "minio_keys": [],
            }
        if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
            return {
                "success": False,
                "stdout": "",
                "stderr": "argv_json must be a JSON array of strings",
                "return_code": -1,
                "execution_time": 0.0,
                "policy_reason": "invalid_argv_json",
                "minio_keys": [],
            }
        return client.kal_run(
            category.strip().lower().replace("-", "_"),
            raw,
            target,
            tenant_id,
            scan_id,
            password_audit_opt_in,
        )


def _register_va_sandbox_enqueue_tools(mcp: FastMCP, client: ArgusClient) -> None:
    """VA-005 — MCP tools that enqueue backend Celery VA runs (allowlisted tools only; no shell)."""

    @mcp.tool()
    def va_enqueue_sandbox_scanner(
        tool_name: str,
        tenant_id: str,
        scan_id: str,
        target: str,
        args_json: str = "",
    ) -> dict[str, Any]:
        """
        Enqueue a sandbox VA scan (dalfox, xsstrike, ffuf, sqlmap, nuclei) as a Celery task.
        Execution uses backend mcp_runner + policy; stdout/stderr go to MinIO under vuln_analysis.
        Optional args_json: JSON array of CLI strings (must keep safe tool prefix). Empty = server defaults.
        Set ARGUS_ADMIN_KEY if the backend requires X-Admin-Key.
        """
        return client.enqueue_va_sandbox_tool(tool_name, tenant_id, scan_id, target, args_json)


def _register_kali_tools(mcp: FastMCP, client: ArgusClient) -> None:
    """Register 150+ Kali tools from registry. Each tool calls backend run_tool."""
    for tool_def in KALI_TOOL_REGISTRY:
        _register_single_kali_tool(mcp, client, tool_def)


def _register_single_kali_tool(mcp: FastMCP, client: ArgusClient, tool_def: ToolDefinition) -> None:
    """Register one Kali tool with dynamic schema. Uses target + additional_args (no **kwargs)."""
    primary_key = _get_primary_arg(tool_def)
    safe_name = f"kali_{tool_def.name}".replace("-", "_")

    def handler(target: str = "", additional_args: str = "") -> dict[str, Any]:
        """Kali tool handler — target is domain/url/host per tool, extra opts in additional_args."""
        args: dict[str, Any] = {primary_key: target, "additional_args": additional_args}
        return client.run_tool(tool_def.name, args)

    handler.__name__ = safe_name
    handler.__doc__ = tool_def.description
    mcp.tool()(handler)


def _get_primary_arg(tool_def: ToolDefinition) -> str:
    """Return primary arg name for tool (target, domain, url, etc.)."""
    for arg in tool_def.args_schema:
        if arg.required and arg.name not in ("additional_args",):
            return arg.name
    return "target"


def main() -> None:
    parser = argparse.ArgumentParser(description="ARGUS MCP Server")
    parser.add_argument(
        "--server",
        default=os.environ.get("ARGUS_SERVER_URL", DEFAULT_SERVER_URL),
        help="ARGUS backend URL",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout (seconds)")
    parser.add_argument("--tenant", default=os.environ.get("ARGUS_TENANT_ID"), help="Tenant ID for scan access")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        help="Transport: stdio (local Cursor) or http (Docker). Default from MCP_TRANSPORT env.",
    )
    args = parser.parse_args()

    server_url = (os.environ.get("ARGUS_SERVER_URL") or args.server or DEFAULT_SERVER_URL).strip()
    client = ArgusClient(server_url, args.timeout, tenant_id=args.tenant)
    mcp = setup_mcp_server(client)

    if args.transport == "http":
        try:
            port = int(os.environ.get("MCP_PORT", "8000"))
            if not 1 <= port <= 65535:
                raise ValueError(f"Port {port} out of range")
        except ValueError as e:
            logger.warning("Invalid MCP_PORT (%s), falling back to 8000", e)
            port = 8000
        logger.info("Starting ARGUS MCP server (HTTP transport on 0.0.0.0:%d)", port)
        mcp.run(transport="http", host="0.0.0.0", port=port)
    else:
        logger.info("Starting ARGUS MCP server (stdio transport)")
        mcp.run()


if __name__ == "__main__":
    main()
