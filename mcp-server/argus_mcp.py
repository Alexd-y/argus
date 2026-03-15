#!/usr/bin/env python3
"""
ARGUS MCP Server — FastMCP, stdio or HTTP transport.

SSE-MCP-007: Tools call backend API. Typed schemas, auth placeholder, tenant awareness.
MCP-002: 150+ Kali pentest tools via backend /api/v1/tools/* endpoints.
MCP-002: HTTP transport for Docker; stdio for local Cursor spawn.
"""

from __future__ import annotations

import argparse
import logging
import os
import shlex
import sys
from typing import Any, Optional

import requests
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from tools.kali_registry import KALI_TOOL_REGISTRY, ToolDefinition

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


class CreateScanRequest(BaseModel):
    """POST /scans request schema."""

    target: str = Field(..., description="URL or domain to scan")
    email: str = Field(default="mcp@argus.local", description="Contact email")
    options: Optional[dict[str, Any]] = Field(default_factory=dict)


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


# ---------------------------------------------------------------------------
# ArgusClient — backend API
# ---------------------------------------------------------------------------


class ArgusClient:
    """HTTP client for ARGUS backend API. Tenant filtering, auth placeholder."""

    def __init__(
        self,
        server_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        tenant_id: Optional[str] = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.tenant_id = tenant_id or os.environ.get("ARGUS_TENANT_ID")
        self.session = requests.Session()
        self._connect()

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json"}
        h.update(_get_auth_headers())
        h.update(_get_tenant_headers(self.tenant_id))
        return h

    def _connect(self) -> None:
        for i in range(MAX_RETRIES):
            try:
                r = self.session.get(
                    f"{self.server_url}/api/v1/health",
                    headers=self._headers(),
                    timeout=5,
                )
                r.raise_for_status()
                logger.info("Connected to ARGUS backend at %s", self.server_url)
                return
            except requests.exceptions.RequestException as e:
                logger.warning("Connection attempt %d/%d failed: %s", i + 1, MAX_RETRIES, e)
                if i < MAX_RETRIES - 1:
                    import time
                    time.sleep(2)
        logger.warning("Could not connect to ARGUS backend; tools may fail")

    def create_scan(self, target: str, email: str = "mcp@argus.local", options: Optional[dict] = None) -> dict[str, Any]:
        """POST /api/v1/scans."""
        url = f"{self.server_url}/api/v1/scans"
        payload = {"target": target, "email": email, "options": options or {}}
        try:
            r = self.session.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            logger.error("create_scan failed: %s", e)
            return {"error": str(e), "scan_id": "", "status": "error"}

    def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        """GET /api/v1/scans/:id."""
        url = f"{self.server_url}/api/v1/scans/{scan_id}"
        try:
            r = self.session.get(url, headers=self._headers(), timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            logger.error("get_scan_status failed: %s", e)
            return {"error": str(e), "id": scan_id, "status": "error"}

    def list_findings(self, scan_id: str) -> dict[str, Any]:
        """GET /api/v1/scans/:id/findings."""
        url = f"{self.server_url}/api/v1/scans/{scan_id}/findings"
        try:
            r = self.session.get(url, headers=self._headers(), timeout=self.timeout)
            r.raise_for_status()
            findings = r.json()
            return {"scan_id": scan_id, "findings": findings, "count": len(findings)}
        except requests.exceptions.RequestException as e:
            logger.error("list_findings failed: %s", e)
            return {"error": str(e), "scan_id": scan_id, "findings": [], "count": 0}

    def list_reports(self, target: Optional[str] = None) -> dict[str, Any]:
        """GET /api/v1/reports?target=."""
        url = f"{self.server_url}/api/v1/reports"
        params = {} if not target else {"target": target}
        try:
            r = self.session.get(url, params=params, headers=self._headers(), timeout=self.timeout)
            r.raise_for_status()
            reports = r.json()
            return {"reports": reports, "count": len(reports)}
        except requests.exceptions.RequestException as e:
            logger.error("list_reports failed: %s", e)
            return {"error": str(e), "reports": [], "count": 0}

    def get_report(self, report_id: str) -> dict[str, Any]:
        """GET /api/v1/reports/:id."""
        url = f"{self.server_url}/api/v1/reports/{report_id}"
        try:
            r = self.session.get(url, headers=self._headers(), timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            logger.error("get_report failed: %s", e)
            return {"error": str(e), "report_id": report_id}

    def run_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """
        Execute a Kali tool via backend. Uses dedicated /tools/{name} when available,
        otherwise POST /tools/execute with constructed command.
        """
        endpoint = tool_name.lower()
        url = f"{self.server_url}/api/v1/tools/{endpoint}"

        # Backend endpoints with dedicated handlers (match backend router)
        dedicated = {
            "nmap", "nuclei", "gobuster", "nikto", "sqlmap", "dirb", "ffuf",
            "subfinder", "hydra", "wpscan", "httpx", "amass", "feroxbuster",
            "dirsearch", "wfuzz", "rustscan", "masscan", "trivy",
        }

        if endpoint in dedicated:
            return self._post_dedicated_tool(url, endpoint, args)

        # Fallback: build command and use /execute
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

    def _post_dedicated_tool(self, url: str, endpoint: str, args: dict[str, Any]) -> dict[str, Any]:
        """POST to dedicated tool endpoint with normalized payload."""
        payload = _normalize_payload_for_endpoint(endpoint, args)
        try:
            r = self.session.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            logger.error("run_tool %s failed: %s", endpoint, e)
            return {"error": str(e), "success": False, "stdout": "", "stderr": str(e), "return_code": -1}

    def _post_execute(self, command: str) -> dict[str, Any]:
        """POST to generic /tools/execute endpoint."""
        url = f"{self.server_url}/api/v1/tools/execute"
        try:
            r = self.session.post(
                url,
                json={"command": command, "use_cache": False},
                headers=self._headers(),
                timeout=self.timeout,
            )
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            logger.error("execute failed: %s", e)
            return {"error": str(e), "success": False, "stdout": "", "stderr": str(e), "return_code": -1}


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
        scan_type: str = "quick",
    ) -> dict[str, Any]:
        """
        Create a new security scan against a target.

        Args:
            target: URL or domain to scan (e.g. https://example.com)
            email: Contact email for the scan
            scan_type: quick, light, or deep

        Returns:
            scan_id, status, message
        """
        options = {"scanType": scan_type}
        return client.create_scan(target=target, email=email, options=options)

    @mcp.tool()
    def get_scan_status(scan_id: str) -> dict[str, Any]:
        """
        Get the status of a scan.

        Args:
            scan_id: UUID of the scan

        Returns:
            id, status, progress, phase, target, created_at
        """
        return client.get_scan_status(scan_id)

    @mcp.tool()
    def list_findings(scan_id: str) -> dict[str, Any]:
        """
        List vulnerability findings for a scan.

        Args:
            scan_id: UUID of the scan

        Returns:
            scan_id, findings (severity, title, description, cwe, cvss), count
        """
        return client.list_findings(scan_id)

    @mcp.tool()
    def get_report(
        report_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Get a report by ID, or list reports filtered by target.

        Args:
            report_id: UUID of the report (if known)
            target: Filter reports by target URL (when report_id not provided)

        Returns:
            report_id, target, summary, findings, technologies
        """
        if report_id:
            return client.get_report(report_id)
        return client.list_reports(target=target)

    _register_kali_tools(mcp, client)

    return mcp


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

    client = ArgusClient(args.server, args.timeout, tenant_id=args.tenant)
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
