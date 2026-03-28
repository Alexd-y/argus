"""Tools router — POST /tools/* for security scanner execution (MVP stubs)."""

import logging
import shlex
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from src.core.config import settings
from src.recon.mcp.kal_executor import run_kal_mcp_tool
from src.recon.mcp.policy import KAL_OPERATION_CATEGORIES
from src.tools.executor import (
    build_gobuster_command,
    build_nikto_command,
    build_nmap_command,
    build_nuclei_command,
    build_sqlmap_command,
    execute_command,
)
from src.tools.guardrails import validate_target_for_tool
from src.tools.guardrails.command_parser import (
    ALLOWED_TOOLS,
    parse_execute_command,
)
from src.tools.guardrails.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tools", tags=["tools"])

# Rate limiter for /execute — in-memory when Redis unavailable
_execute_rate_limiter = RateLimiter(
    redis_client=None,
    max_requests=30,
    window_seconds=60,
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ExecuteRequest(BaseModel):
    """Generic command execution."""

    command: str = Field(..., min_length=1, max_length=4096)
    use_cache: bool = True


class NmapRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    scan_type: str = Field(default="-sV", max_length=64)
    ports: str = Field(default="", max_length=128)
    additional_args: str = Field(default="-T4 -Pn", max_length=512)


class NucleiRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    severity: str = Field(default="", max_length=64)
    tags: str = Field(default="", max_length=256)
    template: str = Field(default="", max_length=256)
    additional_args: str = Field(default="", max_length=512)


class GobusterRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=512)
    mode: str = Field(default="dir", pattern="^(dir|dns|fuzz|vhost)$")
    wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt", max_length=256)
    additional_args: str = Field(default="", max_length=512)


class NiktoRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    additional_args: str = Field(default="", max_length=512)


class SqlmapRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=1024)
    data: str = Field(default="", max_length=2048)
    additional_args: str = Field(default="", max_length=512)


class DirbRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=512)
    wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt", max_length=256)
    additional_args: str = Field(default="", max_length=512)


class FfufRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=512)
    wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt", max_length=256)
    additional_args: str = Field(default="", max_length=512)


class SubfinderRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=256)
    additional_args: str = Field(default="", max_length=512)


class HydraRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    service: str = Field(..., min_length=1, max_length=64)
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=256)
    username_file: str = Field(default="", max_length=256)
    password_file: str = Field(default="", max_length=256)
    additional_args: str = Field(default="", max_length=512)


class WpscanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=512)
    additional_args: str = Field(default="", max_length=512)


class HttpxRequest(BaseModel):
    targets: str = Field(..., min_length=1, max_length=2048)
    additional_args: str = Field(default="", max_length=512)


class AmassRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=256)
    additional_args: str = Field(default="", max_length=512)


class FeroxbusterRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=512)
    wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt", max_length=256)
    additional_args: str = Field(default="", max_length=512)


class DirsearchRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=512)
    wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt", max_length=256)
    additional_args: str = Field(default="", max_length=512)


class WfuzzRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=512)
    wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt", max_length=256)
    additional_args: str = Field(default="", max_length=512)


class RustscanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    ports: str = Field(default="", max_length=128)
    additional_args: str = Field(default="", max_length=512)


class MasscanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    ports: str = Field(default="1-65535", max_length=64)
    rate: str = Field(default="1000", max_length=32)
    additional_args: str = Field(default="", max_length=512)


class TrivyRequest(BaseModel):
    scan_type: str = Field(default="image", pattern="^(image|fs|repo|config)$")
    target: str = Field(default="", max_length=512)
    additional_args: str = Field(default="", max_length=512)


class KalRunRequest(BaseModel):
    """KAL-002 — MCP gated tool argv (category allowlist, hydra double opt-in)."""

    category: str = Field(..., min_length=1, max_length=64)
    argv: list[str] = Field(..., min_length=1, max_length=64)
    target: str = Field(..., min_length=1, max_length=2048)
    tenant_id: str = Field(default="", max_length=256)
    scan_id: str = Field(default="", max_length=256)
    password_audit_opt_in: bool = False

    @field_validator("argv", mode="before")
    @classmethod
    def _coerce_argv(cls, v: object) -> list[str]:
        if not isinstance(v, list):
            raise ValueError("argv must be a list of strings")
        return [str(x) for x in v]

    @field_validator("argv")
    @classmethod
    def _argv_element_lengths(cls, v: list[str]) -> list[str]:
        for a in v:
            if len(a) > 4096:
                raise ValueError("argv element too long")
        return v


# ---------------------------------------------------------------------------
# Generic execute (guardrails: allowlist, target validation, sandbox, rate limit)
# ---------------------------------------------------------------------------


@router.post("/execute")
async def tools_execute(req: ExecuteRequest, request: Request) -> dict[str, Any]:
    """Execute command — only allowed tools (nmap, nuclei, nikto, gobuster, sqlmap)."""
    # Rate limit
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"execute:{client_ip}"
    allowed, reason = _execute_rate_limiter.is_allowed(rate_key)
    if not allowed:
        raise HTTPException(status_code=429, detail=reason)

    # Allowlist: only nmap, nuclei, nikto, gobuster, sqlmap
    tool_name, target = parse_execute_command(req.command)
    if tool_name is None:
        raise HTTPException(
            status_code=400,
            detail=f"Tool not allowed. Allowed: {', '.join(sorted(ALLOWED_TOOLS))}",
        )

    # Target validation when command contains target
    if target:
        validation = validate_target_for_tool(target, tool_name)
        if not validation["allowed"]:
            raise HTTPException(status_code=400, detail=validation["reason"])

    result = execute_command(
        req.command,
        req.use_cache,
        use_sandbox=settings.sandbox_enabled,
    )
    return result


@router.post("/kal/run")
async def tools_kal_run(req: KalRunRequest, request: Request) -> dict[str, Any]:
    """KAL-002 — run allowlisted argv under category policy; optional MinIO raw upload."""
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"kal_run:{client_ip}"
    allowed, reason = _execute_rate_limiter.is_allowed(rate_key)
    if not allowed:
        raise HTTPException(status_code=429, detail=reason)

    cat = str(req.category or "").strip().lower().replace("-", "_")
    if cat not in KAL_OPERATION_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail="Invalid category",
        )

    return run_kal_mcp_tool(
        category=cat,
        argv=list(req.argv),
        target=req.target,
        tenant_id=req.tenant_id.strip() or None,
        scan_id=req.scan_id.strip() or None,
        password_audit_opt_in=req.password_audit_opt_in,
    )


# ---------------------------------------------------------------------------
# Tool endpoints (stubs → execute_command)
# ---------------------------------------------------------------------------


def _run_tool(
    name: str,
    command: str,
    target: str | None = None,
) -> dict[str, Any]:
    """Execute tool with guardrails validation. Target validated before execution."""
    if target:
        validation = validate_target_for_tool(target, name)
        if not validation["allowed"]:
            return {
                "success": False,
                "stdout": "",
                "stderr": validation["reason"],
                "return_code": -1,
                "execution_time": 0.0,
            }
    logger.info("Running %s: %s", name, command[:100])
    result = execute_command(
        command, use_cache=False, use_sandbox=settings.sandbox_enabled
    )
    return result


@router.post("/nmap")
async def tools_nmap(req: NmapRequest) -> dict[str, Any]:
    """Nmap port/service scan."""
    cmd = build_nmap_command(req.target, req.scan_type, req.ports, req.additional_args)
    return _run_tool("nmap", cmd, req.target)


@router.post("/nuclei")
async def tools_nuclei(req: NucleiRequest) -> dict[str, Any]:
    """Nuclei vulnerability scan."""
    cmd = build_nuclei_command(req.target, req.severity, req.tags, req.template, req.additional_args)
    return _run_tool("nuclei", cmd, req.target)


@router.post("/gobuster")
async def tools_gobuster(req: GobusterRequest) -> dict[str, Any]:
    """Gobuster directory/DNS/vhost enumeration."""
    cmd = build_gobuster_command(req.url, req.mode, req.wordlist, req.additional_args)
    return _run_tool("gobuster", cmd, req.url)


@router.post("/nikto")
async def tools_nikto(req: NiktoRequest) -> dict[str, Any]:
    """Nikto web vulnerability scan."""
    cmd = build_nikto_command(req.target, req.additional_args)
    return _run_tool("nikto", cmd)


@router.post("/sqlmap")
async def tools_sqlmap(req: SqlmapRequest) -> dict[str, Any]:
    """SQLMap SQL injection testing."""
    cmd = build_sqlmap_command(req.url, req.data, req.additional_args)
    return _run_tool("sqlmap", cmd, req.url)


@router.post("/dirb")
async def tools_dirb(req: DirbRequest) -> dict[str, Any]:
    """Dirb directory brute-forcing."""
    parts = ["dirb", req.url, req.wordlist]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("dirb", cmd, req.url)


@router.post("/ffuf")
async def tools_ffuf(req: FfufRequest) -> dict[str, Any]:
    """FFuf web fuzzer."""
    parts = ["ffuf", "-u", req.url, "-w", req.wordlist]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("ffuf", cmd, req.url)


@router.post("/subfinder")
async def tools_subfinder(req: SubfinderRequest) -> dict[str, Any]:
    """Subfinder subdomain enumeration."""
    parts = ["subfinder", "-d", req.domain]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("subfinder", cmd, req.domain)


@router.post("/hydra")
async def tools_hydra(req: HydraRequest) -> dict[str, Any]:
    """Hydra password brute-forcing."""
    parts = ["hydra"]
    if req.username:
        parts.extend(["-l", req.username])
    elif req.username_file:
        parts.extend(["-L", req.username_file])
    if req.password:
        parts.extend(["-p", req.password])
    elif req.password_file:
        parts.extend(["-P", req.password_file])
    parts.extend([req.target, req.service])
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("hydra", cmd, req.target)


@router.post("/wpscan")
async def tools_wpscan(req: WpscanRequest) -> dict[str, Any]:
    """WPScan WordPress assessment."""
    parts = ["wpscan", "--url", req.url]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("wpscan", cmd, req.url)


@router.post("/httpx")
async def tools_httpx(req: HttpxRequest) -> dict[str, Any]:
    """httpx HTTP probing."""
    parts = ["httpx", "-u", req.targets]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("httpx", cmd, req.targets)


@router.post("/amass")
async def tools_amass(req: AmassRequest) -> dict[str, Any]:
    """Amass subdomain enumeration."""
    parts = ["amass", "enum", "-d", req.domain]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("amass", cmd, req.domain)


@router.post("/feroxbuster")
async def tools_feroxbuster(req: FeroxbusterRequest) -> dict[str, Any]:
    """Feroxbuster directory brute-forcing."""
    parts = ["feroxbuster", "-u", req.url, "-w", req.wordlist]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("feroxbuster", cmd, req.url)


@router.post("/dirsearch")
async def tools_dirsearch(req: DirsearchRequest) -> dict[str, Any]:
    """Dirsearch directory brute-forcing."""
    parts = ["dirsearch", "-u", req.url, "-w", req.wordlist]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("dirsearch", cmd, req.url)


@router.post("/wfuzz")
async def tools_wfuzz(req: WfuzzRequest) -> dict[str, Any]:
    """Wfuzz web fuzzer."""
    parts = ["wfuzz", "-u", req.url, "-w", req.wordlist]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("wfuzz", cmd, req.url)


@router.post("/rustscan")
async def tools_rustscan(req: RustscanRequest) -> dict[str, Any]:
    """RustScan port scanning."""
    parts = ["rustscan", "-a", req.target]
    if req.ports:
        parts.extend(["--", "-p", req.ports])
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("rustscan", cmd, req.target)


@router.post("/masscan")
async def tools_masscan(req: MasscanRequest) -> dict[str, Any]:
    """Masscan port scanning."""
    parts = ["masscan", req.target, "-p", req.ports, "--rate", req.rate]
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("masscan", cmd, req.target)


@router.post("/trivy")
async def tools_trivy(req: TrivyRequest) -> dict[str, Any]:
    """Trivy vulnerability scanning."""
    parts = ["trivy", req.scan_type]
    if req.target:
        parts.append(req.target)
    if req.additional_args:
        parts.extend(shlex.split(req.additional_args))
    cmd = " ".join(shlex.quote(p) for p in parts)
    return _run_tool("trivy", cmd, req.target if req.target else None)
