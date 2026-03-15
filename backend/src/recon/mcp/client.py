"""MCP fetch client for endpoint discovery with fail-closed policy behavior."""

import asyncio
import logging
from collections.abc import Callable

import httpx

from src.recon.mcp.audit import record_mcp_invocation
from src.recon.mcp.policy import (
    evaluate_recon_stage1_policy,
    evaluate_threat_modeling_policy,
    evaluate_vulnerability_analysis_policy,
    sanitize_args,
)

logger = logging.getLogger(__name__)

# Endpoint format: {status, content_type, exists, notes}
ENDPOINT_FETCH_RESULT = dict


def _sanitize_url_for_log(url: str) -> str:
    """Return URL with sensitive query values redacted for logs."""
    sanitized = sanitize_args({"url": url})
    value = sanitized.get("url", "")
    return str(value) if isinstance(value, str) else ""


def fetch_url_mcp(
    url: str,
    timeout: float = 10.0,
    *,
    operation: str = "endpoint_extraction",
    use_threat_modeling_policy: bool = False,
    use_vulnerability_analysis_policy: bool = False,
) -> dict:
    """Fetch URL via MCP user-fetch with fail-closed behavior.

    Returns dict with keys: status, headers, body, content_type, exists, notes.
    For endpoint_builder compatibility also provides: content_type, exists, notes.

    When use_threat_modeling_policy=True, uses Stage 2 TM policy instead of Stage 1.
    When use_vulnerability_analysis_policy=True, uses Stage 3 VA policy.
    """
    tool_name = "fetch"
    tool_args = {"url": url, "raw": True, "max_length": 5000}
    if use_vulnerability_analysis_policy:
        decision = evaluate_vulnerability_analysis_policy(
            tool_name=tool_name,
            operation="enrichment",
            args=tool_args,
        )
    elif use_threat_modeling_policy:
        decision = evaluate_threat_modeling_policy(
            tool_name=tool_name,
            operation="enrichment",
            args=tool_args,
        )
    else:
        decision = evaluate_recon_stage1_policy(
            tool_name=tool_name,
            operation=operation,
            args=tool_args,
        )
    record_mcp_invocation(
        tool_name=tool_name,
        operation=operation,
        args=tool_args,
        allowed=decision.allowed,
        policy_id=decision.policy_id,
        decision_reason=decision.reason,
    )
    if not decision.allowed:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "content_type": "",
            "exists": False,
            "notes": "mcp_operation_denied_by_policy",
        }

    try:
        return _fetch_via_mcp_sync(url, timeout)
    except Exception:
        logger.info(
            "mcp_fetch_failed",
            extra={
                "url": _sanitize_url_for_log(url),
                "operation": operation,
                "error_code": "mcp_fetch_failed",
            },
        )
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "content_type": "",
            "exists": False,
            "notes": "mcp_fetch_failed",
        }


def _fetch_via_httpx(url: str, timeout: float) -> dict:
    """Fetch via httpx. Returns endpoint-compatible dict."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            ct = resp.headers.get("Content-Type", resp.headers.get("content-type", ""))
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:5000],
                "content_type": ct.split(";")[0].strip() if ct else "",
                "exists": resp.status_code < 400,
                "notes": "",
            }
    except Exception:
        logger.info(
            "httpx_fetch_failed",
            extra={"url": _sanitize_url_for_log(url), "error_code": "httpx_fetch_failed"},
        )
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "content_type": "",
            "exists": False,
            "notes": "httpx_fetch_failed",
        }


def _fetch_via_mcp_sync(url: str, timeout: float) -> dict:
    """Synchronous wrapper for async MCP fetch."""
    return asyncio.run(_fetch_via_mcp_async(url, timeout))


async def _fetch_via_mcp_async(url: str, timeout: float) -> dict:
    """Fetch URL via MCP fetch tool. Raises on failure (caller fail-closes)."""
    try:
        from mcp.client.stdio import stdio_client
        from mcp.types import TextContent

        from mcp import ClientSession
    except ImportError as e:
        raise RuntimeError(f"MCP SDK not available: {e}") from e

    # Prefer mcp-server-fetch (pip); fallback to uvx
    server_params = _get_fetch_server_params()
    if not server_params:
        raise RuntimeError("mcp-server-fetch not available (pip install mcp-server-fetch)")

    async with (
        stdio_client(server_params) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        result = await asyncio.wait_for(
            session.call_tool("fetch", {"url": url, "raw": True, "max_length": 5000}),
            timeout=timeout,
        )

        if result.isError:
            err_text = ""
            for c in result.content:
                if isinstance(c, TextContent):
                    err_text = c.text
                    break
            raise RuntimeError(err_text or "MCP fetch failed")

        body = ""
        for c in result.content:
            if isinstance(c, TextContent):
                body = c.text
                break

        # MCP fetch does not return HTTP status/headers; infer from content
        return {
            "status": 200,
            "headers": {},
            "body": body,
            "content_type": _infer_content_type(url, body),
            "exists": True,
            "notes": "",
        }


def _get_fetch_server_params():
    """Build StdioServerParameters for mcp-server-fetch. Returns None if unavailable."""
    try:
        from mcp.client.stdio import StdioServerParameters
    except ImportError:
        return None

    # Try python -m mcp_server_fetch first (pip install mcp-server-fetch)
    try:
        import mcp_server_fetch  # noqa: F401
        return StdioServerParameters(command="python", args=["-m", "mcp_server_fetch"])
    except ImportError:
        pass

    # Fallback: uvx mcp-server-fetch (if uv in PATH)
    import shutil
    if shutil.which("uvx"):
        return StdioServerParameters(command="uvx", args=["mcp-server-fetch"])

    return None


def _infer_content_type(url: str, body: str) -> str:
    """Infer content type from URL path or body prefix."""
    url_lower = url.lower()
    if "robots.txt" in url_lower:
        return "text/plain"
    if "sitemap.xml" in url_lower or ".xml" in url_lower:
        return "application/xml"
    if "security.txt" in url_lower:
        return "text/plain"
    if "manifest.json" in url_lower or ".json" in url_lower:
        return "application/json"
    if "favicon.ico" in url_lower:
        return "image/x-icon"
    if body.strip().startswith("<"):
        return "text/html"
    if body.strip().startswith("{"):
        return "application/json"
    return "text/plain"


def get_mcp_fetch_func(
    timeout: float = 10.0,
    *,
    operation: str = "endpoint_extraction",
) -> Callable[[str], ENDPOINT_FETCH_RESULT] | None:
    """Return a fetch_func for endpoint_builder when MCP is available.

    Returns callable(url) -> {status, content_type, exists, notes}.
    The callable itself is fail-closed when MCP is unavailable.
    """
    def _fetch(u: str) -> dict:
        r = fetch_url_mcp(u, timeout, operation=operation)
        return {
            "status": r.get("status", 0),
            "content_type": r.get("content_type", ""),
            "exists": r.get("exists", False),
            "notes": r.get("notes", ""),
        }

    return _fetch
