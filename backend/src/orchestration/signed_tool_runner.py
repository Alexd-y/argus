"""Single control-plane runner for signed sandbox tools (overhaul §1).

Plane-agnostic execution entrypoint shared by every tool-invoking path
(exploitation today; recon / VA / MCP next): resolve a tool name to a signed
:class:`~src.sandbox.tool_registry.ToolRegistry` descriptor (aliases folded via
:mod:`src.sandbox.tool_aliases`), compile its argv from the descriptor
``command_template`` through the safe templating layer, and execute it in an
ephemeral, hardened ``docker run`` via :class:`~src.sandbox.docker_adapter.DockerSandboxAdapter`.
No hardcoded argv, ever.

One process-wide registry singleton lives here so the whole codebase converges
on a single signed catalog instance (replacing the per-module registries the
audit flagged). Loading is fail-open: a load failure never blocks execution —
:func:`run_signed_tool` returns ``None`` and the caller falls back to its legacy
path, so adopting this runner is always a strict superset.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from src.pipeline.contracts.tool_job import TargetKind, TargetSpec, ToolJob
from src.sandbox.adapter_base import ToolDescriptor
from src.sandbox.docker_adapter import DockerRunMode, DockerSandboxAdapter
from src.sandbox.k8s_adapter import ApprovalRequiredError, SandboxConfigError
from src.sandbox.templating import TemplateRenderError, extract_placeholders
from src.sandbox.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

_MAX_STDOUT_CHARS = 10_000
_MAX_TIMEOUT_S = 86_400


def _tools_catalog_dir() -> Path:
    """Return the signed tool catalog directory (``backend/config/tools``)."""
    return Path(__file__).resolve().parents[2] / "config" / "tools"


_TOOL_REGISTRY: ToolRegistry | None = None
_TOOL_REGISTRY_LOADED: bool = False


def get_signed_tool_registry() -> ToolRegistry | None:
    """Return the process-wide loaded signed :class:`ToolRegistry`, or ``None``.

    Cached process-wide (including the ``None`` fallback). Fail-open: a load
    failure is logged and returns ``None`` so callers degrade to their legacy
    path rather than aborting.
    """
    global _TOOL_REGISTRY, _TOOL_REGISTRY_LOADED
    if _TOOL_REGISTRY_LOADED:
        return _TOOL_REGISTRY
    _TOOL_REGISTRY_LOADED = True
    try:
        registry = ToolRegistry(tools_dir=_tools_catalog_dir())
        registry.load()
        _TOOL_REGISTRY = registry
    except Exception as exc:  # noqa: BLE001 — advisory registry, fail-open
        logger.warning(
            "signed_tool_registry_load_failed",
            extra={"event": "signed_tool_registry_load_failed", "error": str(exc)},
        )
        _TOOL_REGISTRY = None
    return _TOOL_REGISTRY


def reset_signed_tool_registry() -> None:
    """Test hook: drop the cached registry so the next call reloads it."""
    global _TOOL_REGISTRY, _TOOL_REGISTRY_LOADED
    _TOOL_REGISTRY = None
    _TOOL_REGISTRY_LOADED = False


def resolve_signed_tool(tool: str) -> str | None:
    """Resolve a tool name to its canonical signed ``tool_id`` (or ``None``).

    Folds aliases via :meth:`ToolRegistry.resolve` (e.g. ``sqlmap`` →
    ``sqlmap_safe``, ``ffuf`` → ``ffuf_dir``).
    """
    registry = get_signed_tool_registry()
    if registry is None:
        return None
    descriptor = registry.resolve(tool)
    return descriptor.tool_id if descriptor is not None else None


def to_uuid(value: object) -> UUID:
    """Coerce a value to a UUID, falling back to a fresh one on bad input."""
    try:
        return UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return uuid4()


def run_coro_sync(coro: Any) -> Any:
    """Run an async coroutine from sync code, safe whether or not a loop runs.

    Shared sync→async bridge for the synchronous execution planes (recon / VA /
    KAL-MCP runners) that need to call the async :func:`run_signed_tool`. When no
    event loop runs in the current thread we use :func:`asyncio.run`; when one is
    already running (the sync caller is on the loop thread) we execute the
    coroutine on a dedicated thread with its own loop to avoid re-entrancy.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    result: dict[str, Any] = {}

    def _runner() -> None:
        result["value"] = asyncio.run(coro)

    thread = threading.Thread(target=_runner)
    thread.start()
    thread.join()
    return result.get("value")


def _target_spec_and_params(
    target: str, target_kind: TargetKind
) -> tuple[TargetSpec | None, dict[str, str]]:
    """Build a :class:`TargetSpec` + its natural placeholder params for a target.

    Returns ``(None, {})`` for an empty / malformed target (e.g. a non-http URL),
    signalling the caller to defer. The natural params are the placeholders the
    target itself can satisfy (``url`` / ``domain`` / ``host`` / ``ip`` /
    ``cidr``); ``out_dir`` / ``canary`` are added by the caller.
    """
    value = (target or "").strip()
    if not value:
        return None, {}
    if target_kind is TargetKind.URL:
        if not value.startswith(("http://", "https://")):
            return None, {}
        params = {"url": value}
        host = urlparse(value).hostname
        if host:
            params["domain"] = host
        return TargetSpec(kind=TargetKind.URL, url=value), params
    if target_kind is TargetKind.DOMAIN:
        return TargetSpec(kind=TargetKind.DOMAIN, domain=value), {"domain": value}
    if target_kind is TargetKind.HOST:
        return TargetSpec(kind=TargetKind.HOST, host=value), {"host": value}
    if target_kind is TargetKind.IP:
        return TargetSpec(kind=TargetKind.IP, ip=value), {"ip": value}
    if target_kind is TargetKind.CIDR:
        return TargetSpec(kind=TargetKind.CIDR, cidr=value), {"cidr": value}
    return None, {}


def build_tool_job(
    descriptor: ToolDescriptor,
    *,
    target: str,
    scan_id: str | None,
    tenant_id: str | None,
    timeout: int,
    target_kind: TargetKind = TargetKind.URL,
    extra_parameters: dict[str, str] | None = None,
    correlation_id: str = "argus-single-plane",
) -> ToolJob | None:
    """Build a signed :class:`ToolJob` for any target kind, or ``None`` if unmappable.

    Plane-agnostic: ``target_kind`` selects the :class:`TargetSpec` variant
    (URL / DOMAIN / HOST / IP / CIDR) and its natural placeholder(s). Every
    ``command_template`` placeholder must be satisfiable from the target's
    natural params, the always-available ``out_dir`` / ``canary``, or the
    caller-supplied ``extra_parameters`` (e.g. recon ``wordlist``); an
    unsatisfiable placeholder or an approval-gated descriptor returns ``None`` so
    the caller falls back to its legacy path (no behaviour lost).
    """
    if descriptor.requires_approval:
        return None
    spec, natural = _target_spec_and_params(target, target_kind)
    if spec is None:
        return None
    available = dict(natural)
    available["out_dir"] = "/out"
    extra = extra_parameters or {}
    parameters: dict[str, str] = {}
    for placeholder in extract_placeholders(descriptor.command_template):
        if placeholder == "canary":
            parameters["canary"] = uuid4().hex
        elif placeholder in available:
            parameters[placeholder] = available[placeholder]
        elif placeholder in extra:
            parameters[placeholder] = extra[placeholder]
        else:
            # Cannot be derived from the target / extras → defer to legacy.
            return None
    try:
        return ToolJob(
            id=uuid4(),
            tenant_id=to_uuid(tenant_id),
            scan_id=to_uuid(scan_id),
            tool_id=descriptor.tool_id,
            phase=descriptor.phase,
            risk_level=descriptor.risk_level,
            target=spec,
            parameters=parameters,
            outputs_dir="/out",
            timeout_s=max(1, min(int(timeout), _MAX_TIMEOUT_S)),
            requires_approval=False,
            approval_id=None,
            correlation_id=correlation_id,
        )
    except (ValueError, TypeError):
        return None


def build_url_tool_job(
    descriptor: ToolDescriptor,
    *,
    target: str,
    scan_id: str | None,
    tenant_id: str | None,
    timeout: int,
    correlation_id: str = "argus-single-plane",
) -> ToolJob | None:
    """Build a signed :class:`ToolJob` for a URL target (URL-kind convenience).

    Thin wrapper over :func:`build_tool_job` with ``target_kind=URL`` — preserves
    the original URL-only contract for existing callers.
    """
    return build_tool_job(
        descriptor,
        target=target,
        scan_id=scan_id,
        tenant_id=tenant_id,
        timeout=timeout,
        target_kind=TargetKind.URL,
        correlation_id=correlation_id,
    )


async def run_signed_tool(
    tool: str,
    target: str,
    *,
    timeout: int,
    scan_id: str = "",
    tenant_id: str = "",
    network: str | None = None,
    auth_argv: list[str] | None = None,
    target_kind: TargetKind = TargetKind.URL,
    extra_parameters: dict[str, str] | None = None,
    correlation_id: str = "argus-single-plane",
) -> dict[str, Any] | None:
    """Run ``tool`` against ``target`` via the signed registry + docker adapter.

    Returns a result dict (``stdout`` / ``stderr`` / ``exit_code`` /
    ``duration_ms``), or ``None`` when the signed path is not feasible (registry
    unavailable, tool not in catalog, unmappable descriptor, approval-gated, or a
    render/config error) so the caller can fall back to its legacy path.

    ``target_kind`` selects the target representation (URL by default; DOMAIN /
    HOST / IP / CIDR enable recon / VA planes). ``extra_parameters`` supplies any
    non-target placeholders (e.g. a recon ``wordlist``). ``auth_argv`` is an
    OPTIONAL, caller-validated authenticated-session fragment appended to the
    tool argv by the adapter (validated + redacted there).
    """
    registry = get_signed_tool_registry()
    if registry is None:
        return None
    descriptor = registry.resolve(tool)
    if descriptor is None:
        return None
    tool_job = build_tool_job(
        descriptor,
        target=target,
        scan_id=scan_id,
        tenant_id=tenant_id,
        timeout=timeout,
        target_kind=target_kind,
        extra_parameters=extra_parameters,
        correlation_id=correlation_id,
    )
    if tool_job is None:
        return None
    adapter = DockerSandboxAdapter(
        registry,
        mode=DockerRunMode.DOCKER,
        network=network if isinstance(network, str) else None,
    )
    try:
        result = await adapter.run(tool_job, descriptor, auth_argv=auth_argv)
    except (SandboxConfigError, ApprovalRequiredError, TemplateRenderError) as exc:
        logger.info(
            "signed_tool_runner_skipped",
            extra={"event": "signed_tool_runner_skipped", "tool": tool, "reason": str(exc)},
        )
        return None
    exit_code = (
        result.exit_code if result.exit_code is not None else (0 if result.completed else -1)
    )
    return {
        "stdout": (result.logs_excerpt or "")[:_MAX_STDOUT_CHARS],
        "stderr": "" if result.completed else (result.failure_reason or ""),
        "exit_code": exit_code,
        "duration_ms": int(result.duration_seconds * 1000),
    }


__all__ = [
    "build_tool_job",
    "build_url_tool_job",
    "get_signed_tool_registry",
    "reset_signed_tool_registry",
    "resolve_signed_tool",
    "run_coro_sync",
    "run_signed_tool",
    "to_uuid",
]
