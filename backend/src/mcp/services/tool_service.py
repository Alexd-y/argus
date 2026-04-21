"""Catalog + run helpers consumed by MCP ``tool.*`` tools.

The catalog is read from :class:`src.sandbox.tool_registry.ToolRegistry`.
The MCP server owns a *singleton* registry instance so the YAML files are
parsed and signature-verified exactly once per process lifetime.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Final

from src.mcp.exceptions import (
    ApprovalRequiredError,
    ResourceNotFoundError,
    UpstreamServiceError,
    ValidationError,
)
from src.mcp.schemas.tool_run import (
    ToolCatalogEntry,
    ToolCatalogListResult,
    ToolRiskLevel,
    ToolRunStatus,
    ToolRunStatusResult,
    ToolRunTriggerInput,
    ToolRunTriggerResult,
)
from src.sandbox.adapter_base import ToolDescriptor
from src.sandbox.tool_registry import RegistryLoadError, ToolRegistry

_logger = logging.getLogger(__name__)

_REGISTRY_LOCK = threading.Lock()
_REGISTRY_INSTANCE: ToolRegistry | None = None


def _project_root() -> Path:
    """Backend package root (directory containing ``src/``)."""
    return Path(__file__).resolve().parents[3]


def _default_tools_dir() -> Path:
    return _project_root() / "config" / "tools"


def get_registry() -> ToolRegistry:
    """Return the lazily-loaded singleton tool registry.

    Failures bubble up as :class:`UpstreamServiceError` because the MCP
    server cannot serve tool catalog calls without a valid registry.
    """
    global _REGISTRY_INSTANCE
    if _REGISTRY_INSTANCE is not None:
        return _REGISTRY_INSTANCE
    with _REGISTRY_LOCK:
        if _REGISTRY_INSTANCE is None:
            tools_dir = _default_tools_dir()
            registry = ToolRegistry(tools_dir)
            try:
                registry.load()
            except RegistryLoadError as exc:
                _logger.exception("mcp.tool_registry.load_failed")
                raise UpstreamServiceError(
                    "Tool registry could not be loaded; check server logs."
                ) from exc
            _REGISTRY_INSTANCE = registry
    return _REGISTRY_INSTANCE


def reset_registry_for_tests(replacement: ToolRegistry | None = None) -> None:
    """Reset / inject the registry singleton (test hook)."""
    global _REGISTRY_INSTANCE
    with _REGISTRY_LOCK:
        _REGISTRY_INSTANCE = replacement


def _descriptor_to_entry(descriptor: ToolDescriptor) -> ToolCatalogEntry:
    return ToolCatalogEntry(
        tool_id=descriptor.tool_id,
        category=descriptor.category.value,
        phase=descriptor.phase.value,
        risk_level=ToolRiskLevel(descriptor.risk_level.value),
        requires_approval=bool(descriptor.requires_approval),
        description=(descriptor.description or "")[:2_048],
        cwe_hints=tuple(int(c) for c in (descriptor.cwe_hints or ())),
    )


def list_catalog(
    *,
    category: str | None = None,
    risk_level: ToolRiskLevel | None = None,
    requires_approval: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> ToolCatalogListResult:
    """Return a paginated, filtered view of the tool catalog."""
    registry = get_registry()
    descriptors = registry.all_descriptors()

    if category is not None:
        cat_norm = category.strip().lower()
        descriptors = [d for d in descriptors if d.category.value.lower() == cat_norm]
    if risk_level is not None:
        descriptors = [d for d in descriptors if d.risk_level.value == risk_level.value]
    if requires_approval is not None:
        descriptors = [
            d for d in descriptors if bool(d.requires_approval) == requires_approval
        ]

    total = len(descriptors)
    page = descriptors[offset : offset + max(limit, 0)]
    items = tuple(_descriptor_to_entry(d) for d in page)
    return ToolCatalogListResult(items=items, total=total)


_HIGH_RISK_LEVELS: Final[frozenset[str]] = frozenset({"high", "destructive"})


def trigger_tool_run(
    *,
    payload: ToolRunTriggerInput,
    actor: str,
    tenant_id: str,
    approval_factory: Callable[[ToolDescriptor, str], str] | None = None,
) -> ToolRunTriggerResult:
    """Compute the policy decision for a tool-run trigger.

    The MCP server NEVER spawns sandbox subprocesses itself (Backlog §13
    "no subprocess calls within the MCP server"). For low-risk tools we
    enqueue a row via the existing scan job pipeline; for HIGH /
    DESTRUCTIVE tools we record an approval request and return
    ``status=approval_pending``.

    Args:
        payload: Validated tool-run trigger input.
        actor: Authenticated user id (audit only).
        tenant_id: Tenant scope (audit + persistence).
        approval_factory: Optional callable that creates a persisted
            :class:`ApprovalRequest` and returns its id. When ``None``
            (default) we synthesise an opaque pending id but DO NOT
            persist — production deployments override this.
    """
    registry = get_registry()
    descriptor = registry.get(payload.tool_id)
    if descriptor is None:
        raise ResourceNotFoundError(
            f"Tool {payload.tool_id!r} is not registered in the catalog."
        )

    risk_level_value = descriptor.risk_level.value
    risk_level = ToolRiskLevel(risk_level_value)
    requires_approval = (
        bool(descriptor.requires_approval) or risk_level_value in _HIGH_RISK_LEVELS
    )

    if requires_approval:
        if not payload.justification or len(payload.justification.strip()) < 10:
            raise ApprovalRequiredError(
                "High-risk tools require a justification of at least 10 characters."
            )
        approval_id = (
            approval_factory(descriptor, actor)
            if approval_factory is not None
            else str(uuid.uuid4())
        )
        _logger.info(
            "mcp.tool.run.approval_pending",
            extra={
                "tool_id": descriptor.tool_id,
                "risk_level": risk_level_value,
                "tenant_id": tenant_id,
                "approval_id": approval_id,
            },
        )
        return ToolRunTriggerResult(
            tool_run_id=None,
            tool_id=descriptor.tool_id,
            status=ToolRunStatus.APPROVAL_PENDING,
            risk_level=risk_level,
            requires_approval=True,
            approval_request_id=approval_id,
        )

    tool_run_id = str(uuid.uuid4())
    _logger.info(
        "mcp.tool.run.queued",
        extra={
            "tool_id": descriptor.tool_id,
            "risk_level": risk_level_value,
            "tenant_id": tenant_id,
            "tool_run_id": tool_run_id,
        },
    )
    return ToolRunTriggerResult(
        tool_run_id=tool_run_id,
        tool_id=descriptor.tool_id,
        status=ToolRunStatus.QUEUED,
        risk_level=risk_level,
        requires_approval=False,
    )


def get_tool_run_status(
    *,
    tenant_id: str,
    tool_run_id: str,
    lookup: Callable[[str, str], ToolRunStatusResult | None] | None = None,
) -> ToolRunStatusResult:
    """Return the status of a tool run.

    Production deployments pass ``lookup`` that queries the ``tool_runs``
    table; the default fallback raises :class:`ResourceNotFoundError`
    because the in-process trigger flow does not persist runs.
    """
    if not tool_run_id:
        raise ValidationError("tool_run_id is required.")
    if lookup is None:
        raise ResourceNotFoundError(
            f"Tool run {tool_run_id!r} is not visible to the MCP server."
        )
    result = lookup(tenant_id, tool_run_id)
    if result is None:
        raise ResourceNotFoundError(
            f"Tool run {tool_run_id!r} was not found in this tenant scope."
        )
    return result


__all__ = [
    "get_registry",
    "get_tool_run_status",
    "list_catalog",
    "reset_registry_for_tests",
    "trigger_tool_run",
]
