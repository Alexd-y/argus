"""Tool adapter registry — central lookup for available recon tool adapters."""

import logging

from src.recon.adapters.base import ToolAdapter

logger = logging.getLogger(__name__)

_registry: dict[str, ToolAdapter] = {}


def register(adapter: ToolAdapter) -> None:
    """Register a tool adapter."""
    _registry[adapter.name] = adapter
    logger.info("Adapter registered", extra={"tool": adapter.name})


def get(name: str) -> ToolAdapter | None:
    """Get adapter by tool name."""
    return _registry.get(name)


def get_for_stage(stage: int) -> list[ToolAdapter]:
    """Get all adapters that support a given recon stage."""
    return [a for a in _registry.values() if stage in a.supported_stages]


def list_all() -> list[str]:
    """List all registered adapter names."""
    return list(_registry.keys())


def _auto_register() -> None:
    """Auto-register built-in adapters."""
    from src.recon.adapters.httpx_adapter import HttpxAdapter
    from src.recon.adapters.subfinder_adapter import SubfinderAdapter
    from src.recon.adapters.security import (
        GitleaksAdapter,
        TrivyAdapter,
        SemgrepAdapter,
        TruffleHogAdapter,
        ProwlerAdapter,
        ScoutSuiteAdapter,
        CheckovAdapter,
        TerrascanAdapter,
    )

    register(SubfinderAdapter())
    register(HttpxAdapter())
    register(GitleaksAdapter())
    register(TrivyAdapter())
    register(SemgrepAdapter())
    register(TruffleHogAdapter())
    register(ProwlerAdapter())
    register(ScoutSuiteAdapter())
    register(CheckovAdapter())
    register(TerrascanAdapter())


_auto_register()
