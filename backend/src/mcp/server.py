"""ARGUS Backend MCP server (Backlog/dev1_md §13).

Exposes the ARGUS pentest pipeline to MCP-compatible LLM clients via two
transports:

* ``stdio`` (default) — for desktop / IDE clients (Cursor, Claude Code, etc).
  Authentication falls back to ``MCP_AUTH_TOKEN`` from the environment.
* ``streamable-http`` — for production deployments (e.g. behind an OAuth
  proxy). Bearer token / API key headers are required.

Run with:

.. code-block:: bash

   # stdio (preferred for local use)
   python -m src.mcp.server

   # HTTP / SSE
   python -m src.mcp.server --transport streamable-http --port 8765

Environment variables:

* ``MCP_TRANSPORT``      — ``stdio`` (default) | ``streamable-http`` | ``sse``
* ``MCP_HTTP_HOST``      — bind host for HTTP transports (default ``127.0.0.1``)
* ``MCP_HTTP_PORT``      — bind port for HTTP transports (default ``8765``)
* ``MCP_AUTH_TOKEN``     — static bearer accepted on every transport.
* ``MCP_SERVER_NAME``    — server display name (default ``argus``).
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from mcp.server.fastmcp import FastMCP

from src.core.config import settings
from src.mcp.audit_logger import make_default_audit_logger
from src.mcp.context import (
    set_audit_logger,
    set_notification_dispatcher,
    set_rate_limiter,
)
from src.mcp.prompts import register_all as register_all_prompts
from src.mcp.resources import register_all as register_all_resources
from src.mcp.runtime.rate_limiter import (
    BucketBudget,
    TokenBucketLimiter,
    build_rate_limiter,
)
from src.mcp.services.notifications import (
    JiraAdapter,
    LinearAdapter,
    NotificationDispatcher,
    NotifierBase,
    SlackNotifier,
    is_globally_enabled_via_env,
)
from src.mcp.tools import register_all as register_all_tools

_logger = logging.getLogger(__name__)

_DEFAULT_NAME: Final[str] = "argus"
_DEFAULT_HOST: Final[str] = "127.0.0.1"
_DEFAULT_PORT: Final[int] = 8765

_INSTRUCTIONS = (
    "ARGUS Backend MCP server. Use ``scan.create`` / ``scan.status`` / "
    "``scan.cancel`` to manage scans, ``findings.*`` to triage results, "
    "``tool.catalog.*`` and ``tool.run.*`` for ad-hoc tool runs (HIGH-risk "
    "tools require approval), ``approvals.*`` to record operator decisions, "
    "``policy.evaluate`` / ``scope.verify`` for pre-flight checks, and "
    "``report.generate`` / ``report.download`` to manage reports. All calls "
    "are tenant-scoped and audit-logged."
)

TransportName = Literal["stdio", "sse", "streamable-http"]


def build_app(
    *,
    name: str = _DEFAULT_NAME,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO",
    config_path: str | Path | None = None,
) -> FastMCP:
    """Construct and wire a fresh :class:`FastMCP` application.

    Splitting construction from ``run`` keeps the wiring testable — unit
    tests can call ``build_app()`` and inspect ``app.list_tools()`` /
    ``app.list_resources()`` / ``app.list_prompts()`` without ever opening
    a transport.

    The optional ``config_path`` overrides ``settings.mcp_config_path`` for
    tests that need a custom rate-limiter / notifications block.
    """
    audit_logger = make_default_audit_logger()
    set_audit_logger(audit_logger)

    config = _load_server_config(config_path)
    rate_limiter = _build_rate_limiter_from_config(config)
    set_rate_limiter(rate_limiter)

    dispatcher = _build_notification_dispatcher_from_config(config, audit_logger)
    set_notification_dispatcher(dispatcher)

    app = FastMCP(
        name=name,
        instructions=_INSTRUCTIONS,
        host=host,
        port=port,
        log_level=log_level,
        warn_on_duplicate_tools=True,
        warn_on_duplicate_resources=True,
        warn_on_duplicate_prompts=True,
    )

    register_all_tools(app)
    register_all_resources(app)
    register_all_prompts(app)
    return app


def _load_server_config(config_path: str | Path | None) -> Mapping[str, object]:
    """Best-effort loader for ``server.yaml``; returns an empty mapping on miss.

    Missing files are non-fatal — the server falls back to defaults so the
    stdio transport stays usable in clean checkouts. Bad YAML logs a warning
    and degrades to defaults rather than crashing the server.
    """
    target = Path(config_path) if config_path else Path(settings.mcp_config_path)
    if not target.is_file():
        _logger.info(
            "mcp.server.config_missing",
            extra={"path": str(target)},
        )
        return {}
    try:
        raw = target.read_text(encoding="utf-8")
        parsed = yaml.safe_load(raw)
    except (OSError, yaml.YAMLError) as exc:
        _logger.warning(
            "mcp.server.config_unreadable",
            extra={"path": str(target), "error_class": type(exc).__name__},
        )
        return {}
    if not isinstance(parsed, dict):
        return {}
    return parsed


def _budget_from_dict(raw: object, *, default: BucketBudget) -> BucketBudget:
    if not isinstance(raw, dict):
        return default
    rate = raw.get("rate_per_second", default.rate_per_second)
    burst = raw.get("burst", default.burst)
    try:
        return BucketBudget(
            rate_per_second=float(rate),
            burst=int(burst),
        )
    except (TypeError, ValueError):
        _logger.warning(
            "mcp.server.rate_limiter_budget_invalid",
            extra={"raw": raw, "fallback": str(default)},
        )
        return default


def _budgets_map(
    raw: object, *, default: BucketBudget
) -> dict[str, BucketBudget]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, BucketBudget] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        out[key] = _budget_from_dict(value, default=default)
    return out


def _build_rate_limiter_from_config(
    config: Mapping[str, object],
) -> TokenBucketLimiter:
    raw = config.get("rate_limiter")
    section: Mapping[str, object] = raw if isinstance(raw, Mapping) else {}

    backend = str(section.get("backend", "memory") or "memory").strip().lower()
    if backend not in {"memory", "redis"}:
        _logger.warning(
            "mcp.server.rate_limiter_backend_unknown",
            extra={"backend": backend},
        )
        backend = "memory"

    default_client = _budget_from_dict(
        section.get("default_client_budget"),
        default=BucketBudget(rate_per_second=5.0, burst=30),
    )
    default_tenant = _budget_from_dict(
        section.get("default_tenant_budget"),
        default=BucketBudget(rate_per_second=10.0, burst=60),
    )
    per_client = _budgets_map(
        section.get("per_client_budgets"), default=default_client
    )
    per_tenant = _budgets_map(
        section.get("per_tenant_budgets"), default=default_tenant
    )

    redis_client: Any | None = None
    if backend == "redis":
        try:
            import redis.asyncio as redis_asyncio

            redis_client = redis_asyncio.from_url(settings.redis_url)
        except Exception:  # pragma: no cover — defensive
            _logger.warning(
                "mcp.server.rate_limiter_redis_init_failed",
                exc_info=True,
            )
            backend = "memory"
            redis_client = None

    return build_rate_limiter(
        backend=backend,
        default_client_budget=default_client,
        default_tenant_budget=default_tenant,
        per_client_budgets=per_client,
        per_tenant_budgets=per_tenant,
        redis_client=redis_client,
        redis_key_prefix=str(
            section.get("redis_key_prefix", "argus:mcp:rl") or "argus:mcp:rl"
        ),
    )


def _build_notification_dispatcher_from_config(
    config: Mapping[str, object], audit_logger: object
) -> NotificationDispatcher:
    raw = config.get("notifications")
    section: Mapping[str, object] = raw if isinstance(raw, Mapping) else {}
    config_enabled = bool(section.get("enabled", False))
    enabled = config_enabled and is_globally_enabled_via_env()

    adapters: list[NotifierBase] = [
        SlackNotifier(),
        LinearAdapter(),
        JiraAdapter(),
    ]

    per_tenant_disabled: dict[str, frozenset[str]] = {}
    raw_overrides = section.get("per_tenant_disabled_adapters")
    if isinstance(raw_overrides, Mapping):
        for tenant, names in raw_overrides.items():
            if not isinstance(tenant, str):
                continue
            if isinstance(names, list):
                per_tenant_disabled[tenant] = frozenset(
                    str(n) for n in names if isinstance(n, str)
                )

    dispatcher = NotificationDispatcher(
        adapters=adapters,
        enabled=enabled,
        audit_logger=audit_logger,  # type: ignore[arg-type]
        per_tenant_disabled_adapters=per_tenant_disabled,
    )

    adapter_settings = section.get("adapters")
    if isinstance(adapter_settings, Mapping):
        for adapter_name, adapter_cfg in adapter_settings.items():
            if not isinstance(adapter_name, str):
                continue
            if isinstance(adapter_cfg, Mapping):
                dispatcher.set_adapter_enabled(
                    adapter_name, bool(adapter_cfg.get("enabled", False))
                )

    return dispatcher


def _resolve_transport(cli_value: str | None) -> TransportName:
    raw = (cli_value or settings.mcp_transport or "stdio").strip().lower()
    if raw not in {"stdio", "sse", "streamable-http"}:
        raise SystemExit(
            f"unsupported MCP transport {raw!r}; pick one of stdio | sse | streamable-http"
        )
    return raw  # type: ignore[return-value]


def _parse_port(env_or_cli: str | int | None, default: int) -> int:
    if env_or_cli is None or env_or_cli == "":
        return default
    try:
        port = int(env_or_cli)
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"invalid port value {env_or_cli!r}") from exc
    if not (1 <= port <= 65_535):
        raise SystemExit(f"port {port} out of range")
    return port


def main(argv: list[str] | None = None) -> int:
    """CLI entry point — selects transport and runs the server."""
    parser = argparse.ArgumentParser(
        prog="argus-mcp-server",
        description="ARGUS Backend MCP server (Backlog/dev1_md §13).",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default=None,
        help="MCP transport (default: stdio; overridable via MCP_TRANSPORT).",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Bind host for HTTP transports (default: 127.0.0.1; MCP_HTTP_HOST).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port for HTTP transports (default: 8765; MCP_HTTP_PORT).",
    )
    parser.add_argument(
        "--mount-path",
        default=None,
        help="Optional mount path (used by SSE transport only).",
    )
    parser.add_argument(
        "--log-level",
        default=settings.mcp_log_level,
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    )

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    transport = _resolve_transport(args.transport)
    host = args.host or settings.mcp_http_host or _DEFAULT_HOST
    port = _parse_port(
        args.port if args.port is not None else settings.mcp_http_port,
        default=_DEFAULT_PORT,
    )
    name = settings.mcp_server_name or _DEFAULT_NAME

    _logger.info(
        "mcp.server.start",
        extra={
            "transport": transport,
            "host": host,
            "port": port,
            "server_name": name,
        },
    )

    app = build_app(
        name=name,
        host=host,
        port=port,
        log_level=args.log_level,
    )
    app.run(transport=transport, mount_path=args.mount_path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["build_app", "main"]
