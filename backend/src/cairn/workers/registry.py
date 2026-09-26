"""Driver registry with fail-closed gating.

``wrb`` (the in-process WhiteRabbitNeo driver) is always available. The CLI parity
drivers (claude/codex/pi) are gated: they are only returned under
``execution_mode == "lab_unrestricted"`` AND ``settings.cairn_cli_drivers_enabled``
(default False). Any other request raises ``RuntimeError`` — never a silent
downgrade. ``mock`` is intentionally NOT registered here; tests register their own.
"""

from __future__ import annotations

from src.cairn.workers.adapters import ClaudeCodeDriver, CodexDriver, PiDriver
from src.cairn.workers.base import CairnWorkerDriver
from src.cairn.workers.wrb import WrbAgentDriver
from src.core.config import settings

_WRB = WrbAgentDriver()

# CLI drivers keyed by name; sandbox vs local build differs only for codex/pi.
_CLI_SANDBOX: dict[str, CairnWorkerDriver] = {
    "claudecode": ClaudeCodeDriver(),
    "codex": CodexDriver(local=False),
    "pi": PiDriver(local=False),
}
_CLI_LOCAL: dict[str, CairnWorkerDriver] = {
    "claudecode": ClaudeCodeDriver(),
    "codex": CodexDriver(local=True),
    "pi": PiDriver(local=True),
}

_CLI_DRIVER_NAMES = frozenset(_CLI_SANDBOX)


def _cli_drivers_allowed(execution_mode: str) -> bool:
    return execution_mode == "lab_unrestricted" and bool(
        getattr(settings, "cairn_cli_drivers_enabled", False)
    )


def get_driver(
    name: str,
    *,
    execution: str = "sandbox",
    execution_mode: str = "production",
) -> CairnWorkerDriver:
    """Return the driver for ``name`` or raise ``RuntimeError`` if not permitted."""
    if name == "wrb":
        return _WRB
    if name in _CLI_DRIVER_NAMES:
        if not _cli_drivers_allowed(execution_mode):
            raise RuntimeError(
                f"CLI driver {name!r} requires execution_mode=lab_unrestricted and "
                "cairn_cli_drivers_enabled=true (fail-closed)"
            )
        drivers = _CLI_LOCAL if execution == "local" else _CLI_SANDBOX
        return drivers[name]
    raise RuntimeError(f"unknown Cairn driver {name!r}")


__all__ = ["get_driver"]
