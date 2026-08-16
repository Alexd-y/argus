"""Immutable engagement/scan execution mode contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, StrictStr


class ExecutionMode(StrEnum):
    """Scan/engagement execution mode — immutable after first execution."""

    PRODUCTION = "production"
    LAB_UNRESTRICTED = "lab_unrestricted"
    QUICK = "quick"


ALLOWED_EXECUTION_MODES: Final[frozenset[str]] = frozenset(m.value for m in ExecutionMode)

# Values stored under the ambiguous options key ``mode`` that mean scan *depth*
# (Strix-style), not execution mode. ``quick`` is both a depth alias and
# ExecutionMode.QUICK — only ``execution_mode`` may select Quick.
_SCAN_DEPTH_ALIASES: Final[frozenset[str]] = frozenset({"quick", "standard", "deep", "lab"})

_LEGACY_MODE_FIELD_VALUES: Final[frozenset[str]] = frozenset(
    {
        ExecutionMode.PRODUCTION.value,
        ExecutionMode.LAB_UNRESTRICTED.value,
    }
)


class ExecutionModeImmutableError(ValueError):
    """Raised when a caller attempts to change mode after first execution."""


class ModeContext(BaseModel):
    """Resolved mode for a single engagement/scan decision path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    engagement_id: StrictStr = Field(min_length=1, max_length=36)
    scan_id: StrictStr | None = None
    mode: ExecutionMode
    lab_lease_id: StrictStr | None = None
    first_execution_at: StrictStr | None = None

    @property
    def is_lab(self) -> bool:
        return self.mode is ExecutionMode.LAB_UNRESTRICTED

    @property
    def is_production(self) -> bool:
        return self.mode is ExecutionMode.PRODUCTION

    @property
    def is_quick(self) -> bool:
        return self.mode is ExecutionMode.QUICK


def parse_execution_mode(raw: str | ExecutionMode | None) -> ExecutionMode:
    """Parse mode string; default production; reject unknown values."""
    if raw is None or raw == "":
        return ExecutionMode.PRODUCTION
    if isinstance(raw, ExecutionMode):
        return raw
    normalized = str(raw).strip().lower()
    try:
        return ExecutionMode(normalized)
    except ValueError as exc:
        raise ValueError(f"unsupported_execution_mode:{normalized}") from exc


def coerce_legacy_mode_field(raw: str | ExecutionMode | None) -> ExecutionMode | None:
    """Interpret the ambiguous scan-options key ``mode``.

    Accepts only legacy execution-mode values (``production``, ``lab_unrestricted``).
    Scan-depth aliases including ``quick`` are ignored so that ``scan_mode=quick``
    never becomes ``ExecutionMode.QUICK``. Callers must set ``execution_mode``.
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, ExecutionMode):
        if raw is ExecutionMode.QUICK:
            return None
        return raw
    normalized = str(raw).strip().lower()
    if normalized in _SCAN_DEPTH_ALIASES:
        return None
    if normalized in _LEGACY_MODE_FIELD_VALUES:
        return ExecutionMode(normalized)
    return None


def assert_mode_immutable(
    current: ExecutionMode,
    requested: ExecutionMode | str | None,
    *,
    has_started_execution: bool,
) -> ExecutionMode:
    """Return current mode; refuse mid-scan switches after first execution."""
    requested_mode = parse_execution_mode(requested)
    if not has_started_execution:
        return requested_mode
    if requested_mode is not current:
        raise ExecutionModeImmutableError(
            f"execution_mode_immutable:current={current.value}:requested={requested_mode.value}"
        )
    return current
