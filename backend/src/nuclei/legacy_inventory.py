"""CONT-009 — Inventory of nuclei argv builders and compiler routing status.

Each entry names a call site (module + builder) and whether argv is produced by
:class:`~src.nuclei.profile_compiler.NucleiProfileCompiler` or a legacy hand-built
path that emits ``nuclei_legacy_argv_builder_total`` warnings.

When ``ARGUS_NUCLEI_PROFILE_COMPILER`` is unset or truthy, every inventory key
reports ``compiler``. Explicit ``0`` / ``false`` / ``off`` keeps the static
``legacy_warned`` map for rollback until 2026-09-14.
"""

from __future__ import annotations

import os
from typing import Final, Literal

ArgvBuilderStatus = Literal["compiler", "legacy_warned"]

_COMPILER_FLAG_FALSY: Final[frozenset[str]] = frozenset({"0", "false", "no", "off"})

NUCLEI_ARGV_CALL_SITES: Final[tuple[str, ...]] = (
    "nuclei.profile_compiler.NucleiProfileCompiler.compile",
    "recon.vulnerability_analysis.active_scan.nuclei_va_adapter.build_nuclei_va_argv",
    "recon.exploitation.adapters.nuclei_adapter.build_nuclei_exploit_argv",
    "recon.recon_http_probe.build_recon_nuclei_tech_argv",
    "tools.executor.build_nuclei_command",
    "tasks.tools.run_nuclei_va_argv",
)

_CALL_SITE_STATUS: Final[dict[str, ArgvBuilderStatus]] = {
    "nuclei.profile_compiler.NucleiProfileCompiler.compile": "compiler",
    "recon.vulnerability_analysis.active_scan.nuclei_va_adapter.build_nuclei_va_argv": "legacy_warned",
    "recon.exploitation.adapters.nuclei_adapter.build_nuclei_exploit_argv": "legacy_warned",
    "recon.recon_http_probe.build_recon_nuclei_tech_argv": "legacy_warned",
    "tools.executor.build_nuclei_command": "legacy_warned",
    "tasks.tools.run_nuclei_va_argv": "legacy_warned",
}


def is_profile_compiler_enabled() -> bool:
    """Compiler is the default argv path. Explicit ``0``/``false``/``off`` rolls back."""
    raw = os.environ.get("ARGUS_NUCLEI_PROFILE_COMPILER", "1").strip().lower()
    return raw not in _COMPILER_FLAG_FALSY


def get_call_site_status(call_site: str) -> ArgvBuilderStatus | None:
    """Return routing status for a known inventory key.

    Flag on → every known site is ``compiler``. Flag off → static map
    (legacy fallback still emits ``nuclei_legacy_argv_builder_total``).
    """
    key = call_site.strip()
    if key not in _CALL_SITE_STATUS:
        return None
    if is_profile_compiler_enabled():
        return "compiler"
    return _CALL_SITE_STATUS[key]


__all__ = [
    "NUCLEI_ARGV_CALL_SITES",
    "ArgvBuilderStatus",
    "get_call_site_status",
    "is_profile_compiler_enabled",
]
