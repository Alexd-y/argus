"""Flag-gated adaptive-coverage integration seam for the scan state machine (overhaul §6).

This is the FIRST, deliberately-conservative integration step of the adaptive
driver into :func:`src.orchestration.state_machine.run_scan_state_machine`.

Behaviour when ``ARGUS_ADAPTIVE_LOOP`` is **off** (default): a strict no-op — the
linear FSM is byte-for-byte unchanged and produces the exact same artifacts.

Behaviour when the flag is **on**: after a phase completes, derive a best-effort
:class:`InputSurfaceInventory` from that phase's output (findings / exploit
hypotheses / declared input surfaces), build the runtime
:class:`~src.orchestration.graph.AssetGraph`, mark the surfaces that were actually
exercised (Step 2 — see :func:`tested_surface_ids_from_output`), and return a
coverage snapshot that the caller records as an *append-only* ``ScanTimeline``
entry. Because tested surfaces are now fed in, ``parameter_coverage`` /
``endpoint_coverage`` reflect the real tested/total fraction rather than 0.0.

Contract-preservation guarantees (why this is safe to wire into the live loop):
* It **never executes tools** and never mutates existing artifacts — it only reads
  the already-persisted phase output and emits one additional timeline entry.
* It is fully exception-guarded — any failure degrades to ``None`` (no entry) and
  logs a warning, so an adaptive-coverage hiccup can never fail a real scan.
* It returns ``None`` (nothing recorded) when the flag is off or when no injectable
  surface can be derived, so enabling it on surface-less phases is harmless.

The full adaptive-driver replacement (the loop *driving* execution and producing
ScanState / phase outputs / findings) is staged behind the same flag and layered
on top of this seam; see :mod:`src.orchestration.adaptive_loop` and
:mod:`src.orchestration.adaptive_integration`.
"""

from __future__ import annotations

import logging
from typing import Any

from src.orchestration.graph_builders import (
    apply_tested_surfaces,
    build_asset_graph_from_surfaces,
    coverage_metrics,
)
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
    InputSurfaceItem,
    InputSurfaceLocation,
    _stable_surface_id,
    normalize_path_template,
)

logger = logging.getLogger(__name__)

# Phase-output list keys that may carry per-input rows we can model as surfaces
# (the discovered/analyzed *universe*). Ordered by richness; all present keys are
# merged (dedup happens downstream).
_SURFACE_LIST_KEYS: tuple[str, ...] = ("input_surfaces", "findings", "hypotheses")

# Phase-output list keys that explicitly enumerate surfaces that were *exercised*
# (actively probed). Rows may be surface descriptors (url+param) or bare
# ``surface_id`` strings. ``findings`` are always treated as tested as well — a
# finding is evidence that its surface was probed (see ``tested_surface_ids_from_output``).
_TESTED_LIST_KEYS: tuple[str, ...] = ("tested_surfaces", "surfaces_tested", "probed_surfaces")

# Only unambiguous location values are honoured; everything else defaults to
# "query" so a mislabeled/absent location can never raise on the Literal type.
_VALID_LOCATIONS: frozenset[str] = frozenset(
    {"query", "form", "json", "path", "header", "cookie", "graphql"}
)

_URL_KEYS: tuple[str, ...] = ("url", "target", "endpoint")
_PARAM_KEYS: tuple[str, ...] = ("param_name", "parameter", "param")
_LOCATION_KEYS: tuple[str, ...] = ("input_location", "param_location", "location")


def _first_str(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    """First non-empty string value among ``keys`` in ``row`` (else "")."""
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _resolve_location(row: dict[str, Any]) -> InputSurfaceLocation:
    """Best-effort input location, defaulting to ``query`` for unknown/absent values."""
    raw = _first_str(row, _LOCATION_KEYS).lower()
    if raw in _VALID_LOCATIONS:
        return raw  # type: ignore[return-value]
    return "query"


def _row_to_surface(row: dict[str, Any]) -> InputSurfaceItem | None:
    """Model one phase-output row as an :class:`InputSurfaceItem`, or ``None`` to skip.

    A row needs both a URL-like and a parameter-like field. The ``surface_id`` is
    the row's own ``surface_id`` when present (so an upstream inventory's stable IDs
    are preserved and the tested/universe sets align), else it is derived
    deterministically from ``(method, path_template, param, location)`` — the same
    scheme used everywhere, guaranteeing tested IDs match universe IDs.
    """
    url = _first_str(row, _URL_KEYS)
    param = _first_str(row, _PARAM_KEYS)
    if not url or not param:
        return None
    method = _first_str(row, ("method",)) or "GET"
    location = _resolve_location(row)
    path_template = normalize_path_template(url)
    surface_id = _first_str(row, ("surface_id",)) or _stable_surface_id(
        method, path_template, param, location
    )
    try:
        return InputSurfaceItem(
            surface_id=surface_id,
            url=url,
            method=method,
            param_name=param,
            location=location,
        )
    except Exception:  # pragma: no cover - defensive; a bad row must not abort the scan
        return None


def inventory_from_output(output_data: Any) -> InputSurfaceInventory | None:
    """Best-effort :class:`InputSurfaceInventory` from a persisted phase-output dict.

    Reads the well-known list keys (``input_surfaces``/``findings``/``hypotheses``)
    and models each row that carries both a URL-like and a parameter-like field as
    one injectable surface. Rows lacking either are skipped. Returns ``None`` when
    nothing injectable can be derived (never raises on malformed input).
    """
    if not isinstance(output_data, dict):
        return None

    items: list[InputSurfaceItem] = []
    for key in _SURFACE_LIST_KEYS:
        value = output_data.get(key)
        if not isinstance(value, list):
            continue
        for row in value:
            if not isinstance(row, dict):
                continue
            item = _row_to_surface(row)
            if item is not None:
                items.append(item)

    if not items:
        return None
    return InputSurfaceInventory(items=items)


def tested_surface_ids_from_output(output_data: Any) -> set[str]:
    """Surface IDs that were actually exercised, for real %-coverage (Step 2).

    Sources, all best-effort and non-raising:
    * every ``findings`` row (a finding is evidence its surface was probed), and
    * every explicit tested list (``tested_surfaces``/``surfaces_tested``/
      ``probed_surfaces``) — whose entries may be surface descriptors (url+param) or
      bare ``surface_id`` strings.

    IDs are computed with the same scheme as :func:`inventory_from_output`, so they
    line up with the graph's ``surface_id`` node property that
    :func:`~src.orchestration.graph_builders.apply_tested_surfaces` matches on.
    """
    if not isinstance(output_data, dict):
        return set()

    tested: set[str] = set()

    findings = output_data.get("findings")
    if isinstance(findings, list):
        for row in findings:
            if isinstance(row, dict):
                item = _row_to_surface(row)
                if item is not None:
                    tested.add(item.surface_id)

    for key in _TESTED_LIST_KEYS:
        value = output_data.get(key)
        if not isinstance(value, list):
            continue
        for row in value:
            if isinstance(row, str) and row.strip():
                tested.add(row.strip())
            elif isinstance(row, dict):
                sid = _first_str(row, ("surface_id",))
                if sid:
                    tested.add(sid)
                    continue
                item = _row_to_surface(row)
                if item is not None:
                    tested.add(item.surface_id)

    return tested


def adaptive_coverage_snapshot(output_data: Any, *, enabled: bool) -> dict[str, Any] | None:
    """Coverage snapshot for an append-only timeline entry, or ``None`` to record nothing.

    Returns ``None`` when the adaptive loop is disabled or when the phase output
    yields no injectable surface. Otherwise builds the :class:`AssetGraph`, marks the
    exercised surfaces (Step 2) so ``coverage_metrics`` reports real tested/total
    fractions, and returns a small serializable dict tagged for the timeline. Never
    raises — any internal failure degrades to ``None`` with a warning log.
    """
    if not enabled:
        return None
    try:
        inventory = inventory_from_output(output_data)
        if inventory is None:
            return None
        # Dedup once so the reported surface count matches the graph's distinct nodes
        # (the graph builder dedups internally regardless).
        deduped = inventory.deduplicated()
        graph = build_asset_graph_from_surfaces(deduped)
        tested_ids = tested_surface_ids_from_output(output_data)
        marked = apply_tested_surfaces(graph, tested_ids)
        return {
            "kind": "adaptive_coverage",
            "coverage": coverage_metrics(graph),
            "surfaces": len(deduped.items),
            "tested_surfaces": len(tested_ids),
            "marked_nodes": marked,
        }
    except Exception:
        logger.warning(
            "adaptive_coverage_snapshot_failed",
            extra={"event_type": "adaptive_coverage_snapshot_failed"},
        )
        return None


__all__ = [
    "adaptive_coverage_snapshot",
    "inventory_from_output",
    "tested_surface_ids_from_output",
]
