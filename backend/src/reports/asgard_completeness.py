"""Asgard release gates (fail-closed) — modelled on ``valhalla_completeness.py``.

The gates enforce the paid-tier content contract before an Asgard report is
released. Unlike the Valhalla ``except Exception: pass`` fail-open pattern the
project memory flagged, every gate here is **fail-closed**: a gate that cannot
be evaluated ADDS a ``GATE-ERROR`` blocker instead of silently passing.

Gates (prompt §6):

* ``A-G1`` every Critical/High finding has non-empty ``evidence`` AND
  ``remediation``.
* ``A-G2`` the three paid sections (``tls_analysis``, ``header_analysis``,
  ``dark_web``) are present (an un-run section renders with an explicit
  "not assessed" status, never silently absent).
* ``A-G3`` five-format parity — same finding ids + severity counts + section
  presence across the rendered formats.
* ``A-G4`` raw-leak contract — no ``raw_request``/``raw_response``/``output_raw``/
  ``object_key``/presigned host/``tool:``/``recon:`` pseudo-ids/PoC command
  strings in any rendered format.
* ``A-G5`` AI slots carry gate-passing prose or the deterministic fallback —
  never an empty string counted as success.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Forbidden substrings for the raw-leak contract (A-G4). Case-insensitive.
RAW_LEAK_MARKERS: tuple[str, ...] = (
    "raw_request",
    "raw_response",
    "output_raw",
    "object_key",
    "x-amz-",
    "presigned",
    "proof_of_concept",
    "phase_outputs",
    "phase artifacts",
    "raw tool output",
)
# Pseudo-id prefixes (``tool:…`` / ``recon:…``) and PoC command strings.
_PSEUDO_ID_RE = re.compile(r"\b(?:tool|recon):[A-Za-z0-9_./-]+", re.IGNORECASE)
_POC_CMD_RE = re.compile(r"\b(?:sqlmap|nikto|hydra)\b|curl\s+-{1,2}\w", re.IGNORECASE)

_CRITICAL_HIGH = ("critical", "high")


@dataclass
class AsgardGateViolation:
    gate: str
    detail: str


@dataclass
class AsgardGateReport:
    violations: list[AsgardGateViolation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def blockers(self) -> list[str]:
        return [f"{v.gate}: {v.detail}" for v in self.violations]


def _nonempty(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, (list, tuple, set, dict, str)):
        return len(v) > 0
    return bool(v)


def check_g1(payload: dict[str, Any]) -> list[AsgardGateViolation]:
    """A-G1: every Critical/High finding has non-empty evidence AND remediation."""
    out: list[AsgardGateViolation] = []
    for f in payload.get("findings", []) or []:
        sev = str(f.get("severity") or "").lower()
        if sev not in _CRITICAL_HIGH:
            continue
        fid = f.get("id") or f.get("title") or "?"
        if not _nonempty(f.get("evidence")):
            out.append(AsgardGateViolation("A-G1", f"{sev} finding {fid} has empty evidence"))
        if not _nonempty(f.get("remediation")):
            out.append(AsgardGateViolation("A-G1", f"{sev} finding {fid} has empty remediation"))
    return out


def check_g2(payload: dict[str, Any]) -> list[AsgardGateViolation]:
    """A-G2: the three paid sections are present (even if 'not assessed')."""
    out: list[AsgardGateViolation] = []
    for section in ("tls_analysis", "header_analysis", "dark_web"):
        value = payload.get(section)
        if not isinstance(value, dict) or not value:
            out.append(AsgardGateViolation("A-G2", f"paid section '{section}' is missing"))
    return out


def check_g5(payload: dict[str, Any]) -> list[AsgardGateViolation]:
    """A-G5: AI slots carry non-empty prose (never empty-as-success)."""
    out: list[AsgardGateViolation] = []
    ai = payload.get("ai_conclusions") or {}
    for slot in ("vulnerability_description", "business_risk"):
        if not _nonempty(
            (ai.get(slot) or "").strip() if isinstance(ai.get(slot), str) else ai.get(slot)
        ):
            out.append(AsgardGateViolation("A-G5", f"AI slot '{slot}' is empty"))
    if not _nonempty(ai.get("prioritized_roadmap")):
        out.append(AsgardGateViolation("A-G5", "AI slot 'prioritized_roadmap' is empty"))
    return out


def check_g4(rendered: dict[str, bytes | str]) -> list[AsgardGateViolation]:
    """A-G4: no raw/PoC/object-key leak in any rendered format."""
    out: list[AsgardGateViolation] = []
    for fmt, content in rendered.items():
        text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)
        low = text.lower()
        for marker in RAW_LEAK_MARKERS:
            if marker in low:
                out.append(AsgardGateViolation("A-G4", f"format '{fmt}' leaked marker '{marker}'"))
        if _PSEUDO_ID_RE.search(text):
            out.append(
                AsgardGateViolation("A-G4", f"format '{fmt}' contains a tool:/recon: pseudo-id")
            )
        if _POC_CMD_RE.search(text):
            out.append(AsgardGateViolation("A-G4", f"format '{fmt}' contains a PoC command string"))
    return out


def check_g3(
    finding_sets: dict[str, list[tuple[str, str]]], counts: dict[str, dict[str, int]]
) -> list[AsgardGateViolation]:
    """A-G3: five-format parity — same finding (id, severity) set and counts.

    ``finding_sets`` maps format → list of ``(id, severity)``; ``counts`` maps
    format → severity-count dict. All formats must agree.
    """
    out: list[AsgardGateViolation] = []
    if not finding_sets:
        return [AsgardGateViolation("A-G3", "no formats provided for parity")]
    ref_fmt = next(iter(finding_sets))
    ref_ids = sorted(finding_sets[ref_fmt])
    for fmt, ids in finding_sets.items():
        if sorted(ids) != ref_ids:
            out.append(
                AsgardGateViolation("A-G3", f"format '{fmt}' finding set differs from '{ref_fmt}'")
            )
    if counts:
        ref_counts = counts.get(ref_fmt, {})
        for fmt, c in counts.items():
            if c != ref_counts:
                out.append(
                    AsgardGateViolation(
                        "A-G3", f"format '{fmt}' severity counts differ from '{ref_fmt}'"
                    )
                )
    return out


def _guarded(gate: str, fn, report: AsgardGateReport) -> None:
    """Run one gate fail-closed: an exception ADDS a GATE-ERROR blocker."""
    try:
        report.violations.extend(fn())
    except Exception as exc:  # noqa: BLE001 — fail-closed: an errored gate blocks release
        report.violations.append(
            AsgardGateViolation(gate, f"GATE-ERROR: {type(exc).__name__}: {exc}")
        )


def evaluate_asgard_release(
    payload: dict[str, Any],
    *,
    rendered: dict[str, bytes | str] | None = None,
    finding_sets: dict[str, list[tuple[str, str]]] | None = None,
    counts: dict[str, dict[str, int]] | None = None,
) -> AsgardGateReport:
    """Run A-G1..A-G5 fail-closed and return the aggregated report."""
    report = AsgardGateReport()
    _guarded("A-G1", lambda: check_g1(payload), report)
    _guarded("A-G2", lambda: check_g2(payload), report)
    _guarded("A-G5", lambda: check_g5(payload), report)
    if rendered is not None:
        _guarded("A-G4", lambda: check_g4(rendered), report)
    if finding_sets is not None:
        _guarded("A-G3", lambda: check_g3(finding_sets, counts or {}), report)
    return report


__all__ = [
    "RAW_LEAK_MARKERS",
    "AsgardGateReport",
    "AsgardGateViolation",
    "check_g1",
    "check_g2",
    "check_g3",
    "check_g4",
    "check_g5",
    "evaluate_asgard_release",
]
