"""Wave 4 / Stage 6 — module-size threshold for src/reports (R-6.3.1).

Enforces a line-count ceiling on report modules so no *new* monolith appears, and
ratchets the known oversized modules *down*: an allowlisted module may shrink but never
grow past its recorded cap, and once it drops under the threshold it must graduate off
the allowlist. This is the linter half of the decomposition: valhalla_report_context is
being split section by section (see src/reports/valhalla_sections/), and this test keeps
the split moving in one direction.
"""

from __future__ import annotations

from pathlib import Path

_REPORTS_DIR = Path(__file__).resolve().parents[3] / "src" / "reports"

#: A report module may not exceed this many lines unless it is a grandfathered monolith.
MODULE_LINE_THRESHOLD = 2000

#: Grandfathered oversized modules → their current line cap (a ratchet). Decomposition
#: debt, tracked explicitly: each may only shrink. Lower the cap as code moves out; when
#: one drops below MODULE_LINE_THRESHOLD, delete its entry (the assertion enforces this).
OVERSIZED_ALLOWLIST: dict[str, int] = {
    # Ratcheted down as sections move out (Wave 4 / Stage 6): structured_rows + branding
    # extracted to valhalla_sections/.
    "valhalla_report_context.py": 7860,
    # Reflects the current HEAD size (pre-existing drift from the report waves that
    # grew this module past the old 3610 ratchet) plus the DWM ReportData field +
    # builder thread. Decomposition remains tracked debt — only shrink from here.
    "generators.py": 3975,
    "report_quality_gate.py": 3120,
}


def _loc(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def _rel(path: Path) -> str:
    return path.relative_to(_REPORTS_DIR).as_posix()


def test_no_new_report_monolith() -> None:
    offenders: list[str] = []
    for py in _REPORTS_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        loc = _loc(py)
        name = _rel(py)
        if name in OVERSIZED_ALLOWLIST:
            continue
        if loc > MODULE_LINE_THRESHOLD:
            offenders.append(f"{name}: {loc} > {MODULE_LINE_THRESHOLD} (decompose or allowlist)")
    assert not offenders, "new oversized report module(s):\n" + "\n".join(offenders)


def test_allowlisted_monoliths_only_shrink() -> None:
    for name, cap in OVERSIZED_ALLOWLIST.items():
        path = _REPORTS_DIR / name
        assert path.exists(), f"allowlisted module {name} no longer exists — remove it"
        loc = _loc(path)
        assert loc <= cap, (
            f"{name} grew to {loc} lines (cap {cap}); the ratchet only allows shrinking — "
            f"move code out, do not raise the cap"
        )


def test_allowlist_entries_are_still_oversized() -> None:
    # Keep the allowlist honest: a module that has dropped under the threshold must be
    # removed from the allowlist (so a future regression is caught by the threshold).
    for name in OVERSIZED_ALLOWLIST:
        loc = _loc(_REPORTS_DIR / name)
        assert loc > MODULE_LINE_THRESHOLD, (
            f"{name} is now {loc} lines (≤ {MODULE_LINE_THRESHOLD}) — remove it from "
            f"OVERSIZED_ALLOWLIST so the threshold guards it"
        )
