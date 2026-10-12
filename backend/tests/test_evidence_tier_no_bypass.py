"""R-5.1.2 — no code path assigns an evidence tier outside the arbiter.

A finding's :class:`EvidenceTier` must be decided by
:func:`src.pipeline.contracts.evidence_arbiter.adjudicate` (from collected
artifacts), never hand-set from a hardcoded number or model confidence. This
static guard parses every module under ``src/`` and fails on either
anti-pattern:

* an **assignment** whose target is the attribute / dict-key ``evidence_tier``
  (``x.evidence_tier = …`` / ``d["evidence_tier"] = …``), or
* a **call keyword** ``evidence_tier=<numeric literal>`` (a magic-number tier).

Computed keyword values (``evidence_tier=tier``,
``evidence_tier=EvidenceTier.INFORMATIONAL``, ``evidence_tier=verdict.tier``)
are allowed — those carry a value decided elsewhere (ultimately the arbiter),
not a fabricated constant. The whitelist is intentionally tiny.
"""

from __future__ import annotations

import ast
import pathlib

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src"

# Files permitted to name ``evidence_tier`` as an assignment target. Kept short
# on purpose (R-5.1.2). The arbiter and the derived-scale helpers are the only
# sanctioned owners of the tier; the DB serialization layer assigns it via a
# plain variable kwarg (``evidence_tier=_et``), which this guard does not flag.
_WHITELIST: frozenset[str] = frozenset(
    {
        "pipeline/contracts/evidence_arbiter.py",
        "pipeline/contracts/evidence_scales.py",
    }
)


def _rel(path: pathlib.Path) -> str:
    return str(path.relative_to(_SRC)).replace("\\", "/")


def _violations() -> list[str]:
    found: list[str] = []
    for path in _SRC.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        rel = _rel(path)
        if rel in _WHITELIST:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            # (a) assignment target named evidence_tier
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                targets = [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and target.attr == "evidence_tier":
                    found.append(f"{rel}:{node.lineno}  attribute assignment to .evidence_tier")
                elif (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == "evidence_tier"
                ):
                    found.append(f"{rel}:{node.lineno}  subscript assignment to ['evidence_tier']")
            # (b) call keyword evidence_tier=<numeric literal>
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg == "evidence_tier"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, (int, float))
                        and not isinstance(kw.value.value, bool)
                    ):
                        found.append(
                            f"{rel}:{kw.value.lineno}  hardcoded evidence_tier={kw.value.value!r}"
                        )
    return sorted(found)


def test_no_evidence_tier_assignment_bypasses_the_arbiter() -> None:
    violations = _violations()
    assert not violations, (
        "evidence_tier must be decided by evidence_arbiter.adjudicate, not "
        "hand-set. Offending sites:\n  " + "\n  ".join(violations)
    )
