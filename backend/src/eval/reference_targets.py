"""Reference target set — known-vuln ground truth for measurement (Wave 5, R-9.6).

Loads the versioned ``config/eval/reference_targets.yaml`` (what each target
SHOULD find vs must NOT claim) and scores a scan's findings against it:

* recall — share of expected findings the scan actually produced;
* forbidden hits — findings the scan claimed that the ground truth says are absent
  (false positives).

Pure, dependency-light: the loader reads YAML, the scorer is a pure function over
finding dicts, so both are testable offline without a scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DEFAULT_PATH = Path(__file__).resolve().parents[2] / "config" / "eval" / "reference_targets.yaml"


@dataclass(frozen=True)
class ReferenceFinding:
    vuln_class: str
    location: str = ""
    note: str = ""


@dataclass(frozen=True)
class ReferenceTarget:
    id: str
    url: str
    description: str = ""
    expected: tuple[ReferenceFinding, ...] = field(default_factory=tuple)
    forbidden: tuple[ReferenceFinding, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ReferenceScore:
    target_id: str
    expected_total: int
    matched: tuple[ReferenceFinding, ...]
    missed: tuple[ReferenceFinding, ...]
    forbidden_hits: tuple[ReferenceFinding, ...]

    @property
    def recall(self) -> float:
        return len(self.matched) / self.expected_total if self.expected_total else 0.0


def _coerce_findings(items: Any) -> tuple[ReferenceFinding, ...]:
    out: list[ReferenceFinding] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        vc = str(it.get("vuln_class", "")).strip()
        if not vc:
            continue
        out.append(
            ReferenceFinding(
                vuln_class=vc,
                location=str(it.get("location", "") or ""),
                note=str(it.get("note", "") or ""),
            )
        )
    return tuple(out)


def load_reference_targets(path: str | Path | None = None) -> dict[str, ReferenceTarget]:
    """Load and validate the reference target set, keyed by target id."""
    import yaml

    p = Path(path) if path is not None else _DEFAULT_PATH
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if int(data.get("schema_version", 0)) != 1:
        raise ValueError(
            f"unsupported reference_targets schema_version: {data.get('schema_version')!r}"
        )
    targets: dict[str, ReferenceTarget] = {}
    for entry in data.get("targets", []) or []:
        tid = str(entry.get("id", "")).strip()
        if not tid:
            continue
        targets[tid] = ReferenceTarget(
            id=tid,
            url=str(entry.get("url", "") or ""),
            description=str(entry.get("description", "") or ""),
            expected=_coerce_findings(entry.get("expected")),
            forbidden=_coerce_findings(entry.get("forbidden")),
        )
    return targets


def _finding_matches(ref: ReferenceFinding, finding: dict[str, Any]) -> bool:
    fclass = str(
        finding.get("vuln_class")
        or finding.get("category")
        or finding.get("owasp_category")
        or finding.get("cwe")
        or ""
    ).lower()
    if ref.vuln_class.lower() not in fclass and fclass not in ref.vuln_class.lower():
        return False
    if ref.location:
        floc = str(finding.get("location") or finding.get("url") or finding.get("endpoint") or "")
        if ref.location not in floc:
            return False
    return True


def score_against_reference(
    target: ReferenceTarget,
    findings: list[dict[str, Any]],
) -> ReferenceScore:
    """Score ``findings`` against a reference target's expected/forbidden ground truth."""
    matched: list[ReferenceFinding] = []
    missed: list[ReferenceFinding] = []
    for ref in target.expected:
        if any(_finding_matches(ref, f) for f in findings):
            matched.append(ref)
        else:
            missed.append(ref)
    forbidden_hits = [
        ref for ref in target.forbidden if any(_finding_matches(ref, f) for f in findings)
    ]
    return ReferenceScore(
        target_id=target.id,
        expected_total=len(target.expected),
        matched=tuple(matched),
        missed=tuple(missed),
        forbidden_hits=tuple(forbidden_hits),
    )


__all__ = [
    "ReferenceFinding",
    "ReferenceScore",
    "ReferenceTarget",
    "load_reference_targets",
    "score_against_reference",
]
