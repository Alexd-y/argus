"""Provability metrics (WP E.6) — the measurable, quiet contrast to noisy ARTEX.

Real, computed metrics over a labelled ground truth (e.g. the juice-shop e2e target),
never hardcoded synthetic numbers:

* :func:`precision_recall` — TP/FP/FN + precision/recall/F1 over sets of finding
  identities (a finding identity is any hashable, e.g. ``(location, cwe)``).
* :func:`precision_recall_by_class` — the same, bucketed per vulnerability class
  (CWE family) plus an ``overall`` entry.
* :func:`requests_per_proven_finding` — how many HTTP requests the engine spent per
  *proven* finding. Lower is quieter; ``inf`` when nothing was proven.

Pure module: no DB/LLM/network. A benchmark/release gate feeds it real detections and
the target's ground-truth labels instead of asserting against invented figures.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Set
from dataclasses import dataclass
from typing import Any

__all__ = [
    "PrecisionRecall",
    "precision_recall",
    "precision_recall_by_class",
    "requests_per_proven_finding",
]


@dataclass(frozen=True)
class PrecisionRecall:
    """Confusion-derived metrics for one population."""

    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float


def _f1(precision: float, recall: float) -> float:
    denom = precision + recall
    return (2 * precision * recall / denom) if denom else 0.0


def precision_recall(*, detected: Set[Any], ground_truth: Set[Any]) -> PrecisionRecall:
    """Precision/recall/F1 from a detected set vs. a ground-truth set.

    Both are sets of hashable finding identities; comparison is exact set membership,
    so an identity must match on every field the caller encodes (location + class).
    Empty denominators yield ``0.0`` rather than raising.
    """
    detected_set = set(detected)
    truth_set = set(ground_truth)
    tp = len(detected_set & truth_set)
    fp = len(detected_set - truth_set)
    fn = len(truth_set - detected_set)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return PrecisionRecall(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
    )


def precision_recall_by_class(
    *,
    detected: Iterable[Any],
    ground_truth: Iterable[Any],
    class_of: Callable[[Any], str],
) -> dict[str, PrecisionRecall]:
    """Per-class precision/recall plus an ``"overall"`` bucket.

    ``class_of`` maps a finding identity to its vulnerability class (e.g. the CWE).
    Each class is scored independently on the subset of detections/labels in it.
    """
    detected_set = set(detected)
    truth_set = set(ground_truth)
    classes: set[str] = {class_of(i) for i in detected_set} | {class_of(i) for i in truth_set}
    out: dict[str, PrecisionRecall] = {}
    for cls in classes:
        det_c = {i for i in detected_set if class_of(i) == cls}
        gt_c = {i for i in truth_set if class_of(i) == cls}
        out[cls] = precision_recall(detected=det_c, ground_truth=gt_c)
    out["overall"] = precision_recall(detected=detected_set, ground_truth=truth_set)
    return out


def requests_per_proven_finding(*, total_requests: int, proven_findings: int) -> float:
    """HTTP requests spent per *proven* finding (lower == quieter, more surgical).

    Returns ``inf`` when nothing was proven — honestly "infinitely noisy per proven
    finding" rather than a misleading zero.
    """
    if proven_findings <= 0:
        return float("inf")
    return total_requests / proven_findings
