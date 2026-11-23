"""WP E.6 — measurable provability metrics (the quiet/measurable contrast to ARTEX).

Pure/offline. Real computed precision/recall against a labelled ground truth, plus
``requests-per-proven-finding`` — never hardcoded synthetic numbers.
"""

from __future__ import annotations

import math

from src.reports.provability_metrics import (
    precision_recall,
    precision_recall_by_class,
    requests_per_proven_finding,
)


def test_perfect_match_is_one() -> None:
    gt = {("/login", "CWE-89"), ("/search", "CWE-79")}
    pr = precision_recall(detected=set(gt), ground_truth=gt)
    assert pr.precision == 1.0
    assert pr.recall == 1.0
    assert pr.f1 == 1.0


def test_false_positive_and_false_negative() -> None:
    gt = {("/login", "CWE-89"), ("/search", "CWE-79")}
    detected = {("/login", "CWE-89"), ("/x", "CWE-22")}  # 1 TP, 1 FP, 1 FN
    pr = precision_recall(detected=detected, ground_truth=gt)
    assert pr.true_positives == 1
    assert pr.false_positives == 1
    assert pr.false_negatives == 1
    assert pr.precision == 0.5
    assert pr.recall == 0.5
    assert abs(pr.f1 - 0.5) < 1e-9


def test_empty_detection_is_zero_not_crash() -> None:
    gt = {("/login", "CWE-89")}
    pr = precision_recall(detected=set(), ground_truth=gt)
    assert pr.precision == 0.0
    assert pr.recall == 0.0
    assert pr.f1 == 0.0


def test_requests_per_proven_finding() -> None:
    assert requests_per_proven_finding(total_requests=100, proven_findings=5) == 20.0


def test_requests_per_proven_finding_zero_proven_is_infinite() -> None:
    assert math.isinf(requests_per_proven_finding(total_requests=50, proven_findings=0))


def test_per_cwe_breakdown() -> None:
    gt = {("/login", "CWE-89"), ("/u", "CWE-89"), ("/search", "CWE-79")}
    detected = {("/login", "CWE-89"), ("/search", "CWE-79"), ("/x", "CWE-79")}
    by_class = precision_recall_by_class(
        detected=detected, ground_truth=gt, class_of=lambda item: item[1]
    )
    # CWE-89: TP=1 (login), FN=1 (/u) → recall 0.5, precision 1.0
    assert by_class["CWE-89"].recall == 0.5
    assert by_class["CWE-89"].precision == 1.0
    # CWE-79: TP=1 (search), FP=1 (/x) → precision 0.5, recall 1.0
    assert by_class["CWE-79"].precision == 0.5
    assert by_class["CWE-79"].recall == 1.0
