"""Single canonical finding-selection pipeline.

Both the report generator (``reports/data_collector.ReportDataCollector``) and
the public findings API (``api/routers/scans.get_scan_findings``) must present
the **same** set of findings for a scan. Historically they did not: the report
path used ``reports/finding_dedup`` + ``finding_quality_filter`` +
``evidence_partition``, while the API used ``orchestration/finding_gate`` — two
independent dedup/quality implementations with different predicates, so the UI
could show findings (and severities) the reports did not, and vice-versa.

This module is the one place that decides the canonical finding set. Callers map
the result into their own output shape (report ``FindingRow`` list, API schema),
but the *selection* (dedup, quality filter, severity reconciliation, provability
partition) is shared, so the UI and every report tier stay in lock-step.
"""

from __future__ import annotations

from src.findings.lifecycle_bridge import retain_findings_despite_ai_classification
from src.reports.evidence_partition import partition_findings
from src.reports.finding_dedup import deduplicate_findings
from src.reports.finding_quality_filter import filter_valid_findings
from src.reports.finding_severity_normalizer import reconcile_findings_cvss
from src.reports.report_quality_gate import normalize_findings_for_report


# ``findings`` is a list of ``FindingRow``-like objects (duck-typed; importing the
# concrete type here would create an import cycle with ``data_collector``).
def apply_canonical_finding_pipeline[T](findings: list[T]) -> list[T]:
    """Return the canonical finding set in canonical order.

    Behaviour-identical to the sequence previously inlined in
    ``ReportDataCollector.collect_async`` — kept in one place so the report
    generator and the ``/findings`` API apply the exact same selection:

    1. ``deduplicate_findings``   — CWE+URL hard dup / 0.85 title soft dup, merges
       header-gap and reflected-XSS groups, keeps the richer finding.
    2. ``filter_valid_findings``  — drops only degenerate rows (placeholder title
       / description < 10 chars). Never drops by evidence tier.
    3. ``retain_findings_despite_ai_classification`` — AI ``contradicted`` never
       deletes a finding.
    4. ``normalize_findings_for_report`` — report-shape normalization.
    5. ``reconcile_findings_cvss`` — one consistent severity/cvss value.
    6. ``partition_findings`` — tags ``is_provable`` / ``unconfirmed_reason``
       in place (drops nothing).
    """
    findings = deduplicate_findings(findings)
    findings = filter_valid_findings(findings)
    findings = retain_findings_despite_ai_classification(findings)
    findings = normalize_findings_for_report(findings)
    findings = reconcile_findings_cvss(findings)
    partition_findings(findings)
    return findings
