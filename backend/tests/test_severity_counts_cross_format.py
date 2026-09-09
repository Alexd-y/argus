"""E2E invariant: identical findings → identical severity counts in every format.

The canonical population is a fixed, heterogeneous set of findings (every band,
including the ``unknown`` bucket). The same population is rendered through each
customer-facing / machine-readable format and we assert that the per-band
severity distribution is *byte-for-byte identical* to the canonical count from
:func:`src.findings.severity.aggregate_severity`.

This is the regression gate for "same data → same severity/counters regardless
of report format, tier, pagination, or fetch path" (see
``docs/finding-severity-and-counting.md``). It is a pure, offline test — no
network, no DB, no Docker.
"""

from __future__ import annotations

import csv
import io
import json

from src.api.schemas import Finding, ReportSummary
from src.findings.severity import aggregate_severity, normalize_severity
from src.reports.generators import ReportData, generate_csv, generate_json
from src.reports.sarif_generator import generate_sarif
from src.reports.snapshot_builder import build_snapshot_from_report_data

# A fixed population that exercises the counting pipeline WITHOUT tripping the
# evidence-driven *severity-adjustment* policy (``enforce_severity_by_evidence``
# only mutates ``high``/``critical`` rows that are not VALIDATED, and the
# VALIDATED evidence gate only touches VALIDATED rows). Keeping the rows
# ``candidate`` + non-high/critical isolates the *counting* invariant this test
# guards (P2: one canonical aggregation on every path) from the orthogonal
# severity-downgrade policy. It still covers the two buckets historically
# dropped by ad-hoc counters: informational (CVSS "None") and unknown.
_SEVERITIES: tuple[str, ...] = (
    "medium",
    "medium",
    "low",
    "info",
    "unknown",
    "unknown",
)


def _finding(idx: int, severity: str) -> Finding:
    return Finding(
        finding_id=f"fid-{idx}",
        severity=severity,
        title=f"Finding {idx}",
        description="desc",
        cwe="CWE-79",
        cvss=5.0,
        cvss_score=5.0,
        confidence="likely",
        # Deliberately NOT "validated": the VALIDATED evidence gate would
        # downgrade rows lacking raw req/resp + remediation, which is a
        # severity-policy concern, not a counting one.
        evidence_classification="candidate",  # type: ignore[arg-type]
        is_provable=True,
        evidence_refs=[f"minio://artifacts/scan/req-{idx}.txt"],
    )


def _report() -> ReportData:
    findings = [_finding(i, sev) for i, sev in enumerate(_SEVERITIES)]
    return ReportData(
        report_id="r-1",
        target="https://victim.example.com",
        summary=ReportSummary(),
        findings=findings,
        technologies=["nginx"],
        scan_id="00000000-0000-0000-0000-0000000000aa",
        tenant_id="00000000-0000-0000-0000-000000000001",
        created_at="2026-04-19T12:00:00Z",
    )


def _canonical() -> dict[str, int]:
    return aggregate_severity(_SEVERITIES).as_dict()


def _bands_from_labels(labels: list[object]) -> dict[str, int]:
    """Re-aggregate arbitrary raw labels through the canonical normaliser."""
    return aggregate_severity(labels).as_dict()


def test_canonical_population_is_stable() -> None:
    counts = _canonical()
    assert counts == {
        "critical": 0,
        "high": 0,
        "medium": 2,
        "low": 1,
        "informational": 1,
        "unknown": 2,
    }
    # The bucket sum must equal the population size — no finding is dropped.
    assert sum(counts.values()) == len(_SEVERITIES)


def test_json_export_matches_canonical() -> None:
    blob = json.loads(generate_json(_report()).decode("utf-8"))
    findings = blob.get("findings") or []
    assert len(findings) == len(_SEVERITIES)
    labels = [f.get("severity") for f in findings]
    assert _bands_from_labels(labels) == _canonical()


def test_csv_export_matches_canonical() -> None:
    blob = generate_csv(_report()).decode("utf-8")
    rows = list(csv.reader(io.StringIO(blob)))
    header_idx = next(i for i, r in enumerate(rows) if r and r[0] == "report_id")
    header = rows[header_idx]
    sev_col = header.index("severity")
    id_col = header.index("finding_id")
    labels = [
        r[sev_col]
        for r in rows[header_idx + 1 :]
        if len(r) > max(sev_col, id_col) and r[id_col].startswith("fid-")
    ]
    assert len(labels) == len(_SEVERITIES)
    assert _bands_from_labels(labels) == _canonical()


def test_sarif_export_matches_canonical() -> None:
    payload = json.loads(generate_sarif(_report()).decode("utf-8"))
    results = payload["runs"][0]["results"]
    assert len(results) == len(_SEVERITIES)
    labels = [r["properties"]["severity"] for r in results]
    assert _bands_from_labels(labels) == _canonical()


def test_snapshot_matches_canonical() -> None:
    doc = build_snapshot_from_report_data(_report())
    assert len(doc.findings) == len(_SEVERITIES)
    labels = [f.severity for f in doc.findings]
    assert _bands_from_labels(labels) == _canonical()


def test_all_formats_agree_pairwise() -> None:
    """Cross-check every format against every other, not just the canonical."""
    report = _report()

    json_labels = [
        f.get("severity")
        for f in (json.loads(generate_json(report).decode("utf-8")).get("findings") or [])
    ]
    sarif_labels = [
        r["properties"]["severity"]
        for r in json.loads(generate_sarif(report).decode("utf-8"))["runs"][0]["results"]
    ]
    snapshot_labels = [f.severity for f in build_snapshot_from_report_data(report).findings]

    distributions = {
        "json": _bands_from_labels(json_labels),
        "sarif": _bands_from_labels(sarif_labels),
        "snapshot": _bands_from_labels(snapshot_labels),
        "canonical": _canonical(),
    }
    reference = distributions["canonical"]
    for name, dist in distributions.items():
        assert dist == reference, f"{name} severity distribution diverged: {dist}"


def test_unknown_and_informational_are_first_class() -> None:
    """The two historically-dropped buckets must survive every format."""
    counts = _canonical()
    # "info" (CVSS "None") folds into the informational bucket; "unknown"
    # stays a first-class bucket — neither is ever silently dropped.
    assert counts[normalize_severity("info").value] == 1
    assert counts[normalize_severity("unknown").value] == 2
