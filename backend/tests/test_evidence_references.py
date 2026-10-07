"""Phase 14.3 — evidence/claim reference index + prose-reference enforcement flag."""

from __future__ import annotations

from types import SimpleNamespace

from src.core.config import settings
from src.reports.evidence_references import build_evidence_reference_index
from src.reports.prose_gate import has_reference


def _f(fid: str, evidence: list[str]) -> SimpleNamespace:
    return SimpleNamespace(finding_id=fid, evidence_ids=evidence)


def test_index_is_deterministic_and_first_seen_order() -> None:
    findings = [_f("f-b", ["ev-2", "ev-1"]), _f("f-a", ["ev-1", "ev-3"])]
    a = build_evidence_reference_index(findings)
    b = build_evidence_reference_index(findings)
    assert a == b
    assert a.claim_ref == {"f-b": "CL-0001", "f-a": "CL-0002"}
    # evidence labelled in first-seen order, de-duplicated across findings
    assert a.evidence_ref == {"ev-2": "E-0001", "ev-1": "E-0002", "ev-3": "E-0003"}


def test_reference_marker_matches_prose_gate() -> None:
    idx = build_evidence_reference_index([_f("f-a", ["ev-1", "ev-2"])])
    ref = idx.reference_for(_f("f-a", ["ev-1", "ev-2"]))
    assert ref == "[CL-0001 / E-0001 / E-0002]"
    # prose_gate must accept it as a valid factual reference
    assert has_reference(f"UNION SQLi confirmed on the id parameter {ref}.") is True


def test_dict_findings_supported() -> None:
    idx = build_evidence_reference_index(
        [{"finding_id": "f-a", "evidence_refs": ["ev-9"]}]
    )
    assert idx.claim_ref == {"f-a": "CL-0001"}
    assert idx.evidence_ref == {"ev-9": "E-0001"}
    assert idx.reference_for({"finding_id": "f-a", "evidence_refs": ["ev-9"]}) == "[CL-0001 / E-0001]"


def test_reference_caps_evidence_count() -> None:
    idx = build_evidence_reference_index([_f("f-a", ["e1", "e2", "e3", "e4", "e5"])])
    ref = idx.reference_for(_f("f-a", ["e1", "e2", "e3", "e4", "e5"]))
    # 1 claim + at most 3 evidence labels
    assert ref.count("E-") == 3
    assert ref.startswith("[CL-0001 / E-")


def test_empty_finding_has_no_reference() -> None:
    idx = build_evidence_reference_index([])
    assert idx.reference_for(_f("", [])) == ""


def test_prose_reference_enforcement_defaults_off() -> None:
    # Default must stay False so existing reports (free LLM prose without refs) are
    # not retroactively blocked; operators opt in explicitly.
    assert settings.report_require_prose_references is False
