"""Context package construction: redaction (SI-3) and hash stability."""

from src.reports.llm_remediation.closure_status import (
    ClosureComputationInput,
    compute_permitted_closure_status,
)
from src.reports.llm_remediation.context import (
    build_finding_context,
    redact_text,
)


def test_redact_masks_secrets():
    raw = (
        "Authorization: Bearer abcdefgh12345678\n"
        "password=SuperSecret123\n"
        "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0"
    )
    red = redact_text(raw)
    assert "SuperSecret123" not in red
    assert "abcdefgh12345678" not in red
    assert "«redacted" in red
    assert "eyJhbGciOiJIUzI1NiJ9" not in red


def test_build_context_redacts_and_hashes():
    finding = {
        "finding_id": "F-1",
        "title": "Exposed .env",
        "description": "Leaked api_key=AKIAIOSFODNN7EXAMPLEKEYVALUE1234567890 in body",
        "severity": "high",
    }
    permitted = compute_permitted_closure_status(
        ClosureComputationInput(finding_id="F-1", acceptance_criteria_ids=("C1",))
    )
    ctx = build_finding_context(
        finding,
        report_meta={"report_id": "R1", "report_version": "1", "scan_id": "S1", "tenant_id": "T1"},
        permitted=permitted,
        allowed_evidence_ids=["E1"],
        evidence_fragments={"E1": "cookie: session=deadbeefcafebabedeadbeefcafebabe"},
    )
    assert ctx.finding_id == "F-1"
    assert "AKIAIOSFODNN7EXAMPLEKEYVALUE" not in ctx.payload["finding"]["description"]
    assert "deadbeefcafebabe" not in ctx.payload["evidence"]["fragments"]["E1"]
    assert ctx.payload["retest"]["permitted_closure_status"] == "not_retested"
    assert len(ctx.context_hash) >= 8


def test_context_hash_is_stable_and_sensitive():
    finding = {"finding_id": "F-1", "title": "t", "description": "d"}
    permitted = compute_permitted_closure_status(
        ClosureComputationInput(finding_id="F-1", acceptance_criteria_ids=("C1",))
    )
    meta = {"report_id": "R1", "report_version": "1", "scan_id": "S1", "tenant_id": "T1"}
    a = build_finding_context(finding, report_meta=meta, permitted=permitted)
    b = build_finding_context(finding, report_meta=meta, permitted=permitted)
    assert a.context_hash == b.context_hash

    changed = build_finding_context(
        {**finding, "description": "different"}, report_meta=meta, permitted=permitted
    )
    assert changed.context_hash != a.context_hash


def test_evidence_fragments_filtered_by_allowlist():
    finding = {"finding_id": "F-1", "description": "d"}
    permitted = compute_permitted_closure_status(
        ClosureComputationInput(finding_id="F-1", acceptance_criteria_ids=())
    )
    ctx = build_finding_context(
        finding,
        report_meta={"report_id": "R1", "report_version": "1", "scan_id": "S1", "tenant_id": "T1"},
        permitted=permitted,
        allowed_evidence_ids=["E1"],
        evidence_fragments={"E1": "ok", "E2": "should-not-appear"},
    )
    frags = ctx.payload["evidence"]["fragments"]
    assert "E1" in frags
    assert "E2" not in frags
