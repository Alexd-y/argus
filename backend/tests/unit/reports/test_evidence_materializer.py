"""ARGUS-WSTG-COV-1 §Evidence — Evidence row materialisation from PoC artifacts.

The producer half of store-backed coverage: a finding's uploaded PoC (and
optional screenshot) MinIO keys must become deterministic, idempotent
``Evidence`` row descriptors so a phase retry never duplicates them.
"""

from __future__ import annotations

from src.reports.evidence_materializer import (
    POC_CONTENT_TYPE,
    SCREENSHOT_CONTENT_TYPE,
    build_evidence_id,
    build_finding_evidence_rows,
    build_observation_poc,
)


def test_poc_key_materialises_single_evidence_row():
    rows = build_finding_evidence_rows(
        tenant_id="t1",
        scan_id="s1",
        finding_id="F1",
        poc_object_key="t1/s1/poc/F1.json",
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.finding_id == "F1"
    assert row.scan_id == "s1"
    assert row.tenant_id == "t1"
    assert row.object_key == "t1/s1/poc/F1.json"
    assert row.content_type == POC_CONTENT_TYPE


def test_poc_and_screenshot_materialise_two_rows_distinct_kinds():
    rows = build_finding_evidence_rows(
        tenant_id="t1",
        scan_id="s1",
        finding_id="F1",
        poc_object_key="t1/s1/poc/F1.json",
        screenshot_object_key="t1/s1/poc/screenshots/F1.png",
    )
    assert len(rows) == 2
    content_types = {r.content_type for r in rows}
    assert content_types == {POC_CONTENT_TYPE, SCREENSHOT_CONTENT_TYPE}
    # Distinct object keys → distinct deterministic ids.
    assert len({r.id for r in rows}) == 2


def test_no_keys_yields_no_rows():
    # Object store unavailable / nothing uploaded → no artifact, no evidence.
    assert build_finding_evidence_rows(tenant_id="t1", scan_id="s1", finding_id="F1") == []
    assert (
        build_finding_evidence_rows(
            tenant_id="t1", scan_id="s1", finding_id="F1", poc_object_key="  "
        )
        == []
    )


def test_evidence_id_is_deterministic_and_idempotent():
    a = build_evidence_id("s1", "F1", "k")
    b = build_evidence_id("s1", "F1", "k")
    assert a == b  # same inputs → same id (idempotent upsert key)
    # Different inputs → different ids.
    assert build_evidence_id("s1", "F1", "k2") != a
    assert build_evidence_id("s2", "F1", "k") != a
    assert build_evidence_id("s1", "F2", "k") != a


def test_build_rows_idempotent_across_calls():
    kwargs = {
        "tenant_id": "t1",
        "scan_id": "s1",
        "finding_id": "F1",
        "poc_object_key": "t1/s1/poc/F1.json",
        "screenshot_object_key": "t1/s1/poc/screenshots/F1.png",
    }
    first = build_finding_evidence_rows(**kwargs)
    second = build_finding_evidence_rows(**kwargs)
    assert [r.id for r in first] == [r.id for r in second]


def test_duplicate_object_key_deduplicated():
    rows = build_finding_evidence_rows(
        tenant_id="t1",
        scan_id="s1",
        finding_id="F1",
        poc_object_key="same/key",
        screenshot_object_key="same/key",
    )
    assert len(rows) == 1


# --------------------------------------------------------------------------- #
# build_observation_poc — honest passive-check evidence (TLS/headers/DNS).
# --------------------------------------------------------------------------- #
def test_observation_poc_none_without_evidence_refs():
    # No captured refs → never fabricate an artifact from a bare finding.
    assert build_observation_poc(description="Missing: X-Frame-Options", evidence_refs=[]) is None
    assert build_observation_poc(description="obs", evidence_refs=None) is None


def test_observation_poc_none_without_observation_or_steps():
    # Refs present but nothing observed/reproducible → not an artifact.
    assert build_observation_poc(description="   ", evidence_refs=["tls_scan.json:1"]) is None


def test_observation_poc_built_from_refs_and_description():
    poc = build_observation_poc(
        description="Missing: X-Frame-Options, Content-Security-Policy",
        evidence_refs=["headers.json:3", "tool:web_vuln_heuristics"],
    )
    assert poc is not None
    assert poc["kind"] == "observation"
    assert poc["evidence_refs"] == ["headers.json:3", "tool:web_vuln_heuristics"]
    assert "X-Frame-Options" in poc["observation"]


def test_observation_poc_includes_reproducible_steps():
    poc = build_observation_poc(
        description="Weak TLS",
        evidence_refs=["tls_scan.json:12"],
        reproducible_steps="testssl.sh https://t.example",
    )
    assert poc is not None
    assert poc["reproducible_steps"] == "testssl.sh https://t.example"


def test_observation_poc_caps_lengths_and_refs():
    poc = build_observation_poc(
        description="x" * 9000,
        evidence_refs=[f"ref-{i}" for i in range(200)],
    )
    assert poc is not None
    assert len(poc["observation"]) <= 4000
    assert len(poc["evidence_refs"]) <= 64


def test_observation_poc_filters_blank_refs():
    poc = build_observation_poc(description="obs", evidence_refs=["", "  ", "real-ref", None])
    assert poc is not None
    assert poc["evidence_refs"] == ["real-ref"]


def test_passive_finding_chain_materialises_evidence():
    """A passive finding (real refs + observation, no PoC) yields one Evidence row."""
    poc = build_observation_poc(
        description="No CAA record for alleksy.com",
        evidence_refs=["dns_scan.json:4"],
    )
    assert poc is not None
    rows = build_finding_evidence_rows(
        tenant_id="t1",
        scan_id="s1",
        finding_id="F-dns",
        poc_object_key="t1/s1/poc/F-dns.json",
    )
    assert len(rows) == 1
    assert rows[0].content_type == POC_CONTENT_TYPE
