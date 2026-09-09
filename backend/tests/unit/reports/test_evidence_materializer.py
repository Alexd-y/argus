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
