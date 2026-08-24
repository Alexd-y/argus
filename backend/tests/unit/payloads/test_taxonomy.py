"""Payload taxonomy mapping + profile policy + determinism (R10)."""

from __future__ import annotations

from dataclasses import dataclass

from src.payloads.taxonomy import (
    PayloadProfilePolicy,
    PayloadTaxonomyQuery,
    compute_manifest_hash,
    map_taxonomy_to_families,
)


@dataclass
class FakeFamily:
    family_id: str
    cwe_ids: list[int]
    risk_level: str = "low"
    requires_approval: bool = False
    oast_required: bool = False


FAMILIES = [
    FakeFamily("sqli_safe", [89], risk_level="low"),
    FakeFamily("sqli_error", [89], risk_level="medium"),
    FakeFamily("sqli_destructive", [89], risk_level="destructive", requires_approval=True),
    FakeFamily("xss_safe", [79], risk_level="low"),
    FakeFamily("xss_active", [79], risk_level="medium", requires_approval=True),
    FakeFamily("ssrf_oast", [918], risk_level="high", oast_required=True, requires_approval=True),
    FakeFamily("unrelated", [200], risk_level="low"),
]


def test_taxonomy_maps_by_category_not_keyword():
    q = PayloadTaxonomyQuery(vuln_category="sqli", scan_profile="deep")
    sel = map_taxonomy_to_families(q, FAMILIES)
    # Only SQLi (CWE-89) families, never the CWE-200 "unrelated".
    assert "unrelated" not in sel.family_ids
    assert set(sel.family_ids) >= {"sqli_safe", "sqli_error"}


def test_taxonomy_maps_by_explicit_cwe():
    q = PayloadTaxonomyQuery(cwe_ids=(79,), scan_profile="light")
    sel = map_taxonomy_to_families(q, FAMILIES)
    assert all(fid.startswith("xss") for fid in sel.family_ids)


def test_quick_excludes_destructive_and_high_and_approval():
    q = PayloadTaxonomyQuery(vuln_category="sqli", scan_profile="quick")
    sel = map_taxonomy_to_families(q, FAMILIES)
    assert "sqli_destructive" not in sel.family_ids  # destructive denied
    assert "sqli_safe" in sel.family_ids
    assert "sqli_error" in sel.family_ids  # medium allowed for quick
    assert sel.denied.get("sqli_destructive") in {"risk_destructive_denied", "risk_ceiling_exceeded"}


def test_light_allows_approval_gated_but_not_destructive():
    q = PayloadTaxonomyQuery(vuln_category="xss", scan_profile="light")
    sel = map_taxonomy_to_families(q, FAMILIES)
    assert "xss_active" in sel.family_ids  # medium + approval allowed for light
    assert "xss_safe" in sel.family_ids


def test_deep_allows_high_risk_oast_and_destructive():
    q = PayloadTaxonomyQuery(vuln_category="ssrf", scan_profile="deep")
    sel = map_taxonomy_to_families(q, FAMILIES)
    assert "ssrf_oast" in sel.family_ids
    q2 = PayloadTaxonomyQuery(vuln_category="sqli", scan_profile="deep")
    sel2 = map_taxonomy_to_families(q2, FAMILIES)
    assert "sqli_destructive" in sel2.family_ids


def test_quick_denies_oast_required_when_policy_disallows():
    # ssrf_oast is high-risk + approval + oast → denied for quick.
    q = PayloadTaxonomyQuery(vuln_category="ssrf", scan_profile="quick")
    sel = map_taxonomy_to_families(q, FAMILIES)
    assert "ssrf_oast" not in sel.family_ids


def test_selection_is_deduplicated_and_sorted():
    q = PayloadTaxonomyQuery(vuln_category="sqli", scan_profile="deep")
    dupes = FAMILIES + [FakeFamily("sqli_safe", [89], risk_level="low")]
    sel = map_taxonomy_to_families(q, dupes)
    assert list(sel.family_ids) == sorted(set(sel.family_ids))


def test_manifest_hash_is_stable_and_replayable():
    q = PayloadTaxonomyQuery(vuln_category="sqli", scan_profile="deep")
    a = map_taxonomy_to_families(q, FAMILIES)
    b = map_taxonomy_to_families(q, FAMILIES)
    assert a.manifest_hash == b.manifest_hash
    assert a.manifest_hash == compute_manifest_hash(q, a.family_ids)


def test_manifest_hash_changes_with_profile():
    a = map_taxonomy_to_families(PayloadTaxonomyQuery(vuln_category="sqli", scan_profile="quick"), FAMILIES)
    b = map_taxonomy_to_families(PayloadTaxonomyQuery(vuln_category="sqli", scan_profile="deep"), FAMILIES)
    assert a.manifest_hash != b.manifest_hash


def test_provenance_records_matched_cwes():
    q = PayloadTaxonomyQuery(vuln_category="sqli", scan_profile="deep")
    sel = map_taxonomy_to_families(q, FAMILIES)
    assert sel.provenance["sqli_safe"]["matched_cwes"] == [89]


def test_profile_policy_defaults_fail_closed():
    pol = PayloadProfilePolicy.for_profile("unknown")
    assert pol.max_risk_rank == 1
    assert pol.allow_destructive is False
    assert pol.allow_requires_approval is False
