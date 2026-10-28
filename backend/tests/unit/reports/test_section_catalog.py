"""Wave 4 / Stage 2 (completion) — single section-order authority across products.

The four report products no longer own scattered free-string order tuples: all four are
declared once in section_catalog and validated against one catalog. These pin that the
relocation was verbatim (no layout change), that the catalog is drift-free, and that a
single *linear* order is genuinely impossible (the documented findings↔evidence_inventory
cycle) — which is why the unification is a catalog, not one sequence.
"""

from __future__ import annotations

from src.reports import section_catalog as sc

# Frozen historical orders (what each product rendered before the relocation). The catalog
# must reproduce these byte-for-byte, or a product's layout silently changed.
_HIST_ASGARD = (
    "title_meta",
    "executive_summary_counts",
    "owasp_compliance",
    "dark_web_monitoring",
    "findings",
    "remediation",
    "reproducer",
    "timeline",
    "evidence",
    "screenshots",
)
_HIST_VALHALLA_EXEC = (
    "title_meta",
    "executive_summary",
    "executive_summary_counts",
    "risk_quantification_per_asset",
    "owasp_rollup_matrix",
    "top_findings_by_business_impact",
    "dark_web_monitoring",
    "kev_listed_findings",
    "remediation_roadmap",
    "evidence_refs",
    "timeline_entries",
)
_HIST_LEGACY = (
    "title_meta",
    "executive_summary_counts",
    "owasp_compliance",
    "robots_sitemap",
    "tech_stack",
    "outdated_components",
    "emails",
    "ssl_tls",
    "ssl_tls_table_rows",
    "headers",
    "security_headers_table_rows",
    "dependencies",
    "risk_matrix",
    "critical_vulns",
    "full_valhalla",
    "evidence_inventory",
    "tool_health_summary",
    "threat_modeling_ref",
    "findings",
    "exploit_chains_text",
    "remediation_stages_text",
    "zero_day_text",
    "conclusion_text",
    "dark_web_monitoring",
    "hibp_pwned_password_summary",
    "appendices",
)


def test_catalog_has_no_drift() -> None:
    assert sc.validate_catalog() == []


def test_product_orders_unchanged_by_relocation() -> None:
    sc.assert_order_matches("asgard", _HIST_ASGARD)
    sc.assert_order_matches("valhalla_executive", _HIST_VALHALLA_EXEC)
    sc.assert_order_matches("legacy_valhalla", _HIST_LEGACY)


def test_renderers_reexport_the_catalog_order() -> None:
    from src.reports.asgard_tier_renderer import ASGARD_SECTION_ORDER
    from src.reports.generators import _VALHALLA_REPORT_SECTION_ORDER
    from src.reports.valhalla_tier_renderer import VALHALLA_EXECUTIVE_SECTION_ORDER

    assert ASGARD_SECTION_ORDER == sc.ASGARD_SECTION_ORDER == _HIST_ASGARD
    assert VALHALLA_EXECUTIVE_SECTION_ORDER == sc.VALHALLA_EXECUTIVE_SECTION_ORDER
    assert _VALHALLA_REPORT_SECTION_ORDER == sc.LEGACY_VALHALLA_SECTION_ORDER == _HIST_LEGACY


def test_catalog_covers_every_product_section() -> None:
    for product in sc.PRODUCTS:
        for sid in sc.order_for_product(product):
            assert sid in sc.ALL_SECTION_IDS
            assert product in sc.products_for(sid)


def test_shared_section_membership() -> None:
    # "findings" is rendered by canonical, asgard and legacy; "title_meta" by the 3 tiers.
    assert {"canonical", "asgard", "legacy_valhalla"} <= sc.products_for("findings")
    assert {"asgard", "valhalla_executive", "legacy_valhalla"} <= sc.products_for("title_meta")


def test_single_linear_order_is_impossible_by_design() -> None:
    # The reason the unification is a catalog and not one sequence: canonical orders
    # findings before evidence_inventory, legacy orders them the other way → a cycle.
    canon = list(sc.CANONICAL_SECTION_ORDER)
    legacy = list(sc.LEGACY_VALHALLA_SECTION_ORDER)
    assert canon.index("findings") < canon.index("evidence_inventory")
    assert legacy.index("evidence_inventory") < legacy.index("findings")


def test_project_catalog_drops_unknown_ids() -> None:
    assert sc.project_catalog(["findings", "not_a_section", "title_meta"]) == (
        "findings",
        "title_meta",
    )
