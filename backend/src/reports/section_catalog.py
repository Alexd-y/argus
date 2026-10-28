"""Single section-order authority across all four report products (Wave 4 / Stage 2).

ARGUS renders four distinct report *products*, each historically owning its own free-string
section-order tuple:

* **canonical** — the ``ReportDocumentV1`` renderers (JSON/MD/XML/HTML), ordered by
  :data:`src.reports.section_registry.SECTION_ORDER`;
* **asgard** — the Asgard executive PDF;
* **valhalla_executive** — the Valhalla executive PDF;
* **legacy_valhalla** — the legacy Valhalla HTML/PDF generator.

The stage-2 goal was "one canonical order, the others expressed as filters over it". A single
*linear* order is provably impossible: ``canonical`` renders ``findings`` before
``evidence_inventory`` while ``legacy_valhalla`` renders ``evidence_inventory`` before
``findings`` — a direct cycle, so no one sequence reproduces both products' layouts. What *is*
unifiable, and what this module provides, is a single **catalog** that owns every section id and
which products render it, with each product's order declared here (one home, no more scattered
free-string tuples) and validated against the catalog by :func:`validate_catalog` (drift test):
every ordered id is a known catalog id, and every catalog id is used by at least one product.

Changing a product's order here changes that product's layout — treat each tuple as the contract
it is (CHANGELOG + snapshot regeneration), exactly as before; the tuples are unchanged by this
refactor, only relocated and cross-checked.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from src.reports.section_registry import section_ids as _canonical_section_ids

#: The four report products whose section orders this module unifies.
PRODUCTS: tuple[str, ...] = ("canonical", "asgard", "valhalla_executive", "legacy_valhalla")


# --- The canonical ReportDocumentV1 order lives in section_registry (it carries presence
#     predicates); mirror its id sequence here as this product's order.
CANONICAL_SECTION_ORDER: tuple[str, ...] = tuple(_canonical_section_ids())

# --- Asgard executive PDF. API contract: adding a section needs a CHANGELOG entry + snapshot
#     regeneration. (Moved verbatim from asgard_tier_renderer.)
ASGARD_SECTION_ORDER: tuple[str, ...] = (
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

# --- Valhalla executive PDF. (Moved verbatim from valhalla_tier_renderer.)
VALHALLA_EXECUTIVE_SECTION_ORDER: tuple[str, ...] = (
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

# --- Legacy Valhalla HTML/PDF generator. (Moved verbatim from generators.)
LEGACY_VALHALLA_SECTION_ORDER: tuple[str, ...] = (
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


_PRODUCT_ORDERS: dict[str, tuple[str, ...]] = {
    "canonical": CANONICAL_SECTION_ORDER,
    "asgard": ASGARD_SECTION_ORDER,
    "valhalla_executive": VALHALLA_EXECUTIVE_SECTION_ORDER,
    "legacy_valhalla": LEGACY_VALHALLA_SECTION_ORDER,
}


@dataclass(frozen=True)
class CatalogSection:
    """A section id and the set of products that render it."""

    section_id: str
    products: frozenset[str]


def _build_catalog() -> dict[str, CatalogSection]:
    members: dict[str, set[str]] = {}
    for product, order in _PRODUCT_ORDERS.items():
        for sid in order:
            members.setdefault(sid, set()).add(product)
    return {sid: CatalogSection(sid, frozenset(ps)) for sid, ps in members.items()}


#: The single catalog: every section id across all products → the products that render it.
SECTION_CATALOG: dict[str, CatalogSection] = _build_catalog()

#: Every known section id (the identity authority the product orders are validated against).
ALL_SECTION_IDS: frozenset[str] = frozenset(SECTION_CATALOG)


def order_for_product(product: str) -> tuple[str, ...]:
    """Return the ordered section ids for ``product`` (one of :data:`PRODUCTS`)."""
    if product not in _PRODUCT_ORDERS:
        raise KeyError(f"unknown report product: {product!r}")
    return _PRODUCT_ORDERS[product]


def products_for(section_id: str) -> frozenset[str]:
    """Which products render ``section_id`` (empty frozenset when unknown)."""
    entry = SECTION_CATALOG.get(section_id)
    return entry.products if entry else frozenset()


def project_catalog(section_ids: Iterable[str]) -> tuple[str, ...]:
    """Filter ``section_ids`` to those in the catalog, preserving the input order.

    The achievable "filter over the registry": a caller that wants only catalog-known
    sections from an arbitrary sequence gets them back in their own order, with unknown
    ids dropped (and surfaced by :func:`validate_catalog`, not silently).
    """
    return tuple(s for s in section_ids if s in ALL_SECTION_IDS)


def validate_catalog() -> list[str]:
    """Return catalog/order drift problems (empty == consistent).

    * Every id in every product order must be a catalog id (it is, by construction — this
      guards against a future order referencing an id the catalog builder skipped).
    * Every catalog id must be used by at least one product (no dead entries).
    * Each product order must have no duplicate ids.
    """
    problems: list[str] = []
    for product, order in _PRODUCT_ORDERS.items():
        if len(order) != len(set(order)):
            dupes = sorted({s for s in order if order.count(s) > 1})
            problems.append(f"{product}: duplicate section id(s) {dupes}")
        for sid in order:
            if sid not in ALL_SECTION_IDS:
                problems.append(f"{product}: unknown section id {sid!r}")
    for sid, entry in SECTION_CATALOG.items():
        if not entry.products:
            problems.append(f"catalog id {sid!r} is used by no product (dead entry)")
    return problems


def assert_order_matches(product: str, expected: Sequence[str]) -> None:
    """Raise if ``product``'s catalog order diverges from ``expected`` (layout contract)."""
    actual = order_for_product(product)
    if tuple(actual) != tuple(expected):
        raise AssertionError(
            f"{product} section order drifted from its contract:\n"
            f"  catalog : {list(actual)}\n  expected: {list(expected)}"
        )


__all__ = [
    "ALL_SECTION_IDS",
    "ASGARD_SECTION_ORDER",
    "CANONICAL_SECTION_ORDER",
    "LEGACY_VALHALLA_SECTION_ORDER",
    "PRODUCTS",
    "SECTION_CATALOG",
    "VALHALLA_EXECUTIVE_SECTION_ORDER",
    "CatalogSection",
    "assert_order_matches",
    "order_for_product",
    "products_for",
    "project_catalog",
    "validate_catalog",
]
