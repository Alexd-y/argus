"""Populate an :class:`~src.orchestration.graph.AssetGraph` from scan artifacts.

Bridge module (kept separate from ``graph.py`` so the graph core stays pure and
dependency-free). Converts the deduplicated active-scan
:class:`~src.recon.vulnerability_analysis.active_scan.input_surface_inventory.InputSurfaceInventory`
— the normalized set of injectable web surfaces produced during recon/VA — into
the typed runtime asset graph the planner reads for coverage and next-action
selection (overhaul §6).

Mapping:
* one ``WEB_APP`` node per host,
* one ``ENDPOINT`` node per (method, path-template),
* one ``PARAMETER`` / ``COOKIE`` / ``HEADER`` node per injectable surface,
* edges ``web_app --exposes--> endpoint`` and ``endpoint --accepts--> <input>``.

Population is idempotent (``AssetGraph.add_node`` upserts), so calling it again as
new surfaces are discovered enriches the graph rather than duplicating nodes.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse

from src.orchestration.graph import AssetGraph, AssetNodeType
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
    InputSurfaceItem,
    normalize_path_template,
)

# Injectable-surface location → asset node type. Anything not explicitly a
# cookie/header is modelled as a request PARAMETER (query/form/json/path/graphql).
_LOCATION_NODE_TYPE: dict[str, AssetNodeType] = {
    "cookie": AssetNodeType.COOKIE,
    "header": AssetNodeType.HEADER,
}


def _host_of(url: str) -> str:
    try:
        netloc = urlparse(url.strip()).netloc.lower()
    except (ValueError, AttributeError):
        netloc = ""
    return netloc or "unknown-host"


def _endpoint_id(method: str, path_template: str) -> str:
    return f"endpoint:{method.upper()} {path_template}"


def build_asset_graph_from_surfaces(
    inventory: InputSurfaceInventory | Iterable[InputSurfaceItem],
    *,
    graph: AssetGraph | None = None,
) -> AssetGraph:
    """Build (or enrich) an :class:`AssetGraph` from injectable input surfaces.

    ``inventory`` may be an :class:`InputSurfaceInventory` (deduplicated on the
    caller's behalf) or any iterable of :class:`InputSurfaceItem`. Pass an
    existing ``graph`` to accumulate across multiple discovery passes.
    """
    if isinstance(inventory, InputSurfaceInventory):
        items: Iterable[InputSurfaceItem] = inventory.deduplicated().items
    else:
        items = inventory

    g = graph if graph is not None else AssetGraph()

    for item in items:
        host = _host_of(item.url)
        path_template = normalize_path_template(item.url)
        webapp_id = f"webapp:{host}"
        endpoint_id = _endpoint_id(item.method, path_template)
        input_type = _LOCATION_NODE_TYPE.get(item.location, AssetNodeType.PARAMETER)
        input_id = f"input:{endpoint_id}#{item.location}:{item.param_name}"

        g.add_node(webapp_id, AssetNodeType.WEB_APP, host=host)
        g.add_node(
            endpoint_id,
            AssetNodeType.ENDPOINT,
            method=item.method.upper(),
            path_template=path_template,
            url=item.url,
        )
        g.add_node(
            input_id,
            input_type,
            param_name=item.param_name,
            location=item.location,
            auth_context=item.auth_context,
            surface_id=item.surface_id,
            url=item.url,
        )

        g.add_edge(webapp_id, endpoint_id, "exposes")
        g.add_edge(endpoint_id, input_id, "accepts")

    return g


_INPUT_NODE_TYPES: tuple[AssetNodeType, ...] = (
    AssetNodeType.PARAMETER,
    AssetNodeType.COOKIE,
    AssetNodeType.HEADER,
)


def apply_tested_surfaces(graph: AssetGraph, tested_surface_ids: Iterable[str]) -> int:
    """Mark input nodes whose ``surface_id`` was exercised, for coverage metrics.

    Bridges the active-scan "surfaces tested" signal (e.g. from the injection
    planner) onto the runtime :class:`AssetGraph`: every parameter / cookie /
    header node carrying a matching ``surface_id`` is flagged ``tested``. Returns
    the number of nodes newly marked. Idempotent — re-marking an already-tested
    node is a no-op. Afterwards :meth:`AssetGraph.coverage` /
    :func:`coverage_metrics` yield real %-tested figures (overhaul §6).
    """
    tested = {sid for sid in tested_surface_ids if sid}
    if not tested:
        return 0
    marked = 0
    for node_type in _INPUT_NODE_TYPES:
        for node in graph.nodes_by_type(node_type):
            if node.tested:
                continue
            if node.properties.get("surface_id") in tested:
                graph.mark_tested(node.node_id)
                marked += 1
    # Propagate: an endpoint counts as covered once ≥1 of its accepted inputs
    # was tested, so ``endpoint_coverage`` reflects real reach (overhaul §6).
    for endpoint in graph.nodes_by_type(AssetNodeType.ENDPOINT):
        if endpoint.tested:
            continue
        children = graph.get_children(endpoint.node_id, relation="accepts")
        if any(child.tested for child in children):
            graph.mark_tested(endpoint.node_id)
            marked += 1
    return marked


def coverage_metrics(graph: AssetGraph) -> dict[str, float | int]:
    """Coverage summary for planner / reporting (overhaul §6 metrics).

    Returns per-type fractions (0.0–1.0) plus node/edge counts and the count of
    still-untested input surfaces — the signals the planner uses to decide what
    to probe next and the report surfaces as coverage.
    """
    untested_inputs = sum(len(graph.untested(node_type)) for node_type in _INPUT_NODE_TYPES)
    metrics: dict[str, float | int] = {
        "parameter_coverage": graph.coverage(AssetNodeType.PARAMETER),
        "endpoint_coverage": graph.coverage(AssetNodeType.ENDPOINT),
        "node_count": graph.node_count,
        "edge_count": graph.edge_count,
        "untested_inputs": untested_inputs,
    }
    return metrics


__all__ = [
    "apply_tested_surfaces",
    "build_asset_graph_from_surfaces",
    "coverage_metrics",
]
