"""Unit tests for building an AssetGraph from the input-surface inventory."""

from __future__ import annotations

from src.orchestration.graph import AssetGraph, AssetNodeType
from src.orchestration.graph_builders import (
    apply_tested_surfaces,
    build_asset_graph_from_surfaces,
    coverage_metrics,
)
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
    InputSurfaceItem,
)


def _surface(
    surface_id: str,
    url: str,
    param: str,
    location: str = "query",
    method: str = "GET",
) -> InputSurfaceItem:
    return InputSurfaceItem(
        surface_id=surface_id,
        url=url,
        method=method,
        param_name=param,
        location=location,  # type: ignore[arg-type]
    )


def test_builds_webapp_endpoint_parameter_hierarchy() -> None:
    inv = InputSurfaceInventory(items=[_surface("s1", "http://app.test/search?q=1", "q", "query")])
    g = build_asset_graph_from_surfaces(inv)

    assert isinstance(g, AssetGraph)
    assert len(g.nodes_by_type(AssetNodeType.WEB_APP)) == 1
    assert len(g.nodes_by_type(AssetNodeType.ENDPOINT)) == 1
    assert len(g.nodes_by_type(AssetNodeType.PARAMETER)) == 1

    endpoints = g.get_children("webapp:app.test", relation="exposes")
    assert len(endpoints) == 1
    params = g.get_children(endpoints[0].node_id, relation="accepts")
    assert len(params) == 1
    assert params[0].properties["param_name"] == "q"
    assert params[0].properties["location"] == "query"


def test_cookie_and_header_locations_get_distinct_node_types() -> None:
    inv = InputSurfaceInventory(
        items=[
            _surface("s1", "http://app.test/x", "session", "cookie"),
            _surface("s2", "http://app.test/x", "X-Api-Key", "header"),
        ]
    )
    g = build_asset_graph_from_surfaces(inv)
    assert len(g.nodes_by_type(AssetNodeType.COOKIE)) == 1
    assert len(g.nodes_by_type(AssetNodeType.HEADER)) == 1


def test_accepts_iterable_of_items() -> None:
    g = build_asset_graph_from_surfaces([_surface("s1", "http://app.test/a", "id", "query")])
    assert g.node_count == 3  # webapp + endpoint + param


def test_enriches_existing_graph_idempotently() -> None:
    inv = InputSurfaceInventory(items=[_surface("s1", "http://app.test/a?id=1", "id", "query")])
    g = build_asset_graph_from_surfaces(inv)
    before = g.node_count
    # Re-populate the SAME surfaces into the SAME graph → no duplicates.
    build_asset_graph_from_surfaces(inv, graph=g)
    assert g.node_count == before


def test_deduplicates_surfaces() -> None:
    # Two identical (method, path-template, param, location) surfaces collapse.
    inv = InputSurfaceInventory(
        items=[
            _surface("s1", "http://app.test/a?id=1", "id", "query"),
            _surface("s2", "http://app.test/a?id=2", "id", "query"),
        ]
    )
    g = build_asset_graph_from_surfaces(inv)
    assert len(g.nodes_by_type(AssetNodeType.PARAMETER)) == 1


def test_coverage_reflects_marking() -> None:
    inv = InputSurfaceInventory(
        items=[
            _surface("s1", "http://app.test/a", "p1", "query"),
            _surface("s2", "http://app.test/b", "p2", "query"),
        ]
    )
    g = build_asset_graph_from_surfaces(inv)
    assert g.coverage(AssetNodeType.PARAMETER) == 0.0
    params = g.nodes_by_type(AssetNodeType.PARAMETER)
    g.mark_tested(params[0].node_id)
    assert g.coverage(AssetNodeType.PARAMETER) == 0.5


def test_apply_tested_surfaces_marks_params_and_propagates_endpoints() -> None:
    inv = InputSurfaceInventory(
        items=[
            _surface("s1", "http://app.test/a", "p1", "query"),
            _surface("s2", "http://app.test/b", "p2", "query"),
        ]
    )
    g = build_asset_graph_from_surfaces(inv)
    marked = apply_tested_surfaces(g, ["s1"])
    # 1 parameter node + its endpoint propagated.
    assert marked == 2
    assert g.coverage(AssetNodeType.PARAMETER) == 0.5
    assert g.coverage(AssetNodeType.ENDPOINT) == 0.5


def test_apply_tested_surfaces_idempotent_and_empty() -> None:
    inv = InputSurfaceInventory(items=[_surface("s1", "http://app.test/a", "p1", "query")])
    g = build_asset_graph_from_surfaces(inv)
    assert apply_tested_surfaces(g, []) == 0
    first = apply_tested_surfaces(g, ["s1"])
    assert first >= 1
    assert apply_tested_surfaces(g, ["s1"]) == 0  # idempotent


def test_coverage_metrics_shape() -> None:
    inv = InputSurfaceInventory(
        items=[
            _surface("s1", "http://app.test/a", "p1", "query"),
            _surface("s2", "http://app.test/b", "p2", "query"),
        ]
    )
    g = build_asset_graph_from_surfaces(inv)
    apply_tested_surfaces(g, ["s1"])
    m = coverage_metrics(g)
    assert m["parameter_coverage"] == 0.5
    assert m["endpoint_coverage"] == 0.5
    assert m["untested_inputs"] == 1
    assert m["node_count"] >= 4
    assert m["edge_count"] >= 4
