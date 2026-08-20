"""Unit tests for the runtime asset graph (orchestration/graph.py)."""

from __future__ import annotations

import pytest
from src.orchestration.graph import (
    AssetEdge,
    AssetGraph,
    AssetGraphError,
    AssetNode,
    AssetNodeType,
)


class TestAddNode:
    def test_add_creates_node(self) -> None:
        g = AssetGraph()
        node = g.add_node("host:10.0.0.1", AssetNodeType.HOST, ip="10.0.0.1", ports=[80, 443])
        assert isinstance(node, AssetNode)
        assert g.has_node("host:10.0.0.1")
        assert g.node_count == 1
        assert node.properties["ip"] == "10.0.0.1"
        assert node.tested is False

    def test_add_is_idempotent_and_merges_properties(self) -> None:
        g = AssetGraph()
        g.add_node("ep:1", AssetNodeType.ENDPOINT, method="GET")
        g.add_node("ep:1", AssetNodeType.ENDPOINT, path="/login")
        assert g.node_count == 1
        props = g.get_properties("ep:1")
        assert props == {"method": "GET", "path": "/login"}

    def test_add_merge_keeps_tested_sticky(self) -> None:
        g = AssetGraph()
        g.add_node("p:1", AssetNodeType.PARAMETER, tested=True)
        # A later observation without tested must not clear the flag.
        g.add_node("p:1", AssetNodeType.PARAMETER, name="id")
        assert g.get_node("p:1").tested is True

    def test_type_mismatch_raises(self) -> None:
        g = AssetGraph()
        g.add_node("x", AssetNodeType.HOST)
        with pytest.raises(AssetGraphError):
            g.add_node("x", AssetNodeType.SERVICE)

    def test_empty_id_raises(self) -> None:
        g = AssetGraph()
        with pytest.raises(AssetGraphError):
            g.add_node("", AssetNodeType.HOST)


class TestEdges:
    def test_add_edge_links_nodes(self) -> None:
        g = AssetGraph()
        g.add_node("host:1", AssetNodeType.HOST)
        g.add_node("svc:1", AssetNodeType.SERVICE)
        edge = g.add_edge("host:1", "svc:1", "runs")
        assert isinstance(edge, AssetEdge)
        assert g.edge_count == 1

    def test_add_edge_is_deduplicated(self) -> None:
        g = AssetGraph()
        g.add_node("a", AssetNodeType.HOST)
        g.add_node("b", AssetNodeType.SERVICE)
        g.add_edge("a", "b", "runs")
        g.add_edge("a", "b", "runs")
        assert g.edge_count == 1

    def test_edge_to_unknown_node_raises(self) -> None:
        g = AssetGraph()
        g.add_node("a", AssetNodeType.HOST)
        with pytest.raises(AssetGraphError):
            g.add_edge("a", "missing", "runs")
        with pytest.raises(AssetGraphError):
            g.add_edge("missing", "a", "runs")

    def test_empty_relation_raises(self) -> None:
        g = AssetGraph()
        g.add_node("a", AssetNodeType.HOST)
        g.add_node("b", AssetNodeType.SERVICE)
        with pytest.raises(AssetGraphError):
            g.add_edge("a", "b", "")


class TestQueries:
    def _graph(self) -> AssetGraph:
        g = AssetGraph()
        g.add_node("app", AssetNodeType.WEB_APP)
        g.add_node("ep1", AssetNodeType.ENDPOINT)
        g.add_node("ep2", AssetNodeType.ENDPOINT)
        g.add_node("p1", AssetNodeType.PARAMETER)
        g.add_edge("app", "ep1", "exposes")
        g.add_edge("app", "ep2", "exposes")
        g.add_edge("ep1", "p1", "accepts")
        return g

    def test_get_children_all(self) -> None:
        g = self._graph()
        children = g.get_children("app")
        assert [c.node_id for c in children] == ["ep1", "ep2"]

    def test_get_children_relation_filter(self) -> None:
        g = self._graph()
        g.add_edge("app", "p1", "accepts")
        exposes = g.get_children("app", relation="exposes")
        assert {c.node_id for c in exposes} == {"ep1", "ep2"}

    def test_get_properties_returns_copy(self) -> None:
        g = AssetGraph()
        g.add_node("n", AssetNodeType.HOST, ip="1.2.3.4")
        props = g.get_properties("n")
        props["ip"] = "mutated"
        assert g.get_properties("n")["ip"] == "1.2.3.4"

    def test_nodes_by_type(self) -> None:
        g = self._graph()
        assert {n.node_id for n in g.nodes_by_type(AssetNodeType.ENDPOINT)} == {"ep1", "ep2"}


class TestCoverage:
    def test_coverage_zero_when_none_tested(self) -> None:
        g = AssetGraph()
        g.add_node("p1", AssetNodeType.PARAMETER)
        g.add_node("p2", AssetNodeType.PARAMETER)
        assert g.coverage(AssetNodeType.PARAMETER) == 0.0

    def test_coverage_fraction(self) -> None:
        g = AssetGraph()
        g.add_node("p1", AssetNodeType.PARAMETER)
        g.add_node("p2", AssetNodeType.PARAMETER)
        g.mark_tested("p1")
        assert g.coverage(AssetNodeType.PARAMETER) == 0.5

    def test_coverage_absent_type_is_zero(self) -> None:
        g = AssetGraph()
        assert g.coverage(AssetNodeType.ENDPOINT) == 0.0

    def test_coverage_summary_only_present_types(self) -> None:
        g = AssetGraph()
        g.add_node("h", AssetNodeType.HOST)
        g.add_node("p", AssetNodeType.PARAMETER)
        g.mark_tested("p")
        summary = g.coverage_summary()
        assert summary == {"host": 0.0, "parameter": 1.0}

    def test_untested_queue(self) -> None:
        g = AssetGraph()
        g.add_node("p1", AssetNodeType.PARAMETER)
        g.add_node("p2", AssetNodeType.PARAMETER)
        g.add_node("h1", AssetNodeType.HOST)
        g.mark_tested("p1")
        assert {n.node_id for n in g.untested()} == {"p2", "h1"}
        assert {n.node_id for n in g.untested(AssetNodeType.PARAMETER)} == {"p2"}

    def test_mark_tested_unknown_raises(self) -> None:
        g = AssetGraph()
        with pytest.raises(AssetGraphError):
            g.mark_tested("nope")


class TestSerialisation:
    def test_to_dict_snapshot(self) -> None:
        g = AssetGraph()
        g.add_node("h", AssetNodeType.HOST, ip="1.1.1.1")
        g.add_node("s", AssetNodeType.SERVICE, port=443)
        g.add_edge("h", "s", "runs")
        g.mark_tested("s")
        snap = g.to_dict()
        assert [n["node_id"] for n in snap["nodes"]] == ["h", "s"]
        assert snap["edges"] == [{"source_id": "h", "target_id": "s", "relation": "runs"}]
        assert snap["coverage"] == {"host": 0.0, "service": 1.0}
