"""Runtime asset graph for adaptive pentest orchestration (overhaul §6).

:class:`AssetGraph` is the mutable, in-memory model of everything the scan has
discovered about the target: hosts, services, web applications, endpoints,
injectable parameters, cookies, sessions and headers. Each scan action
(recon / VA / exploitation) adds or enriches nodes and links them with typed
edges, and the planner reads the graph to decide what to probe next and to
compute coverage.

Design goals (KISS + SOLID):
* Pure in-memory, dependency-free (stdlib ``dataclasses`` only) so it is trivial
  to unit-test and cheap to snapshot for reporting / the UI.
* Idempotent ``add_node`` (upsert-merge) so repeated observations of the same
  asset accumulate properties instead of duplicating nodes.
* Deterministic ordering (insertion order preserved) so serialisation and
  coverage metrics are reproducible across runs.
* No LLM / IO coupling — the graph is a passive data structure; orchestration
  code owns the policy of when to mutate it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AssetNodeType(StrEnum):
    """Kinds of asset a scan can discover.

    Lowercase values round-trip cleanly through JSON and match the vocabulary
    used by recon / VA producers.
    """

    HOST = "host"
    SERVICE = "service"
    WEB_APP = "web_app"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    COOKIE = "cookie"
    SESSION = "session"
    HEADER = "header"


@dataclass(slots=True)
class AssetNode:
    """A single discovered asset.

    ``properties`` is an open bag of observed attributes (ip, port, protocol,
    technology, version, method, param location, …). ``tested`` marks whether a
    probe/action has already exercised this asset — the basis for coverage
    metrics and planner de-duplication.
    """

    node_id: str
    node_type: AssetNodeType
    properties: dict[str, Any] = field(default_factory=dict)
    tested: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "properties": dict(self.properties),
            "tested": self.tested,
        }


@dataclass(slots=True, frozen=True)
class AssetEdge:
    """A directed, typed relationship between two asset nodes."""

    source_id: str
    target_id: str
    relation: str

    def to_dict(self) -> dict[str, str]:
        return {"source_id": self.source_id, "target_id": self.target_id, "relation": self.relation}


class AssetGraphError(ValueError):
    """Raised on structural violations (e.g. an edge to a missing node)."""


class AssetGraph:
    """Mutable directed graph of discovered assets.

    Nodes are keyed by ``node_id`` (caller-chosen, stable identity — e.g.
    ``"host:10.0.0.1"`` / ``"endpoint:GET /login"``). Edges are deduplicated on
    ``(source, target, relation)``.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, AssetNode] = {}
        # Adjacency: source_id -> list of edges (insertion order preserved).
        self._edges: dict[str, list[AssetEdge]] = {}
        self._edge_keys: set[tuple[str, str, str]] = set()

    # -- mutation ------------------------------------------------------------

    def add_node(
        self,
        node_id: str,
        node_type: AssetNodeType,
        *,
        tested: bool | None = None,
        **properties: Any,
    ) -> AssetNode:
        """Insert or enrich a node (idempotent upsert-merge).

        A repeated call with the same ``node_id`` merges ``properties`` into the
        existing node (new keys win) rather than creating a duplicate. The
        ``node_type`` must be consistent across calls for the same id.
        """
        if not node_id:
            raise AssetGraphError("node_id must be a non-empty string")
        existing = self._nodes.get(node_id)
        if existing is None:
            node = AssetNode(
                node_id=node_id,
                node_type=node_type,
                properties=dict(properties),
                tested=bool(tested) if tested is not None else False,
            )
            self._nodes[node_id] = node
            self._edges.setdefault(node_id, [])
            return node
        if existing.node_type is not node_type:
            raise AssetGraphError(
                f"node {node_id!r} already exists as {existing.node_type.value!r}, "
                f"cannot re-add as {node_type.value!r}"
            )
        if properties:
            existing.properties.update(properties)
        if tested is not None:
            existing.tested = existing.tested or bool(tested)
        return existing

    def add_edge(self, source_id: str, target_id: str, relation: str) -> AssetEdge:
        """Link two existing nodes with a typed relation (deduplicated).

        Raises :class:`AssetGraphError` if either endpoint is unknown, so the
        graph can never contain a dangling edge.
        """
        if source_id not in self._nodes:
            raise AssetGraphError(f"unknown source node: {source_id!r}")
        if target_id not in self._nodes:
            raise AssetGraphError(f"unknown target node: {target_id!r}")
        if not relation:
            raise AssetGraphError("relation must be a non-empty string")
        key = (source_id, target_id, relation)
        edge = AssetEdge(source_id=source_id, target_id=target_id, relation=relation)
        if key not in self._edge_keys:
            self._edge_keys.add(key)
            self._edges.setdefault(source_id, []).append(edge)
        return edge

    def mark_tested(self, node_id: str, *, tested: bool = True) -> None:
        """Flag a node as exercised (drives coverage metrics)."""
        node = self._nodes.get(node_id)
        if node is None:
            raise AssetGraphError(f"unknown node: {node_id!r}")
        node.tested = tested

    # -- queries -------------------------------------------------------------

    def get_node(self, node_id: str) -> AssetNode | None:
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def get_properties(self, node_id: str) -> dict[str, Any]:
        """Return a COPY of a node's properties (empty if the node is unknown)."""
        node = self._nodes.get(node_id)
        return dict(node.properties) if node is not None else {}

    def get_children(self, node_id: str, *, relation: str | None = None) -> list[AssetNode]:
        """Return the target nodes of ``node_id``'s outgoing edges.

        When ``relation`` is given, only edges with that relation are followed.
        Order follows edge-insertion order; duplicates are removed while
        preserving first occurrence.
        """
        children: list[AssetNode] = []
        seen: set[str] = set()
        for edge in self._edges.get(node_id, []):
            if relation is not None and edge.relation != relation:
                continue
            if edge.target_id in seen:
                continue
            target = self._nodes.get(edge.target_id)
            if target is not None:
                seen.add(edge.target_id)
                children.append(target)
        return children

    def nodes_by_type(self, node_type: AssetNodeType) -> list[AssetNode]:
        return [n for n in self._nodes.values() if n.node_type is node_type]

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edge_keys)

    # -- coverage ------------------------------------------------------------

    def coverage(self, node_type: AssetNodeType) -> float:
        """Fraction (0.0–1.0) of nodes of ``node_type`` marked ``tested``.

        Returns ``0.0`` when there are no nodes of that type (nothing to test =
        no positive coverage claim).
        """
        nodes = self.nodes_by_type(node_type)
        if not nodes:
            return 0.0
        tested = sum(1 for n in nodes if n.tested)
        return tested / len(nodes)

    def coverage_summary(self) -> dict[str, float]:
        """Per-type coverage fractions for every type that has ≥1 node."""
        return {
            node_type.value: self.coverage(node_type)
            for node_type in AssetNodeType
            if self.nodes_by_type(node_type)
        }

    def untested(self, node_type: AssetNodeType | None = None) -> list[AssetNode]:
        """Nodes not yet exercised — the planner's work queue.

        Filtered to ``node_type`` when provided.
        """
        return [
            n
            for n in self._nodes.values()
            if not n.tested and (node_type is None or n.node_type is node_type)
        ]

    # -- serialisation -------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Deterministic snapshot for persistence / reporting / the UI."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for edges in self._edges.values() for e in edges],
            "coverage": self.coverage_summary(),
        }


__all__ = [
    "AssetEdge",
    "AssetGraph",
    "AssetGraphError",
    "AssetNode",
    "AssetNodeType",
]
