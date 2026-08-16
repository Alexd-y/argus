"""QUICK-003 — capability graph Quick eligibility: CVE/TLS in, destructive/post-ex out."""

from __future__ import annotations

from src.capabilities.graph import default_capability_graph
from src.capabilities.schemas import (
    CapabilityFamily,
    CapabilityNode,
    ProductionRisk,
)
from src.quick.disallowed import node_excluded_from_quick

_WEB_CVE = "web.application.cve.known_product"
_WEB_TLS = "web.application.tls.posture"
_POST_EX_IDS = (
    "privilege_escalation.linux.scheduled_tasks",
    "privilege_escalation.linux.sudo_misconfig",
    "privilege_escalation.windows.dll_hijack",
    "privilege_escalation.windows.unquoted_service",
    "network.attack_paths.lateral.smb_relay",
)
_RE_IDS = (
    "reverse_engineering.static.binary_analysis",
    "reverse_engineering.dynamic.debugging",
)


def test_web_cve_and_tls_are_quick_eligible() -> None:
    graph = default_capability_graph()
    eligible_ids = {node.id for node in graph.quick_eligible_nodes()}
    assert _WEB_CVE in eligible_ids
    assert _WEB_TLS in eligible_ids
    cve = graph.get_node(_WEB_CVE)
    tls = graph.get_node(_WEB_TLS)
    assert cve is not None and tls is not None
    assert cve.quick_eligible is True
    assert tls.quick_eligible is True
    assert "quick" in cve.execution_modes
    assert "quick" in tls.execution_modes
    assert node_excluded_from_quick(cve) is False
    assert node_excluded_from_quick(tls) is False


def test_post_exploitation_nodes_are_not_quick_eligible() -> None:
    graph = default_capability_graph()
    eligible_ids = {node.id for node in graph.quick_eligible_nodes()}
    for node_id in _POST_EX_IDS:
        node = graph.get_node(node_id)
        assert node is not None, node_id
        assert node.quick_eligible is False
        assert node_id not in eligible_ids
        assert node_excluded_from_quick(node) is True
        phases = frozenset(node.allowed_phases)
        assert phases & {"exploitation", "post_exploitation"}


def test_destructive_nodes_are_not_quick_eligible() -> None:
    graph = default_capability_graph()
    for node in graph.nodes:
        if node.production_risk is ProductionRisk.DESTRUCTIVE:
            assert node.quick_eligible is False
            assert node_excluded_from_quick(node) is True
    destructive = CapabilityNode(
        id="web.destructive.drop_table",
        family=CapabilityFamily.WEB_APPLICATION,
        production_risk=ProductionRisk.DESTRUCTIVE,
        allowed_phases=("vuln_analysis",),
        tools=("nuclei",),
        quick_eligible=True,
    )
    assert node_excluded_from_quick(destructive) is True


def test_post_ex_only_node_excluded_even_if_flagged_eligible() -> None:
    node = CapabilityNode(
        id="linux.postex.persist",
        family=CapabilityFamily.PRIVILEGE_ESCALATION_LINUX,
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=("post_exploitation",),
        tools=("linpeas",),
        quick_eligible=True,
    )
    assert node_excluded_from_quick(node) is True


def test_reverse_engineering_and_training_not_quick_eligible() -> None:
    graph = default_capability_graph()
    eligible_ids = {node.id for node in graph.quick_eligible_nodes()}
    for node_id in _RE_IDS:
        node = graph.get_node(node_id)
        assert node is not None
        assert node.quick_eligible is False
        assert node_id not in eligible_ids
        assert node_excluded_from_quick(node) is True
    for node in graph.training_nodes():
        assert node.quick_eligible is False
        assert node_excluded_from_quick(node) is True


def test_quick_eligible_nodes_are_sorted_by_id() -> None:
    nodes = default_capability_graph().quick_eligible_nodes()
    ids = tuple(node.id for node in nodes)
    assert ids == tuple(sorted(ids))
    assert _WEB_CVE in ids
    assert _WEB_TLS in ids
