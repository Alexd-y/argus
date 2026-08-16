"""Capability graph drives phase nodes, collections, and ordered plan steps."""

from __future__ import annotations

from src.capabilities.graph import default_capability_graph
from src.eval.rates import reset_eval_rates, snapshot_eval_rates
from src.rag.schemas import ALL_COLLECTIONS, CollectionName


def test_collection_name_has_thirteen_members() -> None:
    assert len(CollectionName) == 13
    assert len(ALL_COLLECTIONS) == 13


def test_nodes_for_phase_filters_mode_and_assets() -> None:
    graph = default_capability_graph()
    web = graph.nodes_for_phase(
        "vuln_analysis",
        "production",
        asset_types=("web_app",),
    )
    assert web
    assert all("web_app" in node.asset_types or "api" in node.asset_types for node in web)
    training = graph.nodes_for_phase("vuln_analysis", "production")
    assert all(not node.training_only for node in training)
    lab_training = graph.nodes_for_phase("vuln_analysis", "lab_unrestricted")
    assert any(node.training_only for node in lab_training)


def test_plan_steps_put_prerequisites_first() -> None:
    reset_eval_rates()
    graph = default_capability_graph()
    steps = graph.plan_steps("vuln_analysis", "production", asset_types=("web_app", "api"))
    ids = [step.node_id for step in steps]
    if (
        "web.application.api.rest" in ids
        and "web.application.forms.input_validation" in ids
    ):
        assert ids.index("web.application.api.rest") < ids.index(
            "web.application.forms.input_validation"
        )
    completed = graph.plan_steps(
        "vuln_analysis",
        "production",
        asset_types=("web_app", "api"),
        completed_node_ids=(ids[0],) if ids else (),
    )
    if completed:
        assert completed[0].completed is True
        rates = snapshot_eval_rates()
        assert rates.plan_steps_total >= 1
        assert 0.0 <= rates.plan_completion_rate <= 1.0


def test_graph_collections_include_catalog_anchors() -> None:
    graph = default_capability_graph()
    production = graph.collections_for_phase("planner", "production")
    assert "argus_product" in production
    assert "episodic_validated" in production
    assert "capability_graph" in production
    assert set(production).issubset({item.value for item in ALL_COLLECTIONS})
