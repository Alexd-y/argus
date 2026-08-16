"""QUICK-009 — out-of-scope = 0 network; cross-tenant = 0; untracked tool exec = 0."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from src.core import unified_ai_metrics as m
from src.execution_mode.mode import ExecutionMode
from src.pipeline.contracts.tool_job import TargetKind, TargetSpec
from src.policy.scope import ScopeEngine, ScopeKind, ScopeRule
from src.quick.disallowed import DISALLOWED_TOOL_IDS
from src.quick.metrics import admit_tracked_tool
from src.quick.planner import QuickPlanner, QuickPlannerRequest, QuickPlannerTarget
from src.quick.rag_profile import QuickRagProfile, deny_lab_research
from src.quick.schemas import (
    AssetFingerprint,
    QuickBudget,
    QuickProfileName,
    QuickScanConfig,
    SeverityFloor,
)
from src.rag.hybrid_search import HybridSearchEngine, InMemoryRagStore
from src.rag.ingestion import deterministic_embed
from src.rag.schemas import CollectionName, RagChunk, RagQuery

pytestmark = pytest.mark.no_auth_override

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_ASSET_ID = "99999999-8888-7777-6666-555555555555"
_TENANT_A = "11111111-2222-3333-4444-555555555555"
_TENANT_B = "66666666-7777-8888-9999-aaaaaaaaaaaa"
_DEADLINE = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _reset_metrics() -> None:
    m.reset_unified_ai_metrics()
    yield
    m.reset_unified_ai_metrics()


def _budget() -> QuickBudget:
    return QuickBudget(
        wall_clock_budget_seconds=900,
        discovery_budget_seconds=180,
        fingerprint_budget_seconds=120,
        verification_budget_seconds=180,
        ai_budget_seconds=90,
        report_budget_seconds=90,
        request_budget=500,
        per_host_budget=50,
        concurrency_budget=4,
        reserve_for_validation_percent=20,
    )


def _config() -> QuickScanConfig:
    return QuickScanConfig(
        profile=QuickProfileName.BALANCED,
        wall_clock_budget_seconds=900,
        ai_budget_seconds=90,
        reserve_for_validation_percent=20,
        max_targets=10,
        max_urls_per_host=50,
        crawl_depth=2,
        severity_floor=SeverityFloor.MEDIUM,
    )


def test_out_of_scope_target_zero_network_requests() -> None:
    engine = ScopeEngine([ScopeRule(kind=ScopeKind.DOMAIN, pattern="app.example")])
    out = TargetSpec(kind=TargetKind.URL, url="https://evil.example/login")
    decision = engine.check(out)
    assert decision.allowed is False

    network_calls: list[str] = []

    def fake_http(url: str) -> None:
        network_calls.append(url)

    request = QuickPlannerRequest(
        scan_id=_SCAN_ID,
        config=_config(),
        budget=_budget(),
        deadline_at=_DEADLINE,
        fingerprints=(AssetFingerprint(asset_id=_ASSET_ID),),
        targets=(
            QuickPlannerTarget(
                target_ref="https://evil.example/login",
                asset_id=_ASSET_ID,
                in_scope=False,
            ),
        ),
        scope_allowed=False,
    )
    plan = QuickPlanner().plan(request)
    assert plan.tasks == ()
    for task in plan.tasks:
        fake_http(task.target_ref)
    assert network_calls == []
    assert m.get_quick_untracked_tool_executions() == 0


def test_cross_tenant_rag_exposure_is_zero() -> None:
    store = InMemoryRagStore()
    foreign = RagChunk(
        id="11111111-2222-3333-4444-555555555555",
        tenant_id=_TENANT_B,
        engagement_id=None,
        document_id="22222222-3333-4444-5555-666666666666",
        source_id="33333333-4444-5555-6666-777777777777",
        collection=CollectionName.FINDING_HISTORY,
        chunk_index=0,
        content="secret finding from other tenant",
        content_hash="a" * 64,
    )
    store.add(foreign, deterministic_embed(foreign.content), foreign.content)
    engine = HybridSearchEngine(store)
    assert engine.cross_tenant_denied(
        "secret finding",
        tenant_id=_TENANT_A,
        other_tenant_id=_TENANT_B,
        mode=ExecutionMode.QUICK,
        collections=(CollectionName.FINDING_HISTORY,),
    ) is True
    hits = engine.search(
        "secret finding",
        tenant_id=_TENANT_A,
        engagement_id=None,
        mode=ExecutionMode.QUICK,
        collections=(CollectionName.FINDING_HISTORY,),
    )
    assert hits == []
    assert CollectionName.LAB_RESEARCH not in deny_lab_research(None)


def test_untracked_tool_execution_is_zero() -> None:
    catalog = {"nuclei", "httpx"}
    planned = {"nuclei"}
    executed: list[str] = []

    def run_tool(tool_id: str) -> None:
        if not admit_tracked_tool(tool_id, catalog_ids=catalog, planned_ids=planned):
            return
        executed.append(tool_id)

    run_tool("nuclei")
    run_tool("sqlmap")
    run_tool("hydra")
    run_tool("unknown-bin")
    assert executed == ["nuclei"]
    assert m.get_quick_untracked_tool_executions() == 3
    for banned in DISALLOWED_TOOL_IDS:
        assert admit_tracked_tool(banned, catalog_ids=catalog | {banned}) is False


def test_quick_rag_profile_does_not_return_foreign_tenant() -> None:
    class _StubRetriever:
        def retrieve(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("vector_unavailable")

    profile = QuickRagProfile(retriever=_StubRetriever())  # type: ignore[arg-type]
    pack = profile._retrieve_with_fallback(
        RagQuery(
            text="nginx",
            collections=deny_lab_research(None),
            max_results=4,
        ),
        tenant_id=_TENANT_A,
        engagement_id=None,
        metadata_prefilter=None,
    )
    assert pack.tenant_id == _TENANT_A
    assert pack.chunks == ()
    assert pack.metadata.get("rag_unavailable") is True
    assert all(chunk.tenant_id != _TENANT_B for chunk in pack.chunks)
