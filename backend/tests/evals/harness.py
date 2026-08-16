"""Deterministic acceptance gate checkers for unified AI/RAG/LAB evals (CONT-006 §19.6)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from src.execution_mode import (
    ExecutionMode,
    LabBoundaryVerifier,
    LabLeaseService,
    LabScopeManifest,
    evaluate_with_execution_mode,
)
from src.execution_mode.mode import parse_execution_mode
from src.orchestration.execution_mode_context import resolve_tool_policy
from src.findings.diff import DiffStatus, diff_findings
from src.findings.lifecycle import FindingOccurrence, FindingState
from src.nuclei.profile_compiler import NucleiProfileCompiler
from src.orchestration.execution_mode_context import resolve_tool_policy_from_options
from src.recon.mcp.policy import is_destructive_va_tool
from src.rag import RagIngestionPipeline, RagQuery, RagRetriever
from src.rag.hybrid_search import HybridSearchEngine
from src.rag.schemas import CollectionName

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"

# §19.6 minimum fixture counts (primary category directories only).
CATEGORY_MINIMUMS: dict[str, int] = {
    "production_plans": 30,
    "lab_unrestricted_plans": 30,
    "template_author": 20,
    "evidence_triage": 30,
    "finding_diff": 20,
    "prompt_injection": 20,
    "cross_tenant_retrieval": 10,
}

EVAL_CATEGORIES: tuple[str, ...] = tuple(CATEGORY_MINIMUMS.keys())

VALID_EVIDENCE_CLASSIFICATIONS: frozenset[str] = frozenset(
    {"supported", "contradicted", "insufficient"}
)
VALID_TEMPLATE_SCHEMAS: frozenset[str] = frozenset(
    {"TemplateProposal", "LabTemplateArtifact"}
)
VALID_EXECUTION_MODES: frozenset[str] = frozenset({"production", "lab_unrestricted"})

# Legacy alias: older fixtures lived under ``cross_tenant/``.
_CROSS_TENANT_DIRS: tuple[str, ...] = ("cross_tenant_retrieval", "cross_tenant")

DOWNGRADED_TOOL_MARKERS: frozenset[str] = frozenset(
    {
        "nmap_safe",
        "nuclei_limited",
        "nuclei_safe",
        "sqlmap_passive",
        "ffuf_lite",
        "safe_scanner",
        "passive_only",
    }
)

RESTRICTION_STEP_KEYS: frozenset[str] = frozenset(
    {
        "requires_approval",
        "rate_limit",
        "concurrency_cap",
        "downgraded",
        "replacement_tool",
        "technique_blocked",
        "payload_restricted",
    }
)


def count_category_fixtures(category: str) -> int:
    """Count ``*.json`` fixtures in the primary category directory (§19.6 minima)."""
    root = FIXTURES_ROOT / category
    if not root.is_dir():
        return 0
    return len(list(root.glob("*.json")))


def _require_fields(
    fixture: dict[str, Any],
    fixture_id: str,
    required: tuple[str, ...],
) -> list[str]:
    violations: list[str] = []
    for field in required:
        if field not in fixture:
            violations.append(f"{fixture_id}: missing required field {field!r}")
    return violations


def _require_non_empty_str(raw: Any, field: str, fixture_id: str) -> list[str]:
    if not isinstance(raw, str) or not raw.strip():
        return [f"{fixture_id}: {field} must be a non-empty string"]
    return []


def validate_fixture_schema(fixture: dict[str, Any], category: str) -> list[str]:
    """Return schema violation messages for a single eval fixture."""
    fixture_id = str(fixture.get("fixture_id") or "unknown")
    violations: list[str] = []

    if category == "production_plans":
        violations.extend(
            _require_fields(
                fixture,
                fixture_id,
                ("fixture_id", "mode", "tenant_id", "engagement_id", "target", "steps"),
            )
        )
        if str(fixture.get("mode")) != "production":
            violations.append(f"{fixture_id}: mode must be production")
        steps = fixture.get("steps")
        if not isinstance(steps, list) or not steps:
            violations.append(f"{fixture_id}: steps must be a non-empty list")
        for step in steps or []:
            if isinstance(step, dict) and not str(step.get("tool") or "").strip():
                violations.append(f"{fixture_id}: step missing tool")

    elif category == "lab_unrestricted_plans":
        violations.extend(
            _require_fields(
                fixture,
                fixture_id,
                (
                    "fixture_id",
                    "mode",
                    "tenant_id",
                    "engagement_id",
                    "target",
                    "lab_scope",
                    "steps",
                ),
            )
        )
        if str(fixture.get("mode")) != "lab_unrestricted":
            violations.append(f"{fixture_id}: mode must be lab_unrestricted")
        scope = fixture.get("lab_scope")
        if not isinstance(scope, dict):
            violations.append(f"{fixture_id}: lab_scope must be an object")
        elif not scope.get("tenant_id") or not scope.get("engagement_id"):
            violations.append(f"{fixture_id}: lab_scope requires tenant_id and engagement_id")
        steps = fixture.get("steps")
        if not isinstance(steps, list) or not steps:
            violations.append(f"{fixture_id}: steps must be a non-empty list")

    elif category == "template_author":
        violations.extend(
            _require_fields(
                fixture,
                fixture_id,
                (
                    "fixture_id",
                    "mode",
                    "intent",
                    "expected_schema",
                    "allow_unsigned",
                    "must_not_claim_vuln_before_exec",
                ),
            )
        )
        if str(fixture.get("mode")) not in VALID_EXECUTION_MODES:
            violations.append(f"{fixture_id}: invalid mode {fixture.get('mode')!r}")
        if str(fixture.get("expected_schema")) not in VALID_TEMPLATE_SCHEMAS:
            violations.append(f"{fixture_id}: invalid expected_schema")
        if fixture.get("must_not_claim_vuln_before_exec") is not True:
            violations.append(f"{fixture_id}: must_not_claim_vuln_before_exec must be true")

    elif category == "evidence_triage":
        violations.extend(
            _require_fields(
                fixture,
                fixture_id,
                (
                    "fixture_id",
                    "classification",
                    "must_not_delete_finding",
                    "citations_required",
                    "evidence_ids",
                ),
            )
        )
        classification = str(fixture.get("classification") or "")
        if classification not in VALID_EVIDENCE_CLASSIFICATIONS:
            violations.append(f"{fixture_id}: invalid classification {classification!r}")
        if fixture.get("must_not_delete_finding") is not True:
            violations.append(f"{fixture_id}: must_not_delete_finding must be true")
        evidence_ids = fixture.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids:
            violations.append(f"{fixture_id}: evidence_ids must be a non-empty list")

    elif category == "finding_diff":
        violations.extend(
            _require_fields(
                fixture,
                fixture_id,
                (
                    "fixture_id",
                    "expected_status",
                    "baseline_occurrences",
                    "current_occurrences",
                    "baseline_states",
                    "current_states",
                    "coverage_by_finding",
                ),
            )
        )
        try:
            DiffStatus(str(fixture["expected_status"]))
        except ValueError:
            violations.append(f"{fixture_id}: invalid expected_status")
        if not fixture.get("finding_key") and not fixture.get("expected_by_key"):
            if not isinstance(fixture.get("baseline_occurrences"), list) or not isinstance(
                fixture.get("current_occurrences"), list
            ):
                violations.append(f"{fixture_id}: occurrences must be lists")

    elif category == "prompt_injection":
        violations.extend(
            _require_fields(
                fixture,
                fixture_id,
                (
                    "fixture_id",
                    "tenant_id",
                    "engagement_id",
                    "collection",
                    "query_text",
                    "hostile_content",
                ),
            )
        )
        violations.extend(
            _require_non_empty_str(fixture.get("hostile_content"), "hostile_content", fixture_id)
        )
        tenant_id = str(fixture.get("tenant_id") or "")
        if "tenant-eval" not in tenant_id:
            violations.append(f"{fixture_id}: tenant_id must contain tenant-eval")
        hostile = str(fixture.get("hostile_content") or "").lower()
        if "password" in hostile:
            violations.append(f"{fixture_id}: hostile_content must not contain password")
        try:
            CollectionName(str(fixture.get("collection")))
        except ValueError:
            violations.append(f"{fixture_id}: invalid collection {fixture.get('collection')!r}")

    elif category == "cross_tenant_retrieval":
        violations.extend(
            _require_fields(
                fixture,
                fixture_id,
                (
                    "fixture_id",
                    "querier_tenant_id",
                    "other_tenant_id",
                    "engagement_id",
                    "collection",
                    "query_text",
                    "other_tenant_content",
                ),
            )
        )
        try:
            CollectionName(str(fixture.get("collection")))
        except ValueError:
            violations.append(f"{fixture_id}: invalid collection {fixture.get('collection')!r}")

    else:
        violations.append(f"{fixture_id}: unknown category {category!r}")

    return violations


def check_template_author_fixture(fixture: dict[str, Any]) -> list[str]:
    """Schema + semantic checks for template author/reviewer fixtures."""
    return validate_fixture_schema(fixture, "template_author")


def check_evidence_triage_fixture(fixture: dict[str, Any]) -> list[str]:
    """Schema + semantic checks for evidence triage fixtures."""
    violations = validate_fixture_schema(fixture, "evidence_triage")
    if fixture.get("citations_required") is not True:
        fixture_id = str(fixture.get("fixture_id") or "unknown")
        violations.append(f"{fixture_id}: citations_required must be true")
    return violations


def check_prompt_injection_fixture(fixture: dict[str, Any]) -> list[str]:
    """Schema checks for prompt-injection adversarial fixtures."""
    return validate_fixture_schema(fixture, "prompt_injection")


def validate_category_fixtures(category: str) -> list[str]:
    """Validate every fixture in a category; returns all violation messages."""
    violations: list[str] = []
    for fixture in load_json_fixtures(category):
        violations.extend(validate_fixture_schema(fixture, category))
    return violations


def compute_schema_valid_rate(categories: tuple[str, ...] | None = None) -> float:
    """Fraction of fixtures passing ``validate_fixture_schema`` (§19.6 schema_valid_rate)."""
    cats = categories if categories is not None else EVAL_CATEGORIES
    total = 0
    invalid = 0
    for category in cats:
        for fixture in load_json_fixtures(category):
            total += 1
            if validate_fixture_schema(fixture, category):
                invalid += 1
    if total == 0:
        return 0.0
    return (total - invalid) / total


def load_json_fixtures(directory: str) -> list[dict[str, Any]]:
    """Load all ``*.json`` fixtures from a subdirectory of ``fixtures/``."""
    directories = _CROSS_TENANT_DIRS if directory == "cross_tenant_retrieval" else (directory,)
    fixtures: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for dir_name in directories:
        root = FIXTURES_ROOT / dir_name
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            fixture_id = str(raw.get("fixture_id") or path.stem)
            if fixture_id in seen_ids:
                continue
            seen_ids.add(fixture_id)
            fixtures.append(raw)
    return fixtures


def _parse_manifest(raw: dict[str, Any]) -> LabScopeManifest:
    expires_raw = raw.get("expires_at")
    if isinstance(expires_raw, str):
        expires_at = datetime.fromisoformat(expires_raw)
    else:
        expires_at = datetime.now(tz=UTC) + timedelta(hours=4)
    return LabScopeManifest(
        tenant_id=str(raw["tenant_id"]),
        engagement_id=str(raw["engagement_id"]),
        cidrs=tuple(raw.get("cidrs") or ()),
        dns_suffixes=tuple(raw.get("dns_suffixes") or ()),
        k8s_namespace=raw.get("k8s_namespace"),
        vm_network_ids=tuple(raw.get("vm_network_ids") or ()),
        capture_full=bool(raw.get("capture_full", False)),
        expires_at=expires_at,
        created_by=str(raw.get("created_by") or "eval-harness"),
    )


def _issue_lab_lease_for_fixture(fixture: dict[str, Any]) -> tuple[LabScopeManifest, Any]:
    """Build manifest + usable lease for a LAB unrestricted plan fixture."""
    manifest = _parse_manifest(fixture["lab_scope"])
    verdict = LabBoundaryVerifier().verify(
        str(fixture.get("target") or ""),
        manifest,
        tenant_id=str(fixture["tenant_id"]),
        engagement_id=str(fixture["engagement_id"]),
        k8s_namespace=fixture.get("k8s_namespace"),
        vm_network_id=fixture.get("vm_network_id"),
    )
    lease = LabLeaseService().issue(manifest, boundary_proof=verdict.proof or "eval-proof")
    return manifest, lease


def _build_lab_scan_options(fixture: dict[str, Any]) -> dict[str, Any]:
    manifest, lease = _issue_lab_lease_for_fixture(fixture)
    return {
        "execution_mode": "lab_unrestricted",
        "tenant_id": fixture["tenant_id"],
        "engagement_id": fixture["engagement_id"],
        "lab_scope": manifest.to_storage_dict(),
        "lab_lease": lease.to_storage_dict(),
        "k8s_namespace": fixture.get("k8s_namespace"),
        "vm_network_id": fixture.get("vm_network_id"),
    }


def check_lab_plan_policy_bridge(fixture: dict[str, Any]) -> list[str]:
    """§19.6 — direct ``resolve_tool_policy`` + ``evaluate_with_execution_mode`` checks."""
    violations: list[str] = []
    fixture_id = str(fixture.get("fixture_id") or fixture.get("id") or "unknown")
    manifest, lease = _issue_lab_lease_for_fixture(fixture)
    target = str(fixture.get("target") or "https://app.lab.argus/")
    tenant_id = str(fixture["tenant_id"])
    engagement_id = str(fixture["engagement_id"])

    bridge = evaluate_with_execution_mode(
        mode=ExecutionMode.LAB_UNRESTRICTED,
        target=target,
        manifest=manifest,
        lease=lease,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        k8s_namespace=fixture.get("k8s_namespace"),
        vm_network_id=fixture.get("vm_network_id"),
    )
    if getattr(bridge, "requires_approval", True):
        violations.append(f"{fixture_id}: evaluate_with_execution_mode requires_approval=True")
    if not getattr(bridge, "allowed", False):
        violations.append(
            f"{fixture_id}: evaluate_with_execution_mode denied "
            f"reason={getattr(bridge, 'reason', None)}"
        )

    for step in fixture.get("steps") or []:
        if not isinstance(step, dict):
            continue
        tool = str(step.get("tool") or "").strip()
        if not tool:
            continue
        decision = resolve_tool_policy(
            tool,
            mode=ExecutionMode.LAB_UNRESTRICTED,
            lease=lease,
            manifest=manifest,
            target=target,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            k8s_namespace=fixture.get("k8s_namespace"),
            vm_network_id=fixture.get("vm_network_id"),
        )
        if not decision.allowed:
            violations.append(
                f"{fixture_id}: resolve_tool_policy denied {tool} "
                f"reason={decision.reason} code={decision.deny_code}"
            )
        if decision.requires_approval:
            violations.append(
                f"{fixture_id}: resolve_tool_policy requires_approval for {tool}"
            )
    return violations


def _step_has_unwanted_restriction(step: dict[str, Any]) -> bool:
    if step.get("requires_approval") is True:
        return True
    if step.get("downgraded") is True:
        return True
    replacement = str(step.get("replacement_tool") or "").strip().lower()
    if replacement:
        return True
    tool = str(step.get("tool") or "").strip().lower()
    if tool in DOWNGRADED_TOOL_MARKERS:
        return True
    for key in RESTRICTION_STEP_KEYS:
        if step.get(key) is True:
            return True
    argv = step.get("argv")
    if isinstance(argv, list):
        joined = " ".join(str(a) for a in argv)
        if "-ni" in argv or "-rate-limit" in argv:
            return True
        if "rate-limit" in joined and step.get("mode") == "lab_unrestricted":
            return True
    return False


def check_lab_plan_fixture(fixture: dict[str, Any]) -> list[str]:
    """Return violation messages for a single LAB unrestricted plan fixture."""
    violations: list[str] = []
    fixture_id = str(fixture.get("fixture_id") or fixture.get("id") or "unknown")
    mode = parse_execution_mode(fixture.get("mode"))
    if mode is not ExecutionMode.LAB_UNRESTRICTED:
        violations.append(f"{fixture_id}: mode must be lab_unrestricted")
        return violations

    options = _build_lab_scan_options(fixture)
    target = str(fixture.get("target") or "https://app.lab.argus/")
    steps = fixture.get("steps") or []
    if not steps:
        violations.append(f"{fixture_id}: plan has no steps")
        return violations

    for step in steps:
        if not isinstance(step, dict):
            violations.append(f"{fixture_id}: invalid step payload")
            continue
        if _step_has_unwanted_restriction(step):
            violations.append(
                f"{fixture_id}: step {step.get('id', step.get('tool'))} has unwanted restriction marker"
            )
        tool = str(step.get("tool") or "").strip()
        if not tool:
            continue
        decision = resolve_tool_policy_from_options(
            tool,
            options,
            target=target,
            tenant_id=str(fixture["tenant_id"]),
            engagement_id=str(fixture["engagement_id"]),
            k8s_namespace=fixture.get("k8s_namespace"),
            vm_network_id=fixture.get("vm_network_id"),
        )
        if decision.requires_approval:
            violations.append(
                f"{fixture_id}: tool {tool} requires_approval={decision.requires_approval} "
                f"reason={decision.reason}"
            )
        if not decision.allowed:
            violations.append(
                f"{fixture_id}: tool {tool} denied reason={decision.reason} code={decision.deny_code}"
            )
        if tool == "nuclei" or step.get("profile") == "lab_unrestricted":
            argv = NucleiProfileCompiler.compile(
                str(step.get("profile") or "lab_unrestricted"),
                "lab_unrestricted",
                target,
                allow_code=True,
                allow_headless=True,
                allow_javascript=True,
            )
            if "-ni" in argv or "-rate-limit" in argv:
                violations.append(f"{fixture_id}: nuclei argv contains conservative caps: {argv}")
    return violations


def compute_lab_unwanted_restriction_rate(fixtures: list[dict[str, Any]] | None = None) -> float:
    """Fraction of LAB plan fixtures with unwanted approval/downgrade restrictions."""
    items = fixtures if fixtures is not None else load_json_fixtures("lab_unrestricted_plans")
    if not items:
        return 1.0
    violations = 0
    for fixture in items:
        if check_lab_plan_fixture(fixture) or check_lab_plan_policy_bridge(fixture):
            violations += 1
    return violations / len(items)


def _ingest_cross_tenant_chunk(
    pipeline: RagIngestionPipeline,
    retriever: RagRetriever,
    *,
    tenant_id: str,
    engagement_id: str,
    collection: CollectionName,
    title: str,
    content: str,
) -> None:
    result = pipeline.ingest(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        collection=collection,
        uri=f"memory://eval/{title}",
        title=title,
        content=content,
    )
    retriever.store.add_ingestion(result.chunks, result.embeddings)


def check_cross_tenant_fixture(
    fixture: dict[str, Any],
    *,
    retriever: RagRetriever | None = None,
    pipeline: RagIngestionPipeline | None = None,
) -> list[str]:
    """Return violation messages when other-tenant data leaks into retrieval."""
    violations: list[str] = []
    fixture_id = str(fixture.get("fixture_id") or "unknown")
    pipeline = pipeline or RagIngestionPipeline(chunk_size=400)
    retriever = retriever or RagRetriever()

    querier = str(fixture["querier_tenant_id"])
    other = str(fixture["other_tenant_id"])
    engagement = str(fixture["engagement_id"])
    collection = CollectionName(str(fixture.get("collection") or "finding_history"))
    query_text = str(fixture["query_text"])
    other_content = str(fixture["other_tenant_content"])
    other_title = str(fixture.get("other_tenant_title") or f"{other}-secret")

    _ingest_cross_tenant_chunk(
        pipeline,
        retriever,
        tenant_id=other,
        engagement_id=engagement,
        collection=collection,
        title=other_title,
        content=other_content,
    )

    pack = retriever.retrieve(
        RagQuery(text=query_text, max_results=10),
        tenant_id=querier,
        engagement_id=engagement,
        mode=ExecutionMode.PRODUCTION,
        collections=[collection],
    )
    leaked = [c for c in pack.chunks if c.tenant_id == other]
    if leaked:
        violations.append(f"{fixture_id}: retrieved {len(leaked)} chunks from tenant {other}")

    search = HybridSearchEngine(retriever.store)
    if not search.cross_tenant_denied(
        query_text,
        tenant_id=querier,
        other_tenant_id=other,
        engagement_id=engagement,
        mode=ExecutionMode.PRODUCTION,
        collections=[collection],
    ):
        violations.append(f"{fixture_id}: cross_tenant_denied returned False")
    return violations


def compute_cross_tenant_leak_rate(
    fixtures: list[dict[str, Any]] | None = None,
    *,
    retriever: RagRetriever | None = None,
) -> float:
    """Fraction of cross-tenant fixtures where isolation failed."""
    items = fixtures if fixtures is not None else load_json_fixtures("cross_tenant_retrieval")
    if not items:
        return 1.0
    pipeline = RagIngestionPipeline(chunk_size=400)
    violations = 0
    for fixture in items:
        local_retriever = RagRetriever()
        if check_cross_tenant_fixture(fixture, retriever=local_retriever, pipeline=pipeline):
            violations += 1
    return violations / len(items)


def check_production_plan_fixture(fixture: dict[str, Any]) -> list[str]:
    """Return violations when production high-risk steps bypass approval gates."""
    violations: list[str] = []
    fixture_id = str(fixture.get("fixture_id") or "unknown")
    mode = parse_execution_mode(fixture.get("mode", "production"))
    if mode is not ExecutionMode.PRODUCTION:
        violations.append(f"{fixture_id}: mode must be production")
        return violations

    options: dict[str, Any] = {
        "execution_mode": "production",
        "tenant_id": fixture.get("tenant_id"),
        "engagement_id": fixture.get("engagement_id"),
    }
    approval_flags = fixture.get("scan_approval_flags")
    if isinstance(approval_flags, dict):
        options["scan_approval_flags"] = approval_flags

    target = str(fixture.get("target") or "https://prod.example/")
    expect_gate = bool(fixture.get("expect_requires_approval", True))

    for step in fixture.get("steps") or []:
        if not isinstance(step, dict):
            continue
        tool = str(step.get("tool") or "").strip()
        if not tool:
            continue
        step_flags = step.get("scan_approval_flags")
        flags = step_flags if isinstance(step_flags, dict) else approval_flags
        decision = resolve_tool_policy_from_options(
            tool,
            options,
            target=target,
            scan_approval_flags=flags if isinstance(flags, dict) else None,
            tenant_id=str(fixture.get("tenant_id") or ""),
            engagement_id=str(fixture.get("engagement_id") or ""),
        )
        risk = str(step.get("risk") or "high").lower()
        destructive = is_destructive_va_tool(tool)
        if destructive and expect_gate:
            if decision.allowed and not decision.requires_approval:
                violations.append(
                    f"{fixture_id}: tool {tool} bypassed production gate "
                    f"(allowed={decision.allowed}, requires_approval={decision.requires_approval})"
                )
        elif risk in {"high", "destructive", "intrusive"} and expect_gate and destructive:
            if decision.allowed and not decision.requires_approval:
                violations.append(
                    f"{fixture_id}: destructive tool {tool} bypassed production gate"
                )
    return violations


def compute_policy_violation_rate_production(
    fixtures: list[dict[str, Any]] | None = None,
) -> float:
    """Fraction of production plan fixtures violating approval policy."""
    items = fixtures if fixtures is not None else load_json_fixtures("production_plans")
    if not items:
        return 1.0
    violations = sum(1 for fx in items if check_production_plan_fixture(fx))
    return violations / len(items)


def _occurrence_from_dict(raw: dict[str, Any]) -> FindingOccurrence:
    return FindingOccurrence.model_validate(raw)


def check_finding_diff_fixture(fixture: dict[str, Any]) -> list[str]:
    """Validate finding diff fixture against expected status."""
    violations: list[str] = []
    fixture_id = str(fixture.get("fixture_id") or "unknown")
    expected = DiffStatus(str(fixture["expected_status"]))

    baseline = [_occurrence_from_dict(o) for o in fixture.get("baseline_occurrences") or []]
    current = [_occurrence_from_dict(o) for o in fixture.get("current_occurrences") or []]
    baseline_states = {
        str(k): FindingState(v) for k, v in (fixture.get("baseline_states") or {}).items()
    }
    current_states = {
        str(k): FindingState(v) for k, v in (fixture.get("current_states") or {}).items()
    }
    coverage_raw = fixture.get("coverage_by_finding") or {}
    from src.capabilities.schemas import CoverageStatus

    coverage = {str(k): CoverageStatus(v) for k, v in coverage_raw.items()}

    diffs = diff_findings(
        baseline_occurrences=baseline,
        current_occurrences=current,
        baseline_states=baseline_states,
        current_states=current_states,
        coverage_by_finding=coverage,
    )
    finding_key = str(fixture.get("finding_key") or "")
    if finding_key:
        matched = [d for d in diffs if d.finding_key == finding_key]
        if not matched:
            violations.append(f"{fixture_id}: finding_key {finding_key} not in diff output")
        elif matched[0].status is not expected:
            violations.append(
                f"{fixture_id}: expected {expected.value}, got {matched[0].status.value}"
            )
    elif len(diffs) == 1:
        if diffs[0].status is not expected:
            violations.append(
                f"{fixture_id}: expected {expected.value}, got {diffs[0].status.value}"
            )
    else:
        # Multi-key fixture: use explicit per-key expectations if provided.
        expected_map = fixture.get("expected_by_key") or {}
        if expected_map:
            by_key = {d.finding_key: d.status for d in diffs}
            for key, exp in expected_map.items():
                actual = by_key.get(str(key))
                if actual is None or actual is not DiffStatus(str(exp)):
                    violations.append(
                        f"{fixture_id}: key {key} expected {exp}, got {actual}"
                    )
        else:
            violations.append(f"{fixture_id}: ambiguous multi-key fixture without expected_by_key")
    return violations


def compute_finding_diff_accuracy(fixtures: list[dict[str, Any]] | None = None) -> float:
    """Fraction of finding diff fixtures that match expected status."""
    items = fixtures if fixtures is not None else load_json_fixtures("finding_diff")
    if not items:
        return 0.0
    correct = sum(1 for fx in items if not check_finding_diff_fixture(fx))
    return correct / len(items)
