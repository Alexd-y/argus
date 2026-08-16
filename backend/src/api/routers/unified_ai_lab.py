"""API routers for nuclei control plane, capabilities, findings retest, lab scripts."""

from __future__ import annotations

import hashlib
import logging
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.api.routers.execution_mode import lookup_usable_lease
from src.api.schemas import ScanCoverageResponse, ScanCoverageResultItem
from src.api_surface.openapi_ingest import OpenApiIngestError, ingest_openapi
from src.api_surface.schemas import ApiDocumentDTO
from src.capabilities.graph import default_capability_graph
from src.core.unified_ai_metrics import record_lab_execution
from src.execution_mode.lab_lease import LabExecutionLease
from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.findings.diff import FindingDiffService
from src.findings.lifecycle import (
    FindingAssessment,
    FindingLifecycleService,
    FindingState,
    LogicalFinding,
)
from src.findings.repository import (
    InMemoryFindingsRepository,
    get_findings_repository,
    set_findings_repository,
)
from src.findings.retest import RetestJob, RetestResultKind
from src.lab.runner import LabRunRequest, LabRunResult, get_lab_runner, reset_lab_runner
from src.nuclei.profile_compiler import load_scan_profile
from src.nuclei.schemas import (
    LabTemplateArtifact,
    NucleiTemplateManifest,
    TemplateSource,
)
from src.nuclei.template_analyzer import NucleiTemplateAnalyzer
from src.nuclei.template_registry import NucleiTemplateRegistry
from src.nuclei.update_controller import NucleiUpdateController
from src.oast.scan_traces import (
    list_scan_oast_traces,
    record_scan_oast_trace,
    reset_scan_oast_traces,
)
from src.orchestration.coverage_phase_sink import snapshot_coverage_dicts

logger = logging.getLogger(__name__)

nuclei_router = APIRouter(prefix="/nuclei", tags=["nuclei"])
lab_router = APIRouter(prefix="/lab", tags=["lab"])
findings_ext_router = APIRouter(tags=["findings-lifecycle"])
coverage_router = APIRouter(tags=["coverage"])
api_surface_router = APIRouter(prefix="/api-surface", tags=["api-surface"])
rag_trace_router = APIRouter(prefix="/rag", tags=["rag-trace"])
oast_trace_router = APIRouter(prefix="/oast", tags=["oast-trace"])

_TEMPLATE_REGISTRY = NucleiTemplateRegistry()
_UPDATE_CONTROLLER = NucleiUpdateController()
_ANALYZER = NucleiTemplateAnalyzer()
_LAB_SCRIPTS: dict[str, dict[str, Any]] = {}
_LAB_ARTIFACTS: dict[str, dict[str, Any]] = {}
_LAB_EXECS: dict[str, dict[str, Any]] = {}
_API_DOCS: dict[str, ApiDocumentDTO] = {}
_RAG_TRACES: dict[str, dict[str, Any]] = {}


class TemplateIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: StrictStr
    template_id: StrictStr | None = None
    source: StrictStr = "tenant"
    mode: StrictStr = "production"


class GenerateTemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: StrictStr
    mode: StrictStr = "lab_unrestricted"


class NucleiReleaseRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: StrictStr
    digest_sha256: StrictStr = Field(min_length=64, max_length=64)
    provenance: dict[str, Any] = Field(default_factory=dict)


class LabScriptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    language: StrictStr
    source: StrictStr
    argv: list[StrictStr] = Field(default_factory=list)
    lease_id: StrictStr


class LabArtifactExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_id: StrictStr
    argv: list[StrictStr] = Field(default_factory=list)


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: StrictStr
    observation: StrictStr = ""
    inference: StrictStr = ""
    citation_ids: list[StrictStr] = Field(default_factory=list)
    scan_id: StrictStr | None = None


class ApiSurfaceIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: StrictStr
    document: StrictStr
    mode: StrictStr = "production"
    base_url: StrictStr | None = None


class RagTraceRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: StrictStr
    query: StrictStr
    citations: list[dict[str, Any]] = Field(default_factory=list)
    collection: StrictStr = "scan_evidence"


class OastTraceRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: StrictStr
    protocol: StrictStr = "dns"
    correlation_status: StrictStr = "matched"
    token_id: StrictStr | None = None
    payload_hash: StrictStr | None = None


def _sha(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _tenant_from_header(x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id")) -> str:
    if not x_tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant_required")
    return x_tenant_id


async def _require_usable_lease(lease_id: str | None) -> LabExecutionLease:
    lease = await lookup_usable_lease(lease_id)
    if lease is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="lab_lease_required",
        )
    return lease


def _record_lab(tool: str, action: str) -> None:
    try:
        record_lab_execution(tool=tool, action=action)
    except (TypeError, ValueError, RuntimeError, OSError):
        logger.warning(
            "lab_execution_metric_failed",
            extra={"event": "lab_execution_metric_failed", "tool": tool, "action": action},
        )


@nuclei_router.get("/profiles")
def list_nuclei_profiles() -> dict[str, Any]:
    ids = [
        "fingerprint_safe",
        "vuln_default",
        "oast_confirm",
        "dast_bounded",
        "lab_unrestricted",
    ]
    return {"profiles": [load_scan_profile(i).model_dump(mode="json") for i in ids]}


@nuclei_router.get("/templates")
def list_templates() -> dict[str, Any]:
    return {
        "templates": [
            _TEMPLATE_REGISTRY.get(tid).model_dump(mode="json")
            for tid in _TEMPLATE_REGISTRY.list_template_ids()
            if _TEMPLATE_REGISTRY.get(tid) is not None
        ]
    }


@nuclei_router.post("/templates/ingest", status_code=status.HTTP_201_CREATED)
def ingest_template(body: TemplateIngestRequest) -> dict[str, Any]:
    mode = parse_execution_mode(body.mode)
    tid = body.template_id or f"tpl-{uuid4().hex[:10]}"
    digest = _sha(body.content)
    if mode is ExecutionMode.LAB_UNRESTRICTED:
        artifact = LabTemplateArtifact(
            artifact_id=str(uuid4()),
            template_id=tid,
            content_sha256=digest,
            yaml_content=body.content,
        )
        _TEMPLATE_REGISTRY.ingest_lab_artifact(artifact, mode=mode)
        manifest = _TEMPLATE_REGISTRY.get(tid)
        payload = manifest.model_dump(mode="json") if manifest else {"template_id": tid}
        payload["artifact_id"] = artifact.artifact_id
        return payload
    source = (
        TemplateSource(body.source)
        if body.source in TemplateSource._value2member_map_
        else TemplateSource.TENANT
    )
    manifest = NucleiTemplateManifest(
        template_id=tid,
        version="1",
        source=source,
        sha256=digest,
        signature="dev" if source is TemplateSource.INTERNAL else None,
        verified=source is TemplateSource.INTERNAL,
        protocols=("http",),
        capabilities=("http",),
        risk_level="info",
        requires_oast=False,
        execution_modes=("production", "lab_unrestricted"),
        provenance={"source": body.source},
    )
    _TEMPLATE_REGISTRY.register(manifest, mode=mode, skip_signature_gate=True)
    return manifest.model_dump(mode="json")


@nuclei_router.post("/templates/generate", status_code=status.HTTP_201_CREATED)
def generate_template(body: GenerateTemplateRequest) -> dict[str, Any]:
    mode = parse_execution_mode(body.mode)
    if mode is not ExecutionMode.LAB_UNRESTRICTED:
        raise HTTPException(status_code=400, detail="generate_requires_lab_unrestricted")
    tid = f"gen-{uuid4().hex[:8]}"
    content = f"id: {tid}\ninfo:\n  name: {body.intent}\n"
    artifact = LabTemplateArtifact(
        artifact_id=str(uuid4()),
        template_id=tid,
        content_sha256=_sha(content),
        yaml_content=content,
    )
    _TEMPLATE_REGISTRY.ingest_lab_artifact(artifact, mode=mode)
    manifest = _TEMPLATE_REGISTRY.get(tid)
    payload = manifest.model_dump(mode="json") if manifest else {"template_id": tid}
    payload["artifact_id"] = artifact.artifact_id
    return payload


@nuclei_router.post("/templates/{template_id}/validate")
def validate_template(
    template_id: str,
    mode: str = Query(default="production"),
) -> dict[str, Any]:
    manifest = _TEMPLATE_REGISTRY.get(template_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="template_not_found")
    analysis = _ANALYZER.analyze_manifest(manifest)
    parsed = parse_execution_mode(mode)
    allowed = (
        analysis.lab_allowed
        if parsed is ExecutionMode.LAB_UNRESTRICTED
        else analysis.production_allowed
    )
    return {
        "template_id": template_id,
        "mode": parsed.value,
        "allowed": allowed,
        "requires_approval": False if parsed is ExecutionMode.LAB_UNRESTRICTED else not allowed,
        "analysis": analysis.model_dump(mode="json"),
    }


@nuclei_router.get("/releases")
def list_nuclei_releases() -> dict[str, Any]:
    releases = _UPDATE_CONTROLLER.list_releases()
    return {
        "releases": [record.model_dump(mode="json") for record in releases],
        "active_release_id": _UPDATE_CONTROLLER.active_release_id,
    }


@nuclei_router.post("/releases", status_code=status.HTTP_201_CREATED)
def register_nuclei_release(body: NucleiReleaseRegisterRequest) -> dict[str, Any]:
    release_id = str(uuid4())
    record = _UPDATE_CONTROLLER.register_release(
        release_id,
        body.version,
        body.digest_sha256,
        provenance=body.provenance,
    )
    return record.model_dump(mode="json")


@nuclei_router.post("/releases/{release_id}/activate")
def activate_nuclei_release(release_id: str) -> dict[str, Any]:
    try:
        record = _UPDATE_CONTROLLER.activate_release(release_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="release_not_found") from exc
    return record.model_dump(mode="json")


@nuclei_router.post("/releases/{release_id}/rollback")
def rollback_nuclei_release(release_id: str) -> dict[str, Any]:
    try:
        record = _UPDATE_CONTROLLER.rollback_release(release_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="release_not_found") from exc
    return record.model_dump(mode="json")


@lab_router.post("/scripts", status_code=status.HTTP_201_CREATED)
async def create_lab_script(
    body: LabScriptRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> dict[str, Any]:
    lease = await _require_usable_lease(body.lease_id)
    script_id = str(uuid4())
    payload = {
        "script_id": script_id,
        "tenant_id": x_tenant_id or lease.tenant_id,
        "language": body.language,
        "source": body.source,
        "argv": body.argv,
        "lease_id": lease.lease_id,
        "requires_approval": False,
    }
    _LAB_SCRIPTS[script_id] = payload
    _record_lab(tool=body.language, action="lab_script_create")
    return payload


def _lab_run_to_row(
    *,
    exec_id: str,
    lease: LabExecutionLease,
    run: LabRunResult,
    script_id: str | None = None,
    artifact_id: str | None = None,
) -> dict[str, Any]:
    if run.error_code == "lab_namespace_mismatch":
        raise HTTPException(status_code=409, detail="lab_namespace_mismatch")
    row: dict[str, Any] = {
        "execution_id": exec_id,
        "lease_id": lease.lease_id,
        "status": run.status,
        "return_code": run.return_code,
        "stdout": run.stdout,
        "stderr": run.stderr,
        "runner": run.runner,
        "argv": list(run.argv),
        "error_code": run.error_code,
        "requires_approval": False,
        "capture_full": lease.capture_full,
        "execution_time_sec": run.execution_time_sec,
    }
    if script_id is not None:
        row["script_id"] = script_id
    if artifact_id is not None:
        row["artifact_id"] = artifact_id
    return row


@lab_router.post("/scripts/{script_id}/execute", status_code=status.HTTP_200_OK)
async def execute_lab_script(
    script_id: str,
    lease_id: str | None = Query(default=None),
) -> dict[str, Any]:
    script = _LAB_SCRIPTS.get(script_id)
    if not script:
        raise HTTPException(status_code=404, detail="script_not_found")
    lease = await _require_usable_lease(lease_id or str(script.get("lease_id") or ""))
    argv = script.get("argv") or []
    run = get_lab_runner().execute(
        LabRunRequest(
            language=str(script.get("language") or "python"),
            source=str(script.get("source") or ""),
            argv=tuple(str(item) for item in argv) if isinstance(argv, list) else (),
            lease_id=lease.lease_id,
            k8s_namespace=lease.k8s_namespace,
            capture_full=bool(lease.capture_full),
        )
    )
    exec_id = str(uuid4())
    row = _lab_run_to_row(exec_id=exec_id, lease=lease, run=run, script_id=script_id)
    _LAB_EXECS[exec_id] = row
    _record_lab(tool=str(script.get("language") or "script"), action="lab_script_execute")
    logger.info(
        "lab_script_execute",
        extra={
            "event": "lab_script_execute",
            "execution_id": exec_id,
            "requires_approval": False,
            "status": run.status,
            "return_code": run.return_code,
        },
    )
    return row


@lab_router.post("/artifacts/{artifact_id}/execute", status_code=status.HTTP_200_OK)
async def execute_lab_artifact(artifact_id: str, body: LabArtifactExecuteRequest) -> dict[str, Any]:
    lease = await _require_usable_lease(body.lease_id)
    stored = _LAB_ARTIFACTS.setdefault(
        artifact_id,
        {"artifact_id": artifact_id, "lease_id": lease.lease_id},
    )
    nuclei_artifact = _TEMPLATE_REGISTRY.get_artifact(artifact_id)
    yaml_content = nuclei_artifact.yaml_content if nuclei_artifact is not None else None
    language = "nuclei" if yaml_content else str(stored.get("language") or "python")
    source = str(stored.get("source") or "")
    run = get_lab_runner().execute(
        LabRunRequest(
            language=language,
            source=source,
            argv=tuple(body.argv),
            lease_id=lease.lease_id,
            k8s_namespace=lease.k8s_namespace,
            capture_full=bool(lease.capture_full),
            yaml_content=yaml_content,
        )
    )
    exec_id = str(uuid4())
    row = _lab_run_to_row(exec_id=exec_id, lease=lease, run=run, artifact_id=artifact_id)
    _LAB_EXECS[exec_id] = row
    stored["last_execution_id"] = exec_id
    _record_lab(tool="lab_artifact", action="lab_artifact_execute")
    return row


@lab_router.get("/executions/{execution_id}")
def get_lab_execution(execution_id: str) -> dict[str, Any]:
    row = _LAB_EXECS.get(execution_id)
    if not row:
        raise HTTPException(status_code=404, detail="not_found")
    return row


@findings_ext_router.post("/findings/{finding_key}/assessments")
async def add_assessment(
    finding_key: str,
    body: AssessmentRequest,
    tenant_id: str = Depends(_tenant_from_header),
) -> dict[str, Any]:
    repo = get_findings_repository()
    finding = await repo.get_logical_finding(tenant_id=tenant_id, finding_key=finding_key)
    if finding is None:
        finding = LogicalFinding(
            finding_key=finding_key,
            tenant_id=tenant_id,
            engagement_id="unknown",
        )
    assessment = FindingAssessment(
        finding_key=finding_key,
        tenant_id=tenant_id,
        classification=body.classification,
        observation=body.observation,
        inference=body.inference,
        citation_ids=tuple(body.citation_ids),
    )
    FindingLifecycleService().attach_assessment(finding, assessment)
    await repo.save_assessment(assessment)
    await repo.upsert_logical_finding(finding, scan_id=body.scan_id)
    return finding.model_dump(mode="json")


@findings_ext_router.post("/findings/{finding_key}/retest")
async def retest_finding(
    finding_key: str,
    scan_id: str | None = Query(default=None),
    outcome: str = Query(default="not_executed"),
    tenant_id: str = Depends(_tenant_from_header),
) -> dict[str, Any]:
    repo = get_findings_repository()
    finding = await repo.get_logical_finding(tenant_id=tenant_id, finding_key=finding_key)
    if not finding:
        raise HTTPException(status_code=404, detail="finding_not_found")
    service = FindingLifecycleService()
    kind = RetestResultKind.NOT_EXECUTED
    try:
        kind = RetestResultKind(outcome)
    except ValueError:
        kind = RetestResultKind.NOT_EXECUTED
    if kind is RetestResultKind.NOT_REPRODUCED:
        service.propose_resolved_candidate(finding, coverage_equivalent=True)
        service.confirm_resolved_via_retest(finding)
    elif kind is RetestResultKind.STILL_PRESENT:
        if finding.state in {FindingState.RESOLVED, FindingState.RESOLVED_CANDIDATE}:
            service.mark_regressed(finding)
    job = RetestJob(
        finding_key=finding_key,
        tenant_id=finding.tenant_id,
        engagement_id=finding.engagement_id,
        scan_id=scan_id,
        coverage_equivalent=True,
        result=kind,
    )
    await repo.upsert_logical_finding(finding, scan_id=scan_id)
    await repo.save_retest_job(job)
    return {"job": job.model_dump(mode="json"), "finding": finding.model_dump(mode="json")}


@findings_ext_router.get("/scans/{scan_id}/occurrences")
async def scan_occurrences(
    scan_id: str,
    tenant_id: str = Depends(_tenant_from_header),
) -> dict[str, Any]:
    repo = get_findings_repository()
    occurrences = await repo.list_occurrences_for_scan(tenant_id=tenant_id, scan_id=scan_id)
    ordered = sorted(occurrences, key=lambda occ: occ.first_seen_at)
    return {
        "scan_id": scan_id,
        "occurrences": [occ.model_dump(mode="json") for occ in ordered],
    }


@findings_ext_router.get("/scans/{scan_id}/diff/{baseline_id}")
async def scan_diff(
    scan_id: str,
    baseline_id: str,
    tenant_id: str = Depends(_tenant_from_header),
) -> dict[str, Any]:
    repo = get_findings_repository()
    baseline = await repo.list_logical_findings_for_scan(tenant_id=tenant_id, scan_id=baseline_id)
    current = await repo.list_logical_findings_for_scan(tenant_id=tenant_id, scan_id=scan_id)
    entries = FindingDiffService().diff(baseline=baseline, current=current)
    return {
        "scan_id": scan_id,
        "baseline_id": baseline_id,
        "entries": [e.model_dump(mode="json") for e in entries],
    }


@coverage_router.get("/assets/{asset_id}/capabilities")
def asset_capabilities(asset_id: str) -> dict[str, Any]:
    graph = default_capability_graph()
    return {
        "asset_id": asset_id,
        "capability_ids": [n.id for n in graph.nodes[:20]],
    }


@coverage_router.get("/assets/{asset_id}/endpoints")
def asset_endpoints(asset_id: str) -> dict[str, Any]:
    doc = _API_DOCS.get(asset_id)
    endpoints = [ep.model_dump(mode="json") for ep in (doc.endpoints if doc else ())]
    return {"asset_id": asset_id, "endpoints": endpoints}


@coverage_router.get("/scans/{scan_id}/coverage", response_model=ScanCoverageResponse)
def scan_coverage(scan_id: str) -> ScanCoverageResponse:
    """Canonical coverage path. ``reason_code`` is additive (QUICK-007)."""
    raw_results = snapshot_coverage_dicts(scan_id)
    results: list[ScanCoverageResultItem] = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        payload = dict(item)
        payload.setdefault("reason_code", None)
        if "template_ids" not in payload:
            payload["template_ids"] = []
        if "evidence_ids" not in payload:
            payload["evidence_ids"] = []
        results.append(ScanCoverageResultItem.model_validate(payload))
    return ScanCoverageResponse(scan_id=scan_id, requirements=[], results=results)


@api_surface_router.post("/ingest", status_code=status.HTTP_201_CREATED)
def ingest_api_surface(
    body: ApiSurfaceIngestRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> dict[str, Any]:
    tenant_id = x_tenant_id or "unknown"
    try:
        document = ingest_openapi(
            body.document,
            tenant_id=tenant_id,
            asset_id=body.asset_id,
            mode=body.mode,
            base_url=body.base_url,
        )
    except OpenApiIngestError as exc:
        raise HTTPException(status_code=400, detail="openapi_ingest_failed") from exc
    _API_DOCS[body.asset_id] = document
    return document.model_dump(mode="json")


@rag_trace_router.post("/traces", status_code=status.HTTP_201_CREATED)
def record_rag_trace(body: RagTraceRecordRequest) -> dict[str, Any]:
    row = {
        "scan_id": body.scan_id,
        "query": body.query,
        "citations": body.citations,
        "collection": body.collection,
    }
    _RAG_TRACES[body.scan_id] = row
    return row


@rag_trace_router.get("/traces/{scan_id}")
def get_rag_trace(scan_id: str) -> dict[str, Any]:
    row = _RAG_TRACES.get(scan_id)
    if row is None:
        return {"scan_id": scan_id, "query": "", "citations": [], "collection": "scan_evidence"}
    return row


@oast_trace_router.post("/traces", status_code=status.HTTP_201_CREATED)
def record_oast_trace(body: OastTraceRecordRequest) -> dict[str, Any]:
    return record_scan_oast_trace(
        scan_id=body.scan_id,
        protocol=body.protocol,
        token_id=body.token_id,
        payload_hash=body.payload_hash,
    )


@oast_trace_router.get("/traces/{scan_id}")
def get_oast_trace(scan_id: str) -> dict[str, Any]:
    return {"scan_id": scan_id, "interactions": list_scan_oast_traces(scan_id)}


def _reset_stores_for_tests() -> None:
    global _TEMPLATE_REGISTRY, _UPDATE_CONTROLLER
    set_findings_repository(InMemoryFindingsRepository())
    reset_lab_runner()
    _LAB_SCRIPTS.clear()
    _LAB_ARTIFACTS.clear()
    _LAB_EXECS.clear()
    _API_DOCS.clear()
    _RAG_TRACES.clear()
    reset_scan_oast_traces()
    _TEMPLATE_REGISTRY = NucleiTemplateRegistry()
    _UPDATE_CONTROLLER = NucleiUpdateController()
