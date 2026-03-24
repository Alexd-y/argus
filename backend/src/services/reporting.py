"""RPT-005 — Report template context: ScanReportData + tiered AI sections (sync or Celery)."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.datetime_format import format_created_at_iso_z
from src.orchestration.prompt_registry import (
    EXPLOITATION,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_COMPLIANCE_CHECK,
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA,
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    VULN_ANALYSIS,
)
from src.reports.ai_text_generation import run_ai_text_generation
from src.reports.data_collector import ReportDataCollector, ScanReportData
from src.reports.generators import ReportData, build_report_data_from_scan_report
from src.storage.s3 import (
    OBJECT_TYPE_RAW,
    RAW_ARTIFACT_PHASES,
    get_presigned_url_by_key,
    list_scan_artifacts,
)

logger = logging.getLogger(__name__)

# HTML report (Jinja): human labels for raw artifact phase groups (RU)
_SCAN_ARTIFACT_PHASE_LABELS: dict[str, str] = {
    "recon": "Разведка",
    "threat_modeling": "Моделирование угроз",
    "vuln_analysis": "Анализ уязвимостей",
    "exploitation": "Эксплуатация",
    "post_exploitation": "Постэксплуатация",
    "legacy_raw": "Raw (устаревший путь)",
    "other": "Прочее",
}

# Matches ``{timestamp}_{artifact_type}.{ext}`` from ``build_raw_phase_object_key`` / RawPhaseSink
_RAW_TOOL_OUTPUT_NAME_RE = re.compile(
    r"^\d{8}T\d{6}_[0-9a-f]{12}_[a-z][a-z0-9_]{0,127}\.[a-zA-Z0-9]{1,16}$"
)

# Raw artifact basename: ``{ts}_{artifact_type}.{ext}`` — active VA tools use ``tool_<name>_scan_...``
_ACTIVE_WEB_SCAN_TOOL_RE = re.compile(r"_tool_([a-z0-9]+)_scan_", re.IGNORECASE)
_ACTIVE_WEB_SCAN_PHASE_KEYS: frozenset[str] = frozenset(
    {(VULN_ANALYSIS or "vuln_analysis").lower(), (EXPLOITATION or "exploitation").lower()}
)

# OWASP2-007 / RPT: AI slots that contextualize active (dynamic) testing in the report
_ACTIVE_WEB_SCAN_AI_KEYS_ORDERED: tuple[str, ...] = (
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP,
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
)

_ACTIVE_WEB_SCAN_AI_LABELS_RU: dict[str, str] = {
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION: "Описание уязвимостей (ИИ)",
    REPORT_AI_SECTION_REMEDIATION_STEP: "Шаги устранения (ИИ)",
    REPORT_AI_SECTION_BUSINESS_RISK: "Бизнес-риски (ИИ)",
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP: "Дорожная карта приоритетов (ИИ)",
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS: "Рекомендации по усилению (ИИ)",
}

# Safe, non-executable documentation string (no live XSS payload; placeholder only)
ACTIVE_WEB_SCAN_CURL_XSS_EXAMPLE = (
    "curl -sS -G 'https://TARGET.example/search' "
    "--data-urlencode 'q=REPLACE_WITH_SAFE_ENCODED_TEST_STRING'"
)

_ACTIVE_WEB_SCAN_AI_SUMMARY_MAX_LEN = 720

_SCAN_ARTIFACT_PHASE_ORDER: tuple[str, ...] = (
    "recon",
    "threat_modeling",
    "vuln_analysis",
    "exploitation",
    "post_exploitation",
    "legacy_raw",
    "other",
)


def _phase_bucket_for_artifact_key(key: str, tenant_id: str, scan_id: str) -> str:
    """Map object key to a stable grouping key for the Artifacts table (RAW-005)."""
    parts = key.split("/")
    if len(parts) < 3 or parts[0] != tenant_id or parts[1] != scan_id:
        return "other"
    rest = parts[2:]
    if not rest:
        return "other"
    if rest[0] == OBJECT_TYPE_RAW:
        return "legacy_raw"
    if len(rest) >= 2 and rest[0] in RAW_ARTIFACT_PHASES and rest[1] == OBJECT_TYPE_RAW:
        return rest[0]
    return "other"


def _phase_query_value(bucket: str) -> str:
    """Query param ``phase`` for GET /scans/{id}/artifacts; empty = list all raw-scoped keys."""
    return bucket if bucket in RAW_ARTIFACT_PHASES else ""


def _is_raw_tool_output_file_name(file_name: str) -> bool:
    """True if basename matches phase-scoped raw upload pattern (orchestrator tool stdout/stderr, etc.)."""
    if not file_name or not isinstance(file_name, str):
        return False
    return bool(_RAW_TOOL_OUTPUT_NAME_RE.fullmatch(file_name.strip()))


def _artifact_display_file_name(key: str, tenant_id: str, scan_id: str) -> str:
    """Suffix after ``.../raw/`` for listing (avoids rsplit on ``/`` inside arbitrary keys e.g. ``</script>``)."""
    prefix = f"{tenant_id}/{scan_id}/"
    if not key.startswith(prefix):
        return key.rsplit("/", 1)[-1] if "/" in key else key
    rest = key[len(prefix) :]
    raw_marker = f"/{OBJECT_TYPE_RAW}/"
    idx = rest.find(raw_marker)
    if idx >= 0:
        return rest[idx + len(raw_marker) :]
    if rest.startswith(f"{OBJECT_TYPE_RAW}/"):
        return rest[len(OBJECT_TYPE_RAW) + 1 :]
    return key.rsplit("/", 1)[-1] if "/" in key else key


def build_scan_artifacts_section_context(
    tenant_id: str,
    scan_id: str,
    *,
    attempt_listing: bool,
) -> dict[str, Any]:
    """
    Context for ``partials/artifacts.html.j2``: grouped raw artifacts, presigned URLs when available.

    File names and labels are passed through Jinja autoescape (no XSS from MinIO keys).
    """
    if not attempt_listing or not (tenant_id or "").strip() or not (scan_id or "").strip():
        return {"status": "skipped", "phase_blocks": []}

    rows = list_scan_artifacts(tenant_id, scan_id, raw_only=True)
    if rows is None:
        return {"status": "unavailable", "phase_blocks": []}

    grouped: dict[str, list[dict[str, Any]]] = {k: [] for k in _SCAN_ARTIFACT_PHASE_ORDER}
    for row in rows:
        key = row.get("key") or ""
        if not key:
            continue
        bucket = _phase_bucket_for_artifact_key(key, tenant_id, scan_id)
        if bucket not in grouped:
            grouped[bucket] = []
        file_name = _artifact_display_file_name(key, tenant_id, scan_id)
        lm = row.get("last_modified")
        grouped[bucket].append(
            {
                "file_name": file_name,
                "key": key,
                "size": int(row.get("size") or 0),
                "last_modified": format_created_at_iso_z(lm) if lm is not None else format_created_at_iso_z(None),
                "download_url": get_presigned_url_by_key(key),
            }
        )

    phase_blocks: list[dict[str, Any]] = []
    for bucket in _SCAN_ARTIFACT_PHASE_ORDER:
        items = grouped.get(bucket) or []
        if not items:
            continue
        items.sort(key=lambda x: str(x.get("key") or ""))
        tool_output_rows = [r for r in items if _is_raw_tool_output_file_name(str(r.get("file_name") or ""))]
        other_rows = [r for r in items if not _is_raw_tool_output_file_name(str(r.get("file_name") or ""))]
        phase_blocks.append(
            {
                "phase_key": bucket,
                "phase_label": _SCAN_ARTIFACT_PHASE_LABELS.get(bucket, bucket),
                "phase_query": _phase_query_value(bucket),
                "rows": items,
                "tool_output_rows": tool_output_rows,
                "other_rows": other_rows,
            }
        )

    return {"status": "ok", "phase_blocks": phase_blocks}


REPORT_TIERS: frozenset[str] = frozenset({"midgard", "asgard", "valhalla"})


def findings_rows_for_jinja(data: ScanReportData) -> list[dict[str, Any]]:
    """Serializable finding rows for RPT-008 templates (autoescaped at render)."""
    return [
        {
            "severity": f.severity or "",
            "title": f.title or "",
            "description": f.description or "",
            "cwe": f.cwe,
            "cvss": f.cvss,
        }
        for f in data.findings
    ]


def recon_summary_for_jinja(data: ScanReportData) -> dict[str, Any]:
    """Recon / scan lifecycle summary for report HTML (no raw MinIO bodies)."""
    target = ""
    if data.scan and data.scan.target_url:
        target = data.scan.target_url
    elif data.report and data.report.target:
        target = data.report.target or ""
    technologies: list[str] = []
    if data.report and data.report.technologies:
        technologies = [str(t) for t in data.report.technologies]
    summary_counts: dict[str, Any] = {}
    raw_summary = data.report.summary if data.report else None
    if isinstance(raw_summary, dict):
        for k in ("critical", "high", "medium", "low", "info"):
            if k in raw_summary:
                summary_counts[k] = raw_summary[k]
    timeline_preview: list[dict[str, Any]] = []
    for t in sorted(data.timeline, key=lambda x: (x.order_index, x.phase))[:24]:
        snippet = ""
        if t.entry is not None:
            snippet = str(t.entry)[:240]
        timeline_preview.append(
            {"phase": t.phase, "order_index": t.order_index, "snippet": snippet}
        )
    return {
        "target_url": target,
        "scan": data.scan.model_dump(mode="json") if data.scan else None,
        "summary_counts": summary_counts,
        "technologies": technologies,
        "timeline_preview": timeline_preview,
        "phase_inputs_count": len(data.phase_inputs),
        "phase_outputs_count": len(data.phase_outputs),
        "timeline_count": len(data.timeline),
        "findings_count": len(data.findings),
    }


def exploitation_outputs_for_jinja(data: ScanReportData) -> list[dict[str, Any]]:
    """Phase outputs tagged as exploitation (Valhalla section)."""
    phase_key = (EXPLOITATION or "exploitation").lower()
    out: list[dict[str, Any]] = []
    for row in data.phase_outputs:
        if (row.phase or "").lower() == phase_key:
            out.append({"phase": row.phase, "output_data": row.output_data})
    return out

_SECTIONS_MIDGARD: tuple[str, ...] = (
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
)

_SECTIONS_ASGARD: tuple[str, ...] = (
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_COMPLIANCE_CHECK,
)

_SECTIONS_VALHALLA: tuple[str, ...] = (
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_COMPLIANCE_CHECK,
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP,
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
)


def report_tier_sections(tier: str) -> tuple[str, ...]:
    """RPT-004 section keys to run for the given report tier."""
    t = (tier or "midgard").lower()
    if t == "asgard":
        return _SECTIONS_ASGARD
    if t == "valhalla":
        return _SECTIONS_VALHALLA
    return _SECTIONS_MIDGARD


def normalize_report_tier(tier: str) -> str:
    t = (tier or "midgard").lower()
    return t if t in REPORT_TIERS else "midgard"


def _truncate_report_text(text: str, max_len: int) -> str:
    t = (text or "").strip()
    if len(t) <= max_len:
        return t
    return t[: max_len - 1].rstrip() + "…"


def _collect_active_web_scan_tool_names(scan_artifacts: dict[str, Any]) -> list[str]:
    """Unique tool ids inferred from vuln_analysis / exploitation raw artifact names."""
    found: set[str] = set()
    blocks = scan_artifacts.get("phase_blocks") if isinstance(scan_artifacts, dict) else None
    if not isinstance(blocks, list):
        return []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        pk = str(block.get("phase_key") or "").lower()
        if pk not in _ACTIVE_WEB_SCAN_PHASE_KEYS:
            continue
        for row in block.get("rows") or []:
            if not isinstance(row, dict):
                continue
            fn = str(row.get("file_name") or "")
            for m in _ACTIVE_WEB_SCAN_TOOL_RE.finditer(fn):
                found.add(m.group(1).lower())
            if "va_active_scan" in fn.lower():
                found.add("va_active_scan")
    return sorted(found)


def _active_web_scan_artifact_rows_exist(scan_artifacts: dict[str, Any]) -> bool:
    blocks = scan_artifacts.get("phase_blocks") if isinstance(scan_artifacts, dict) else None
    if not isinstance(blocks, list):
        return False
    for block in blocks:
        if not isinstance(block, dict):
            continue
        pk = str(block.get("phase_key") or "").lower()
        if pk not in _ACTIVE_WEB_SCAN_PHASE_KEYS:
            continue
        rows = block.get("rows")
        if isinstance(rows, list) and len(rows) > 0:
            return True
    return False


def _active_web_scan_ai_summary_rows(
    ai_section_texts: dict[str, str],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for key in _ACTIVE_WEB_SCAN_AI_KEYS_ORDERED:
        raw = ai_section_texts.get(key)
        if not isinstance(raw, str) or not raw.strip():
            continue
        label = _ACTIVE_WEB_SCAN_AI_LABELS_RU.get(key, key)
        rows.append(
            {
                "section_key": key,
                "label": label,
                "text": _truncate_report_text(raw, _ACTIVE_WEB_SCAN_AI_SUMMARY_MAX_LEN),
            }
        )
    return rows


def build_active_web_scan_section_context(
    tier: str,
    scan_artifacts: dict[str, Any],
    ai_section_texts: dict[str, str],
) -> dict[str, Any]:
    """
    OWASP2-007 — «Активное веб-сканирование»: инструменты по артефактам, ссылка на блок артефактов, краткий ИИ-контекст.
    """
    tier_norm = normalize_report_tier(tier)
    tools_run = _collect_active_web_scan_tool_names(scan_artifacts)
    ai_rows = _active_web_scan_ai_summary_rows(ai_section_texts)
    has_artifact_signal = _active_web_scan_artifact_rows_exist(scan_artifacts)
    has_signals = bool(tools_run) or bool(ai_rows) or has_artifact_signal
    stub = {"midgard": False, "asgard": True, "valhalla": True}.get(tier_norm, False)
    visible = stub or has_signals
    return {
        "visible": visible,
        "tier": tier_norm,
        "tools_run": tools_run,
        "artifacts_section_id": "scan-artifacts",
        "ai_summary_rows": ai_rows,
        "curl_xss_example": ACTIVE_WEB_SCAN_CURL_XSS_EXAMPLE,
        "has_signals": has_signals,
    }


@dataclass
class ReportContextBuildResult:
    """Outcome of ``ReportGenerator.build_context`` (no storage side effects)."""

    scan_report_data: ScanReportData
    template_context: dict[str, Any]
    ai_section_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    celery_task_ids: dict[str, str] | None = None


class ReportGenerator:
    """
    Collects ``ScanReportData``, runs or schedules RPT-004 AI sections by tier,
    and builds a Jinja-oriented context dict. Export bytes and object storage
    upload stay outside this class.
    """

    def __init__(self, collector: ReportDataCollector | None = None) -> None:
        self._collector = collector or ReportDataCollector()

    async def collect_scan_report_data(
        self,
        session: AsyncSession,
        tenant_id: str,
        scan_id: str,
        *,
        report_id: str | None = None,
        include_minio: bool = True,
    ) -> ScanReportData:
        return await self._collector.collect_async(
            session,
            tenant_id,
            scan_id,
            report_id=report_id,
            include_minio=include_minio,
        )

    @staticmethod
    def build_ai_input_payload(data: ScanReportData) -> dict[str, Any]:
        """Compact, log-safe context for RPT-004 prompts (no artifact bodies)."""
        severity_counts: dict[str, int] = {}
        for f in data.findings:
            sev = f.severity or "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        findings_short = [
            {"severity": f.severity, "title": (f.title or "")[:240], "cwe": f.cwe}
            for f in data.findings[:80]
        ]
        payload: dict[str, Any] = {
            "scan_id": data.scan_id,
            "tenant_id": data.tenant_id,
            "finding_count": len(data.findings),
            "severity_counts": severity_counts,
            "findings": findings_short,
            "timeline_phases": [t.phase for t in data.timeline[:40]],
        }
        if data.scan is not None:
            payload["target_url"] = data.scan.target_url
            payload["scan_status"] = data.scan.status
            payload["scan_phase"] = data.scan.phase
        if data.report is not None:
            payload["report_tier"] = data.report.tier
            payload["report_target"] = data.report.target
        return payload

    def run_ai_sections_sync(
        self,
        tenant_id: str,
        scan_id: str,
        tier: str,
        data: ScanReportData,
        *,
        redis_client: Any | None = None,
        llm_callable: Callable[[str, dict], str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Invoke ``run_ai_text_generation`` for each tier section (same payload per section)."""
        tier_norm = normalize_report_tier(tier)
        payload = self.build_ai_input_payload(data)
        results: dict[str, dict[str, Any]] = {}
        for section_key in report_tier_sections(tier_norm):
            results[section_key] = run_ai_text_generation(
                tenant_id,
                scan_id,
                tier_norm,
                section_key,
                payload,
                redis_client=redis_client,
                llm_callable=llm_callable,
            )
        return results

    def schedule_ai_sections_celery(
        self,
        tenant_id: str,
        scan_id: str,
        tier: str,
        data: ScanReportData,
    ) -> dict[str, str]:
        """Enqueue ``argus.ai_text_generation`` per section; returns Celery task ids."""
        from src.tasks import ai_text_generation_task

        tier_norm = normalize_report_tier(tier)
        payload = self.build_ai_input_payload(data)
        ids: dict[str, str] = {}
        for section_key in report_tier_sections(tier_norm):
            async_result = ai_text_generation_task.delay(
                tenant_id,
                scan_id,
                tier_norm,
                section_key,
                payload,
            )
            ids[section_key] = async_result.id
        logger.info(
            "report_ai_sections_scheduled",
            extra={
                "event": "report_ai_sections_scheduled",
                "scan_id": scan_id,
                "tenant_id": tenant_id,
                "tier": tier_norm,
                "sections_n": len(ids),
            },
        )
        return ids

    @staticmethod
    def ai_results_to_text_map(ai_section_results: dict[str, dict[str, Any]]) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, res in ai_section_results.items():
            if res.get("status") == "ok" and isinstance(res.get("text"), str):
                out[key] = res["text"]
        return out

    def prepare_template_context(
        self,
        tier: str,
        data: ScanReportData,
        ai_section_texts: dict[str, str],
        *,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Pure Jinja context: scan/report snapshots, per-tier slot maps, and shared ``ai_sections``.
        RPT-008 can extend ``jinja.*.slots`` or add partials under ``tier_stubs``.
        """
        tier_norm = normalize_report_tier(tier)
        jinja_tiers: dict[str, Any] = {}
        for name in ("midgard", "asgard", "valhalla"):
            keys = report_tier_sections(name)
            jinja_tiers[name] = {
                "active": name == tier_norm,
                "slots": {k: ai_section_texts.get(k, "") for k in keys},
            }
        ctx: dict[str, Any] = {
            "tier": tier_norm,
            "tenant_id": data.tenant_id,
            "scan_id": data.scan_id,
            "scan": data.scan.model_dump(mode="json") if data.scan else None,
            "report": data.report.model_dump(mode="json") if data.report else None,
            "findings_count": len(data.findings),
            "timeline_count": len(data.timeline),
            "phase_inputs_count": len(data.phase_inputs),
            "phase_outputs_count": len(data.phase_outputs),
            "findings": findings_rows_for_jinja(data),
            "recon_summary": recon_summary_for_jinja(data),
            "exploitation": exploitation_outputs_for_jinja(data),
            "ai_sections": dict(ai_section_texts),
            "jinja": jinja_tiers,
            "tier_stubs": {
                "midgard": {"label": "Midgard", "focus": "summary", "active_web_scan": False},
                "asgard": {"label": "Asgard", "focus": "technical", "active_web_scan": True},
                "valhalla": {
                    "label": "Valhalla",
                    "focus": "leadership_technical",
                    "active_web_scan": True,
                },
            },
        }
        if extra:
            ctx.update(extra)
        if "scan_artifacts" not in ctx:
            ctx["scan_artifacts"] = {"status": "skipped", "phase_blocks": []}
        ctx["active_web_scan"] = build_active_web_scan_section_context(
            tier_norm,
            ctx["scan_artifacts"],
            ai_section_texts,
        )
        return ctx

    async def build_context(
        self,
        session: AsyncSession,
        tenant_id: str,
        scan_id: str,
        tier: str,
        *,
        report_id: str | None = None,
        include_minio: bool = True,
        sync_ai: bool = True,
        redis_client: Any | None = None,
        llm_callable: Callable[[str, dict], str] | None = None,
    ) -> ReportContextBuildResult:
        """
        Load scan graph + artifacts, then either run AI inline or schedule Celery tasks.
        Does not upload rendered artifacts (see ``src.reports.storage.upload`` at call site).
        """
        tier_norm = normalize_report_tier(tier)
        raw = await self.collect_scan_report_data(
            session,
            tenant_id,
            scan_id,
            report_id=report_id,
            include_minio=include_minio,
        )
        celery_ids: dict[str, str] | None = None
        ai_results: dict[str, dict[str, Any]] = {}
        if sync_ai:
            ai_results = self.run_ai_sections_sync(
                tenant_id,
                scan_id,
                tier_norm,
                raw,
                redis_client=redis_client,
                llm_callable=llm_callable,
            )
        else:
            celery_ids = self.schedule_ai_sections_celery(tenant_id, scan_id, tier_norm, raw)

        texts = self.ai_results_to_text_map(ai_results)
        scan_artifacts_ctx = build_scan_artifacts_section_context(
            tenant_id,
            scan_id,
            attempt_listing=include_minio,
        )
        template_context = self.prepare_template_context(
            tier_norm,
            raw,
            texts,
            extra={"scan_artifacts": scan_artifacts_ctx},
        )
        return ReportContextBuildResult(
            scan_report_data=raw,
            template_context=template_context,
            ai_section_results=ai_results,
            celery_task_ids=celery_ids,
        )

    @staticmethod
    def to_generator_report_data(
        data: ScanReportData,
        ai_section_texts: dict[str, str],
        *,
        report_id: str | None = None,
    ) -> ReportData:
        """Delegate to ``build_report_data_from_scan_report`` for HTML/JSON/PDF/CSV generators."""
        exec_key = (
            REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA
            if ai_section_texts.get(REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA)
            else REPORT_AI_SECTION_EXECUTIVE_SUMMARY
        )
        executive = (
            ai_section_texts.get(exec_key)
            or ai_section_texts.get(REPORT_AI_SECTION_EXECUTIVE_SUMMARY)
            or ai_section_texts.get(REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA)
        )
        rem = ai_section_texts.get(REPORT_AI_SECTION_REMEDIATION_STEP, "")
        remediation: list[str] = [rem] if rem else []
        insights = [t for t in ai_section_texts.values() if t]
        return build_report_data_from_scan_report(
            data,
            report_id=report_id,
            executive_summary=executive,
            remediation=remediation,
            ai_insights=insights,
        )
