"""Build RPT-008 Jinja context from ``ReportData`` when full ``ScanReportData`` is unavailable."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from src.core.config import settings
from src.core.llm_config import has_any_llm_key
from src.owasp_top10_2025 import OWASP_TOP10_2025_CATEGORY_TITLES
from src.orchestration.prompt_registry import (
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
)
from src.reports.ai_text_generation import (
    REPORT_AI_SKIPPED_GENERATION_FAILED,
    REPORT_AI_SKIPPED_NO_LLM,
)

if TYPE_CHECKING:
    from src.reports.generators import ReportData


def minimal_jinja_context_from_report_data(data: ReportData, tier: str) -> dict[str, Any]:
    """
    Aligns with ``ReportGenerator.prepare_template_context`` shape for HTML-only export paths
    (e.g. API regenerate) without a second DB collect pass.
    """
    from src.reports import generators as gen
    from src.reports.valhalla_report_context import ValhallaReportContext
    from src.services.reporting import (
        build_active_web_scan_section_context,
        normalize_report_tier,
        report_tier_sections,
    )

    tier_norm = normalize_report_tier(tier)
    texts: dict[str, str] = dict(_ai_text_slots_from_report_data(data, tier_norm))
    for sk in report_tier_sections(tier_norm):
        if (texts.get(sk) or "").strip():
            continue
        texts[sk] = (
            REPORT_AI_SKIPPED_NO_LLM
            if not has_any_llm_key()
            else REPORT_AI_SKIPPED_GENERATION_FAILED
        )
    jinja_tiers: dict[str, Any] = {}
    for name in ("midgard", "asgard", "valhalla"):
        keys = report_tier_sections(name)
        slots = {k: texts.get(k, "") for k in keys}
        jinja_tiers[name] = {"active": name == tier_norm, "slots": slots}

    timeline_preview: list[dict[str, Any]] = []
    for t in sorted(data.timeline, key=lambda x: (x.order_index, x.phase))[:24]:
        snippet = ""
        if t.entry is not None:
            snippet = str(t.entry)[:240]
        timeline_preview.append(
            {"phase": t.phase, "order_index": t.order_index, "snippet": snippet}
        )

    from src.orchestration.prompt_registry import EXPLOITATION

    phase_key = (EXPLOITATION or "exploitation").lower()
    exploitation: list[dict[str, Any]] = [
        {"phase": p.phase, "output_data": p.output_data}
        for p in data.phase_outputs
        if (p.phase or "").lower() == phase_key
    ]

    summary_dump = data.summary.model_dump()
    recon_summary = {
        "target_url": data.target or "",
        "scan": None,
        "summary_counts": {
            k: summary_dump.get(k)
            for k in ("critical", "high", "medium", "low", "info")
            if k in summary_dump
        },
        "technologies": list(data.technologies or []),
        "timeline_preview": timeline_preview,
        "phase_inputs_count": 0,
        "phase_outputs_count": len(data.phase_outputs),
        "timeline_count": len(data.timeline),
        "findings_count": len(data.findings),
    }

    scan_artifacts_min = _build_scan_artifacts_from_raw(data.raw_artifacts)
    active_web = build_active_web_scan_section_context(tier_norm, scan_artifacts_min, texts)

    finding_dicts = [
        gen._finding_to_dict(
            f,
            tenant_id=(data.tenant_id or None),
            scan_id=(data.scan_id or None),
        )
        for f in data.findings
    ]

    valhalla_ctx: dict[str, Any] | None = None
    if tier_norm == "valhalla":
        valhalla_ctx = ValhallaReportContext().model_dump(mode="json")

    out: dict[str, Any] = {
        "embed_poc_screenshot_inline": settings.report_poc_embed_screenshot_inline,
        "tier": tier_norm,
        "target": data.target or "",
        "tenant_id": data.tenant_id or "",
        "scan_id": data.scan_id or "",
        "scan_artifacts": scan_artifacts_min,
        "active_web_scan": active_web,
        "scan": None,
        "report": None,
        "findings_count": len(data.findings),
        "timeline_count": len(data.timeline),
        "phase_inputs_count": 0,
        "phase_outputs_count": len(data.phase_outputs),
        "findings": finding_dicts,
        "owasp_compliance_rows": gen.build_owasp_compliance_rows(finding_dicts),
        "owasp_top10_labels": OWASP_TOP10_2025_CATEGORY_TITLES,
        "recon_summary": recon_summary,
        "exploitation": exploitation,
        "ai_sections": dict(texts),
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
    if valhalla_ctx is not None:
        out["valhalla_context"] = valhalla_ctx
        out["report_executor_display_name"] = settings.report_executor_display_name
        out["tool_runs"] = []
        out["valhalla_appendix_nmap_excerpt"] = ""
        out["valhalla_appendix_phase_inputs_excerpt"] = ""
        tl_rows: list[dict[str, Any]] = []
        for t in sorted(data.timeline, key=lambda x: (x.order_index, x.phase))[:32]:
            snippet = ""
            if t.entry is not None:
                try:
                    snippet = json.dumps(t.entry, ensure_ascii=False)[:800]
                except (TypeError, ValueError):
                    snippet = str(t.entry)[:800]
            tl_rows.append({
                "phase": t.phase or "",
                "order_index": t.order_index,
                "snippet": snippet,
            })
        out["valhalla_appendix_timeline_rows"] = tl_rows
    return out


_PHASE_LABELS: dict[str, str] = {
    "recon": "Разведка",
    "threat_modeling": "Моделирование угроз",
    "vuln_analysis": "Анализ уязвимостей",
    "exploitation": "Эксплуатация",
    "post_exploitation": "Постэксплуатация",
    "unknown": "Прочее",
}

_PHASE_ORDER: tuple[str, ...] = (
    "recon",
    "threat_modeling",
    "vuln_analysis",
    "exploitation",
    "post_exploitation",
    "unknown",
)


def _build_scan_artifacts_from_raw(raw_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """Transform ``ReportData.raw_artifacts`` into ``scan_artifacts`` Jinja context.

    When no artifacts are available, returns ``{"status": "skipped", ...}``.
    """
    if not raw_artifacts:
        return {"status": "skipped", "phase_blocks": []}

    grouped: dict[str, list[dict[str, Any]]] = {}
    for art in raw_artifacts:
        phase = art.get("phase") or "unknown"
        if phase not in grouped:
            grouped[phase] = []
        file_name = art.get("artifact_type") or art.get("key", "").rsplit("/", 1)[-1]
        grouped[phase].append({
            "file_name": file_name,
            "key": art.get("key", ""),
            "size": art.get("size_bytes", 0),
            "last_modified": art.get("last_modified") or "",
            "download_url": art.get("url"),
        })

    phase_blocks: list[dict[str, Any]] = []
    for phase_key in _PHASE_ORDER:
        items = grouped.pop(phase_key, None)
        if not items:
            continue
        items.sort(key=lambda x: str(x.get("key") or ""))
        phase_blocks.append({
            "phase_key": phase_key,
            "phase_label": _PHASE_LABELS.get(phase_key, phase_key),
            "phase_query": phase_key if phase_key != "unknown" else "",
            "rows": items,
            "tool_output_rows": items,
            "other_rows": [],
        })
    for phase_key in sorted(grouped.keys()):
        items = grouped[phase_key]
        if not items:
            continue
        items.sort(key=lambda x: str(x.get("key") or ""))
        phase_blocks.append({
            "phase_key": phase_key,
            "phase_label": _PHASE_LABELS.get(phase_key, phase_key),
            "phase_query": "",
            "rows": items,
            "tool_output_rows": items,
            "other_rows": [],
        })

    return {"status": "ok", "phase_blocks": phase_blocks}


def _ai_text_slots_from_report_data(data: Any, tier_norm: str) -> dict[str, str]:
    texts: dict[str, str] = {}
    if data.executive_summary:
        if tier_norm == "valhalla":
            texts[REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA] = data.executive_summary
        texts[REPORT_AI_SECTION_EXECUTIVE_SUMMARY] = data.executive_summary
    insights = (
        data.ai_insights
        if isinstance(data.ai_insights, list)
        else ([data.ai_insights] if data.ai_insights else [])
    )
    if insights:
        texts[REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION] = "\n\n".join(
            str(x) for x in insights[:12]
        )
    rem = (
        data.remediation
        if isinstance(data.remediation, list)
        else ([data.remediation] if data.remediation else [])
    )
    if rem:
        from src.orchestration.prompt_registry import REPORT_AI_SECTION_REMEDIATION_STEP

        texts[REPORT_AI_SECTION_REMEDIATION_STEP] = "\n\n".join(str(x) for x in rem[:8])
    return texts
