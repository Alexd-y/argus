"""AI preparation bundler — creates sanitized data packages for LLM consumption."""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_recon import (
    Engagement,
    Hypothesis,
    NormalizedFinding,
    ReconTarget,
    ScanJob,
)
from src.recon.services.artifact_service import create_artifact

logger = logging.getLogger(__name__)


async def prepare_ai_bundle(
    db: AsyncSession, engagement_id: str
) -> dict[str, Any]:
    """Build a sanitized AI-consumable data bundle from recon findings.

    The bundle is structured for safe LLM consumption:
    - No raw credentials or secrets (only masked references)
    - Summarized and categorized findings
    - Structured for prompt injection
    """
    eng_result = await db.execute(
        select(Engagement).where(Engagement.id == engagement_id)
    )
    engagement = eng_result.scalar_one_or_none()
    if not engagement:
        return {"error": f"Engagement {engagement_id} not found"}

    targets_result = await db.execute(
        select(ReconTarget).where(ReconTarget.engagement_id == engagement_id)
    )
    targets = list(targets_result.scalars().all())

    findings_result = await db.execute(
        select(NormalizedFinding).where(
            NormalizedFinding.engagement_id == engagement_id
        )
    )
    findings = list(findings_result.scalars().all())

    hypotheses_result = await db.execute(
        select(Hypothesis).where(Hypothesis.engagement_id == engagement_id)
    )
    hypotheses = list(hypotheses_result.scalars().all())

    jobs_count = (await db.execute(
        select(func.count()).select_from(
            select(ScanJob.id).where(ScanJob.engagement_id == engagement_id).subquery()
        )
    )).scalar() or 0

    findings_by_type: dict[str, list[dict]] = {}

    for f in findings:
        ftype = f.finding_type
        findings_by_type.setdefault(ftype, [])
        safe_data = _sanitize_finding(f)
        findings_by_type[ftype].append(safe_data)

    bundle = {
        "metadata": {
            "engagement_name": engagement.name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": "Authorized reconnaissance data only. Do not use for unauthorized purposes.",
        },
        "engagement": {
            "name": engagement.name,
            "status": engagement.status,
            "environment": engagement.environment,
            "target_count": len(targets),
            "targets": [
                {"domain": t.domain, "type": t.target_type}
                for t in targets
            ],
        },
        "findings_summary": {
            "total": len(findings),
            "by_type": {k: len(v) for k, v in findings_by_type.items()},
            "jobs_executed": jobs_count,
        },
        "findings_detail": {
            ftype: entries[:100]
            for ftype, entries in findings_by_type.items()
        },
        "hypotheses": [
            {
                "title": h.title,
                "category": h.category,
                "priority": h.priority,
                "description": h.description or "",
                "status": h.status,
            }
            for h in hypotheses
        ],
        "attack_surface": {
            "subdomains": [
                f["value"] for f in findings_by_type.get("subdomain", [])[:200]
            ],
            "urls": [
                f["value"] for f in findings_by_type.get("url", [])[:200]
            ],
            "services": [
                f["value"] for f in findings_by_type.get("service", [])[:100]
            ],
            "technologies": list(set(
                f["value"] for f in findings_by_type.get("technology", [])
            ))[:50],
            "api_endpoints": [
                f["value"] for f in findings_by_type.get("api_endpoint", [])[:100]
            ],
        },
    }

    return bundle


def _sanitize_finding(finding: NormalizedFinding) -> dict[str, Any]:
    """Sanitize a finding for safe AI consumption — mask secrets, strip raw data."""
    data = dict(finding.data) if finding.data else {}

    if finding.finding_type == "secret_candidate":
        data["value_masked"] = data.get("value_masked", "***REDACTED***")
        data.pop("value", None)

    return {
        "value": finding.value,
        "type": finding.finding_type,
        "source": finding.source_tool,
        "confidence": finding.confidence,
        "verified": finding.is_verified,
        "data": data,
    }


def export_ai_bundle_json(bundle: dict[str, Any]) -> str:
    """Serialize bundle to JSON string for file storage."""
    return json.dumps(bundle, indent=2, default=str, ensure_ascii=False)


def export_ai_bundle_markdown(bundle: dict[str, Any]) -> str:
    """Serialize bundle to Markdown format for LLM prompt context."""
    lines = [
        "# Recon Data Bundle for AI Analysis",
        "",
        f"**Engagement:** {bundle.get('engagement', {}).get('name', 'Unknown')}",
        f"**Generated:** {bundle.get('metadata', {}).get('generated_at', '')}",
        "",
        "## Scope",
        "",
    ]

    targets = bundle.get("engagement", {}).get("targets", [])
    for t in targets:
        lines.append(f"- {t['domain']} ({t['type']})")

    summary = bundle.get("findings_summary", {})
    lines.extend([
        "",
        "## Findings Summary",
        "",
        f"Total findings: {summary.get('total', 0)}",
        "",
        "| Type | Count |",
        "|------|-------|",
    ])
    for ftype, count in sorted(summary.get("by_type", {}).items(), key=lambda x: -x[1]):
        lines.append(f"| {ftype} | {count} |")

    hypotheses = bundle.get("hypotheses", [])
    if hypotheses:
        lines.extend(["", "## Hypotheses", ""])
        for h in hypotheses:
            lines.append(f"- **[{h['priority'].upper()}]** {h['title']}: {h['description']}")

    lines.extend([
        "",
        "---",
        "",
        "*Data from authorized reconnaissance. Analyze within approved scope only.*",
    ])
    return "\n".join(lines)


async def save_ai_bundle(
    db: AsyncSession,
    tenant_id: str,
    engagement_id: str,
    bundle: dict[str, Any],
) -> None:
    """Save AI bundle as derived artifacts in both JSON and Markdown formats."""
    json_content = export_ai_bundle_json(bundle)
    await create_artifact(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        target_id=None,
        job_id=None,
        stage=18,
        filename="ai_bundle.json",
        data=json_content.encode("utf-8"),
        content_type="application/json",
        artifact_type="derived",
    )

    md_content = export_ai_bundle_markdown(bundle)
    await create_artifact(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        target_id=None,
        job_id=None,
        stage=18,
        filename="ai_bundle.md",
        data=md_content.encode("utf-8"),
        content_type="text/markdown",
        artifact_type="derived",
    )

    logger.info("AI bundle saved", extra={"engagement_id": engagement_id})
