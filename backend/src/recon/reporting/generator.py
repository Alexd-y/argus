"""Report generator — orchestrates all report builders and stores to MinIO."""

import logging
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_recon import (
    Artifact,
    Hypothesis,
    NormalizedFinding,
    ReconTarget,
    ScanJob,
)
from src.recon.reporting.csv_builder import (
    build_api_inventory,
    build_asset_inventory,
    build_param_inventory,
    build_service_inventory,
)
from src.recon.reporting.endpoint_builder import build_endpoint_inventory
from src.recon.reporting.headers_builder import build_headers_summary, build_tls_summary
from src.recon.reporting.js_builder import build_js_findings
from src.recon.reporting.markdown_builder import (
    build_attack_surface_map,
    build_host_groups,
    build_hypotheses_report,
    build_priorities_report,
    build_recon_summary,
)
from src.recon.services.artifact_service import create_artifact

logger = logging.getLogger(__name__)


def _extract_live_host_base_urls(findings: list[NormalizedFinding]) -> list[str]:
    """Extract unique base URLs (scheme + netloc) from URL findings with status 200."""
    seen: set[str] = set()
    result: list[str] = []
    for f in findings:
        if f.finding_type != "url":
            continue
        data = f.data or {}
        status = data.get("status_code")
        if status != 200:
            continue
        url = data.get("url", f.value)
        if not url:
            continue
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            result.append(base)
    return sorted(result)


async def generate_all_reports(
    db: AsyncSession,
    tenant_id: str,
    engagement_id: str,
    engagement_name: str,
) -> list[Artifact]:
    """Generate all recon reports and upload as derived artifacts."""
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

    targets_result = await db.execute(
        select(ReconTarget.domain).where(ReconTarget.engagement_id == engagement_id)
    )
    target_domains = [r[0] for r in targets_result.all()]

    jobs_count = (await db.execute(
        select(func.count()).select_from(
            select(ScanJob.id).where(ScanJob.engagement_id == engagement_id).subquery()
        )
    )).scalar() or 0

    artifacts_count = (await db.execute(
        select(func.count()).select_from(
            select(Artifact.id).where(Artifact.engagement_id == engagement_id).subquery()
        )
    )).scalar() or 0

    findings_by_type: dict[str, int] = {}
    for f in findings:
        findings_by_type[f.finding_type] = findings_by_type.get(f.finding_type, 0) + 1

    created_artifacts: list[Artifact] = []
    stage = 18  # REPORTING

    reports = [
        ("recon_summary.md", "text/markdown", build_recon_summary(
            engagement_name, target_domains, findings_by_type,
            jobs_count, artifacts_count, len(hypotheses),
        )),
        ("asset_inventory.csv", "text/csv", build_asset_inventory(findings)),
        ("service_inventory.csv", "text/csv", build_service_inventory(findings)),
        ("api_inventory.csv", "text/csv", build_api_inventory(findings)),
        ("param_inventory.csv", "text/csv", build_param_inventory(findings)),
        ("hypotheses.md", "text/markdown", build_hypotheses_report(hypotheses)),
        ("attack_surface.md", "text/markdown", build_attack_surface_map(findings, hypotheses)),
        ("host_groups.md", "text/markdown", build_host_groups(findings)),
        ("priorities.md", "text/markdown", build_priorities_report(hypotheses, findings_by_type)),
        ("js_findings.md", "text/markdown", build_js_findings(
            live_urls=[f.value for f in findings if f.finding_type == "url"],
            html_path=None,
        )),
    ]

    live_hosts = _extract_live_host_base_urls(findings)
    if live_hosts:
        reports.extend([
            ("headers_summary.md", "text/markdown", build_headers_summary(live_hosts)),
            ("tls_summary.md", "text/markdown", build_tls_summary(live_hosts)),
            ("endpoint_inventory.csv", "text/csv", build_endpoint_inventory(live_hosts)),
        ])

    for filename, content_type, content in reports:
        artifact = await create_artifact(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            target_id=None,
            job_id=None,
            stage=stage,
            filename=filename,
            data=content.encode("utf-8"),
            content_type=content_type,
            artifact_type="report",
        )
        if artifact:
            created_artifacts.append(artifact)

    logger.info(
        "Reports generated",
        extra={"engagement_id": engagement_id, "count": len(created_artifacts)},
    )
    return created_artifacts


def generate_stage1_report_from_dir(recon_dir: str | Path) -> list[Path]:
    """Generate Stage 1 reports from a local recon directory.

    Convenience wrapper around stage1_report_generator.generate_stage1_report.
    Use when recon artifacts exist on disk (e.g. svalbard-stage1 export).

    Args:
        recon_dir: Path to recon directory containing 00_scope, 01_domains, etc.

    Returns:
        List of generated file paths.
    """
    from src.recon.reporting.stage1_report_generator import generate_stage1_report

    return generate_stage1_report(recon_dir)
