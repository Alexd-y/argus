"""CLI command — show engagement status."""

import asyncio
import logging

import typer
from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

status_app = typer.Typer(help="Show recon engagement status.")


@status_app.command("show")
def show(
    engagement_id: str = typer.Argument(..., help="Engagement UUID"),
) -> None:
    """Show engagement progress — jobs, artifacts, findings per stage."""
    asyncio.run(_show_status(engagement_id))


async def _show_status(engagement_id: str) -> None:
    """Async implementation of status display."""
    from src.db.session import async_session_factory
    from src.db.models_recon import Engagement, ScanJob, Artifact, NormalizedFinding
    from sqlalchemy import select, func

    async with async_session_factory() as session:
        eng = await session.execute(
            select(Engagement).where(Engagement.id == engagement_id)
        )
        engagement = eng.scalar_one_or_none()
        if not engagement:
            console.print(f"[red]Engagement {engagement_id} not found[/red]")
            raise typer.Exit(code=1)

        console.print(f"\n[bold]Engagement:[/bold] {engagement.name}")
        console.print(f"[bold]Status:[/bold] {engagement.status}")
        console.print(f"[bold]Environment:[/bold] {engagement.environment}")
        console.print(f"[bold]Created:[/bold] {engagement.created_at}")

        jobs_result = await session.execute(
            select(ScanJob.stage, ScanJob.status, func.count(ScanJob.id))
            .where(ScanJob.engagement_id == engagement_id)
            .group_by(ScanJob.stage, ScanJob.status)
        )
        jobs_data = jobs_result.all()

        artifacts_result = await session.execute(
            select(func.count(Artifact.id))
            .where(Artifact.engagement_id == engagement_id)
        )
        artifact_count = artifacts_result.scalar() or 0

        findings_result = await session.execute(
            select(NormalizedFinding.finding_type, func.count(NormalizedFinding.id))
            .where(NormalizedFinding.engagement_id == engagement_id)
            .group_by(NormalizedFinding.finding_type)
        )
        findings_data = findings_result.all()

        table = Table(title="Jobs by Stage")
        table.add_column("Stage", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Count", justify="right")
        for stage, status, count in jobs_data:
            table.add_row(str(stage), status, str(count))
        console.print(table)

        console.print(f"\n[bold]Total artifacts:[/bold] {artifact_count}")

        if findings_data:
            ft = Table(title="Findings by Type")
            ft.add_column("Type", style="cyan")
            ft.add_column("Count", justify="right")
            for ftype, count in findings_data:
                ft.add_row(ftype, str(count))
            console.print(ft)
