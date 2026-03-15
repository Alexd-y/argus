"""CLI command — export engagement artifacts to local directory."""

import asyncio
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress

from src.recon.cli.commands.init_engagement import create_recon_tree

logger = logging.getLogger(__name__)
console = Console()

export_app = typer.Typer(help="Export recon engagement data.")


@export_app.command("artifacts")
def artifacts(
    engagement_id: str = typer.Argument(..., help="Engagement UUID"),
    output_dir: Path = typer.Option(
        Path("./export"), "--output-dir", "-o", help="Export directory"
    ),
) -> None:
    """Export all artifacts from MinIO to local folder structure."""
    asyncio.run(_export_artifacts(engagement_id, output_dir))


async def _export_artifacts(engagement_id: str, output_dir: Path) -> None:
    """Async implementation of artifact export."""
    from src.db.session import async_session_factory
    from src.db.models_recon import Engagement, Artifact
    from src.recon.storage import download_artifact, get_stage_name
    from sqlalchemy import select

    async with async_session_factory() as session:
        eng = await session.execute(
            select(Engagement).where(Engagement.id == engagement_id)
        )
        engagement = eng.scalar_one_or_none()
        if not engagement:
            console.print(f"[red]Engagement {engagement_id} not found[/red]")
            raise typer.Exit(code=1)

        base = output_dir / engagement.name
        recon_root = create_recon_tree(base)

        arts = await session.execute(
            select(Artifact)
            .where(Artifact.engagement_id == engagement_id)
            .order_by(Artifact.stage, Artifact.created_at)
        )
        artifact_list = list(arts.scalars().all())

        if not artifact_list:
            console.print("[yellow]No artifacts found for this engagement[/yellow]")
            return

        exported = 0
        with Progress() as progress:
            task = progress.add_task("Exporting...", total=len(artifact_list))
            for art in artifact_list:
                data = download_artifact(art.object_key)
                if data:
                    stage_name = get_stage_name(art.stage) if art.stage is not None else "misc"
                    dest_dir = recon_root / stage_name
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    dest_file = dest_dir / art.filename
                    dest_file.write_bytes(data)
                    exported += 1
                progress.advance(task)

        console.print(f"[green]Exported {exported}/{len(artifact_list)} artifacts to {recon_root}[/green]")
