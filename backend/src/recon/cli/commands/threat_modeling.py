"""CLI command — threat modeling run (create + execute Stage 2)."""

import asyncio
import logging
from pathlib import Path

import typer
from rich.console import Console

from src.core.config import settings
from src.db.session import async_session_factory
from src.recon.services.threat_model_run_service import (
    create_threat_model_run,
    get_engagement,
    resolve_recon_dir,
)
from src.recon.threat_modeling.pipeline import (
    ThreatModelPipelineError,
    execute_threat_modeling_run,
)

logger = logging.getLogger(__name__)
console = Console()

threat_modeling_app = typer.Typer(help="Threat modeling (Stage 2) commands.")


@threat_modeling_app.command("run")
def run_cmd(
    engagement: str = typer.Option(..., "--engagement", "-e", help="Engagement ID"),  # noqa: B008
    target: str | None = typer.Option(None, "--target", "-t", help="Optional target ID"),  # noqa: B008
    recon_dir: Path | None = typer.Option(  # noqa: B008
        None,
        "--recon-dir",
        "-r",
        help="Path to recon directory (file-based). Default: from engagement config or pentest_reports_{id}/recon/",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """Trigger Stage 2 threat modeling: create run + execute pipeline.

    Uses DB for artifact storage. If --recon-dir is provided and exists,
    loads input bundle from files; otherwise loads from DB artifacts.
    """
    async def _do_run() -> None:
        async with async_session_factory() as db:
            try:
                tenant_id = settings.default_tenant_id
                eng = await get_engagement(db, tenant_id, engagement)
                if not eng:
                    console.print(f"[red]Engagement {engagement} not found.[/red]")
                    raise typer.Exit(1)

                recon_path: Path | None = None
                if recon_dir and recon_dir.is_dir():
                    recon_path = recon_dir
                else:
                    resolved = resolve_recon_dir(engagement, eng.scope_config)
                    if resolved.exists() and resolved.is_dir():
                        recon_path = resolved

                run = await create_threat_model_run(
                    db, tenant_id, engagement, target_id=target
                )
                console.print(f"[dim]Created run {run.id} (job_id={run.job_id})[/dim]")

                result = await execute_threat_modeling_run(
                    engagement,
                    run.run_id,
                    run.job_id,
                    target_id=target,
                    recon_dir=recon_path,
                    db=db,
                    existing_run_id=run.id,
                )
                console.print("[green]Threat modeling completed.[/green]")
                console.print(f"  Status: {result.status}")
                console.print(f"  Artifacts: {len(result.artifact_refs)}")
                await db.commit()
            except ThreatModelPipelineError as e:
                console.print(f"[red]Pipeline blocked: {e}[/red]")
                if e.blocking_reason:
                    console.print(f"  Reason: {e.blocking_reason}")
                await db.rollback()
                raise typer.Exit(1) from e
            except Exception:
                await db.rollback()
                raise

    asyncio.run(_do_run())
