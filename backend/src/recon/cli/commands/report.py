"""CLI command — generate Stage 1 reports from recon directory."""

import logging
from pathlib import Path

import typer
from rich.console import Console

from src.recon.reporting.stage1_report_generator import generate_stage1_report

logger = logging.getLogger(__name__)
console = Console()

report_app = typer.Typer(help="Generate recon reports.")


@report_app.command("stage1")
def stage1(
    recon_dir: Path = typer.Argument(
        ...,
        help="Path to recon directory (e.g. .../recon/svalbard-stage1/)",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    artifacts_base: Path | None = typer.Option(
        None,
        "--artifacts-base",
        help="Base path for artifacts/stage1/{scan_id}/ layout (REC-008). When omitted, only upload from recon_dir.",
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """Generate Stage 1 reports from recon directory artifacts.

    Runs parsers on 00_scope, 01_domains, 02_subdomains, 03_dns, 04_live_hosts
    and writes: dns_summary.md, subdomain_classification.csv, live_hosts_detailed.csv,
    tech_profile.csv, headers_summary.md, tls_summary.md, endpoint_inventory.csv.
    REC-008/009: aggregates raw_tool_outputs, uploads to MinIO, optionally copies to artifacts/stage1/{scan_id}/.
    """
    generated = generate_stage1_report(recon_dir, artifacts_base=artifacts_base)
    if generated:
        console.print(f"[green]Generated {len(generated)} report(s):[/green]")
        for p in generated:
            console.print(f"  - {p}")
    else:
        console.print("[yellow]No reports generated. Ensure recon dir has 00_scope..04_live_hosts.[/yellow]")
