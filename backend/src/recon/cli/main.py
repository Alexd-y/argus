"""ARGUS Recon CLI — Typer-based command line interface."""

import typer

from src.recon.cli.commands.init_engagement import init_app
from src.recon.cli.commands.status import status_app
from src.recon.cli.commands.export import export_app
from src.recon.cli.commands.report import report_app
from src.recon.cli.commands.threat_modeling import threat_modeling_app
from src.recon.cli.commands.vulnerability_analysis import vulnerability_analysis_app

app = typer.Typer(
    name="argus-recon",
    help="ARGUS Recon — reconnaissance orchestration for authorized pentesting.",
    no_args_is_help=True,
)

app.add_typer(init_app, name="init")
app.add_typer(status_app, name="status")
app.add_typer(export_app, name="export")
app.add_typer(report_app, name="report")
app.add_typer(threat_modeling_app, name="threat-modeling")
app.add_typer(vulnerability_analysis_app, name="vulnerability-analysis")


if __name__ == "__main__":
    app()
