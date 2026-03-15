"""CLI command — initialize engagement folder structure."""

import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.tree import Tree

logger = logging.getLogger(__name__)
console = Console()

init_app = typer.Typer(help="Initialize a new recon engagement workspace.")

RECON_FOLDER_STRUCTURE: dict[str, list[str]] = {
    "00_scope": ["scope.txt", "roe.txt", "targets.txt", "contacts.txt"],
    "01_domains": ["whois.txt", "rdap.txt", "dns_records.txt", "ns.txt", "mx.txt", "txt.txt", "caa.txt"],
    "02_subdomains": ["subdomains_raw.txt", "subdomains_all.txt", "subdomains_clean.txt"],
    "03_dns": ["resolved.txt", "unresolved.txt", "cname_map.csv"],
    "04_live_hosts": ["live_hosts.txt", "http_probe.csv"],
    "05_clustering": ["host_groups.md"],
    "06_fingerprint": ["tech_profile.csv"],
    "07_endpoints": ["interesting_endpoints.txt"],
    "08_crawl": ["urls_raw.txt", "urls_dedup.txt", "params_candidates.txt"],
    "09_params": ["param_inventory.csv"],
    "10_js": ["js_findings.md", "api_candidates.txt", "secrets_candidates.txt"],
    "11_api": ["api_inventory.csv", "graphql_notes.md", "swagger_refs.txt", "cors_notes.md"],
    "12_ports": ["service_inventory.csv", "unusual_services.txt"],
    "13_tls": ["tls_scan.txt", "headers_summary.md", "cookie_notes.md"],
    "14_content": ["content_discovery.txt", "interesting_paths_high.txt"],
    "15_osint": [
        "github_findings.md", "repo_findings.md", "doc_metadata.md",
        "employees_public_refs.md", "third_party_refs.md",
    ],
    "16_hypothesis": ["hypotheses.md"],
    "17_attack_map": ["attack_surface.md"],
    "18_reporting": [
        "recon_summary.md", "asset_inventory.csv", "service_inventory_final.csv",
        "findings_for_next_phase.md", "priorities.md",
    ],
}

SUBDIRS: dict[str, list[str]] = {
    "06_fingerprint": ["headers", "screenshots"],
    "12_ports": ["nmap", "naabu"],
    "13_tls": ["certs"],
    "14_content": ["ffuf", "ferox"],
    "10_js": ["raw"],
}


def create_recon_tree(base_dir: Path, scope_file: Path | None = None) -> Path:
    """Create the full recon folder structure under base_dir/recon/."""
    recon_root = base_dir / "recon"
    recon_root.mkdir(parents=True, exist_ok=True)

    for folder_name, files in RECON_FOLDER_STRUCTURE.items():
        folder_path = recon_root / folder_name
        folder_path.mkdir(parents=True, exist_ok=True)

        for fname in files:
            fpath = folder_path / fname
            if not fpath.exists():
                fpath.touch()

    for folder_name, subdirs in SUBDIRS.items():
        for subdir in subdirs:
            (recon_root / folder_name / subdir).mkdir(parents=True, exist_ok=True)

    if scope_file and scope_file.exists():
        dest = recon_root / "00_scope" / "scope.txt"
        dest.write_text(scope_file.read_text(encoding="utf-8"), encoding="utf-8")
        logger.info("Scope file copied", extra={"src": str(scope_file), "dst": str(dest)})

    return recon_root


def display_tree(recon_root: Path) -> None:
    """Display the created folder tree using Rich."""
    tree = Tree(f"[bold green]{recon_root.name}/[/bold green]")
    for folder in sorted(recon_root.iterdir()):
        if folder.is_dir():
            branch = tree.add(f"[bold blue]{folder.name}/[/bold blue]")
            for item in sorted(folder.iterdir()):
                if item.is_dir():
                    sub_branch = branch.add(f"[blue]{item.name}/[/blue]")
                    for sub_item in sorted(item.iterdir()):
                        sub_branch.add(f"[dim]{sub_item.name}[/dim]")
                else:
                    branch.add(f"[dim]{item.name}[/dim]")
    console.print(tree)


@init_app.command("create")
def create(
    name: str = typer.Argument(..., help="Engagement name (used as folder name)"),
    output_dir: Path = typer.Option(
        Path("./output"), "--output-dir", "-o", help="Base output directory"
    ),
    scope_file: Path | None = typer.Option(
        None, "--scope-file", "-s", help="Path to scope.txt to copy into workspace"
    ),
) -> None:
    """Create a new recon engagement workspace with full folder structure."""
    base = output_dir / name
    if base.exists():
        console.print(f"[yellow]Warning: directory {base} already exists[/yellow]")

    recon_root = create_recon_tree(base, scope_file)
    console.print(f"[green]Engagement workspace created at: {recon_root}[/green]")
    display_tree(recon_root)

    folder_count = sum(1 for _ in recon_root.rglob("*") if _.is_dir())
    file_count = sum(1 for _ in recon_root.rglob("*") if _.is_file())
    console.print(f"\n[bold]{folder_count}[/bold] directories, [bold]{file_count}[/bold] files created.")
