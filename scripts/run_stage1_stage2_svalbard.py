#!/usr/bin/env python3
"""Run Stage 1 (Intelligence Gathering) + Stage 2 (Threat Modeling) for svalbard.ca.

Uses ARGUS pipeline: containers, AI, MCP. No Cursor Agent.
Output: combined HTML + PDF report.
"""
import asyncio
import html
import sys
from pathlib import Path
from uuid import uuid4

# Add backend to path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from dotenv import load_dotenv
load_dotenv(backend_dir / ".env")

from src.recon.reporting.stage1_report_generator import generate_stage1_report
from src.recon.threat_modeling.pipeline import execute_threat_modeling_run

ARGUS_ROOT = Path(__file__).resolve().parent.parent
RECON_DIR = ARGUS_ROOT / "pentest_reports_svalbard" / "recon" / "svalbard-stage1"
REPORTS_DIR = ARGUS_ROOT / "pentest_reports_svalbard"
TARGET = "svalbard.ca"


def run_stage1() -> bool:
    """Generate Stage 1 report."""
    print("[Stage 1] Intelligence Gathering...")
    paths = generate_stage1_report(
        RECON_DIR,
        use_mcp=True,
        skip_intel=False,
        artifacts_base=ARGUS_ROOT,
    )
    if not paths:
        print("[Stage 1] ERROR: No artifacts generated")
        return False
    print(f"[Stage 1] Generated {len(paths)} artifacts")
    return True


async def run_stage2() -> tuple[bool, str | None]:
    """Run Stage 2 Threat Modeling. Returns (success, job_id)."""
    print("[Stage 2] Threat Modeling...")
    run_id = str(uuid4())[:8]
    job_id = f"tm_{run_id}"
    try:
        result = await execute_threat_modeling_run(
            engagement_id="svalbard",
            run_id=run_id,
            job_id=job_id,
            recon_dir=RECON_DIR,
            artifacts_base=ARGUS_ROOT,
            db=None,
            mcp_tools=["fetch"],
            use_llm_fallback=True,
        )
        print(f"[Stage 2] Status: {result.status}, Artifacts: {len(result.artifact_refs)}")
        return (result.status == "completed", job_id)
    except Exception as e:
        print(f"[Stage 2] ERROR: {e}")
        return (False, None)


def build_combined_html(stage2_dir: Path | None = None) -> Path:
    """Build combined HTML report (Stage 1 + Stage 2)."""
    stage1_html = RECON_DIR / "stage1_report.html"
    # TM2-009: when artifacts_base used, threat_model.md is in stage2/{job_id}/
    threat_model_md = (stage2_dir / "threat_model.md") if stage2_dir else RECON_DIR / "threat_model.md"

    stage1_content = ""
    if stage1_html.exists():
        stage1_content = stage1_html.read_text(encoding="utf-8", errors="replace")

    stage2_content = ""
    if threat_model_md.exists():
        stage2_md = threat_model_md.read_text(encoding="utf-8", errors="replace")
        stage2_content = f"""
<section class="section" style="margin-top:2rem; border-top:3px solid #1565c0;">
<h1 style="color:#0d47a1; font-size:1.5rem;">Этап 2: Моделирование угроз (Threat Modeling)</h1>
<div class="meta">
<p><strong>Target:</strong> {TARGET}</p>
<p><strong>Methodology:</strong> ARGUS Threat Modeling — 9 AI tasks, MCP enrichment</p>
</div>
<div class="section">
<pre style="white-space:pre-wrap; font-size:0.9rem;">{html.escape(stage2_md)}</pre>
</div>
</section>
"""

    # Extract body from stage1 or build minimal
    if stage1_content:
        # Insert Stage 2 before </body>
        if "</body>" in stage1_content:
            combined = stage1_content.replace("</body>", stage2_content + "\n</body>")
        else:
            combined = stage1_content + stage2_content
        # Update title
        combined = combined.replace(
            "<title>Stage 1 Recon Report",
            "<title>Stage 1+2 Pentest Report",
            1,
        )
    else:
        combined = f"""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><title>Stage 1+2 — {TARGET}</title></head>
<body><h1>ARGUS Pentest — {TARGET}</h1>{stage2_content}</body></html>"""

    out_path = REPORTS_DIR / "stage1-stage2-svalbard.html"
    out_path.write_text(combined, encoding="utf-8")
    return out_path


def main() -> int:
    print("=== ARGUS Stage 1 + Stage 2 — svalbard.ca ===\n")

    if not RECON_DIR.is_dir():
        print(f"ERROR: Recon dir not found: {RECON_DIR}")
        return 1

    # Stage 1
    if not run_stage1():
        return 1

    # Stage 2
    stage2_ok, stage2_job_id = asyncio.run(run_stage2())
    if not stage2_ok:
        print("Stage 2 failed; continuing with Stage 1 report only.")
    stage2_dir = (ARGUS_ROOT / "stage2" / stage2_job_id) if stage2_job_id else None

    # Combined report
    html_path = build_combined_html(stage2_dir=stage2_dir)
    print(f"\n[Report] HTML: {html_path}")

    # Copy stage1 for standalone
    stage1_src = RECON_DIR / "stage1_report.html"
    if stage1_src.exists():
        (REPORTS_DIR / "stage1-svalbard.html").write_bytes(stage1_src.read_bytes())

    print("\n=== Done ===")
    print(f"HTML: {html_path}")
    print(f"PDF: Run generate-pdf.ps1 -baseName stage1-stage2-svalbard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
