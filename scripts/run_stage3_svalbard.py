#!/usr/bin/env python3
"""Run Stage 3 Vulnerability Analysis for svalbard.ca (file-based)."""
import asyncio
import sys
from pathlib import Path
from uuid import uuid4

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))
from dotenv import load_dotenv
load_dotenv(backend_dir / ".env")

from src.recon.vulnerability_analysis.pipeline import execute_vulnerability_analysis_run

RECON_DIR = Path(__file__).resolve().parent.parent / "pentest_reports_svalbard" / "recon" / "svalbard-stage1"

def main():
    run_id = str(uuid4())[:8]
    job_id = f"va_{run_id}"
    result = asyncio.run(execute_vulnerability_analysis_run(
        engagement_id="svalbard",
        run_id=run_id,
        job_id=job_id,
        recon_dir=RECON_DIR,
        db=None,
        mcp_tools=[],
        use_llm_fallback=True,
    ))
    print(f"Status: {result.status}")
    return 0 if result.status == "completed" else 1

if __name__ == "__main__":
    sys.exit(main())
