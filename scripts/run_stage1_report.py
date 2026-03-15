#!/usr/bin/env python3
"""Run Stage 1 report generation for svalbard-stage1. Called from PowerShell script."""
import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

# Add backend to path and load .env for local runs
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))
env_path = backend_dir / ".env"
load_dotenv(env_path)

from src.recon.reporting.stage1_report_generator import generate_stage1_report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Stage 1 recon report")
    parser.add_argument(
        "--no-mcp",
        action="store_true",
        help="Disable MCP fetch for endpoint discovery (use httpx only)",
    )
    parser.add_argument(
        "--skip-intel",
        action="store_true",
        help="Skip intel adapters (faster run, no Shodan/crt.sh/RDAP/NVD fetch)",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Fast mode: skip intel, use mock fetch for endpoints (no network calls)",
    )
    args = parser.parse_args()
    use_mcp = not args.no_mcp and not args.fast
    skip_intel = args.skip_intel or args.fast

    def _mock_endpoint_fetch(_url: str) -> dict:
        return {"status": 0, "content_type": "", "exists": False, "notes": "fast mode"}

    def _mock_headers_fetch(url: str) -> dict:
        return {"status_code": 0, "headers": {}, "url": url}

    recon_dir = Path(__file__).resolve().parent.parent / "pentest_reports_svalbard" / "recon" / "svalbard-stage1"
    fetch_func = _mock_endpoint_fetch if args.fast else None
    headers_fetch_func = _mock_headers_fetch if args.fast else None
    paths = generate_stage1_report(
        recon_dir,
        use_mcp=use_mcp,
        skip_intel=skip_intel,
        fetch_func=fetch_func,
        headers_fetch_func=headers_fetch_func,
    )
    print(f"Generated: {len(paths)} files")
    for p in paths:
        print(f"  - {p.name}")
    return 0 if paths else 1

if __name__ == "__main__":
    sys.exit(main())
