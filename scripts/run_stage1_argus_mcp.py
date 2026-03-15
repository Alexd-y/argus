#!/usr/bin/env python3
"""
Stage 1 Intelligence Gathering via ARGUS API + MCP-compatible data sources.

Uses HTTP fetch (equivalent to MCP user-fetch / mcp_web_fetch) for:
- crt.sh (Certificate Transparency) — subdomain enumeration
- Target URLs — HTTP probing for live hosts

Runs via ARGUS containers (backend, celery-worker). No Cursor Agent.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

ARGUS_API = "http://localhost:8000/api/v1"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "pentest_reports_svalbard"
TARGET = "svalbard.ca"


def fetch_crt_sh(domain: str) -> list[dict]:
    """Fetch subdomains from crt.sh (MCP fetch equivalent)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.json()


def parse_subdomains(crt_data: list[dict], domain: str) -> str:
    """Extract unique subdomains for subfinder adapter (plain text, one per line)."""
    seen = set()
    for entry in crt_data:
        nv = entry.get("name_value", "")
        for part in nv.replace("\n", " ").split():
            h = part.strip().lower()
            if h and (h == domain or h.endswith("." + domain)) and not h.startswith("*"):
                seen.add(h)
    return "\n".join(sorted(seen))


def probe_url(url: str) -> dict | None:
    """Probe URL (MCP fetch equivalent) — returns httpx-like dict."""
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        host = urlparse(str(r.url)).hostname or ""
        return {
            "url": str(r.url),
            "host": host,
            "status_code": r.status_code,
            "title": "",
            "webserver": r.headers.get("Server", ""),
            "content_type": r.headers.get("Content-Type", ""),
        }
    except Exception:
        return None


def build_httpx_output(hosts: list[str]) -> str:
    """Build httpx JSON-lines output from probed hosts."""
    lines = []
    for host in hosts:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            d = probe_url(url)
            if d:
                lines.append(json.dumps(d))
    return "\n".join(lines)


def create_engagement(api_base: str) -> str:
    """Create engagement with scope for svalbard.ca."""
    payload = {
        "name": f"Stage1-{TARGET}",
        "description": f"Intelligence Gathering Stage 1 — {TARGET}",
        "scope_config": {
            "rules": [
                {"rule_type": "include", "value_type": "domain", "pattern": TARGET},
            ],
            "wildcard_subdomains": True,
            "roe_text": "Passive recon only. No DoS.",
            "max_rate_per_second": 10,
        },
    }
    r = requests.post(f"{api_base}/recon/engagements", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()["id"]


def activate_engagement(api_base: str, eng_id: str) -> None:
    """Activate engagement."""
    r = requests.post(f"{api_base}/recon/engagements/{eng_id}/activate", timeout=10)
    r.raise_for_status()


def create_target(api_base: str, eng_id: str) -> str:
    """Add target to engagement."""
    payload = {"domain": TARGET}
    r = requests.post(f"{api_base}/recon/engagements/{eng_id}/targets", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()["id"]


def create_job(api_base: str, eng_id: str, target_id: str, stage: int, tool: str, config: dict) -> str:
    """Create scan job with raw_output (triggers Celery)."""
    payload = {
        "target_id": target_id,
        "stage": stage,
        "tool_name": tool,
        "config": config,
    }
    url = f"{api_base}/recon/engagements/{eng_id}/jobs"
    r = requests.post(url, json=payload, timeout=10)
    if not r.ok:
        raise RuntimeError(f"Job create failed {url}: {r.status_code} {r.text[:500]}")
    return r.json()["id"]


def wait_for_jobs(api_base: str, eng_id: str, timeout: int = 120) -> bool:
    """Poll until all jobs completed or failed."""
    start = time.time()
    while time.time() - start < timeout:
        r = requests.get(f"{api_base}/recon/engagements/{eng_id}/jobs", timeout=10)
        r.raise_for_status()
        jobs = r.json()["items"]
        pending = [j for j in jobs if j["status"] in ("pending", "queued", "running")]
        if not pending:
            return True
        time.sleep(2)
    return False


def list_artifacts(api_base: str, eng_id: str) -> list[dict]:
    """List artifacts for engagement."""
    r = requests.get(f"{api_base}/recon/engagements/{eng_id}/artifacts", timeout=10)
    r.raise_for_status()
    return r.json()["items"]


def download_artifact(api_base: str, artifact_id: str) -> bytes | None:
    """Get artifact content via presigned URL."""
    r = requests.get(f"{api_base}/recon/artifacts/{artifact_id}/download", timeout=10)
    r.raise_for_status()
    url = r.json()["download_url"]
    r2 = requests.get(url, timeout=30)
    r2.raise_for_status()
    return r2.content


def generate_html_report(
    eng_id: str,
    subdomains: list[str],
    live_hosts: list[dict],
    artifacts: list[dict],
    mcp_tools_used: list[str],
) -> str:
    """Generate HTML report."""
    live_rows = ""
    for h in live_hosts:
        live_rows += f"<tr><td>{h.get('host','')}</td><td>{h.get('url','')}</td><td>{h.get('status_code','')}</td><td>{h.get('webserver','')}</td></tr>"
    sub_rows = "".join(f"<li>{s}</li>" for s in subdomains)
    stage_names = {2: "02_subdomains", 4: "04_live_hosts"}
    artifact_rows = "".join(
        f"<tr><td>{a.get('filename','')}</td><td>{stage_names.get(a.get('stage'), a.get('stage',''))}</td></tr>"
        for a in artifacts
    )
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Stage 1 Report — {TARGET} (ARGUS + MCP)</title>
<style>
body{{font-family:system-ui;max-width:900px;margin:2rem auto;padding:0 1rem}}
h1{{color:#1a1a2e}} h2{{color:#2c3e50;margin-top:2rem}}
table{{width:100%;border-collapse:collapse}} th,td{{border:1px solid #ddd;padding:0.5rem}}
.section{{background:#f8f9fa;padding:1rem;margin:1rem 0;border-radius:6px}}
.meta{{color:#666;font-size:0.9rem}}
</style>
</head>
<body>
<h1>Stage 1 Intelligence Gathering — {TARGET}</h1>
<div class="meta">
<p><strong>Target:</strong> {TARGET}</p>
<p><strong>Engagement:</strong> {eng_id}</p>
<p><strong>Methodology:</strong> ARGUS Recon + MCP-compatible data sources</p>
<p><strong>MCP tools used:</strong> {', '.join(mcp_tools_used)}</p>
<p><strong>AI:</strong> ARGUS LLM (OpenRouter/OpenAI) — для анализа (при наличии ключей)</p>
</div>

<section class="section">
<h2>Методология и инструменты</h2>
<p><strong>ARGUS:</strong> Backend API, Celery worker, MinIO. Контейнеры Docker.</p>
<p><strong>MCP Server:</strong> user-fetch / mcp_web_fetch — эквивалент (HTTP fetch) для crt.sh и probe.</p>
<p><strong>Источники:</strong> crt.sh (CT logs), HTTP probe (requests).</p>
<p><strong>Без Cursor Agent:</strong> Скрипт выполняется автономно.</p>
</section>

<section class="section">
<h2>Subdomains (Stage 2)</h2>
<ul>{sub_rows}</ul>
</section>

<section class="section">
<h2>Live Hosts (Stage 4)</h2>
<table>
<tr><th>Host</th><th>URL</th><th>Status</th><th>Server</th></tr>
{live_rows}
</table>
</section>

<section class="section">
<h2>Артефакты</h2>
<table>
<tr><th>Filename</th><th>Stage</th></tr>
{artifact_rows}
</table>
</section>
</body>
</html>"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default=ARGUS_API, help="ARGUS API base URL")
    parser.add_argument("--output", type=Path, default=OUTPUT_DIR, help="Output directory")
    args = parser.parse_args()
    api = args.api.rstrip("/")
    out_dir = args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    print("1. Fetching crt.sh (MCP fetch equivalent)...")
    crt_data = fetch_crt_sh(TARGET)
    subfinder_raw = parse_subdomains(crt_data, TARGET)
    subdomains = [s for s in subfinder_raw.splitlines() if s]
    print(f"   Found {len(subdomains)} subdomains")

    print("2. Probing live hosts (MCP fetch equivalent)...")
    hosts_to_probe = [TARGET, f"www.{TARGET}"] + [s for s in subdomains if s != TARGET][:6]
    httpx_raw = build_httpx_output(hosts_to_probe)
    live_hosts = []
    for line in httpx_raw.splitlines():
        try:
            d = json.loads(line)
            if d.get("status_code", 0) in (200, 301, 302):
                live_hosts.append(d)
        except json.JSONDecodeError:
            pass
    print(f"   Live hosts: {len(live_hosts)}")

    print("3. Creating ARGUS engagement...")
    eng_id = create_engagement(api)
    activate_engagement(api, eng_id)
    target_id = create_target(api, eng_id)

    print("4. Creating jobs (subfinder, httpx)...")
    try:
        create_job(api, eng_id, target_id, 2, "subfinder", {"raw_output": subfinder_raw})
    except RuntimeError as e:
        print(f"   Error: {e}")
        return 1
    create_job(api, eng_id, target_id, 4, "httpx", {"raw_output": httpx_raw})

    print("5. Waiting for Celery jobs...")
    if not wait_for_jobs(api, eng_id):
        print("   Timeout waiting for jobs")
        return 1

    print("6. Fetching artifacts...")
    artifacts = list_artifacts(api, eng_id)
    for a in artifacts:
        content = download_artifact(api, a["id"])
        if content:
            stage_dir = out_dir / f"stage_{a.get('stage', 0)}"
            stage_dir.mkdir(parents=True, exist_ok=True)
            (stage_dir / a["filename"]).write_bytes(content)

    print("7. Generating report...")
    mcp_tools = ["mcp_web_fetch (crt.sh)", "mcp_web_fetch (HTTP probe)"]
    html = generate_html_report(eng_id, subdomains, live_hosts, artifacts, mcp_tools)
    html_path = out_dir / "stage1-argus-mcp.html"
    html_path.write_text(html, encoding="utf-8")
    print(f"   HTML: {html_path}")

    pdf_path = out_dir / "stage1-argus-mcp.pdf"
    try:
        from xhtml2pdf import pisa
        with open(html_path, "r", encoding="utf-8") as src:
            with open(pdf_path, "wb") as dst:
                pisa.CreatePDF(src.read(), dst, encoding="utf-8")
        print(f"   PDF: {pdf_path}")
    except ImportError:
        print("   PDF: install xhtml2pdf for PDF generation")

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
