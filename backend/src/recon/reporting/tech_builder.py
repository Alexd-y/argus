"""Tech fingerprint builder — builds tech_profile.csv from Stage 1 artifacts."""

import csv
import io
import logging
import re
from pathlib import Path

from src.recon.parsers.http_probe_parser import parse_http_probe

logger = logging.getLogger(__name__)

COLUMNS = ["indicator_type", "value", "evidence", "confidence"]

# Server header -> (indicator_type, confidence). Compiled at load.
_SERVER_SIGNATURES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^Vercel$", re.I), "platform", "high"),
    (re.compile(r"^Microsoft-HTTPAPI", re.I), "platform", "high"),
    (re.compile(r"^nginx", re.I), "platform", "high"),
    (re.compile(r"^Apache", re.I), "platform", "high"),
    (re.compile(r"^cloudflare", re.I), "cdn", "high"),
    (re.compile(r"^AmazonS3", re.I), "platform", "high"),
    (re.compile(r"^Netlify", re.I), "platform", "high"),
    (re.compile(r"^GitHub\.com", re.I), "platform", "high"),
    (re.compile(r"^Google", re.I), "platform", "medium"),
    (re.compile(r"^AWS", re.I), "platform", "medium"),
    (re.compile(r"^Akamai", re.I), "cdn", "high"),
    (re.compile(r"^Fastly", re.I), "cdn", "high"),
    (re.compile(r"^squid", re.I), "platform", "medium"),
    (re.compile(r"^Caddy", re.I), "platform", "high"),
    (re.compile(r"^OpenResty", re.I), "platform", "medium"),
    (re.compile(r"^IIS", re.I), "platform", "high"),
    (re.compile(r"^LiteSpeed", re.I), "platform", "high"),
    (re.compile(r"^Gunicorn", re.I), "framework", "high"),
    (re.compile(r"^uvicorn", re.I), "framework", "high"),
    (re.compile(r"^Werkzeug", re.I), "framework", "high"),
    (re.compile(r"^Express", re.I), "framework", "medium"),
    (re.compile(r"^PHP", re.I), "framework", "medium"),
    (re.compile(r"^ASP\.NET", re.I), "framework", "high"),
    (re.compile(r"^Kestrel", re.I), "framework", "high"),
    (re.compile(r"^Sucuri", re.I), "waf", "high"),
    (re.compile(r"^Cloudflare", re.I), "waf", "high"),
    (re.compile(r"^AWSWAF", re.I), "waf", "high"),
    (re.compile(r"^Mod_Security", re.I), "waf", "high"),
    (re.compile(r"^Barracuda", re.I), "waf", "medium"),
    (re.compile(r"^F5", re.I), "waf", "medium"),
]


def _match_server(server: str) -> list[tuple[str, str, str]]:
    """Match server header against signatures. Returns list of (indicator_type, value, confidence)."""
    if not server or not server.strip():
        return []
    server_orig = server.strip()
    results: list[tuple[str, str, str]] = []

    for pattern, itype, conf in _SERVER_SIGNATURES:
        if pattern.search(server_orig):
            value = server_orig[:80]
            key = (itype, value)
            if key not in {(r[0], r[1]) for r in results}:
                results.append((itype, value, conf))
    return results


def build_tech_profile(http_probe_path: str | Path) -> str:
    """Build tech_profile.csv from http_probe.csv.

    Parses server header to infer platform, framework, cdn, waf.
    Columns: indicator_type, value, evidence, confidence.
    """
    http_probe_path = Path(http_probe_path)
    http_rows = parse_http_probe(http_probe_path)

    indicators: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for row in http_rows:
        server = (row.get("server") or "").strip()
        host = (row.get("host") or "").strip()
        if not server:
            continue

        matches = _match_server(server)
        for indicator_type, value, confidence in matches:
            key = (indicator_type, value)
            if key in seen:
                continue
            seen.add(key)
            evidence = f"Server header on {host}" if host else "Server header"
            indicators.append({
                "indicator_type": indicator_type,
                "value": value,
                "evidence": evidence,
                "confidence": confidence,
            })

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(COLUMNS)
    for ind in indicators:
        writer.writerow([
            ind["indicator_type"],
            ind["value"],
            ind["evidence"],
            ind["confidence"],
        ])

    return output.getvalue()
