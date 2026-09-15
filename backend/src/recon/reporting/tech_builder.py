"""Tech fingerprint builder — builds tech_profile.csv and tech_profile.json from Stage 1 artifacts."""

import csv
import io
import logging
import re
from pathlib import Path

from src.recon.parsers.http_probe_parser import parse_http_probe
from src.schemas.recon.stage1 import TechProfileEntry

logger = logging.getLogger(__name__)

COLUMNS = ["indicator_type", "value", "evidence", "confidence"]

_CONFIDENCE_MAP = {"high": 0.9, "medium": 0.5, "low": 0.3}

# Server header -> (indicator_type, confidence). Compiled at load.
_SERVER_SIGNATURES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^Vercel$", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^Microsoft-HTTPAPI", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^nginx", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^Apache", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^cloudflare", re.IGNORECASE), "cdn", "high"),
    (re.compile(r"^AmazonS3", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^Netlify", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^GitHub\.com", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^Google", re.IGNORECASE), "platform", "medium"),
    (re.compile(r"^AWS", re.IGNORECASE), "platform", "medium"),
    (re.compile(r"^Akamai", re.IGNORECASE), "cdn", "high"),
    (re.compile(r"^Fastly", re.IGNORECASE), "cdn", "high"),
    (re.compile(r"^squid", re.IGNORECASE), "platform", "medium"),
    (re.compile(r"^Caddy", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^OpenResty", re.IGNORECASE), "platform", "medium"),
    (re.compile(r"^IIS", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^LiteSpeed", re.IGNORECASE), "platform", "high"),
    (re.compile(r"^Gunicorn", re.IGNORECASE), "framework", "high"),
    (re.compile(r"^uvicorn", re.IGNORECASE), "framework", "high"),
    (re.compile(r"^Werkzeug", re.IGNORECASE), "framework", "high"),
    (re.compile(r"^Express", re.IGNORECASE), "framework", "medium"),
    (re.compile(r"^PHP", re.IGNORECASE), "framework", "medium"),
    (re.compile(r"^ASP\.NET", re.IGNORECASE), "framework", "high"),
    (re.compile(r"^Kestrel", re.IGNORECASE), "framework", "high"),
    (re.compile(r"^Sucuri", re.IGNORECASE), "waf", "high"),
    (re.compile(r"^Cloudflare", re.IGNORECASE), "waf", "high"),
    (re.compile(r"^AWSWAF", re.IGNORECASE), "waf", "high"),
    (re.compile(r"^Mod_Security", re.IGNORECASE), "waf", "high"),
    (re.compile(r"^Barracuda", re.IGNORECASE), "waf", "medium"),
    (re.compile(r"^F5", re.IGNORECASE), "waf", "medium"),
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


def _build_tech_indicators(http_probe_path: Path) -> list[dict[str, str]]:
    """Build raw tech indicators from http_probe.csv. Returns list of dicts with host, indicator_type, value, evidence, confidence."""
    http_rows = parse_http_probe(http_probe_path)
    indicators: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for row in http_rows:
        server = (row.get("server") or "").strip()
        host = (row.get("host") or row.get("url") or "").strip()
        if not server:
            continue

        matches = _match_server(server)
        for indicator_type, value, confidence in matches:
            key = (indicator_type, value)
            if key in seen:
                continue
            seen.add(key)
            evidence = f"Server header on {host}" if host else "Server header"
            indicators.append(
                {
                    "host": host or "unknown",
                    "indicator_type": indicator_type,
                    "value": value,
                    "evidence": evidence,
                    "confidence": confidence,
                }
            )
    return indicators


def build_tech_profile(http_probe_path: str | Path) -> str:
    """Build tech_profile.csv from http_probe.csv.

    Parses server header to infer platform, framework, cdn, waf.
    Columns: indicator_type, value, evidence, confidence.
    """
    http_probe_path = Path(http_probe_path)
    indicators = _build_tech_indicators(http_probe_path)

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(COLUMNS)
    for ind in indicators:
        writer.writerow(
            [
                ind["indicator_type"],
                ind["value"],
                ind["evidence"],
                ind["confidence"],
            ]
        )

    return output.getvalue()


def build_tech_profile_json(http_probe_path: str | Path) -> list[TechProfileEntry]:
    """Build tech profile as list of TechProfileEntry from http_probe.csv.

    Same logic as build_tech_profile but returns validated TechProfileEntry[].
    Output can be serialized to tech_profile.json.
    """
    http_probe_path = Path(http_probe_path)
    indicators = _build_tech_indicators(http_probe_path)

    entries: list[TechProfileEntry] = []
    for ind in indicators:
        conf_str = (ind.get("confidence") or "").lower()
        confidence = _CONFIDENCE_MAP.get(conf_str)
        host = (ind.get("host") or "unknown").strip()[:512]
        if not host:
            host = "unknown"
        entries.append(
            TechProfileEntry(
                host=host,
                indicator_type=ind["indicator_type"][:128],
                value=ind["value"][:1024],
                evidence=(ind.get("evidence") or "")[:2000],
                confidence=confidence,
            )
        )
    return entries[:2000]
