"""Live host detailed builder — builds live_hosts_detailed.csv from Stage 1 artifacts."""

import csv
import io
import logging
from pathlib import Path
from urllib.parse import urlparse

from src.recon.parsers.cname_parser import parse_cname
from src.recon.parsers.http_probe_parser import parse_http_probe
from src.recon.parsers.resolved_parser import parse_resolved

logger = logging.getLogger(__name__)

COLUMNS = [
    "host",
    "ip",
    "cname",
    "final_url",
    "redirect_chain",
    "status",
    "title",
    "server",
    "content_length",
    "content_hash",
    "cluster_id",
    "notes",
]


def _build_cluster_key(row: dict) -> str:
    """Build cluster key from title+server+status for same-content grouping."""
    title = (row.get("title") or "").strip()
    server = (row.get("server") or "").strip()
    status = (row.get("status") or "").strip()
    return f"{title}|{server}|{status}"


def _derive_notes(row: dict, cluster_size: int) -> str:
    """Derive notes from redirect and cluster context."""
    notes: list[str] = []
    redirect = (row.get("redirect") or "").strip()
    status = (row.get("status") or "").strip()
    if redirect:
        try:
            parsed = urlparse(redirect)
            path = (parsed.path or "/").rstrip("/") or "/"
            notes.append("redirect to root" if path == "/" else "redirect")
        except Exception:
            notes.append("redirect")
    if cluster_size > 1:
        notes.append("shared 404" if status == "404" else "shared response")
    return "; ".join(notes) if notes else ""


def build_live_hosts_detailed(
    resolved_path: str | Path,
    cname_path: str | Path,
    http_probe_path: str | Path,
) -> str:
    """Build live_hosts_detailed.csv from resolved, cname, and http_probe artifacts.

    Joins:
    - IP from resolved parser (by host)
    - CNAME from cname parser (by host)
    - final_url, redirect_chain, status, title, server from http_probe
    - content_length: 0 (placeholder, would need fetch)
    - content_hash: empty (placeholder for same-content clustering)
    - cluster_id: groups hosts with same title+server+status
    - notes: e.g. "shared 404", "redirect to root"
    """
    resolved_path = Path(resolved_path)
    cname_path = Path(cname_path)
    http_probe_path = Path(http_probe_path)

    resolved = parse_resolved(resolved_path)
    cname_rows = parse_cname(cname_path)
    http_rows = parse_http_probe(http_probe_path)

    cname_by_host: dict[str, str] = {}
    for r in cname_rows:
        host = (r.get("host") or "").strip()
        value = (r.get("value") or "").strip()
        if host and value:
            cname_by_host[host] = value

    cluster_keys: dict[str, int] = {}
    cluster_id_counter = 0

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    writer.writerow(COLUMNS)

    for row in http_rows:
        host = (row.get("host") or "").strip()
        if not host:
            continue

        url = (row.get("url") or "").strip()
        redirect = (row.get("redirect") or "").strip()
        status = (row.get("status") or "").strip()
        title = (row.get("title") or "").strip()
        server = (row.get("server") or "").strip()

        ips = resolved.get(host, [])
        ip = ",".join(ips) if ips else ""
        cname = cname_by_host.get(host, "")

        final_url = redirect if redirect else url
        redirect_chain = f"{url} -> {redirect}" if redirect else url

        cluster_key = _build_cluster_key({"title": title, "server": server, "status": status})
        if cluster_key not in cluster_keys:
            cluster_id_counter += 1
            cluster_keys[cluster_key] = cluster_id_counter
        cluster_id = cluster_keys[cluster_key]

        cluster_size = sum(
            1
            for r in http_rows
            if _build_cluster_key(
                {"title": r.get("title"), "server": r.get("server"), "status": r.get("status")}
            )
            == cluster_key
        )
        notes = _derive_notes({"redirect": redirect, "url": url, "status": status}, cluster_size)

        writer.writerow([
            host,
            ip,
            cname,
            final_url,
            redirect_chain,
            status,
            title,
            server,
            0,
            "",
            cluster_id,
            notes,
        ])

    return output.getvalue()
