"""Recon results builder — aggregates Stage 1 artifacts into ReconResults schema.

Produces recon_results.json validated against ReconResults (stage1.py).
"""

from __future__ import annotations

import csv
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from src.recon.parsers import parse_cname, parse_dns, parse_resolved, parse_whois
from src.recon.parsers.http_probe_parser import parse_http_probe
from src.recon.reporting.endpoint_builder import extract_live_hosts_from_http_probe
from src.recon.reporting.headers_builder import (
    KEY_HEADERS,
    _fetch_headers_httpx,
    _normalize_headers,
    get_ssl_cert_entry,
)

from app.schemas.recon.stage1 import (
    ReconResults,
    SslCertEntry,
    TechProfileEntry,
)

logger = logging.getLogger(__name__)

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-f:]+$", re.IGNORECASE)

_CONFIDENCE_MAP = {"high": 0.9, "medium": 0.5, "low": 0.3}


def _derive_target_domain(recon_dir: Path) -> str:
    """Extract target domain from scope.txt, targets.txt, or directory name."""
    scope_path = recon_dir / "00_scope" / "scope.txt"
    if scope_path.exists():
        try:
            text = scope_path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"Target:\s*([^\s#\n]+)", text, re.I)
            if m:
                return m.group(1).strip()
        except OSError:
            pass
    targets_path = recon_dir / "00_scope" / "targets.txt"
    if targets_path.exists():
        try:
            text = targets_path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"Primary Domain\s*\n\s*([^\s#\n]+)", text, re.I)
            if m:
                return m.group(1).strip()
        except OSError:
            pass
    name = recon_dir.name
    if "-stage" in name.lower():
        return name.split("-")[0]
    return name or "unknown"


def _extract_host_from_evidence(evidence: str) -> str:
    """Extract host/URL from tech_profile evidence (e.g. 'Server header on https://app.example.com')."""
    if not evidence or " on " not in evidence:
        return "unknown"
    part = evidence.split(" on ", 1)[-1].strip()
    return part if part else "unknown"


def _aggregate_dns(
    recon_dir: Path,
    target_domain: str,
) -> dict[str, dict[str, list[str]]]:
    """Aggregate DNS from parse_dns, parse_resolved, parse_cname by type for domain + subdomains."""
    domains_dir = recon_dir / "01_domains"
    dns_dir = recon_dir / "03_dns"

    result: dict[str, dict[str, list[str]]] = {}

    def _add(domain: str, rtype: str, value: str) -> None:
        if domain and rtype in DNS_RECORD_TYPES and value:
            result.setdefault(domain, {}).setdefault(rtype, [])
            if value not in result[domain][rtype]:
                result[domain][rtype].append(value)

    for fname in ["dns_records.txt", "ns.txt", "mx.txt", "txt.txt", "caa.txt"]:
        for rec in parse_dns(domains_dir / fname):
            rtype = (rec.get("type") or "").upper()
            if rtype in DNS_RECORD_TYPES:
                val = (rec.get("value") or "").strip()
                if val:
                    _add(target_domain, rtype, val)

    resolved = parse_resolved(dns_dir / "resolved.txt")
    for subdomain, ips in resolved.items():
        for ip in ips:
            ip = ip.strip()
            if not ip:
                continue
            if _IPV4_RE.match(ip):
                _add(subdomain, "A", ip)
            elif _IPV6_RE.match(ip):
                _add(subdomain, "AAAA", ip)

    for row in parse_cname(dns_dir / "cname_map.csv"):
        if (row.get("record_type") or "").upper() == "CNAME":
            host = (row.get("host") or "").strip()
            target = (row.get("value") or "").strip()
            if host and target:
                _add(host, "CNAME", target)

    return result


def _load_whois(recon_dir: Path) -> dict | list:
    """Load full WHOIS from parse_whois, with raw text when available."""
    for base in [recon_dir / "01_domains", recon_dir / "03_dns"]:
        whois_path = base / "whois.txt"
        if whois_path.exists():
            parsed = parse_whois(whois_path)
            try:
                raw = whois_path.read_text(encoding="utf-8", errors="replace")
                return {"raw": raw.strip(), **parsed}
            except OSError:
                return parsed
    return {}


def _load_ssl_certs(
    live_hosts: list[str],
) -> dict[str, list[SslCertEntry]]:
    """Build SSL cert entries for HTTPS hosts using get_ssl_cert_entry."""
    ssl_certs: dict[str, list[SslCertEntry]] = {}
    for url in live_hosts:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        scheme = (parsed.scheme or "").lower()
        if not host or scheme != "https":
            continue
        entry = get_ssl_cert_entry(host)
        if entry and "error" not in entry:
            try:
                cert = SslCertEntry(
                    common_name=str(entry["common_name"]),
                    subject_alternative_names=list(entry.get("subject_alternative_names", [])),
                    issuer=str(entry["issuer"]),
                    validity_not_before=entry["validity_not_before"],
                    validity_not_after=entry["validity_not_after"],
                )
                ssl_certs.setdefault(url, []).append(cert)
            except Exception as exc:
                logger.debug(
                    "ssl_cert_validation_skipped",
                    extra={"host": host, "error": str(exc)[:80]},
                )
    return ssl_certs


def _load_tech_stack(recon_dir: Path, http_probe_path: Path) -> list[TechProfileEntry]:
    """Build tech stack from tech_profile.csv + Server headers from http_probe."""
    tech_entries: list[TechProfileEntry] = []
    seen: set[tuple[str, str, str]] = set()

    tech_path = recon_dir / "tech_profile.csv"
    if tech_path.exists():
        try:
            with tech_path.open(encoding="utf-8", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    host = _extract_host_from_evidence(row.get("evidence", ""))
                    itype = (row.get("indicator_type") or "unknown").strip()
                    value = (row.get("value") or "").strip()
                    evidence = (row.get("evidence") or "").strip()
                    conf_str = (row.get("confidence") or "").lower()
                    confidence = _CONFIDENCE_MAP.get(conf_str)

                    key = (host, itype, value)
                    if key in seen or not value:
                        continue
                    seen.add(key)
                    tech_entries.append(
                        TechProfileEntry(
                            host=host,
                            indicator_type=itype,
                            value=value[:1024],
                            evidence=evidence[:2000],
                            confidence=confidence,
                        )
                    )
        except (OSError, csv.Error) as e:
            logger.warning(
                "tech_profile_load_failed",
                extra={"path": str(tech_path), "error": str(e)[:80]},
            )

    for row in parse_http_probe(http_probe_path):
        server = (row.get("server") or "").strip()
        host = (row.get("host") or row.get("url") or "").strip()
        if not server or not host:
            continue
        key = (host, "platform", server[:80])
        if key in seen:
            continue
        seen.add(key)
        tech_entries.append(
            TechProfileEntry(
                host=host,
                indicator_type="platform",
                value=server[:1024],
                evidence=f"Server header on {host}",
                confidence=0.8,
            )
        )

    return tech_entries[:2000]


def _load_http_headers(live_hosts: list[str]) -> dict[str, dict[str, object]]:
    """Build HTTP headers analysis per host from fetch (same data source as build_headers_artifacts)."""
    http_headers: dict[str, dict[str, object]] = {}
    for url in live_hosts:
        entry = _fetch_headers_httpx(url)
        raw = entry.get("headers") or {}
        headers = _normalize_headers(raw if isinstance(raw, dict) else {})
        filtered: dict[str, object] = {}
        for h in KEY_HEADERS:
            key = h.lower()
            if key in headers and headers[key].strip():
                filtered[h] = headers[key]
        if filtered:
            http_headers[url] = filtered
    return http_headers


def build_recon_results(recon_dir: Path, scan_id: str) -> ReconResults:
    """Build ReconResults from Stage 1 recon artifacts.

    Aggregates DNS (A, AAAA, CNAME, MX, TXT, NS), WHOIS, SSL certs, tech stack,
    and HTTP headers into a schema-validated ReconResults instance.

    Args:
        recon_dir: Path to recon directory (e.g. .../recon/svalbard-stage1/).
        scan_id: Scan identifier for the run.

    Returns:
        ReconResults validated against schema.
    """
    recon_dir = Path(recon_dir)
    target_domain = _derive_target_domain(recon_dir)
    live_dir = recon_dir / "04_live_hosts"
    http_probe_path = live_dir / "http_probe.csv"

    live_hosts: list[str] = []
    if http_probe_path.exists():
        live_hosts = extract_live_hosts_from_http_probe(http_probe_path)

    dns = _aggregate_dns(recon_dir, target_domain)
    whois = _load_whois(recon_dir)
    ssl_certs = _load_ssl_certs(live_hosts)
    tech_stack = (
        _load_tech_stack(recon_dir, http_probe_path)
        if http_probe_path.exists()
        else []
    )
    http_headers = _load_http_headers(live_hosts)

    return ReconResults(
        target_domain=target_domain,
        scan_id=scan_id,
        generated_at=datetime.now(UTC),
        dns=dns,
        whois=whois,
        ssl_certs=ssl_certs,
        tech_stack=tech_stack,
        http_headers=http_headers,
    )
