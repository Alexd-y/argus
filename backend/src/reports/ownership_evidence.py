"""VHQ-012 — Ownership evidence collector for Valhalla report provability.

Gathers domain/TLS/DNS/IP ownership signals from recon results and
assembles an OwnershipEvidenceModel to prove the target actually belongs
to the assessed organization.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_WHOIS_KEY_HINTS = frozenset({
    "registrar", "organization", "org_name", "org", "registrant_org",
    "creation_date", "expiry_date", "expiration_date", "registry_expiry_date",
})

_DNS_SOA_RE = re.compile(r"origin\s*=\s*([^\s;]+)", re.IGNORECASE)
_DNS_NS_RE = re.compile(r"nameserver\s*=\s*([^\s;]+)", re.IGNORECASE)
_DNS_MX_RE = re.compile(r"(\S+\.\w+)\s+\d+\s+MX", re.IGNORECASE)


def build_ownership_evidence(
    target_url: str,
    recon_results: dict[str, Any] | None,
    ssl_tls: Any | None = None,
) -> dict[str, Any]:
    """Assemble ownership evidence dict from recon + TLS data.

    Returns a plain dict matching OwnershipEvidenceModel schema.
    """
    from src.reports.valhalla_report_context import OwnershipEvidenceModel

    parsed = urlparse(target_url or "")
    domain = parsed.hostname or parsed.netloc or ""
    if not domain and isinstance(recon_results, dict):
        for key in ("target", "domain", "host", "url"):
            v = recon_results.get(key)
            if isinstance(v, str) and v.strip():
                domain = urlparse(v).hostname or v.strip()
                break

    whois_registrar = ""
    whois_org = ""
    whois_creation = ""
    whois_expiry = ""

    if isinstance(recon_results, dict):
        whois_data = recon_results.get("whois")
        if isinstance(whois_data, dict):
            whois_registrar = str(whois_data.get("registrar") or whois_data.get("registrar_name") or "")[:256]
            whois_org = str(whois_data.get("organization") or whois_data.get("registrant_organization") or whois_data.get("org") or "")[:256]
            whois_creation = str(whois_data.get("creation_date") or whois_data.get("created_date") or "")[:64]
            whois_expiry = str(whois_data.get("expiry_date") or whois_data.get("expiration_date") or whois_data.get("registry_expiry_date") or "")[:64]
        elif isinstance(whois_data, str) and whois_data.strip():
            text = whois_data.strip()
            for pattern, field in [
                (r"Registrar:\s*(.+)", "registrar"),
                (r"Registrant Organization:\s*(.+)", "org"),
                (r"Creation Date:\s*(.+)", "creation"),
                (r"Registry Expiry Date:\s*(.+)", "expiry"),
            ]:
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    val = m.group(1).strip()[:256]
                    if field == "registrar":
                        whois_registrar = val
                    elif field == "org":
                        whois_org = val
                    elif field == "creation":
                        whois_creation = val[:64]
                    elif field == "expiry":
                        whois_expiry = val[:64]

    tls_subject = ""
    tls_issuer = ""
    tls_sans: list[str] = []
    if ssl_tls is not None:
        tls_subject = getattr(ssl_tls, "cert_subject", "") or ""
        tls_issuer = getattr(ssl_tls, "cert_issuer", "") or getattr(ssl_tls, "issuer", "") or ""
        tls_sans = list(getattr(ssl_tls, "san", []) or [])

    dns_soa = ""
    dns_ns: list[str] = []
    dns_mx: list[str] = []

    if isinstance(recon_results, dict):
        dns_data = recon_results.get("dns")
        if isinstance(dns_data, dict):
            soa_raw = dns_data.get("soa") or dns_data.get("SOA") or ""
            if isinstance(soa_raw, str):
                m = _DNS_SOA_RE.search(soa_raw)
                if m:
                    dns_soa = m.group(1).strip()[:256]
            ns_raw = dns_data.get("ns") or dns_data.get("nameservers") or []
            if isinstance(ns_raw, list):
                dns_ns = [str(n).strip()[:256] for n in ns_raw[:16] if str(n).strip()]
            elif isinstance(ns_raw, str):
                for m in _DNS_NS_RE.finditer(ns_raw):
                    dns_ns.append(m.group(1).strip()[:256])
                    if len(dns_ns) >= 16:
                        break
            mx_raw = dns_data.get("mx") or dns_data.get("mail") or []
            if isinstance(mx_raw, list):
                dns_mx = [str(m).strip()[:256] for m in mx_raw[:8] if str(m).strip()]
            elif isinstance(mx_raw, str):
                for m in _DNS_MX_RE.finditer(mx_raw):
                    dns_mx.append(m.group(1).strip()[:256])
                    if len(dns_mx) >= 8:
                        break

    ip_org = ""
    ip_asn = ""
    ip_country = ""

    if isinstance(recon_results, dict):
        ip_data = recon_results.get("ip_lookup") or recon_results.get("ipinfo") or recon_results.get("asn")
        if isinstance(ip_data, dict):
            ip_org = str(ip_data.get("org") or ip_data.get("organization") or "")[:256]
            ip_asn = str(ip_data.get("asn") or "")[:64]
            ip_country = str(ip_data.get("country") or ip_data.get("country_code") or "")[:64]

    ownership_signals = sum([
        bool(whois_org),
        bool(whois_registrar),
        bool(tls_subject),
        bool(tls_issuer),
        bool(dns_soa),
        bool(dns_ns),
        bool(ip_org),
    ])
    if ownership_signals >= 4:
        confidence = "high"
    elif ownership_signals >= 2:
        confidence = "medium"
    elif ownership_signals >= 1:
        confidence = "low"
    else:
        confidence = "insufficient"

    model = OwnershipEvidenceModel(
        domain=domain[:512],
        whois_registrar=whois_registrar,
        whois_org=whois_org,
        whois_creation_date=whois_creation,
        whois_expiry_date=whois_expiry,
        tls_subject=tls_subject[:512],
        tls_issuer=tls_issuer[:512],
        tls_SANs=tls_sans[:32],
        dns_soa_primary_ns=dns_soa,
        dns_ns_records=dns_ns[:16],
        dns_mx_records=dns_mx[:8],
        ip_whois_org=ip_org,
        ip_whois_asn=ip_asn,
        ip_country=ip_country,
        ownership_confidence=confidence,
    )

    logger.info(
        "ownership_evidence_built",
        extra={
            "event": "ownership_evidence_built",
            "domain": domain[:128],
            "confidence": confidence,
            "signals": ownership_signals,
        },
    )
    return model