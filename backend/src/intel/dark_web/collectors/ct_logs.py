"""Free, keyless infrastructure-exposure collectors (§6).

* :class:`CrtShCollector` / :class:`CertSpotterCollector` — Certificate
  Transparency logs for a DOMAIN selector -> subdomains issued a certificate.
  Both emit the SAME content string per discovered subdomain so the coordinator
  de-duplicates a subdomain found by both into a single observation.
* :class:`ShodanInternetDbCollector` — resolves a DOMAIN selector's A records and
  queries Shodan InternetDB per IP for open ports + known CVEs (keyless).

All three are gated by a settings flag (not a key) and run ONLY inside an
already triple-gated sweep. Each degrades to ``[]`` on any failure.
"""

from __future__ import annotations

from src.data_sources.ct_osint_client import (
    CertSpotterClient,
    CrtShClient,
    ShodanInternetDbClient,
)
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)

_MAX_SUBDOMAINS = 200
_MAX_IPS = 3


def _ct_content(subdomain: str, domain: str) -> str:
    """Collector-independent content so crt.sh + certspotter hits de-dup to one."""
    return f"Subdomain '{subdomain}' observed in Certificate Transparency logs for {domain}."


def _iter_subdomains(names: object, domain: str) -> list[str]:
    """Normalise CT name fields into in-scope subdomains of ``domain`` (deduped)."""
    out: list[str] = []
    seen: set[str] = set()
    candidates: list[str] = []
    if isinstance(names, str):
        candidates = names.replace("\\n", "\n").splitlines()
    elif isinstance(names, list):
        candidates = [str(n) for n in names]
    for raw in candidates:
        name = raw.strip().lower().lstrip("*.").lstrip(".")
        if not name or name in seen:
            continue
        # In-scope only: the target domain itself or a subdomain of it.
        if name != domain and not name.endswith("." + domain):
            continue
        seen.add(name)
        out.append(name)
        if len(out) >= _MAX_SUBDOMAINS:
            break
    return out


class _CtCollectorBase(BaseCollector):
    network = SourceNetwork.CLEARNET_INDEX
    accepts = (SelectorKind.DOMAIN,)

    def is_enabled(self) -> bool:
        return self._client.is_available()  # type: ignore[attr-defined]

    def _records_for(
        self, selector: DarkWebSelector, subdomains: list[str]
    ) -> list[DarkWebRawRecord]:
        domain = selector.value.strip().lower().lstrip(".")
        out: list[DarkWebRawRecord] = []
        for sub in subdomains:
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.CLEARNET_INDEX,
                    source_ref=sub,
                    exposure_hint=ExposureType.MENTION,
                    content=_ct_content(sub, domain),
                    collector=self._collector_tag,  # type: ignore[attr-defined]
                    extra={"subdomain": sub, "via": "ct_log"},
                )
            )
        return out


class CrtShCollector(_CtCollectorBase):
    name = "ct_crtsh"
    _collector_tag = "ct_crtsh@1"

    def __init__(self, client: CrtShClient | None = None) -> None:
        self._client = client or CrtShClient()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        domain = selector.value.strip().lower().lstrip(".")
        resp = await self._client.query(domain=domain)
        subs: set[str] = set()
        for row in resp.get("data") or []:
            if isinstance(row, dict):
                for key in ("name_value", "common_name"):
                    for s in _iter_subdomains(row.get(key), domain):
                        subs.add(s)
        return self._records_for(selector, sorted(subs)[:_MAX_SUBDOMAINS])


class CertSpotterCollector(_CtCollectorBase):
    name = "ct_certspotter"
    _collector_tag = "ct_certspotter@1"

    def __init__(self, client: CertSpotterClient | None = None) -> None:
        self._client = client or CertSpotterClient()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        domain = selector.value.strip().lower().lstrip(".")
        resp = await self._client.query(domain=domain)
        subs: set[str] = set()
        for row in resp.get("data") or []:
            if isinstance(row, dict):
                for s in _iter_subdomains(row.get("dns_names"), domain):
                    subs.add(s)
        return self._records_for(selector, sorted(subs)[:_MAX_SUBDOMAINS])


async def _resolve_ips(domain: str, max_ips: int = _MAX_IPS) -> list[str]:
    """Best-effort A-record resolution (dnspython async). Never raises."""
    try:
        import dns.asyncresolver

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        answer = await resolver.resolve(domain, "A")
        ips: list[str] = []
        for rec in answer:
            ip = rec.to_text().strip()
            if ip and ip not in ips:
                ips.append(ip)
            if len(ips) >= max_ips:
                break
        return ips
    except Exception:  # noqa: BLE001 — resolution failure degrades to no Shodan query
        return []


class ShodanInternetDbCollector(BaseCollector):
    name = "shodan_internetdb"
    network = SourceNetwork.FEED
    accepts = (SelectorKind.DOMAIN,)

    def __init__(self, client: ShodanInternetDbClient | None = None) -> None:
        self._client = client or ShodanInternetDbClient()

    def is_enabled(self) -> bool:
        return self._client.is_available()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        domain = selector.value.strip().lower().lstrip(".")
        out: list[DarkWebRawRecord] = []
        for ip in await _resolve_ips(domain):
            resp = await self._client.query(ip=ip)
            data = resp.get("data") or {}
            if not isinstance(data, dict) or not data:
                continue
            ports = [str(p) for p in (data.get("ports") or []) if p is not None][:50]
            vulns = [str(v) for v in (data.get("vulns") or []) if v][:50]
            if not ports and not vulns:
                continue
            parts = [f"Exposed service at {ip} ({domain})."]
            if ports:
                parts.append("Open ports: " + ", ".join(ports) + ".")
            if vulns:
                # Including the CVE ids lets classifier_rules escalate severity.
                parts.append("Known CVEs: " + ", ".join(vulns) + ".")
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.FEED,
                    source_ref=ip,
                    exposure_hint=ExposureType.MENTION,
                    content=" ".join(parts),
                    collector="shodan_internetdb@1",
                    extra={"ip": ip, "ports": ports, "vulns": vulns},
                )
            )
        return out


__all__ = [
    "CertSpotterCollector",
    "CrtShCollector",
    "ShodanInternetDbCollector",
]
