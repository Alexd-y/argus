"""Censys intel adapter — host and certificate intelligence via Censys Search API v2."""

from __future__ import annotations

from typing import Any

from src.data_sources.censys_client import CensysClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


class CensysIntelAdapter(IntelAdapter):
    """Censys API adapter for host and certificate discovery (API ID + secret)."""

    @property
    def name(self) -> str:
        return "censys"

    @property
    def env_key(self) -> str | None:
        return "CENSYS_API_KEY"

    def is_available(self) -> bool:
        return CensysClient().is_available()

    def _censys_error(self, data: dict[str, Any]) -> str | None:
        if data.get("rate_limited"):
            return "rate_limited"
        err = data.get("error")
        if err:
            return str(err)
        if data == {}:
            return "empty_response"
        return None

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {
                "source": self.name,
                "findings": [],
                "skipped": True,
                "error": None,
                "raw": None,
            }

        client = CensysClient()
        findings: list[dict[str, Any]] = []
        q_host = f'dns.names:"{domain}"'
        try:
            data = await client.query(type="search", q=q_host, per_page=25)
        except Exception:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "Censys query failed",
                "raw": None,
            }

        err = self._censys_error(data)
        if err:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": err,
                "raw": None,
            }

        hits: list[Any] = []
        raw_data = data.get("data") or {}
        if isinstance(raw_data, dict):
            result = raw_data.get("result") or {}
            hits = list(result.get("hits") or [])

        for hit in hits[:20]:
            if not isinstance(hit, dict):
                continue
            ip = hit.get("ip") or ""
            if not ip:
                continue
            services = hit.get("services") or []
            if not isinstance(services, list):
                services = []
            for svc in services[:10]:
                if not isinstance(svc, dict):
                    continue
                port = svc.get("port")
                service_name = svc.get("service_name") or svc.get("extended_service_name") or ""
                if port:
                    findings.append(
                        _finding(
                            FindingType.SERVICE,
                            f"{ip}:{port}",
                            {
                                "ip": ip,
                                "port": port,
                                "service": service_name,
                                "source": self.name,
                            },
                            self.name,
                            0.85,
                        )
                    )
            findings.append(
                _finding(
                    FindingType.IP_ADDRESS,
                    ip,
                    {"ip": ip, "source": self.name, "domain": domain},
                    self.name,
                    0.8,
                )
            )

        try:
            cert_data = await client.query(
                type="certificates",
                q=domain,
                per_page=25,
            )
            cert_raw = cert_data.get("data") or {}
            cert_hits: list[Any] = []
            if isinstance(cert_raw, dict):
                cert_hits = list((cert_raw.get("result") or {}).get("hits") or [])
            seen_names: set[str] = set()
            for cert in cert_hits[:20]:
                if not isinstance(cert, dict):
                    continue
                names = cert.get("names") or []
                if not names and isinstance(cert.get("parsed"), dict):
                    parsed = cert["parsed"]
                    names = parsed.get("names") or parsed.get("subject_dn", "").split(",")
                if not isinstance(names, list):
                    names = [names] if names else []
                for n in names:
                    sub = str(n).strip().lstrip("*.").lower().rstrip(".")
                    if sub and "." in sub and sub not in seen_names and domain in sub:
                        seen_names.add(sub)
                        findings.append(
                            _finding(
                                FindingType.SUBDOMAIN,
                                sub,
                                {
                                    "source": self.name,
                                    "parent_domain": domain,
                                    "from_cert": True,
                                },
                                self.name,
                                0.85,
                            )
                        )
        except Exception:
            pass

        return {
            "source": self.name,
            "findings": findings,
            "skipped": False,
            "error": None,
            "raw": {"hits_count": len(hits)},
        }
