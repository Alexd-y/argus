"""SecurityTrails intel adapter — domain and subdomain intelligence via SECURITYTRAILS_API_KEY."""

from __future__ import annotations

from typing import Any

from src.data_sources.securitytrails_client import SecurityTrailsClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


def _st_error(data: dict[str, Any]) -> str | None:
    if data.get("rate_limited"):
        return "rate_limited"
    if data.get("error"):
        return str(data["error"])
    if data == {}:
        return "empty_response"
    return None


class SecurityTrailsIntelAdapter(IntelAdapter):
    """SecurityTrails adapter for subdomain and DNS intelligence."""

    @property
    def name(self) -> str:
        return "securitytrails"

    @property
    def env_key(self) -> str | None:
        return "SECURITYTRAILS_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {
                "source": self.name,
                "findings": [],
                "skipped": True,
                "error": None,
                "raw": None,
            }

        client = SecurityTrailsClient()
        findings: list[dict[str, Any]] = []

        try:
            sub_data = await client.query(domain=domain, type="subdomains")
        except Exception:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "SecurityTrails query failed",
                "raw": None,
            }

        err = _st_error(sub_data)
        if err:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": err,
                "raw": None,
            }

        raw = sub_data.get("data") or {}
        subdomains = raw.get("subdomains") or []
        if not isinstance(subdomains, list):
            subdomains = []

        for prefix in subdomains[:200]:
            p = str(prefix).strip().lower()
            if not p:
                continue
            sub = f"{p}.{domain}".lower()
            findings.append(
                _finding(
                    FindingType.SUBDOMAIN,
                    sub,
                    {"source": self.name, "parent_domain": domain},
                    self.name,
                    0.9,
                )
            )

        try:
            domain_data = await client.query(domain=domain, type="domain")
            if not _st_error(domain_data):
                d_raw = domain_data.get("data") or {}
                current_dns = d_raw.get("current_dns") or {}
                if isinstance(current_dns, dict):
                    for record_type, records in current_dns.items():
                        if not isinstance(records, dict):
                            continue
                        values = records.get("values") or []
                        if not isinstance(values, list):
                            continue
                        for val in values[:10]:
                            if not isinstance(val, dict):
                                continue
                            v = val.get("ip") or val.get("value") or ""
                            if v:
                                findings.append(
                                    _finding(
                                        FindingType.DNS_RECORD,
                                        f"{domain} {str(record_type).upper()} {v}",
                                        {
                                            "hostname": domain,
                                            "record_type": str(record_type).upper(),
                                            "value": str(v),
                                            "source": self.name,
                                        },
                                        self.name,
                                        0.9,
                                    )
                                )
        except Exception:
            pass

        return {
            "source": self.name,
            "findings": findings,
            "skipped": False,
            "error": None,
            "raw": {"subdomains_count": len(subdomains)},
        }
