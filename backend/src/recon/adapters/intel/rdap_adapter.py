"""RDAP/WHOIS intel adapter — public API, no key required."""

from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

RDAP_BASE = "https://rdap.org"


class RdapIntelAdapter(IntelAdapter):
    """RDAP adapter for domain registration and nameserver intelligence."""

    @property
    def name(self) -> str:
        return "rdap"

    @property
    def env_key(self) -> str | None:
        return None

    async def fetch(self, domain: str) -> dict[str, Any]:
        domain = domain.strip().lower().split("/")[0].split(":")[0]
        if not domain or "." not in domain:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "Invalid domain",
                "raw": None,
            }

        url = f"{RDAP_BASE}/domain/{domain}"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
        except Exception:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "RDAP query failed",
                "raw": None,
            }

        findings: list[dict[str, Any]] = []

        nameservers = data.get("nameservers", [])
        for ns in nameservers:
            if not isinstance(ns, dict) or "ldhName" not in ns:
                continue
            ns_name = ns["ldhName"].lower().rstrip(".")
            if ns_name and "." in ns_name:
                findings.append(
                    _finding(
                        FindingType.DNS_RECORD,
                        f"{domain} NS {ns_name}",
                        {
                            "hostname": domain,
                            "record_type": "NS",
                            "value": ns_name,
                            "source": self.name,
                        },
                        self.name,
                        0.95,
                    )
                )

        status = data.get("status", [])
        if status:
            findings.append(
                _finding(
                    FindingType.OSINT_ENTRY,
                    f"rdap_status:{domain}",
                    {"domain": domain, "status": status, "source": self.name},
                    self.name,
                    0.9,
                )
            )

        entities = data.get("entities", [])
        registrant = None
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrant" in roles or "registrar" in roles:
                for vcard in ent.get("vcardArray", [[]])[1:]:
                    for prop in vcard:
                        if prop[0] == "fn":
                            registrant = prop[-1]
                            break
                if registrant:
                    break

        if registrant:
            findings.append(
                _finding(
                    FindingType.OSINT_ENTRY,
                    f"registrant:{domain}",
                    {"domain": domain, "registrant": registrant, "source": self.name},
                    self.name,
                    0.85,
                )
            )

        return {
            "source": self.name,
            "findings": findings,
            "skipped": False,
            "error": None,
            "raw": {"ldhName": data.get("ldhName"), "status": data.get("status")},
        }
