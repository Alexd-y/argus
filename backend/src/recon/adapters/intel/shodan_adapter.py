"""Shodan intel adapter — host/domain intelligence via SHODAN_API_KEY."""

import socket
from typing import Any

from src.data_sources.shodan_client import ShodanClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


def _resolve_ip(domain: str) -> str | None:
    """Resolve domain to IP for Shodan lookup."""
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, OSError):
        return None


def _is_ip(target: str) -> bool:
    """Check if target is an IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


class ShodanIntelAdapter(IntelAdapter):
    """Shodan API adapter for host intelligence."""

    @property
    def name(self) -> str:
        return "shodan"

    @property
    def env_key(self) -> str | None:
        return "SHODAN_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {
                "source": self.name,
                "findings": [],
                "skipped": True,
                "error": None,
                "raw": None,
            }

        ip = domain if _is_ip(domain) else _resolve_ip(domain)
        if not ip:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": f"Cannot resolve {domain} to IP",
                "raw": None,
            }

        client = ShodanClient()
        try:
            data = await client.query(endpoint=f"shodan/host/{ip}")
            if not data:
                return {
                    "source": self.name,
                    "findings": [],
                    "skipped": False,
                    "error": "Empty response",
                    "raw": None,
                }

            findings: list[dict[str, Any]] = []
            hostnames = data.get("hostnames", [])
            for hn in hostnames:
                if hn and isinstance(hn, str):
                    findings.append(
                        _finding(
                            FindingType.SUBDOMAIN,
                            hn.lower().rstrip("."),
                            {"source": self.name, "ip": ip},
                            self.name,
                            0.9,
                        )
                    )

            org = data.get("org")
            if org:
                findings.append(
                    _finding(
                        FindingType.OSINT_ENTRY,
                        f"org:{org}",
                        {"source": self.name, "ip": ip, "org": org},
                        self.name,
                        0.95,
                    )
                )

            for item in data.get("data", [])[:20]:
                port = item.get("port")
                product = item.get("product") or item.get("_shodan", {}).get("module", "")
                version = item.get("version", "")
                if port:
                    svc = f"{ip}:{port}"
                    findings.append(
                        _finding(
                            FindingType.SERVICE,
                            svc,
                            {
                                "ip": ip,
                                "port": port,
                                "product": product,
                                "version": version,
                                "source": self.name,
                            },
                            self.name,
                            0.85,
                        )
                    )

            return {
                "source": self.name,
                "findings": findings,
                "skipped": False,
                "error": None,
                "raw": data,
            }
        except Exception:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "Shodan query failed",
                "raw": None,
            }
