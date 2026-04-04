"""VirusTotal intel adapter — domain reputation via VIRUSTOTAL_API_KEY."""

from __future__ import annotations

from typing import Any

from src.data_sources.virustotal_client import VirusTotalClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


def _vt_error(data: dict[str, Any]) -> str | None:
    if data.get("rate_limited"):
        return "rate_limited"
    if data.get("error"):
        return str(data["error"])
    if data == {}:
        return "empty_response"
    return None


class VirusTotalIntelAdapter(IntelAdapter):
    """VirusTotal adapter for domain reputation and DNS-related signals."""

    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def env_key(self) -> str | None:
        return "VIRUSTOTAL_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {
                "source": self.name,
                "findings": [],
                "skipped": True,
                "error": None,
                "raw": None,
            }

        client = VirusTotalClient()
        findings: list[dict[str, Any]] = []

        try:
            data = await client.query(domain=domain, type="domain")
        except Exception:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "VirusTotal query failed",
                "raw": None,
            }

        err = _vt_error(data)
        if err:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": err,
                "raw": None,
            }

        vt_outer = data.get("data") or {}
        vt_data: dict[str, Any] = {}
        if isinstance(vt_outer, dict):
            inner = vt_outer.get("data")
            vt_data = inner if isinstance(inner, dict) else vt_outer
        attrs = vt_data.get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}

        for record in (attrs.get("last_dns_records") or [])[:30]:
            if not isinstance(record, dict):
                continue
            rtype = record.get("type", "")
            value = record.get("value", "")
            if value:
                findings.append(
                    _finding(
                        FindingType.DNS_RECORD,
                        f"{domain} {rtype} {value}",
                        {
                            "hostname": domain,
                            "record_type": rtype,
                            "value": value,
                            "source": self.name,
                        },
                        self.name,
                        0.85,
                    )
                )

        analysis = attrs.get("last_analysis_stats") or {}
        if isinstance(analysis, dict):
            malicious = analysis.get("malicious", 0)
            suspicious = analysis.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                findings.append(
                    _finding(
                        FindingType.OSINT_ENTRY,
                        f"vt_reputation:{domain}",
                        {
                            "domain": domain,
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "harmless": analysis.get("harmless", 0),
                            "source": self.name,
                        },
                        self.name,
                        0.9,
                    )
                )

        categories = attrs.get("categories") or {}
        if categories and isinstance(categories, dict):
            findings.append(
                _finding(
                    FindingType.OSINT_ENTRY,
                    f"vt_categories:{domain}",
                    {"domain": domain, "categories": categories, "source": self.name},
                    self.name,
                    0.7,
                )
            )

        return {
            "source": self.name,
            "findings": findings,
            "skipped": False,
            "error": None,
            "raw": {"analysis_stats": analysis if isinstance(analysis, dict) else {}},
        }
