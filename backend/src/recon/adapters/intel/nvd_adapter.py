"""NVD (National Vulnerability Database) intel adapter — public API, rate limited."""

from typing import Any

from src.data_sources.nvd_client import NVDClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


class NvdIntelAdapter(IntelAdapter):
    """NVD adapter for CVE/vulnerability intelligence."""

    @property
    def name(self) -> str:
        return "nvd"

    @property
    def env_key(self) -> str | None:
        return None

    async def fetch(self, domain: str) -> dict[str, Any]:
        client = NVDClient()
        keyword = domain.replace(".", " ").split()[0] if domain else "web"
        try:
            data = await client.query(
                params={"keywordSearch": keyword, "resultsPerPage": 10}
            )
        except Exception:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "NVD query failed",
                "raw": None,
            }

        vulns = data.get("vulnerabilities", [])
        findings: list[dict[str, Any]] = []

        for v in vulns[:10]:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = (d.get("value", ""))[:500]
                    break
            findings.append(
                _finding(
                    FindingType.OSINT_ENTRY,
                    cve_id,
                    {
                        "cve_id": cve_id,
                        "description": desc,
                        "keyword": keyword,
                        "source": self.name,
                    },
                    self.name,
                    0.8,
                )
            )

        return {
            "source": self.name,
            "findings": findings,
            "skipped": False,
            "error": None,
            "raw": {"totalResults": data.get("totalResults", 0)},
        }
