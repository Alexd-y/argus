"""crt.sh intel adapter — certificate transparency, no API key required."""

from typing import Any

from src.data_sources.crtsh_client import CrtShClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


class CrtShIntelAdapter(IntelAdapter):
    """crt.sh certificate transparency adapter for subdomain discovery."""

    @property
    def name(self) -> str:
        return "crtsh"

    @property
    def env_key(self) -> str | None:
        return None

    async def fetch(self, domain: str) -> dict[str, Any]:
        client = CrtShClient()
        try:
            data = await client.query(params={"q": f"%.{domain}", "output": "json"})
            results = data.get("results", data.get("data", []))
            if not isinstance(results, list):
                results = []

            seen: set[str] = set()
            findings: list[dict[str, Any]] = []

            for entry in results:
                name_value = entry.get("name_value", "")
                for line in name_value.split("\n"):
                    sub = line.strip().lstrip("*.").lower().rstrip(".")
                    if not sub or "." not in sub or sub in seen:
                        continue
                    seen.add(sub)
                    findings.append(
                        _finding(
                            FindingType.SUBDOMAIN,
                            sub,
                            {"source": self.name, "parent_domain": domain},
                            self.name,
                            0.9,
                        )
                    )

            return {
                "source": self.name,
                "findings": findings,
                "skipped": False,
                "error": None,
                "raw": {"count": len(results)},
            }
        except Exception:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "crt.sh query failed",
                "raw": None,
            }
