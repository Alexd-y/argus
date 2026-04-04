"""GitHub intel adapter — global security advisories via GITHUB_TOKEN."""

from __future__ import annotations

from typing import Any

from src.data_sources.github_client import GitHubClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


class GitHubIntelAdapter(IntelAdapter):
    """GitHub REST: list reviewed advisories and filter by a short keyword from the domain."""

    @property
    def name(self) -> str:
        return "github"

    @property
    def env_key(self) -> str | None:
        return "GITHUB_TOKEN"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {
                "source": self.name,
                "findings": [],
                "skipped": True,
                "error": None,
                "raw": None,
            }

        client = GitHubClient()
        keyword = domain.split(".")[0].lower() if "." in domain else domain.lower()
        findings: list[dict[str, Any]] = []

        try:
            data = await client.query(
                endpoint="advisories",
                params={"per_page": 50, "type": "reviewed"},
            )
        except Exception as e:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": f"GitHub query failed: {type(e).__name__}",
                "raw": None,
            }

        if not data:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "GitHub query failed",
                "raw": None,
            }

        if isinstance(data, dict):
            if data.get("message"):
                return {
                    "source": self.name,
                    "findings": [],
                    "skipped": False,
                    "error": "GitHub API error",
                    "raw": None,
                }
            advisories: list[Any] = []
        elif isinstance(data, list):
            advisories = data
        else:
            advisories = []

        matched: list[dict[str, Any]] = []
        for adv in advisories:
            if not isinstance(adv, dict):
                continue
            summary = (adv.get("summary") or "") + " " + (adv.get("description") or "")
            cve_id = str(adv.get("cve_id") or "")
            ghsa_id = str(adv.get("ghsa_id") or "")
            hay = f"{summary} {cve_id} {ghsa_id}".lower()
            if keyword and keyword not in hay:
                continue
            matched.append(adv)

        for adv in matched[:10]:
            ghsa_id = str(adv.get("ghsa_id", "") or "")
            cve_id = str(adv.get("cve_id") or "")
            summary = (adv.get("summary") or "")[:300]
            severity = str(adv.get("severity") or "medium").lower()

            if ghsa_id:
                findings.append(
                    _finding(
                        FindingType.VULNERABILITY,
                        cve_id or ghsa_id,
                        {
                            "ghsa_id": ghsa_id,
                            "cve_id": cve_id,
                            "summary": summary,
                            "severity": severity,
                            "keyword": keyword,
                            "source": self.name,
                        },
                        self.name,
                        0.7,
                    )
                )

        return {
            "source": self.name,
            "findings": findings,
            "skipped": False,
            "error": None,
            "raw": {"advisories_count": len(advisories), "matched_count": len(matched)},
        }
