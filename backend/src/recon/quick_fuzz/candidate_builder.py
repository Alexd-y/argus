"""Candidate builder — transforms fuzz results into VULN_ANALYSIS candidates.

A ``FuzzCandidate`` is a narrowed-down endpoint + parameter combination that
deserves deep testing with heavy tools (nuclei, sqlmap, dalfox, etc.) during
the VULN_ANALYSIS phase. The quick fuzzer produces these candidates as
intermediate output feeding the next phase.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FuzzCandidate(BaseModel):
    """A candidate endpoint for deep VULN_ANALYSIS testing."""

    url: str = Field(description="Target URL where the trigger occurred.")
    parameter: str = Field(default="", description="Parameter name that triggered.")
    category: str = Field(default="", description="Fuzz category (sqli, xss, etc.).")
    payload: str = Field(default="", description="The payload that triggered.")
    evidence: str = Field(default="", description="Response snippet confirming trigger.")
    severity_hint: str = Field(default="medium", description="Severity hint for VA phase.")
    status_code: int = Field(default=0, description="HTTP status code of the response.")


def build_candidates_from_fuzz_results(
    fuzz_results: list[dict[str, Any]],
) -> list[FuzzCandidate]:
    """Convert raw fuzz result dicts into structured ``FuzzCandidate`` models.

    Only includes results where ``triggered=True`` — i.e. a detection
    signature was found in the response. Non-triggered results are skipped
    because they don't deserve deep testing.
    """
    candidates: list[FuzzCandidate] = []

    for result in fuzz_results:
        if not result.get("triggered"):
            continue

        category = str(result.get("category", "")).lower()

        severity_map = {
            "sqli": "high",
            "command_injection": "high",
            "ssti": "high",
            "xxe": "high",
            "xss": "medium",
            "ssrf": "medium",
            "nosql": "medium",
            "path_traversal": "medium",
            "prompt_injection": "medium",
            "open_redirect": "low",
        }

        candidate = FuzzCandidate(
            url=str(result.get("url", "")),
            parameter=str(result.get("param", "")),
            category=category,
            payload=str(result.get("payload", ""))[:200],
            evidence=str(result.get("response_snippet", ""))[:500],
            severity_hint=severity_map.get(category, "medium"),
            status_code=int(result.get("status", 0)),
        )
        candidates.append(candidate)

    return candidates
