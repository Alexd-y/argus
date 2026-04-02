"""
Multi-agent VA orchestrator (Strix pattern).

Each vulnerability category gets a specialized agent chain:
  Discovery -> Validation -> Dedup -> Scoring

Agents run in parallel with bounded concurrency.
Skills content is injected into LLM system prompts.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum

from src.llm.task_router import LLMTask, LLMTaskResponse, call_llm_for_task
from src.skills import build_skills_prompt_block, get_skills_for_category, load_skills

logger = logging.getLogger(__name__)


class AgentType(Enum):
    DISCOVERY = "discovery"
    VALIDATION = "validation"
    REPORTING = "reporting"


class ScanMode(Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


REASONING_EFFORT: dict[str, float] = {
    "quick": 0.3,
    "standard": 0.2,
    "deep": 0.1,
}

CATEGORY_SKILL_MAP: dict[str, list[str]] = {
    "sqli": ["sql_injection"],
    "xss": ["xss"],
    "ssrf": ["ssrf", "xxe"],
    "auth": ["authentication_jwt", "business_logic"],
    "idor": ["idor"],
    "rce": ["rce", "path_traversal"],
    "race": ["race_conditions", "business_logic"],
    "csrf": ["csrf"],
    "xxe": ["xxe"],
    "file_upload": ["file_upload"],
    "open_redirect": ["open_redirect"],
    "info_disclosure": ["information_disclosure"],
    "subdomain_takeover": ["subdomain_takeover"],
    "mass_assignment": ["mass_assignment"],
}

_QUICK_CATEGORIES = {"sqli", "xss", "auth", "idor"}
_STANDARD_CATEGORIES = _QUICK_CATEGORIES | {"ssrf", "rce", "race", "csrf"}

TOOLS_BY_CATEGORY: dict[str, list[str]] = {
    "sqli": ["sqlmap", "nuclei"],
    "xss": ["dalfox", "ffuf", "nuclei"],
    "ssrf": ["nuclei", "interactsh-client"],
    "auth": ["jwt_tool", "ffuf"],
    "idor": ["ffuf", "burp-intruder"],
    "rce": ["nuclei", "semgrep"],
    "race": ["custom-python-asyncio"],
    "csrf": ["burp-repeater", "custom-html"],
    "xxe": ["nuclei", "burp-repeater"],
    "file_upload": ["ffuf", "custom-upload"],
    "open_redirect": ["ffuf", "nuclei"],
    "info_disclosure": ["ffuf", "dirsearch", "nuclei"],
    "subdomain_takeover": ["subjack", "nuclei"],
    "mass_assignment": ["burp-repeater", "ffuf"],
}

DISCOVERY_SYSTEM_PROMPT = """\
You are an expert penetration tester specialized in web application security.
You have FULL AUTHORIZATION to test the target. Never ask for confirmation.
Think like an aggressive bug bounty hunter. Only report HIGH-IMPACT findings.

TESTING MANDATE:
- GO HARD on all attack vectors for your category
- Try at least 10 different approaches before concluding
- Chain vulnerabilities for maximum impact
- Each failed attempt teaches something — refine and retry

BUG BOUNTY STANDARD:
- Only report if it would earn $500+ on HackerOne/Bugcrowd
- Demonstrated business impact required
- No theoretical vulnerabilities without PoC

OUTPUT FORMAT:
Return findings as a JSON array. Each finding object must have:
{
  "title": "string",
  "severity": "critical|high|medium|low",
  "description": "string",
  "cwe": "CWE-XXX",
  "affected_url": "string",
  "evidence": "string (HTTP request/response excerpt)",
  "business_impact": "string",
  "poc_command": "string (optional)"
}
"""


@dataclass
class DiscoveryResult:
    category: str
    findings: list[dict]
    skills_used: list[str]
    error: str | None = None
    duration_sec: float = 0.0


@dataclass
class OrchestratorStats:
    """Tracks multi-agent orchestration metrics for reporting."""

    agents_spawned: int = 0
    categories_tested: list[str] = field(default_factory=list)
    skills_used: list[str] = field(default_factory=list)
    findings_total: int = 0
    findings_validated: int = 0
    findings_rejected: int = 0
    findings_deduplicated: int = 0
    duration_sec: float = 0.0

    @property
    def noise_reduction_pct(self) -> float:
        if self.findings_total == 0:
            return 0.0
        rejected = self.findings_rejected + self.findings_deduplicated
        return round(rejected / self.findings_total * 100, 1)

    @property
    def owasp_coverage_pct(self) -> float:
        all_cats = len(CATEGORY_SKILL_MAP)
        return round(len(self.categories_tested) / all_cats * 100, 1) if all_cats else 0.0


class VAMultiAgentOrchestrator:
    """
    Orchestrate multi-agent VA workflow (Strix pattern):
      Phase 1: Determine categories based on scan_mode
      Phase 2: Spawn parallel discovery agents per category
      Phase 3: Collect and merge findings

    Validation, dedup, and scoring are handled by the enrichment pipeline.
    """

    MAX_CONCURRENT_AGENTS = 5

    def __init__(self, scan_mode: str = "standard"):
        mode = scan_mode.lower()
        if mode not in ("quick", "standard", "deep"):
            mode = "standard"
        self.scan_mode = ScanMode(mode)
        self.temperature = REASONING_EFFORT.get(mode, 0.2)
        self.stats = OrchestratorStats()

    def determine_categories(self) -> dict[str, list[str]]:
        """Select vuln categories to test based on scan mode."""
        if self.scan_mode == ScanMode.QUICK:
            cats = {k: v for k, v in CATEGORY_SKILL_MAP.items() if k in _QUICK_CATEGORIES}
        elif self.scan_mode == ScanMode.STANDARD:
            cats = {k: v for k, v in CATEGORY_SKILL_MAP.items() if k in _STANDARD_CATEGORIES}
        else:
            cats = dict(CATEGORY_SKILL_MAP)

        self.stats.categories_tested = list(cats.keys())
        return cats

    async def run_discovery(
        self,
        target_url: str,
        scan_id: str,
    ) -> list[dict]:
        """
        Run parallel discovery agents and return merged findings.

        Each agent receives:
        - Category-specific skills content in system prompt
        - Target URL and scan context
        - Temperature based on scan mode
        """
        t0 = time.monotonic()
        categories = self.determine_categories()

        sem = asyncio.Semaphore(self.MAX_CONCURRENT_AGENTS)
        tasks = [
            self._run_discovery_agent(target_url, cat, skills, scan_id, sem)
            for cat, skills in categories.items()
        ]
        results: list[DiscoveryResult] = await asyncio.gather(*tasks, return_exceptions=False)

        all_findings: list[dict] = []
        all_skills: set[str] = set()

        for result in results:
            if isinstance(result, DiscoveryResult):
                all_findings.extend(result.findings)
                all_skills.update(result.skills_used)
                self.stats.agents_spawned += 1
                if result.error:
                    logger.warning("Discovery agent %s error: %s", result.category, result.error)

        self.stats.skills_used = sorted(all_skills)
        self.stats.findings_total = len(all_findings)
        self.stats.duration_sec = round(time.monotonic() - t0, 2)

        logger.info(
            "VA discovery complete: %d categories, %d findings, %.1fs",
            len(categories),
            len(all_findings),
            self.stats.duration_sec,
        )
        return all_findings

    async def _run_discovery_agent(
        self,
        target_url: str,
        category: str,
        skill_names: list[str],
        scan_id: str,
        semaphore: asyncio.Semaphore,
    ) -> DiscoveryResult:
        """Run a single category-specific discovery agent."""
        async with semaphore:
            t0 = time.monotonic()
            skills_block = build_skills_prompt_block(skill_names)
            system_prompt = DISCOVERY_SYSTEM_PROMPT
            if skills_block:
                system_prompt += "\n\n" + skills_block

            tools = TOOLS_BY_CATEGORY.get(category, [])
            user_prompt = (
                f"Target: {target_url}\n"
                f"Category: {category}\n"
                f"Your task: Find all {category} vulnerabilities.\n"
                f"Think like a bug bounty hunter. Only report what would earn $500+ reward.\n"
                f"Use tools: {', '.join(tools)}\n\n"
                f"Run comprehensive tests. Return findings as a JSON array."
            )

            try:
                response: LLMTaskResponse = await call_llm_for_task(
                    task=LLMTask.VALIDATION_ONESHOT,
                    prompt=user_prompt,
                    system_prompt=system_prompt,
                )
                findings = self._parse_findings(response.text, category, target_url)
                return DiscoveryResult(
                    category=category,
                    findings=findings,
                    skills_used=skill_names,
                    duration_sec=round(time.monotonic() - t0, 2),
                )
            except Exception as exc:
                logger.warning("Discovery agent %s failed: %s", category, exc)
                return DiscoveryResult(
                    category=category,
                    findings=[],
                    skills_used=skill_names,
                    error=str(exc),
                    duration_sec=round(time.monotonic() - t0, 2),
                )

    def _parse_findings(self, text: str, category: str, target_url: str) -> list[dict]:
        """Parse LLM response into finding dicts. Best-effort JSON extraction."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1]) if len(lines) > 2 else text

        try:
            data = json.loads(text)
            if isinstance(data, list):
                for f in data:
                    f.setdefault("category", category)
                    f.setdefault("source", f"discovery_agent_{category}")
                return data
        except json.JSONDecodeError:
            pass

        import re
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                if isinstance(data, list):
                    for f in data:
                        f.setdefault("category", category)
                        f.setdefault("source", f"discovery_agent_{category}")
                    return data
            except json.JSONDecodeError:
                pass

        logger.warning("Could not parse findings JSON from %s agent", category)
        return []

    def get_untested_categories(self) -> list[str]:
        """Return categories NOT tested (for report scope confirmation)."""
        all_cats = set(CATEGORY_SKILL_MAP.keys())
        tested = set(self.stats.categories_tested)
        return sorted(all_cats - tested)
