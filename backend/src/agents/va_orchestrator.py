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
import re
import time
from dataclasses import dataclass, field
from enum import Enum

from src.cache.scan_knowledge_base import get_knowledge_base
from src.llm.facade import call_llm_unified
from src.llm.task_router import LLMTask
from src.skills import build_skills_prompt_block

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

# OWASP Top 10:2025 id → ARGUS VA category keys (for KB tool hints).
OWASP_TO_ARGUS_CATEGORIES: dict[str, list[str]] = {
    "A01": ["idor", "auth"],
    "A02": ["info_disclosure"],
    "A03": [],
    "A04": ["auth"],
    "A05": ["sqli", "xss", "rce"],
    "A06": ["race", "auth"],
    "A07": ["auth"],
    "A08": ["file_upload", "mass_assignment"],
    "A09": ["info_disclosure"],
    "A10": ["ssrf", "xxe"],
}

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
      Step 3: Collect and merge findings

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
        self._kb_enrichment: dict[str, object] | None = None
        self._category_extra_tools: dict[str, list[str]] = {}

    @staticmethod
    def enrich_from_recon(recon_findings: list[dict]) -> dict[str, object]:
        """
        Parse OWASP/CWE hints from recon-style dicts (flexible keys) and merge KB strategy.

        Recognizes common shapes: top-level cwe/owasp fields, nested metadata, string tags.
        """
        owasp_ids: set[str] = set()
        cwe_ids: set[str] = set()

        def add_owasp(raw: str | None) -> None:
            if not raw or not isinstance(raw, str):
                return
            s = raw.strip().upper()
            m = re.search(r"A(0[1-9]|10)\b", s)
            if m:
                owasp_ids.add(f"A{m.group(1)}")

        def add_cwe(raw: str | None) -> None:
            if raw is None:
                return
            if isinstance(raw, int):
                cwe_ids.add(f"CWE-{raw}")
                return
            if not isinstance(raw, str):
                return
            m = re.search(r"(?:CWE-)?(\d+)", raw.strip(), re.I)
            if m:
                cwe_ids.add(f"CWE-{m.group(1)}")

        owasp_keys = (
            "owasp",
            "owasp_id",
            "owaspId",
            "owasp_category",
            "owasp_top10",
            "owaspTop10",
            "category_owasp",
            "owaspCategory",
        )
        cwe_keys = (
            "cwe",
            "cwe_id",
            "cweId",
            "CWE",
            "vulnerability_cwe",
            "vulnerabilityCwe",
            "cwe_list",
            "cwes",
        )

        max_walk_depth = 8
        max_walk_nodes = 2000
        walk_nodes = 0

        def walk(obj: object, depth: int = 0) -> None:
            nonlocal walk_nodes
            if depth > max_walk_depth or walk_nodes >= max_walk_nodes:
                return
            walk_nodes += 1
            if isinstance(obj, dict):
                for k, val in obj.items():
                    lk = str(k).lower()
                    if lk in {x.lower() for x in owasp_keys} or (
                        "owasp" in lk and "top" in lk
                    ):
                        if isinstance(val, list):
                            for x in val:
                                if isinstance(x, str):
                                    add_owasp(x)
                                elif isinstance(x, dict):
                                    walk(x, depth + 1)
                        elif isinstance(val, str):
                            add_owasp(val)
                    if lk in {x.lower() for x in cwe_keys} or lk == "cwe":
                        if isinstance(val, list):
                            for x in val:
                                if isinstance(x, (str, int)):
                                    add_cwe(str(x) if isinstance(x, str) else x)
                                elif isinstance(x, dict):
                                    walk(x, depth + 1)
                        else:
                            add_cwe(val if isinstance(val, (str, int)) else None)
                    walk(val, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item, depth + 1)
            elif isinstance(obj, str):
                for m in re.finditer(r"\bA(0[1-9]|10)\b", obj, re.I):
                    owasp_ids.add(f"A{m.group(1).upper()}")
                for m in re.finditer(r"CWE-?\s*(\d+)", obj, re.I):
                    cwe_ids.add(f"CWE-{m.group(1)}")

        for finding in recon_findings:
            if isinstance(finding, dict):
                walk_nodes = 0
                walk(finding)

        kb = get_knowledge_base()
        o_sorted = sorted(owasp_ids)
        c_sorted = sorted(cwe_ids)
        strategy = kb.get_scan_strategy(o_sorted, c_sorted)
        skills = strategy.get("skills", [])
        tools = strategy.get("tools", [])
        return {
            "owasp_ids": o_sorted,
            "cwe_ids": c_sorted,
            "strategy": strategy,
            "skills": skills if isinstance(skills, list) else [],
            "tools": tools if isinstance(tools, list) else [],
        }

    def determine_categories(self, recon_findings: list[dict] | None = None) -> dict[str, list[str]]:
        """Select vuln categories to test based on scan mode; optional recon OWASP/CWE enrichment via KB."""
        if self.scan_mode == ScanMode.QUICK:
            cats = {k: list(v) for k, v in CATEGORY_SKILL_MAP.items() if k in _QUICK_CATEGORIES}
        elif self.scan_mode == ScanMode.STANDARD:
            cats = {k: list(v) for k, v in CATEGORY_SKILL_MAP.items() if k in _STANDARD_CATEGORIES}
        else:
            cats = {k: list(v) for k, v in CATEGORY_SKILL_MAP.items()}

        self._kb_enrichment = None
        self._category_extra_tools = {}

        if recon_findings:
            enriched = self.enrich_from_recon(recon_findings)
            oids = enriched.get("owasp_ids", [])
            cids = enriched.get("cwe_ids", [])
            if (isinstance(oids, list) and oids) or (isinstance(cids, list) and cids):
                self._kb_enrichment = enriched
                strategy = enriched.get("strategy", {})
                kb_skills: set[str] = set()
                if isinstance(strategy, dict):
                    sk = strategy.get("skills", [])
                    if isinstance(sk, list):
                        kb_skills = {x for x in sk if isinstance(x, str)}

                skill_to_categories: dict[str, set[str]] = {}
                for cat, sl in CATEGORY_SKILL_MAP.items():
                    for s in sl:
                        skill_to_categories.setdefault(s, set()).add(cat)

                def merge_category(cat: str) -> None:
                    skill_list = CATEGORY_SKILL_MAP.get(cat)
                    if not skill_list:
                        return
                    allowed = set(skill_list)
                    prev = set(cats.get(cat, list(skill_list)))
                    merged = prev | (kb_skills & allowed)
                    cats[cat] = sorted(merged)

                for cat in list(cats.keys()):
                    merge_category(cat)

                kb_derived_cats: set[str] = set()
                for s in kb_skills:
                    kb_derived_cats |= skill_to_categories.get(s, set())
                for cat in kb_derived_cats:
                    merge_category(cat)

                if isinstance(oids, list):
                    for oid in oids:
                        if not isinstance(oid, str):
                            continue
                        for va_cat in OWASP_TO_ARGUS_CATEGORIES.get(oid.strip().upper(), []):
                            if va_cat:
                                merge_category(va_cat)

                kb = get_knowledge_base()
                extra_tools: dict[str, list[str]] = {}
                if isinstance(oids, list):
                    for oid in oids:
                        if not isinstance(oid, str):
                            continue
                        tools = kb.get_tools_for_owasp(oid)
                        for va_cat in OWASP_TO_ARGUS_CATEGORIES.get(oid.upper(), []):
                            if va_cat not in cats:
                                continue
                            bucket = extra_tools.setdefault(va_cat, [])
                            for t in tools:
                                if t not in bucket:
                                    bucket.append(t)
                self._category_extra_tools = extra_tools

        self.stats.categories_tested = list(cats.keys())
        return cats

    async def run_discovery(
        self,
        target_url: str,
        scan_id: str,
        recon_findings: list[dict] | None = None,
    ) -> list[dict]:
        """
        Run parallel discovery agents and return merged findings.

        Each agent receives:
        - Category-specific skills content in system prompt
        - Target URL and scan context
        - Temperature based on scan mode
        """
        t0 = time.monotonic()
        categories = self.determine_categories(recon_findings)

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
        _scan_id: str,
        semaphore: asyncio.Semaphore,
    ) -> DiscoveryResult:
        """Run a single category-specific discovery agent."""
        async with semaphore:
            t0 = time.monotonic()
            skills_block = build_skills_prompt_block(skill_names)
            system_prompt = DISCOVERY_SYSTEM_PROMPT
            if skills_block:
                system_prompt += "\n\n" + skills_block

            base_tools = TOOLS_BY_CATEGORY.get(category, [])
            extra = self._category_extra_tools.get(category, [])
            tools = list(dict.fromkeys([*base_tools, *extra]))
            user_prompt = (
                f"Target: {target_url}\n"
                f"Category: {category}\n"
                f"Your task: Find all {category} vulnerabilities.\n"
                f"Think like a bug bounty hunter. Only report what would earn $500+ reward.\n"
                f"Use tools: {', '.join(tools)}\n\n"
                f"Run comprehensive tests. Return findings as a JSON array."
            )

            try:
                text = await call_llm_unified(
                    system_prompt,
                    user_prompt,
                    task=LLMTask.VALIDATION_ONESHOT,
                    scan_id=_scan_id or None,
                    phase="va_discovery",
                )
                findings = self._parse_findings(text, category, target_url)
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

    def _parse_findings(self, text: str, category: str, _target_url: str) -> list[dict]:
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
