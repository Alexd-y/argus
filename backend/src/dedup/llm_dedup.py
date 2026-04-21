"""
LLM-based vulnerability deduplication.

Replaces difflib-based dedup with semantic LLM analysis.
Uses XML-structured responses for reliable parsing (Strix pattern).
Falls back to is_duplicate=False on any error (safe-by-default).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from src.llm.task_router import LLMTask, call_llm_for_task

logger = logging.getLogger(__name__)

DEDUPE_SYSTEM_PROMPT = """\
You are a security vulnerability deduplication expert.
Determine if a candidate vulnerability is a DUPLICATE of any existing report.

SAME VULNERABILITY (is_duplicate=true) when ALL of:
- Same ROOT CAUSE (not just same vulnerability type)
- Same AFFECTED COMPONENT (same endpoint, file, or parameter)
- Same EXPLOITATION METHOD (same attack vector)
- Would be FIXED BY THE SAME CODE CHANGE

NOT DUPLICATES even if same vulnerability type:
- Different endpoints: SQLi in /login != SQLi in /search
- Different parameters in same endpoint
- Different root causes: stored XSS != reflected XSS
- Different severity due to different impact scope
- Different authentication requirements to trigger

ARE DUPLICATES despite:
- Different title wording or description detail
- Different PoC payloads (same vuln, different proof)
- Different report thoroughness level

LEAN TOWARD NOT DUPLICATE when uncertain.

Respond ONLY in this XML format, no text outside tags:
<dedupe_result>
  <is_duplicate>true/false</is_duplicate>
  <duplicate_id>existing_id_or_empty_string</duplicate_id>
  <confidence>0.0-1.0</confidence>
  <reason>mention specific endpoint/parameter/root cause</reason>
</dedupe_result>
"""

DEDUPE_USER_TEMPLATE = """\
CANDIDATE VULNERABILITY:
Title: {candidate_title}
Type: {candidate_cwe} / {candidate_owasp}
Affected URL: {candidate_url}
Description: {candidate_desc}
Evidence: {candidate_evidence}

EXISTING REPORTS TO COMPARE AGAINST:
{existing_reports_xml}

Is the candidate a duplicate of any existing report?
"""


@dataclass(frozen=True)
class DedupResult:
    is_duplicate: bool
    confidence: float = 0.0
    duplicate_id: str | None = None
    reason: str = ""


def _extract_xml_tag(text: str, tag: str) -> str:
    """Extract content of an XML tag from text. Returns empty string on miss."""
    match = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _parse_dedupe_response(text: str) -> DedupResult:
    """Parse XML response from LLM. Returns safe defaults on parse failure."""
    try:
        is_dup = _extract_xml_tag(text, "is_duplicate").lower() == "true"
        raw_conf = _extract_xml_tag(text, "confidence") or "0.0"
        confidence = min(max(float(raw_conf), 0.0), 1.0)
        dup_id = _extract_xml_tag(text, "duplicate_id") or None
        reason = _extract_xml_tag(text, "reason")
        return DedupResult(
            is_duplicate=is_dup,
            confidence=confidence,
            duplicate_id=dup_id,
            reason=reason,
        )
    except Exception:
        return DedupResult(is_duplicate=False, confidence=0.0, reason="XML parse failed")


def _build_existing_xml(findings: list[dict]) -> str:
    """Format existing findings as XML blocks for the LLM prompt."""
    parts: list[str] = []
    for f in findings[-20:]:
        fid = f.get("id", "unknown")
        title = str(f.get("title", ""))[:200]
        cwe = f.get("cwe", "N/A")
        owasp = f.get("owasp_category", "N/A")
        url = f.get("affected_url", f.get("url", "N/A"))
        desc = str(f.get("description", ""))[:500]
        parts.append(
            f'<report id="{fid}">\n'
            f"  <title>{title}</title>\n"
            f"  <type>{cwe}/{owasp}</type>\n"
            f"  <url>{url}</url>\n"
            f"  <description>{desc}</description>\n"
            f"</report>"
        )
    return "\n".join(parts)


async def check_duplicate(
    candidate: dict,
    existing_findings: list[dict],
) -> DedupResult:
    """
    LLM-based deduplication check.

    Safe-by-default: on any error returns ``is_duplicate=False``.
    Uses ``LLMTask.DEDUP_ANALYSIS`` (cheapest model route).
    """
    if not existing_findings:
        return DedupResult(is_duplicate=False, confidence=1.0, reason="No existing reports")

    existing_xml = _build_existing_xml(existing_findings)

    user_prompt = DEDUPE_USER_TEMPLATE.format(
        candidate_title=str(candidate.get("title", ""))[:200],
        candidate_cwe=candidate.get("cwe", "N/A"),
        candidate_owasp=candidate.get("owasp_category", "N/A"),
        candidate_url=candidate.get("affected_url", candidate.get("url", "N/A")),
        candidate_desc=str(candidate.get("description", ""))[:500],
        candidate_evidence=str(candidate.get("evidence", ""))[:300],
        existing_reports_xml=existing_xml,
    )

    try:
        response = await call_llm_for_task(
            task=LLMTask.DEDUP_ANALYSIS,
            prompt=user_prompt,
            system_prompt=DEDUPE_SYSTEM_PROMPT,
        )
        return _parse_dedupe_response(response.text)
    except Exception as exc:
        logger.warning("Dedup check failed for %s: %s", candidate.get("id"), exc)
        return DedupResult(is_duplicate=False, confidence=0.0, reason=f"LLM call failed: {type(exc).__name__}")


async def check_duplicates_batch(
    findings: list[dict],
    confidence_threshold: float = 0.7,
) -> tuple[list[dict], list[dict]]:
    """
    Run dedup on a list of findings sequentially.

    Returns ``(unique_findings, duplicate_findings)``.
    A finding is marked duplicate only if ``is_duplicate=True``
    and ``confidence >= confidence_threshold``.
    """
    unique: list[dict] = []
    duplicates: list[dict] = []

    for finding in findings:
        if not unique:
            finding["dedup_status"] = "unique"
            unique.append(finding)
            continue

        result = await check_duplicate(finding, unique)
        if result.is_duplicate and result.confidence >= confidence_threshold:
            finding["dedup_status"] = "duplicate"
            finding["dedup_reason"] = result.reason
            finding["dedup_duplicate_of"] = result.duplicate_id
            duplicates.append(finding)
            logger.info(
                "Finding '%s' is duplicate (conf=%.2f): %s",
                finding.get("title", "?"),
                result.confidence,
                result.reason,
            )
        else:
            finding["dedup_status"] = "unique"
            unique.append(finding)

    return unique, duplicates
