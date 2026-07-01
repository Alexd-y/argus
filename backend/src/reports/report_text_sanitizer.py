"""VHQ-010 — Post-process AI-generated report text to clean:
- Markdown artifacts (``` fences, **bold** markers, code blocks in HTML)
- Raw prompt leakage (prompt instructions that LLM regurgitated)
- Common AI-isms and boilerplate patterns
- Duplicate paragraph detection
- Code garbage (C/C++/Python/Java snippets)
- ANSI escape sequences from terminal output
- Cross-reference placeholder spam (\"See «...»\")
"""

import re
import logging

logger = logging.getLogger(__name__)

# ANSI escape sequence stripper — terminal control chars from raw tool output
_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# Code garbage patterns (C/C++/Python/Java/Shell)
_CODE_GARBAGE = [
    re.compile(r'^\s*#include\s*[<"]', re.I | re.MULTILINE),
    re.compile(r'\bint\s+main\s*\(\s*\)', re.I),
    re.compile(r'\bstd::(cout|cin|cerr|endl|vector|string)\b', re.I),
    re.compile(r'\bSystem\.out\.println', re.I),
    re.compile(r'\bpublic\s+static\s+void\s+main', re.I),
    re.compile(r'^\s*#!/bin/(bash|sh|zsh)\b', re.I | re.MULTILINE),
    re.compile(r'\bdef\s+(main|test|foo|bar)\s*\(\s*\)', re.I),
]

# AI stub patterns — telltale signs of unhelpful LLM fallback output
_AI_STUB_PATTERNS = [
    re.compile(r'\bHello[,!]\s*World[!.]?\b', re.I),
    re.compile(r'#include\s*<iostream>', re.I),
    re.compile(r'#include\s*<stdio\.h>', re.I),
    re.compile(r'\bint\s+main\s*\(\s*\)\s*\{', re.I),
    re.compile(r'<h[1-6][^>]*>\s*This is a (?:code block|title|heading)\s*</h[1-6]>', re.I),
    re.compile(r'\bSee Attack Scenarios\b', re.I),
    re.compile(r'\bNo remediation matrix available\b', re.I),
    re.compile(r'\bReview finding details and apply appropriate fix\b', re.I),
    re.compile(r'\bUnknown component\b', re.I),
    re.compile(r'\bDevelopment team\b(?!\s+of)'),
    re.compile(r'high\s*\|\s*medium\s*\|\s*low', re.I),
    re.compile(r'\(See\s+\w+\s+Scenarios\)', re.I),
    re.compile(r'iostream>\s*\{', re.I),
    re.compile(r'cout\s*<<\s*"Hello', re.I),
    re.compile(r'printf\s*\(\s*"Hello', re.I),
    re.compile(r'\bprint\s*\(\s*"Hello', re.I),
    re.compile(r'\bpotential security compromise\b', re.I),
    re.compile(r'\bassess before deployment\b', re.I),
    re.compile(r'\bfollow security best practices\b', re.I),
    re.compile(r'\bimplement proper (?:security )?measures?\b', re.I),
    re.compile(r'\bregularly (?:update|patch|review)\b', re.I),
    re.compile(r'\bcould (?:allow|lead to|result in|enable)\b', re.I),
    re.compile(r'\bposes? a risk\b', re.I),
    re.compile(r'\bis a significant concern\b', re.I),
    re.compile(r'\bvalidate all input\b', re.I),
    re.compile(r'\bfinding no longer reproducible under same conditions\b', re.I),
    re.compile(r'\bverify finding is no longer reproducible\b', re.I),
    re.compile(r'\bSee\s+«[^»]+»\s+(?:section|Section)\b', re.I),
]

# Cross-reference placeholder pattern
_CROSS_REF_RE = re.compile(
    r'\(See\s+«[^»]+»\s+(?:section|Section)\s+for\s+additional\s+details\.?\)',
    re.IGNORECASE,
)

# HTML tags leaking into AI text sections
_HTML_TAG_LEAKAGE = [
    (re.compile(r'<li>\s*', re.I), ''),
    (re.compile(r'</li>\s*', re.I), ''),
    (re.compile(r'<p>\s*', re.I), ''),
    (re.compile(r'</p>\s*', re.I), ''),
]

# Patterns that indicate the LLM regurgitated the prompt instead of answering.
# NOTE: keep markers specific to prompt scaffolding so legitimate prose is not stripped.
# The EFFORT ESTIMATE / IMPLEMENTATION CONTROL / VERIFICATION COMMAND / GROUNDING RULES /
# "Finding reference: finding_id" / "Avoid one-line boilerplate" markers and the embedded
# context-JSON keys below were observed leaking verbatim into a real remediation_step section.
_PROMPT_LEAKAGE_PATTERNS = [
    r"ROLE:\s*You are an?\s",
    r"FOCUS:\s*(?:assess|describe|explain|outline|list|map|propose)\s",
    r"\bCONSTRAINTS:\s",
    r"\bGROUNDING:\s",
    r"\bGROUNDING RULES:\s",
    r"\bSTRICT RULES FOR ALL REPORT SECTIONS:\s",
    r"\bLANGUAGE:\s*Write in English",
    r"\bSECTION_ID:\s*\w+",
    r"\bALREADY WRITTEN SECTIONS\b",
    r"\bContext JSON:\s*\n?\{",
    r"\bEFFORT ESTIMATE:\s",
    r"\bIMPLEMENTATION CONTROL:\s",
    r"\bVERIFICATION COMMAND:\s",
    r"\bFinding reference:\s*finding_id\b",
    r"\bAvoid one-line boilerplate\b",
    r'"cwe_ids_found"\s*:',
    r'"executive_severity_totals"\s*:',
    r'"finding_count"\s*:\s*\d',
    r'"validation_status"\s*:\s*"',
    r"^(?:1\.|2\.|3\.|4\.|5\.)\s+Do any findings\b",
    r"\bDo\s+NOT\s+repeat\s+the\s+findings\s+list\b",
    r"\bDo NOT repeat content from the Executive Summary\b",
    r"\bDo NOT summarize individual findings\b",
    r"\bTie discussion to concrete\b",
    r"\bseparate known CVE-backed risk\b",
    r"\bPlain prose, 2–4 paragraphs\.\s+End with the rating line\b",
]

# Markdown artifacts that shouldn't appear in HTML report
_MARKDOWN_ARTIFACTS = [
    (re.compile(r"```(?:json|html|code|text)?\s*\n"), "\n"),
    (re.compile(r"```"), ""),
    (re.compile(r"\*\*(.+?)\*\*"), r"\1"),
    (re.compile(r"`([^`]+)`"), r"\1"),
]

# Generic AI boilerplate that adds no value
_AI_BOILERPLATE = [
    r"\bcomprehensive (?:penetration test|security assessment)\b",
    r"\bthe assessment revealed\b",
    r"\bit is (?:important|crucial|essential|vital|critical|key)\s+(?:to|that|for)\b",
    r"\bin (?:terms|relation) of\b",
    r"\b(?:relatively stable|positive observation)\b",
    r"\babsence of critical vulnerabilities\b",
    r"\bno critical vulnerabilities\b",
    r"\bno findings means secure\b",
    r"\bconfirmed these findings without false positives\b",
    r"\bunauthorized transactions\b",
    r"\bregulatory fines\b",
    r"\bfinancial fraud\b",
    r"\bcomprehensive penetration test\b",
    r"\bin today's (?:digital|cyber|threat) landscape\b",
    r"\bstate-of-the-art\b",
    r"\best?ablished protocols?\b",
    r"\brobust security measures?\b",
    r"\bleveraging advanced\b",
    r"\bseamlessly (?:integrates?|ensures?)\b",
]

# Section titles that should NOT appear inside generated text
_SECTION_TITLE_LEAKAGE = [
    r"^(?:Executive Summary|Vulnerability Description|Remediation Steps?|Business Risk|"
    r"Compliance Check|Prioritization Roadmap|Hardening Recommendations|"
    r"Attack Scenarios|Exploit Chains|Remediation Stages|Zero-Day Potential|"
    r"Cost Summary|Novel Vulnerability Indication)",
]

_COMPILED_LEAKAGE = [re.compile(p, re.IGNORECASE) for p in _PROMPT_LEAKAGE_PATTERNS]
_COMPILED_BOILER = [re.compile(p, re.IGNORECASE) for p in _AI_BOILERPLATE]
_COMPILED_TITLE = [re.compile(p, re.IGNORECASE) for p in _SECTION_TITLE_LEAKAGE]


def sanitize_ai_report_text(text: str) -> str:
    """Clean AI-generated text for HTML/MD embedding. Removes prompt leakage,
    Markdown artifacts, AI boilerplate, code garbage, ANSI escapes, and cross-ref spam."""
    if not text or not isinstance(text, str):
        return text or ""

    original_len = len(text)

    # 0. Strip ANSI escape sequences first (terminal control chars)
    text = _ANSI_ESCAPE_RE.sub('', text)

    # 1. Remove prompt leakage
    for pat in _COMPILED_LEAKAGE:
        text = pat.sub("", text)

    # 2. Clean Markdown artifacts
    for pat, replacement in _MARKDOWN_ARTIFACTS:
        text = pat.sub(replacement, text)

    # 3. Remove AI boilerplate
    for pat in _COMPILED_BOILER:
        text = pat.sub("", text)

    # 4. Remove section title leakage inside body
    for pat in _COMPILED_TITLE:
        text = pat.sub("", text, count=1)

    # 5. Strip code garbage (C/C++/Python/Java/Shell snippets)
    for pat in _CODE_GARBAGE:
        text = pat.sub('', text)

    # 5b. Detect and replace AI stub output (Hello World, code blocks, placeholders)
    if contains_ai_stub_output(text):
        return "No evidence-backed narrative available for this section. The generated content contained placeholder text and has been replaced with structured data from findings."

    # 6. Strip HTML tags leaking into AI text sections
    for pat, replacement in _HTML_TAG_LEAKAGE:
        text = pat.sub(replacement, text)

    # 7. Replace cross-reference placeholder spam with meaningful text
    # Count cross-refs; if > 50% of content is cross-refs, replace whole section
    cross_refs = _CROSS_REF_RE.findall(text)
    if cross_refs:
        text_without_refs = _CROSS_REF_RE.sub('', text).strip()
        meaningful_chars = sum(1 for c in text_without_refs if c.isalnum())
        if meaningful_chars < 50:
            text = "No evidence-backed narrative available. See the relevant technical section for structured findings data."
        else:
            text = text_without_refs

    # 8. Collapse multiple blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    # 9. Remove leading/trailing whitespace
    text = text.strip()

    if len(text) < original_len * 0.3 and original_len > 100:
        logger.warning(
            "report_text_sanitizer_heavy_truncation",
            extra={"original_len": original_len, "sanitized_len": len(text)},
        )

    return text


def contains_raw_prompt_leakage(text: str) -> bool:
    """Detect if AI output contains unprocessed prompt instructions."""
    if not text:
        return False
    for pat in _COMPILED_LEAKAGE:
        if pat.search(text):
            return True
    return False


def contains_ai_stub_output(text: str) -> bool:
    """Detect if AI output is a stub/placeholder instead of real content.

    Catches: Hello World programs, HTML code blocks as section content,
    placeholder patterns like 'high|medium|low', 'See Attack Scenarios',
    'No remediation matrix available', generic boilerplate fix actions.
    """
    if not text or not isinstance(text, str):
        return False
    for pat in _AI_STUB_PATTERNS:
        if pat.search(text):
            return True
    return False


def find_duplicate_paragraphs(text: str, threshold: float = 0.80) -> list[str]:
    """Find paragraphs that appear nearly-identical across sections."""
    paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 50]
    duplicates = []
    seen_terms: list[frozenset[str]] = []
    for p in paragraphs:
        words = frozenset(p.lower().split())
        if not words:
            continue
        best_overlap = 0.0
        for s in seen_terms:
            overlap = len(words & s) / max(len(words | s), 1)
            if overlap > best_overlap:
                best_overlap = overlap
        if best_overlap > threshold:
            duplicates.append(p[:120] + "..." if len(p) > 120 else p)
        seen_terms.append(words)
    return duplicates
