"""VHQ-002 — Deduplicate findings before report generation.

Removes duplicate findings that appear from both tool detection and LLM
heuristics (e.g. "missing security headers" as both confirmed and
web_vuln_heuristics finding).

Two findings are considered duplicates when:
- **Hard dedup**: identical CWE *and* identical normalised affected URL.
- **Soft dedup**: title similarity > 85 % (handles LLM paraphrase variants).

When a duplicate pair is detected the finding with the richer data
(description, PoC, CVSS) is kept.
"""

from __future__ import annotations

import contextlib
import logging
import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse, parse_qs

from src.reports.report_quality_gate import is_http_header_gap_topic

logger = logging.getLogger(__name__)

_TITLE_SIMILARITY_THRESHOLD = 0.85

# VAL-002 — canonical title for merged HTTP response header gap findings
_CANONICAL_HTTP_HEADER_TITLE = "Missing or incomplete HTTP security response headers"
# VAL-002 / VAL-006 — store 2025 A02 (Security Misconfiguration). Valhalla reports render **A05:2021** for user-facing text.
_DEFAULT_HEADER_GAP_OWASP = "A02"
_DEFAULT_HEADER_GAP_CWE = "CWE-693"


def _affected_url_for_merge(candidate: Any) -> str:
    u = _get_attr(candidate, "affected_url")
    if isinstance(u, str) and u.strip():
        return u.strip()
    poc = _get_attr(candidate, "proof_of_concept")
    if isinstance(poc, dict):
        for k in ("request_url", "url", "affected_url"):
            v = poc.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def _set_fields_on_finding(keeper: Any, updates: dict[str, Any]) -> None:
    if isinstance(keeper, dict):
        keeper.update(updates)
        return
    for k, v in updates.items():
        with contextlib.suppress(Exception):
            setattr(keeper, k, v)


def _merge_header_gap_group(group: list[Any]) -> Any:
    if len(group) == 1:
        f0 = group[0]
        if is_http_header_gap_topic(f0):
            _set_fields_on_finding(
                f0,
                {
                    "title": _CANONICAL_HTTP_HEADER_TITLE,
                    "owasp_category": _get_attr(f0, "owasp_category") or _DEFAULT_HEADER_GAP_OWASP,
                    "cwe": _get_attr(f0, "cwe") or _DEFAULT_HEADER_GAP_CWE,
                },
            )
        return f0
    best = max(group, key=_richness_score)
    merged_desc = str(_get_attr(best, "description") or "").strip()
    for o in group:
        if o is best:
            continue
        m = str(_get_attr(o, "description") or "").strip()
        if m and m not in merged_desc:
            merged_desc = f"{merged_desc}\n\n(merged) {m}" if merged_desc else m
    refs_a = _get_attr(best, "evidence_refs")
    rlist: list[str] = []
    if isinstance(refs_a, list):
        rlist.extend(str(x) for x in refs_a if x is not None)
    seen = {str(x) for x in rlist}
    for o in group:
        if o is best:
            continue
        er = _get_attr(o, "evidence_refs")
        if isinstance(er, list):
            for x in er:
                s = str(x)
                if s and s not in seen:
                    seen.add(s)
                    rlist.append(s)
    updates = {
        "title": _CANONICAL_HTTP_HEADER_TITLE,
        "description": merged_desc,
        "owasp_category": _get_attr(best, "owasp_category") or _DEFAULT_HEADER_GAP_OWASP,
        "cwe": _get_attr(best, "cwe") or _DEFAULT_HEADER_GAP_CWE,
        "evidence_refs": (rlist[:64] if rlist else _get_attr(best, "evidence_refs")),
    }
    _set_fields_on_finding(best, updates)
    return best


def _is_xss_finding(f: Any) -> bool:
    cwe = str(_get_attr(f, "cwe") or "").lower()
    if cwe in {"cwe-79", "cwe-83", "79"} or "cwe-79" in cwe:
        return True
    blob = f"{_get_attr(f, 'title') or ''}\n{_get_attr(f, 'description') or ''}".lower()
    return "xss" in blob or "cross-site scripting" in blob


def _xss_group_key(f: Any) -> str:
    u = _normalize_url(_affected_url_for_merge(f) or "")
    poc = _get_attr(f, "proof_of_concept")
    if not isinstance(poc, dict):
        poc = {}
    param = str(poc.get("parameter") or poc.get("param") or "")
    m = re.search(r"[?&]([a-zA-Z0-9_]+)=", u)
    if m and not param:
        param = m.group(1)
    if not param:
        try:
            qs = parse_qs(urlparse(u).query, keep_blank_values=True)
            param = ",".join(sorted(qs.keys())[:3])
        except Exception:
            param = ""
    cwe = str(_get_attr(f, "cwe") or "CWE-79")
    return f"{u}::{param}::{cwe}"


def merge_reflected_xss_findings(findings: list[Any]) -> list[Any]:
    """Merge duplicate reflected/stored XSS rows that share URL/parameter/CWE (e.g. scanner noise)."""
    if not findings:
        return findings
    xssish: list[Any] = []
    others: list[Any] = []
    for f in findings:
        if _is_xss_finding(f):
            xssish.append(f)
        else:
            others.append(f)
    if not xssish:
        return findings
    by_key: dict[str, list[Any]] = {}
    for f in xssish:
        by_key.setdefault(_xss_group_key(f), []).append(f)
    merged: list[Any] = []
    for _k, group in by_key.items():
        best = max(group, key=_richness_score)
        if len(group) > 1:
            desc = str(_get_attr(best, "description") or "").strip()
            for o in group:
                if o is best:
                    continue
                t = str(_get_attr(o, "description") or "").strip()
                if t and t not in desc:
                    desc = f"{desc}\n(merged similar XSS) {t}" if desc else t
            _set_fields_on_finding(
                best,
                {"description": desc[:20000] if desc else _get_attr(best, "description")},
            )
        merged.append(best)
    return others + merged


def merge_http_security_header_gaps(findings: list[Any]) -> list[Any]:
    """VAL-002: collapse same-URL header-gap duplicates to one canonical-titled finding."""
    if not findings:
        return findings
    headerish: list[Any] = []
    others: list[Any] = []
    for f in findings:
        if is_http_header_gap_topic(f):
            headerish.append(f)
        else:
            others.append(f)
    if not headerish:
        return findings
    by_key: dict[str, list[Any]] = {}
    for f in headerish:
        u = _normalize_url(_affected_url_for_merge(f))
        key = u or "__no_url__"
        by_key.setdefault(key, []).append(f)
    merged_headers: list[Any] = []
    for _k, group in by_key.items():
        merged_headers.append(_merge_header_gap_group(group))
    return others + merged_headers


def deduplicate_findings(findings: list[Any]) -> list[Any]:
    """Return a new list with duplicate findings removed.

    Keeps the finding with the higher *richness score* when a duplicate
    pair is detected.  The input list is not mutated.
    """
    if not findings:
        return findings

    findings = merge_http_security_header_gaps(list(findings))

    seen: list[Any] = []
    removed_count = 0

    for candidate in findings:
        is_dup = False
        for i, existing in enumerate(seen):
            if _is_hard_duplicate(candidate, existing) or _is_soft_duplicate(candidate, existing):
                is_dup = True

            if is_dup:
                if _richness_score(candidate) > _richness_score(existing):
                    seen[i] = candidate
                removed_count += 1
                break

        if not is_dup:
            seen.append(candidate)

    if removed_count > 0:
        logger.info(
            "finding_dedup_complete",
            extra={
                "component": "finding_dedup",
                "event": "dedup_complete",
                "removed": removed_count,
                "before": len(findings),
                "after": len(seen),
            },
        )

    return seen


# ---------------------------------------------------------------------------
# Duplicate detection helpers
# ---------------------------------------------------------------------------

def _is_hard_duplicate(candidate: Any, existing: Any) -> bool:
    """Same CWE + same normalised affected URL."""
    cand_cwe = _get_attr(candidate, "cwe")
    exist_cwe = _get_attr(existing, "cwe")
    if not cand_cwe or not exist_cwe or cand_cwe != exist_cwe:
        return False

    cand_url = _normalize_url(_get_attr(candidate, "affected_url") or "")
    exist_url = _normalize_url(_get_attr(existing, "affected_url") or "")
    return bool(cand_url and exist_url and cand_url == exist_url)


def _is_soft_duplicate(candidate: Any, existing: Any) -> bool:
    """Title similarity above threshold (catches LLM paraphrase duplicates)."""
    cand_title = (_get_attr(candidate, "title") or "").lower().strip()
    exist_title = (_get_attr(existing, "title") or "").lower().strip()
    if not cand_title or not exist_title:
        return False
    return SequenceMatcher(None, cand_title, exist_title).ratio() > _TITLE_SIMILARITY_THRESHOLD


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Lowercase, strip fragments and trailing slashes for comparison."""
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip().lower())
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    except Exception:
        return url.strip().lower()


def _get_attr(obj: Any, name: str) -> Any:
    """Retrieve attribute from dict-like or object transparently."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _richness_score(finding: Any) -> int:
    """Higher score = more useful data attached to this finding."""
    score = 0
    desc = _get_attr(finding, "description")
    if desc and str(desc).strip():
        score += 2
    poc = _get_attr(finding, "proof_of_concept") or _get_attr(finding, "poc")
    if poc and (isinstance(poc, dict) and poc or str(poc).strip()):
        score += 3
    cvss = _get_attr(finding, "cvss_score") or _get_attr(finding, "cvss")
    try:
        if cvss is not None and float(cvss) > 0:
            score += 1
    except (TypeError, ValueError):
        pass
    cwe = _get_attr(finding, "cwe")
    if cwe:
        score += 1
    return score
