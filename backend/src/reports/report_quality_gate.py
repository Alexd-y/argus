"""Evidence-bound quality gate for generated reports.

The gate is intentionally conservative: missing coverage, failed tools, weak
evidence, or conflicting scoring data must produce "not assessed" /
"inconclusive" language instead of implied security assurance.
"""

from __future__ import annotations

import re
import contextlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

from src.reports.finding_severity_normalizer import severity_from_cvss

EvidenceQuality = Literal["none", "weak", "moderate", "strong"]

# VAL-001 — header-gap / passive header observation default (CVSS 3.1); severity capped to Medium without chain.
HEADER_ONLY_DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
HEADER_ONLY_DEFAULT_CVSS_SCORE = 4.3
HEADER_ONLY_MAX_CVSS_SCORE = 6.9  # top of Medium band when capping advisory header-only issues

_HEADER_ADVISORY_RE = re.compile(
    r"security\s+header|missing\s+header|http\s+response\s+header|incomplete\s+http\s+security|"
    r"content-security-policy|\bcsp\b|strict-transport|hsts|x-frame-options|"
    r"x-content-type|referrer-policy|permissions-policy",
    re.I,
)
_EXPLOIT_CHAIN_RE = re.compile(
    r"\b(rce|remote\s+code\s+execution|sql\s+injection|\bxss\b|cross-site\s+scripting|"
    r"auth(?:entication)?\s+bypass|command\s+injection|ssrf|xxe|lfi|path\s+traversal)\b",
    re.I,
)
ValidationStatus = Literal["missing", "unverified", "partially_validated", "validated"]

FORBIDDEN_CERTAINTY_PHRASES: tuple[str, ...] = (
    "relatively stable",
    "positive observation",
    "absence of critical vulnerabilities",
    "no critical vulnerabilities",
    "no findings means secure",
    "confirmed these findings without false positives",
    "unauthorized transactions",
    "regulatory fines",
    "financial fraud",
    "data breach",
    "unauthorized access",
    "significant vulnerability",
    "critical http security headers",
    "critical http headers",
    "critical headers",
    "could be exploited by attackers",
    "attackers can exploit this directly",
    "compromise the application",
    "gain unauthorized access",
    "confirmed exploitability",
    "exploitation is possible",
    "severe consequences",
    "financial losses",
    "absence of effective rate limiting",
    "does not implement rate limiting",
    "allowing attackers to perform rapid login attempts",
    "confirmed vulnerability",
    "account compromise",
    "brute force is possible as proven",
    "comprehensive penetration test",
)

LOW_WSTG_LIMITATION = (
    "This assessment does not represent comprehensive application penetration testing. "
    "Several OWASP WSTG categories were not assessed or were only partially assessed."
)

_FAILED_STATUSES = frozenset(
    {"failed", "error", "timeout", "cancelled", "canceled", "aborted", "stderr", "nonzero"}
)
_CRITICAL_SCANNER_DOMAINS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("tls_assessment", ("testssl", "sslscan", "sslyze", "tlsx"), "TLS assessment"),
    ("technology_stack", ("whatweb",), "technology fingerprinting"),
    ("email_exposure", ("theharvester", "harvester"), "email OSINT"),
    ("web_server_checks", ("nikto",), "web server checks"),
    ("port_exposure", ("nmap", "naabu", "masscan"), "port exposure"),
)
_RATE_LIMIT_RE = re.compile(
    r"\b(rate[-\s]?limit|http\s*429|too many requests|lockout|captcha)\b", re.I
)
_LOGIN_RE = re.compile(r"\b(login|signin|sign-in|auth|authentication)\b", re.I)


@dataclass
class ReportQualityGate:
    warnings: list[str] = field(default_factory=list)
    wstg_coverage_pct: float = 0.0
    wstg_low_coverage: bool = False
    critical_scanner_failed: bool = False
    failed_domains: dict[str, str] = field(default_factory=dict)
    scan_type: str = "standard"
    authenticated: bool = False
    coverage_label: str = "partial"
    tool_health: str = "healthy"
    evidence_confidence: EvidenceQuality = "none"
    report_mode_label: str = "Automated scan"
    section_status: dict[str, str] = field(default_factory=dict)
    #: Heuristic gate: injection-class findings must cite evidence_refs (fail flag).
    injection_evidence_fail: bool = False
    injection_evidence_warnings: list[str] = field(default_factory=list)
    #: Machine-readable injection / destructive-policy gate tokens (additive for consumers).
    injection_finding_gates: list[str] = field(default_factory=list)
    #: Per-family assessed / not_assessed (+ reason); optional scan overlay; default empty families.
    active_injection_coverage: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "warnings": list(dict.fromkeys(self.warnings)),
            "wstg_coverage_pct": self.wstg_coverage_pct,
            "wstg_low_coverage": self.wstg_low_coverage,
            "critical_scanner_failed": self.critical_scanner_failed,
            "failed_domains": dict(self.failed_domains),
            "scan_type": self.scan_type,
            "authenticated": self.authenticated,
            "coverage_label": self.coverage_label,
            "tool_health": self.tool_health,
            "evidence_confidence": self.evidence_confidence,
            "report_mode_label": self.report_mode_label,
            "section_status": dict(self.section_status),
            "injection_evidence_fail": self.injection_evidence_fail,
            "injection_evidence_warnings": list(dict.fromkeys(self.injection_evidence_warnings)),
            "injection_finding_gates": list(dict.fromkeys(self.injection_finding_gates)),
            "active_injection_coverage": dict(self.active_injection_coverage),
        }


def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _copy_with(obj: Any, updates: dict[str, Any]) -> Any:
    if hasattr(obj, "model_copy"):
        return obj.model_copy(update=updates)
    if isinstance(obj, dict):
        out = dict(obj)
        out.update(updates)
        return out
    for k, v in updates.items():
        with contextlib.suppress(Exception):
            setattr(obj, k, v)
    return obj


def _normalized_title(finding: Any) -> str:
    return str(_get_attr(finding, "title", "") or "").strip()


def _text_blob(finding: Any) -> str:
    poc = _get_attr(finding, "proof_of_concept")
    parts = [
        _normalized_title(finding),
        str(_get_attr(finding, "description", "") or ""),
        str(_get_attr(finding, "cwe", "") or ""),
        str(_get_attr(finding, "evidence_type", "") or ""),
        " ".join(str(x) for x in (_get_attr(finding, "evidence_refs", []) or [])),
    ]
    if isinstance(poc, dict):
        parts.extend(str(v) for v in poc.values() if not isinstance(v, (dict, list)))
        for v in poc.values():
            if isinstance(v, list):
                parts.extend(str(x) for x in v[:20])
    return "\n".join(parts)


def _is_rate_limit_finding(finding: Any) -> bool:
    blob = _text_blob(finding)
    return bool(_RATE_LIMIT_RE.search(blob) and _LOGIN_RE.search(blob))


def _poc_dict(finding: Any) -> dict[str, Any]:
    poc = _get_attr(finding, "proof_of_concept")
    return dict(poc) if isinstance(poc, dict) else {}


def _finding_endpoint(finding: Any) -> str:
    poc = _poc_dict(finding)
    for key in ("request_url", "affected_url", "target_url", "url"):
        raw = poc.get(key)
        if isinstance(raw, str) and raw.strip():
            return _normalize_endpoint(raw)
    for raw in (_normalized_title(finding), str(_get_attr(finding, "description", "") or "")):
        m = re.search(r"https?://[^\s'\"<>]+|/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+", raw)
        if m:
            return _normalize_endpoint(m.group(0))
    return "login"


def _normalize_endpoint(raw: str) -> str:
    value = raw.strip()
    try:
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            return (
                f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path.rstrip('/') or '/'}"
            )
    except Exception:
        pass
    return value.lower().rstrip("/") or "login"


def _has_poc(finding: Any) -> bool:
    poc = _poc_dict(finding)
    if not poc:
        return False
    meaningful = (
        "request",
        "response",
        "request_url",
        "request_method",
        "response_status",
        "response_statuses",
        "raw_request",
        "raw_response",
        "screenshot_key",
        "payload",
    )
    return any(poc.get(k) not in (None, "", [], {}) for k in meaningful)


def score_evidence_quality(finding: Any) -> EvidenceQuality:
    poc = _poc_dict(finding)
    refs = _get_attr(finding, "evidence_refs", []) or []
    blob = _text_blob(finding).lower()
    if "unknown finding" in blob:
        return "none"
    if not poc and not refs:
        return "none"
    if _is_rate_limit_finding(finding):
        method = str(poc.get("request_method") or "").upper()
        statuses = poc.get("response_statuses") or poc.get("statuses") or []
        attempt_count = (
            len(statuses) if isinstance(statuses, list) else int(poc.get("attempt_count") or 0)
        )
        has_raw = bool(poc.get("request") or poc.get("raw_request")) and bool(
            poc.get("response") or poc.get("raw_response")
        )
        has_time = bool(poc.get("timestamps") or poc.get("timestamp"))
        auth_flow = bool(poc.get("auth_flow_validated") or poc.get("login_post_validated"))
        no_throttle = bool(
            poc.get("no_lockout_observed")
            or poc.get("no_captcha_observed")
            or poc.get("no_throttle_observed")
        )
        if (
            method == "POST"
            and attempt_count >= 10
            and auth_flow
            and no_throttle
            and has_time
            and has_raw
        ):
            return "strong"
        if method == "POST" and attempt_count >= 5 and has_raw:
            return "moderate"
        return "weak"
    if _has_poc(finding) and len(refs) >= 2:
        return "strong"
    if _has_poc(finding) or refs:
        return "moderate"
    return "none"


def validation_status_for_quality(evidence_quality: EvidenceQuality) -> ValidationStatus:
    if evidence_quality == "strong":
        return "validated"
    if evidence_quality == "moderate":
        return "partially_validated"
    if evidence_quality == "weak":
        return "unverified"
    return "missing"


# --- Active injection / evidence heuristics (VAL / lab quality gate) ---

_INJECTION_OAST_RE = re.compile(
    r"\b(oast|interactsh|interact\.sh|burp(?:ollaborator)?|collaborator\.[a-z0-9._-]+|"
    r"dns\.callback|xss\.ht|webhook\.site|canarytoken|"
    r"oastify|projectdiscovery\.io/interact)\b",
    re.I,
)
_INJECTION_XSS_EXEC_RE = re.compile(
    r"\b(dalfox|xsstrike|playwright|puppeteer|selenium|headless|chromium|"
    r"browser_executed|dom[_\s-]?sink|burp.*scanner|oast|interactsh|collaborator)\b",
    re.I,
)


def map_injection_family(finding: Any) -> str | None:
    """Normalize injection family from structured field or CWE/title heuristics."""
    raw = str(_get_attr(finding, "injection_family") or "").strip().lower()
    if raw in {"sqli", "sql_injection", "sql-injection"}:
        return "sqli"
    if raw in {"xss", "dom_xss", "reflected_xss"}:
        return "xss"
    if raw in {"ssrf", "server-side request forgery"}:
        return "ssrf"
    if raw in {"xxe", "xml external entity"}:
        return "xxe"
    if raw in {"rce", "command_injection", "command injection", "code injection"}:
        return "rce"
    cwe = str(_get_attr(finding, "cwe") or "").lower()
    blob = f"{_normalized_title(finding)}\n{str(_get_attr(finding, 'description', '') or '')}".lower()
    if "cwe-89" in cwe or cwe in {"89", "cwe-89"} or "sql injection" in blob or "sqli" in blob:
        return "sqli"
    if "cwe-79" in cwe or cwe in {"79"} or "cross-site scripting" in blob or re.search(
        r"\bxss\b", blob
    ):
        return "xss"
    if "cwe-918" in cwe or cwe in {"918"} or "ssrf" in blob:
        return "ssrf"
    if "cwe-611" in cwe or cwe in {"611"} or "xxe" in blob or "xml external" in blob:
        return "xxe"
    if (
        re.search(r"\bremote\s+code\s+execution\b", blob)
        or re.search(r"\brce\b", blob)
        or re.search(r"\bcommand\s+injection\b", blob)
        or "cwe-78" in blob
        or "cwe-94" in blob
        or "cwe-78" in cwe
    ):
        return "rce"
    return None


def _injection_evidence_blob(finding: Any) -> str:
    parts = list(_text_blob(finding).lower().split())
    refs = _get_attr(finding, "evidence_refs", []) or []
    parts.append(" ".join(str(x) for x in refs).lower())
    return " ".join(parts)


def has_oast_callback_signal(finding: Any) -> bool:
    """Heuristic: OAST / out-of-band callback mentioned in evidence or PoC."""
    meta = _get_attr(finding, "finding_meta")
    if isinstance(meta, dict) and meta.get("oast_callback") in (True, 1, "1", "true", "yes", "validated"):
        return True
    poc = _poc_dict(finding)
    if poc.get("oast_callback") in (True, 1, "1", "true", "yes", "validated"):
        return True
    if poc.get("interactsh_hit") in (True, 1, "1", "true", "yes"):
        return True
    if poc.get("oob_callback") in (True, 1, "1", "true", "yes"):
        return True
    if poc.get("oob_received") in (True, 1, "1", "true", "yes"):
        return True
    return bool(_INJECTION_OAST_RE.search(_injection_evidence_blob(finding)))


def _poc_truthy_flag(poc: dict[str, Any], *keys: str) -> bool:
    for k in keys:
        v = poc.get(k)
        if v in (True, 1, "1", "true", "yes", "validated"):
            return True
    return False


def has_xss_browser_or_oast_signal(finding: Any) -> bool:
    """Browser execution, headless, scanner tool, or OAST in PoC / combined evidence (confirmed XSS)."""
    poc = _poc_dict(finding)
    if _poc_truthy_flag(
        poc,
        "browser_validation",
        "browser_executed",
        "dom_sink_validated",
        "oast",
        "oast_callback",
        "out_of_band",
    ):
        return True
    return bool(_INJECTION_XSS_EXEC_RE.search(_injection_evidence_blob(finding)))


def _sqli_param_guess(poc: dict[str, Any]) -> bool:
    for k in ("parameter", "param", "injection_point", "injection_parameter"):
        v = poc.get(k)
        if isinstance(v, str) and v.strip():
            return True
    raw = str(poc.get("raw_request") or "") + str(poc.get("request") or "")
    if re.search(r"[?&][a-zA-Z0-9_.]+\s*=", raw):
        return True
    return False


def _sqli_has_param_and_method_hint(finding: Any) -> bool:
    """SQLi should name (or show) a parameter and HTTP method when possible."""
    poc = _poc_dict(finding)
    has_param = _sqli_param_guess(poc)
    raw = str(poc.get("raw_request") or "") + str(poc.get("request") or "")
    m = str(poc.get("request_method") or poc.get("method") or "").strip().upper()
    has_method = m in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} or bool(
        re.search(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+http", raw, re.M | re.I)
    ) or bool(re.search(r"^\s*(GET|POST|PUT|PATCH|DELETE)\s+/[\w./?&=%-]+", raw, re.M | re.I))
    return has_param and has_method


def _evidence_quality_resolved(finding: Any) -> str:
    raw = str(_get_attr(finding, "evidence_quality", "") or "").strip().lower()
    if raw in {"none", "weak", "moderate", "strong"}:
        return raw
    return score_evidence_quality(finding)


def evaluate_injection_finding_rules(finding: Any) -> list[str]:
    """
    Heuristic quality rules for SQLi/XSS/SSRF/XXE/RCE-style findings.
    Returns a list of machine-friendly violation tokens for tests and logging.
    """
    from src.recon.vulnerability_analysis.active_scan.injection_findings_normalize import (
        has_sqli_timing_repeated_samples,
        is_time_based_sqli_finding,
    )

    family = map_injection_family(finding)
    if not family:
        return []

    out: list[str] = []
    title = _normalized_title(finding) or "(untitled)"
    refs = _get_attr(finding, "evidence_refs", []) or []
    if not refs:
        out.append(f"injection_qg:missing_evidence_refs:{title}")
    conf = str(_get_attr(finding, "confidence", "") or "").lower()
    val_st = str(_get_attr(finding, "validation_status", "") or "").lower()
    q = _evidence_quality_resolved(finding)
    high_assertion = conf == "confirmed" or val_st == "validated"
    if high_assertion and q != "strong":
        out.append(f"injection_qg:confirmed_without_strong_evidence:{title}")
    if high_assertion and not _has_poc(finding):
        out.append(f"injection_qg:high_assertion_missing_poc_fields:{title}")
    if family == "sqli" and not _sqli_has_param_and_method_hint(finding):
        out.append(f"injection_qg:sqli_missing_param_or_method:{title}")
    if (
        family == "sqli"
        and is_time_based_sqli_finding(finding)
        and high_assertion
        and not has_sqli_timing_repeated_samples(finding)
    ):
        out.append(f"injection_qg:sqli_time_based_missing_repeated_samples:{title}")
    if family == "xss" and high_assertion and not has_xss_browser_or_oast_signal(finding):
        out.append(f"injection_qg:xss_confirmed_missing_browser_or_oast:{title}")
    if family in {"ssrf", "xxe", "rce"} and high_assertion and not has_oast_callback_signal(finding):
        out.append(f"injection_qg:{family}_confirmed_missing_oast:{title}")
    return out


def _destructive_tool_names_cited_structured(finding: Any) -> frozenset[str]:
    """Return destructive VA tool ids explicitly recorded on the finding (structured fields only)."""
    from src.core.config import settings
    from src.recon.mcp.policy import resolve_va_active_scan_tool_canonical

    cited: set[str] = set()
    poc = _poc_dict(finding)
    for fk in ("tool", "scanner", "active_scan_tool", "va_tool", "tool_name"):
        v = poc.get(fk)
        if not isinstance(v, str) or not str(v).strip():
            w = _get_attr(finding, fk, None)
            v = w if isinstance(w, str) else ""
        if isinstance(v, str) and v.strip():
            c = resolve_va_active_scan_tool_canonical(v.strip())
            if c and c in settings.destructive_tools:
                cited.add(c)
    return frozenset(cited)


def aggregate_injection_evidence_violations(findings: Iterable[Any]) -> tuple[list[str], bool]:
    """Returns (warning lines, fail_flag).

    Fail when injection quality rules emit blocking tokens (missing refs, weak
    confirmation evidence, SQLi surface gaps, XSS / OOB confirmation gaps).
    """
    all_v: list[str] = []
    fail = False
    for f in findings:
        vs = evaluate_injection_finding_rules(f)
        for v in vs:
            all_v.append(v)
            if any(v.startswith(p) for p in _INJECTION_COVERAGE_FAIL_PREFIXES):
                fail = True
    return all_v, fail


def _normalize_family_coverage_entry(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    st = str(value.get("status") or "").strip().lower()
    if st not in {"assessed", "not_assessed", "partial"}:
        return None
    reason = str(value.get("reason") or "").strip()
    if len(reason) > 500:
        reason = reason[:500]
    return {"status": st, "reason": reason}


_INJECTION_COVERAGE_FAIL_PREFIXES: tuple[str, ...] = (
    "injection_qg:missing_evidence_refs:",
    "injection_qg:confirmed_without_strong_evidence:",
    "injection_qg:sqli_missing_param_or_method:",
    "injection_qg:sqli_time_based_missing_repeated_samples:",
    "injection_qg:xss_confirmed_missing_browser_or_oast:",
    "injection_qg:ssrf_confirmed_missing_oast:",
    "injection_qg:xxe_confirmed_missing_oast:",
    "injection_qg:rce_confirmed_missing_oast:",
)


def _confidence_rank(conf: str) -> int:
    order = {"confirmed": 4, "likely": 3, "possible": 2, "advisory": 1}
    return order.get(conf.strip().lower(), 0)


def _aggregate_family_confidence(findings: list[Any]) -> str:
    best = "possible"
    best_r = 0
    for f in findings:
        c = str(_get_attr(f, "confidence", "likely") or "likely").lower()
        r = _confidence_rank(c)
        if r > best_r:
            best_r = r
            best = c
    return best if best_r else "likely"


def _unique_surfaces_for_family(findings: list[Any]) -> int:
    seen: set[str] = set()
    for f in findings:
        ep = _finding_endpoint(f)
        if ep and ep != "login":
            seen.add(ep)
    return len(seen)


def _tool_label_for_family(findings: list[Any]) -> str:
    tools: list[str] = []
    for f in findings:
        poc = _poc_dict(f)
        for key in ("tool", "scanner", "active_scan_tool", "va_tool"):
            v = poc.get(key)
            if isinstance(v, str) and v.strip():
                tools.append(v.strip())
                break
    if not tools:
        return ""
    uniq = list(dict.fromkeys(tools))
    return ", ".join(uniq[:5])


def _normalize_active_injection_table_row(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    fam = str(row.get("family") or "").strip().lower()
    if not fam:
        return None
    ev = row.get("evidence_ids") if row.get("evidence_ids") is not None else row.get("evidenceIds")
    if not isinstance(ev, list):
        ev = []
    st = row.get("surfaces_tested") if row.get("surfaces_tested") is not None else row.get("surfacesTested")
    if isinstance(st, list):
        surfaces: int | str = len(st)
    elif isinstance(st, int):
        surfaces = st
    else:
        try:
            surfaces = int(st) if st is not None and str(st).strip().isdigit() else 0
        except (TypeError, ValueError):
            surfaces = 0
    assessed_raw = str(row.get("assessed") or row.get("assessed_label") or "").strip().lower()
    assessed: str | None = assessed_raw if assessed_raw in {"yes", "no", "partial"} else None
    out: dict[str, Any] = {
        "family": fam,
        "tool": str(row.get("tool") or "").strip()[:256],
        "status": str(row.get("status") or "").strip()[:128] or "—",
        "surfaces_tested": surfaces,
        "evidence_ids": [str(x) for x in ev][:50],
        "not_assessed_reason": str(
            row.get("not_assessed_reason") or row.get("notAssessedReason") or ""
        ).strip()[:500],
        "findings_count": int(row.get("findings_count") or row.get("findingsCount") or 0),
        "confidence": str(row.get("confidence") or "").strip()[:64] or "—",
    }
    if assessed is not None:
        out["assessed"] = assessed
    return out


def _build_active_injection_table_rows(
    findings: list[Any] | None,
    families: dict[str, dict[str, str]],
    not_assessed_reasons: dict[str, Any],
    tools_health: dict[str, Any],
    client_rows: list[Any] | None,
) -> list[dict[str, Any]]:
    by_fam: dict[str, list[Any]] = {}
    for f in findings or []:
        m = map_injection_family(f)
        if m:
            by_fam.setdefault(m, []).append(f)
    merged: dict[str, dict[str, Any]] = {}
    for fam, fs in by_fam.items():
        fam_entry = families.get(fam) or {}
        st = str(fam_entry.get("status") or "").strip().lower()
        if st == "assessed":
            assessed = "yes"
        elif st == "partial":
            assessed = "partial"
        elif st == "not_assessed":
            assessed = "no"
        else:
            assessed = "yes"
        nar_v = not_assessed_reasons.get(fam)
        nar_s = str(nar_v).strip() if nar_v is not None else ""
        reason = str(fam_entry.get("reason") or "").strip() or nar_s
        merged[fam] = {
            "family": fam,
            "assessed": assessed,
            "tool": _tool_label_for_family(fs),
            "status": "findings_recorded" if fs else ("not_run" if assessed == "no" else "no_findings"),
            "surfaces_tested": _unique_surfaces_for_family(fs) if fs else 0,
            "evidence_ids": list(
                dict.fromkeys(
                    str(x)
                    for f in fs
                    for x in (_get_attr(f, "evidence_refs", []) or [])
                    if str(x).strip()
                )
            )[:50],
            "not_assessed_reason": reason[:500],
            "findings_count": len(fs),
            "confidence": _aggregate_family_confidence(fs),
        }
    for fam, fam_entry in families.items():
        if fam in merged:
            st = str(fam_entry.get("status") or "").strip().lower()
            if st == "assessed":
                merged[fam]["assessed"] = "yes"
            elif st == "partial":
                merged[fam]["assessed"] = "partial"
            elif st == "not_assessed":
                merged[fam]["assessed"] = "no"
            r = str(fam_entry.get("reason") or "").strip()
            if r:
                merged[fam]["not_assessed_reason"] = r[:500]
            continue
        st = str(fam_entry.get("status") or "").strip().lower()
        assessed = (
            "yes"
            if st == "assessed"
            else ("partial" if st == "partial" else ("no" if st == "not_assessed" else "no"))
        )
        nar_v = not_assessed_reasons.get(fam)
        nar_s = str(nar_v).strip() if nar_v is not None else ""
        reason = str(fam_entry.get("reason") or "").strip() or nar_s
        merged[fam] = {
            "family": fam,
            "assessed": assessed,
            "tool": "",
            "status": "overlay_only",
            "surfaces_tested": 0,
            "evidence_ids": [],
            "not_assessed_reason": reason[:500],
            "findings_count": 0,
            "confidence": "—",
        }
    if isinstance(client_rows, list):
        for raw in client_rows:
            norm = _normalize_active_injection_table_row(raw)
            if not norm:
                continue
            fam = norm["family"]
            base = dict(merged.get(fam, {}))
            for k, v in norm.items():
                if v is None:
                    continue
                base[k] = v
            merged[fam] = base
    finalized: list[dict[str, Any]] = []
    for k in sorted(merged.keys()):
        row = dict(merged[k])
        row.setdefault("assessed", "no")
        finalized.append(row)
    return finalized


def build_active_injection_coverage(
    findings: list[Any] | None,
    scan_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Merge optional scan payload ``active_injection_coverage.families`` with
    finding-derived ``assessed`` rows. Backward compatible: missing client data
    yields ``families: {}`` plus legacy placeholder fields.
    """
    opts = dict(scan_options) if isinstance(scan_options, dict) else {}
    raw_client = opts.get("active_injection_coverage")
    families: dict[str, dict[str, str]] = {}
    not_assessed_reasons: dict[str, Any] = {}
    tools_health: dict[str, Any] = {}
    client_table_rows: list[Any] | None = None
    if isinstance(raw_client, dict):
        raw_fam = raw_client.get("families")
        if isinstance(raw_fam, dict):
            for k, v in raw_fam.items():
                fk = str(k).strip().lower()
                if not fk:
                    continue
                norm = _normalize_family_coverage_entry(v)
                if norm:
                    families[fk] = norm
        nar = raw_client.get("not_assessed_reasons")
        if isinstance(nar, dict):
            not_assessed_reasons = dict(nar)
        th = raw_client.get("toolsHealth")
        if isinstance(th, dict):
            tools_health = dict(th)
        ctr = raw_client.get("table_rows")
        if isinstance(ctr, list):
            client_table_rows = list(ctr)
    for f in findings or []:
        m = map_injection_family(f)
        if m and m not in families:
            families[m] = {"status": "assessed", "reason": "observed_in_findings"}
    fams_observed: list[str] = []
    for f in findings or []:
        m = map_injection_family(f)
        if m and m not in fams_observed:
            fams_observed.append(m)
    table_rows = _build_active_injection_table_rows(
        findings, families, not_assessed_reasons, tools_health, client_table_rows
    )
    return {
        "families": families,
        "not_assessed_reasons": not_assessed_reasons,
        "toolsHealth": tools_health,
        "table_rows": table_rows,
        "injection_families_observed": fams_observed,
        "reasons": [
            "Active injection scheduler and parser rows are optional; "
            "``families`` / ``table_rows`` may be supplied on the scan payload for explicit coverage.",
        ],
    }


def build_active_injection_coverage_placeholder(findings: list[Any] | None) -> dict[str, Any]:
    """Backward-compatible wrapper (no scan options)."""
    return build_active_injection_coverage(findings, None)


def _float_or_none(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _cvss_numeric_sources(finding: Any) -> dict[str, float]:
    """All distinct CVSS field locations for conflict detection and merge (VAL-001)."""
    values: dict[str, float] = {}
    top_score = _float_or_none(_get_attr(finding, "cvss_score"))
    if top_score is not None:
        values["cvss_score"] = top_score
    top_cvss = _float_or_none(_get_attr(finding, "cvss"))
    if top_cvss is not None:
        values["cvss"] = top_cvss
    poc = _poc_dict(finding)
    for key in ("cvss_score", "cvss_base_score", "base_score", "cvss"):
        val = _float_or_none(poc.get(key))
        if val is not None:
            values[f"poc.{key}"] = val
    return values


def _pick_canonical_cvss_score(finding: Any, sources: dict[str, float]) -> float | None:
    if not sources:
        return None
    for attr in ("cvss_score", "cvss"):
        v = _float_or_none(_get_attr(finding, attr))
        if v is not None:
            return float(v)
    poc = _poc_dict(finding)
    for k in ("cvss_score", "cvss_base_score", "cvss", "base_score"):
        v = _float_or_none(poc.get(k))
        if v is not None:
            return float(v)
    return float(next(iter(sources.values())))


def _canonical_cvss_vector(finding: Any, poc: dict[str, Any]) -> str | None:
    v = _get_attr(finding, "cvss_vector")
    if isinstance(v, str) and v.strip() and ("/AV:" in v or "CVSS:3" in v):
        return v.strip()
    for k in ("cvss_vector", "cvss_v3_vector", "vectorString", "vector_string"):
        pv = poc.get(k)
        if isinstance(pv, str) and pv.strip() and ("/AV:" in pv or "CVSS:3" in pv):
            return pv.strip()
    return None


def _has_meaningful_exploit_evidence(finding: Any) -> bool:
    poc = _poc_dict(finding)
    if not poc:
        return False
    blob = " ".join(str(v) for v in poc.values() if not isinstance(v, (dict, list))).lower()
    blob += " " + str(poc).lower()
    if any(
        x in blob
        for x in (
            "payload",
            "<script",
            "union select",
            "sleep(",
            "alert(",
            "javascript:",
            "raw_request",
            "raw_response",
            "screenshot_key",
        )
    ):
        return True
    if poc.get("payload") or poc.get("payload_entered") or poc.get("javascript_code"):
        return True
    return False


def _is_header_only_advisory_finding(finding: Any) -> bool:
    title = str(_get_attr(finding, "title") or "").lower()
    desc = str(_get_attr(finding, "description") or "").lower()
    blob = f"{title}\n{desc}"
    if not _HEADER_ADVISORY_RE.search(blob):
        return False
    if _EXPLOIT_CHAIN_RE.search(blob) and _has_meaningful_exploit_evidence(finding):
        return False
    return True


def is_header_only_advisory_finding(finding: Any) -> bool:
    """Public wrapper for VHL/VAL: header-gap / passive header observations (not exploit chains)."""
    return _is_header_only_advisory_finding(finding)


def is_http_header_gap_topic(finding: Any) -> bool:
    """True when title/description concern HTTP security / response headers (used for report deduplication)."""
    title = str(_get_attr(finding, "title") or "").lower()
    desc = str(_get_attr(finding, "description") or "").lower()
    return bool(_HEADER_ADVISORY_RE.search(f"{title}\n{desc}"))


def _normalize_exploit_fields(finding: Any, header_only_advisory: bool) -> tuple[bool, str | None]:
    poc = _poc_dict(finding)
    ed_raw = _get_attr(finding, "exploit_demonstrated")
    if ed_raw is None and isinstance(poc.get("exploit_demonstrated"), bool):
        ed_raw = poc.get("exploit_demonstrated")
    summary = _get_attr(finding, "exploit_summary")
    if summary is None and poc.get("exploit_summary") is not None:
        summary = poc.get("exploit_summary")

    passive_header = header_only_advisory or not _has_meaningful_exploit_evidence(finding)
    if passive_header or not _has_poc(finding):
        return False, None
    ed = bool(ed_raw)
    if not ed:
        return False, None
    s = str(summary).strip() if summary is not None else ""
    return True, (s if s else None)


def _strip_legacy_cvss_from_poc(poc: dict[str, Any]) -> None:
    for k in ("cvss_base_score", "base_score", "cvss"):
        poc.pop(k, None)


def _apply_cvss_cap_for_severity_band(cvss: float | None, severity: str) -> float | None:
    if cvss is None:
        return None
    caps = {"low": 3.9, "medium": 6.9, "high": 8.9, "critical": 10.0, "info": 0.0}
    cap = caps.get(severity.lower())
    if cap is None:
        return cvss
    return min(cvss, cap)


def severity_cvss_band_mismatch_reason(finding: Any) -> str | None:
    """When assigned severity does not match CVSS v3.1 bands for the canonical score."""
    score = _float_or_none(_get_attr(finding, "cvss_score"))
    if score is None:
        score = _float_or_none(_get_attr(finding, "cvss"))
    if score is None:
        return None
    sev = str(_get_attr(finding, "severity") or "").strip().lower()
    alias = {"informational": "info"}
    sev = alias.get(sev, sev)
    expected = severity_from_cvss(score)
    if expected and sev and sev != expected:
        return f"severity={sev} inconsistent with cvss={score:.1f} (expected {expected})"
    return None


def cvss_conflict_reason(finding: Any) -> str | None:
    """Return a reason when cvss/cvss_score/cvss_base_score disagree."""
    values = _cvss_numeric_sources(finding)
    if len(values) < 2:
        return None
    rounded = {k: round(v, 1) for k, v in values.items()}
    if len(set(rounded.values())) > 1:
        detail = ", ".join(f"{k}={v:.1f}" for k, v in sorted(rounded.items()))
        return f"Conflicting CVSS fields: {detail}"
    return None


def _is_xss_finding(finding: Any) -> bool:
    cwe = str(_get_attr(finding, "cwe") or "").lower()
    if cwe in {"cwe-79", "79", "cwe-83"} or "cwe-79" in cwe:
        return True
    t = f"{_normalized_title(finding)}\n{str(_get_attr(finding, 'description', '') or '')}".lower()
    return "xss" in t or "cross-site scripting" in t


def _normalize_one_finding(finding: Any) -> Any | None:
    if str(_get_attr(finding, "evidence_type", "") or "").lower() == "threat_model_inference":
        return None
    quality = score_evidence_quality(finding)
    status = validation_status_for_quality(quality)
    confidence = str(_get_attr(finding, "confidence", "likely") or "likely").lower()
    severity = str(_get_attr(finding, "severity", "") or "").lower()
    poc = dict(_poc_dict(finding))
    refs = list(_get_attr(finding, "evidence_refs", []) or [])
    notes = str(_get_attr(finding, "applicability_notes", "") or "").strip()

    sources = _cvss_numeric_sources(finding)
    cvss = _pick_canonical_cvss_score(finding, sources) if sources else None
    if cvss is not None:
        cvss = round(float(cvss), 1)

    cvss_vector = _canonical_cvss_vector(finding, poc)
    header_only = _is_header_only_advisory_finding(finding)

    if header_only:
        if cvss is None:
            cvss = HEADER_ONLY_DEFAULT_CVSS_SCORE
            if not cvss_vector:
                cvss_vector = HEADER_ONLY_DEFAULT_CVSS_VECTOR
        elif cvss > HEADER_ONLY_MAX_CVSS_SCORE:
            cvss = HEADER_ONLY_MAX_CVSS_SCORE
        if not cvss_vector and cvss is not None:
            cvss_vector = HEADER_ONLY_DEFAULT_CVSS_VECTOR

    exploit_demonstrated, exploit_summary = _normalize_exploit_fields(finding, header_only)

    if quality in ("none", "weak") and confidence == "confirmed":
        confidence = "likely" if quality == "weak" else "possible"
    if quality == "weak" and status != "validated":
        confidence = "possible" if _is_rate_limit_finding(finding) else confidence

    if _is_rate_limit_finding(finding):
        cvss = 3.7 if cvss is None or cvss > 3.7 else cvss
        status = "unverified" if quality in ("weak", "none") else status
        if not refs:
            refs = ["rapid login-path requests without HTTP 429"]
        notes = (
            "Evidence is limited to a rate-limit signal. Full authentication flow behavior, "
            "per-account lockout, CAPTCHA, and throttling were not validated."
        )
        poc.setdefault("evidence_quality", quality)
        poc.setdefault("validation_status", status)

    if _is_xss_finding(finding) and not _has_meaningful_exploit_evidence(finding):
        if severity in {"high", "critical"}:
            severity = "medium"
        confidence = "possible" if quality in ("none", "weak") else confidence
        status = "unverified" if quality in ("none", "weak", "moderate") else status
        if cvss is not None and float(cvss) > 6.9:
            cvss = 6.9
        if notes == "" and quality == "weak":
            notes = "XSS-style finding lacks reflected/DOM/HTTP response or browser validation in evidence."

    if map_injection_family(finding) == "xss" and confidence == "confirmed":
        if not has_xss_browser_or_oast_signal(finding):
            confidence = "likely"

    if severity in {"high", "critical"} and not _has_poc(finding) and not header_only:
        if quality == "none":
            return None
        if quality in {"weak", "moderate"}:
            severity = "medium" if quality == "moderate" else "low"
            status = "unverified" if quality == "weak" else "partially_validated"
            confidence = "likely"
            cvss = _apply_cvss_cap_for_severity_band(cvss, severity)

    if cvss is not None:
        final_severity = severity_from_cvss(cvss) or "info"
    else:
        final_severity = severity or "info"

    _strip_legacy_cvss_from_poc(poc)
    if cvss is not None:
        poc["cvss_score"] = cvss
    if cvss_vector:
        poc["cvss_vector"] = cvss_vector
    poc["exploit_demonstrated"] = exploit_demonstrated
    if exploit_summary:
        poc["exploit_summary"] = exploit_summary
    elif "exploit_summary" in poc:
        del poc["exploit_summary"]

    updates = {
        "severity": final_severity,
        "cvss": cvss,
        "cvss_score": cvss,
        "cvss_vector": cvss_vector,
        "exploit_demonstrated": exploit_demonstrated,
        "exploit_summary": exploit_summary,
        "proof_of_concept": poc or None,
        "confidence": (
            confidence
            if confidence in {"confirmed", "likely", "possible", "advisory"}
            else "likely"
        ),
        "evidence_refs": refs,
        "applicability_notes": notes,
        "evidence_quality": quality,
        "validation_status": status,
    }
    return _copy_with(finding, updates)


def _richness_score_for_merge(finding: Any) -> int:
    quality_rank = {"none": 0, "weak": 1, "moderate": 2, "strong": 3}
    quality = str(_get_attr(finding, "evidence_quality", "") or score_evidence_quality(finding))
    score = quality_rank.get(quality, 0) * 10
    score += len(_get_attr(finding, "evidence_refs", []) or [])
    if _has_poc(finding):
        score += 5
    return score


def _merge_rate_limit_findings(findings: list[Any]) -> list[Any]:
    groups: dict[str, Any] = {}
    others: list[Any] = []
    for f in findings:
        if not _is_rate_limit_finding(f):
            others.append(f)
            continue
        key = _finding_endpoint(f)
        existing = groups.get(key)
        if existing is None:
            groups[key] = f
            continue
        primary, secondary = (
            (f, existing)
            if _richness_score_for_merge(f) > _richness_score_for_merge(existing)
            else (existing, f)
        )
        refs = list(
            dict.fromkeys(
                [str(x) for x in (_get_attr(primary, "evidence_refs", []) or [])]
                + [str(x) for x in (_get_attr(secondary, "evidence_refs", []) or [])]
                + [_normalized_title(primary), _normalized_title(secondary)]
            )
        )
        poc = _poc_dict(primary)
        merged_signals = poc.get("merged_signals")
        if not isinstance(merged_signals, list):
            merged_signals = []
        for item in (_normalized_title(primary), _normalized_title(secondary)):
            if item and item not in merged_signals:
                merged_signals.append(item)
        poc["merged_signals"] = merged_signals[:10]
        groups[key] = _copy_with(
            primary,
            {
                "title": "Missing or insufficient rate limiting on login endpoint",
                "description": (
                    "Possible missing or insufficient rate limiting on the login endpoint. "
                    "Evidence combines rapid login-path requests without HTTP 429 and related "
                    "authentication-control signals, but account lockout, CAPTCHA, and full login "
                    "POST behavior were not validated."
                ),
                "cwe": _get_attr(primary, "cwe") or _get_attr(secondary, "cwe") or "CWE-307",
                "owasp_category": _get_attr(primary, "owasp_category")
                or _get_attr(secondary, "owasp_category")
                or "A07",
                "severity": "low",
                "cvss": 3.7,
                "cvss_score": 3.7,
                "confidence": "possible",
                "validation_status": "unverified",
                "evidence_quality": "weak",
                "evidence_refs": refs,
                "proof_of_concept": poc,
            },
        )
    merged = list(groups.values())
    for i, f in enumerate(merged):
        if _normalized_title(f) != "Missing or insufficient rate limiting on login endpoint":
            poc = _poc_dict(f)
            merged[i] = _copy_with(
                f,
                {
                    "title": "Missing or insufficient rate limiting on login endpoint",
                    "description": (
                        "Possible missing or insufficient rate limiting on the login endpoint. "
                        "Evidence quality is weak unless full authentication flow behavior is validated."
                    ),
                    "cwe": _get_attr(f, "cwe") or "CWE-307",
                    "owasp_category": _get_attr(f, "owasp_category") or "A07",
                    "severity": "low",
                    "cvss": 3.7,
                    "cvss_score": 3.7,
                    "confidence": "possible",
                    "validation_status": "unverified",
                    "evidence_quality": "weak",
                    "proof_of_concept": poc or None,
                },
            )
    return others + merged


def normalize_findings_for_report(findings: Iterable[Any]) -> list[Any]:
    """Normalize evidence status, CVSS surface, confidence, and rate-limit duplicates."""
    from src.reports.finding_dedup import merge_http_security_header_gaps, merge_reflected_xss_findings

    base = merge_http_security_header_gaps(list(findings))
    normalized: list[Any] = []
    for finding in base:
        norm = _normalize_one_finding(finding)
        if norm is not None:
            normalized.append(norm)
    return merge_reflected_xss_findings(_merge_rate_limit_findings(normalized))


_HEADER_TABLE_GAP_NOTE = (
    "Insufficient raw HTTP security header artifact to populate the structured security headers "
    "table; treat as an advisory coverage gap, not a validated header inspection."
)


def apply_security_header_table_gap_to_findings(findings: Iterable[Any], vc: Any | None) -> list[Any]:
    """When header-gap findings exist but no header rows were parsed, mark advisory + explicit note."""
    items = list(findings)
    if vc is None or not items:
        return items
    sec_analysis = _get_attr(vc, "security_headers_analysis")
    sec_rows = _get_attr(sec_analysis, "rows", []) if sec_analysis is not None else []
    sec_table = _get_attr(vc, "security_headers_table_rows", [])
    if not isinstance(sec_table, list):
        sec_table = []
    if sec_rows or sec_table:
        return items
    if not any(is_header_only_advisory_finding(f) for f in items):
        return items

    out: list[Any] = []
    for f in items:
        if not is_header_only_advisory_finding(f):
            out.append(f)
            continue
        existing = str(_get_attr(f, "applicability_notes", "") or "").strip()
        merged_notes = f"{existing} {_HEADER_TABLE_GAP_NOTE}".strip() if existing else _HEADER_TABLE_GAP_NOTE
        sev = str(_get_attr(f, "severity", "") or "").lower()
        updates: dict[str, Any] = {
            "confidence": "advisory",
            "applicability_notes": merged_notes,
        }
        if sev in {"high", "critical", "medium"}:
            updates["severity"] = "low"
            cap_cvss = 3.7
            updates["cvss"] = cap_cvss
            updates["cvss_score"] = cap_cvss
        poc = dict(_poc_dict(f))
        if updates.get("cvss") is not None:
            poc["cvss_score"] = updates["cvss"]
        updates["proof_of_concept"] = poc or None
        out.append(_copy_with(f, updates))
    return out


def _wstg_pct(vc: Any) -> float:
    raw = _get_attr(vc, "wstg_coverage")
    if not isinstance(raw, dict):
        return 0.0
    return _float_or_none(raw.get("coverage_percentage")) or 0.0


def _tool_error_rows(vc: Any) -> list[dict[str, str]]:
    cov = _get_attr(vc, "coverage")
    rows = _get_attr(cov, "tool_errors_summary", None)
    if rows is None and isinstance(cov, dict):
        rows = cov.get("tool_errors_summary")
    if not isinstance(rows, list):
        return []
    out: list[dict[str, str]] = []
    for row in rows:
        if isinstance(row, dict):
            out.append({k: str(v) for k, v in row.items()})
    return out


def _mandatory_sections(vc: Any) -> dict[str, str]:
    raw = _get_attr(vc, "mandatory_sections")
    if raw is None:
        return {}
    if hasattr(raw, "model_dump"):
        raw = raw.model_dump(mode="python")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key, val in raw.items():
        if isinstance(val, dict):
            out[str(key)] = str(val.get("status") or "")
        else:
            out[str(key)] = str(_get_attr(val, "status", "") or "")
    return out


def _scan_options(data: Any) -> dict[str, Any]:
    scan = _get_attr(data, "scan")
    opts = _get_attr(scan, "options")
    return dict(opts) if isinstance(opts, dict) else {}


def _scan_type_from_options(options: dict[str, Any], scan: Any) -> str:
    for key in ("scanType", "scan_type", "scan_mode", "mode"):
        raw = options.get(key) or _get_attr(scan, key, None)
        if isinstance(raw, str) and raw.strip():
            return raw.strip().lower()
    return "standard"


def _authenticated_from_options(options: dict[str, Any]) -> bool:
    for key in ("authenticated", "auth_enabled", "has_auth", "use_auth", "authenticated_scan"):
        raw = options.get(key)
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str) and raw.strip().lower() in {"1", "true", "yes", "y"}:
            return True
    return False


def _overall_evidence_quality(findings: Iterable[Any]) -> EvidenceQuality:
    rank = {"none": 0, "weak": 1, "moderate": 2, "strong": 3}
    best = "none"
    for f in findings:
        q = str(_get_attr(f, "evidence_quality", "") or score_evidence_quality(f))
        if rank.get(q, 0) > rank[best]:
            best = q
    return best  # type: ignore[return-value]


def build_report_quality_gate(data: Any) -> ReportQualityGate:
    vc = _get_attr(data, "valhalla_context")
    findings = list(_get_attr(data, "findings", []) or [])
    options = _scan_options(data)
    scan = _get_attr(data, "scan")
    rep = _get_attr(data, "report")
    report_tier = str(_get_attr(rep, "tier", "") or "").strip().lower() if rep is not None else ""
    gate = ReportQualityGate()
    gate.scan_type = _scan_type_from_options(options, scan)
    gate.authenticated = _authenticated_from_options(options)
    gate.wstg_coverage_pct = _wstg_pct(vc)
    gate.wstg_low_coverage = gate.wstg_coverage_pct < 70.0
    if gate.wstg_low_coverage:
        gate.warnings.append(LOW_WSTG_LIMITATION)
    gate.section_status = _mandatory_sections(vc)
    for section, status in gate.section_status.items():
        if status in {
            "partial",
            "parsed_from_fallback",
            "completed_with_fallback",
            "parser_error",
            "artifact_missing_body",
            "not_executed",
            "no_data",
            "not_assessed",
        }:
            gate.warnings.append(
                f"{section}: {status}; no security conclusion should be drawn from missing data."
            )
    if any(is_header_only_advisory_finding(f) for f in findings):
        sec_analysis = _get_attr(vc, "security_headers_analysis")
        sec_rows = _get_attr(sec_analysis, "rows", []) if sec_analysis is not None else []
        sec_table_rows = _get_attr(vc, "security_headers_table_rows", [])
        if not sec_rows and not sec_table_rows:
            gate.warnings.append(
                "security_headers_analysis: header finding exists but no parsed security headers table was populated."
            )
    for row in _tool_error_rows(vc):
        tool = str(row.get("tool") or "").lower()
        status = str(row.get("status") or "").lower()
        note = str(row.get("note") or "").lower()
        failure_text = f"{status} {note}"
        if (
            status not in _FAILED_STATUSES
            and "fail" not in failure_text
            and "error" not in failure_text
            and "denied" not in failure_text
            and "docker" not in failure_text
        ):
            continue
        for domain, needles, label in _CRITICAL_SCANNER_DOMAINS:
            if any(n in tool for n in needles):
                gate.failed_domains[domain] = label
    gate.critical_scanner_failed = bool(gate.failed_domains)
    if gate.critical_scanner_failed:
        failed = ", ".join(sorted(gate.failed_domains.values()))
        gate.warnings.append(
            f"Critical scanner execution failed for {failed}. Affected domains are not assessed."
        )
    gate.evidence_confidence = _overall_evidence_quality(findings)
    for f in findings:
        mismatch = severity_cvss_band_mismatch_reason(f)
        if mismatch:
            gate.warnings.append(mismatch)
    if gate.critical_scanner_failed and len(gate.failed_domains) >= 3:
        gate.tool_health = "failed"
    elif gate.critical_scanner_failed:
        gate.tool_health = "degraded"
    else:
        gate.tool_health = "healthy"
    if gate.wstg_low_coverage or gate.critical_scanner_failed:
        gate.coverage_label = "inconclusive" if gate.critical_scanner_failed else "partial"
    else:
        gate.coverage_label = "full"
    # Valhalla: same title logic as ``build_valhalla_report_context`` / ``full_valhalla`` (evaluate_valhalla_engagement_title_and_full).
    if report_tier == "valhalla" and vc is not None:
        eng_title, _ = evaluate_valhalla_engagement_title_and_full(
            wstg_coverage_pct=gate.wstg_coverage_pct,
            mandatory_section_status=dict(gate.section_status),
            findings=findings,
            tool_error_rows=_tool_error_rows(vc) or None,
        )
        gate.report_mode_label = eng_title
    elif report_tier == "valhalla":
        gate.report_mode_label = "Valhalla Security Assessment — Partial Coverage"
    elif gate.wstg_low_coverage:
        gate.report_mode_label = (
            f"{gate.scan_type.capitalize()} automated scan — WSTG coverage under 70%"
        )
    elif gate.scan_type in {"quick", "light"} and gate.tool_health in {"degraded", "failed"}:
        gate.report_mode_label = (
            f"{gate.scan_type.capitalize()} automated scan with degraded tool execution"
        )
    else:
        gate.report_mode_label = f"{gate.scan_type.capitalize()} automated scan"

    inj_warn, inj_fail = aggregate_injection_evidence_violations(findings)
    gate.injection_evidence_warnings = inj_warn
    gate.injection_evidence_fail = inj_fail
    gate.warnings.extend(inj_warn)

    raw_flags = options.get("scan_approval_flags")
    flags_dict = raw_flags if isinstance(raw_flags, dict) else None
    destructive_gates: list[str] = []
    for f in findings:
        for dt in sorted(_destructive_tool_names_cited_structured(f)):
            if not (flags_dict and bool(flags_dict.get(str(dt).lower(), False))):
                title = _normalized_title(f) or "untitled"
                destructive_gates.append(
                    f"destructive_policy:tool_cited_without_scan_flag:{dt}:{title}"
                )
    for tok in destructive_gates:
        gate.warnings.append(tok)

    gate.injection_finding_gates = list(dict.fromkeys([*inj_warn, *destructive_gates]))
    gate.active_injection_coverage = build_active_injection_coverage(findings, options)

    return gate


def _severity_counts(findings: Iterable[Any]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(_get_attr(f, "severity", "") or "").lower()
        if sev in out:
            out[sev] += 1
    return out


def _rate_limit_finding(findings: list[Any]) -> Any | None:
    for f in findings:
        if _is_rate_limit_finding(f):
            return f
    return None


def _failed_area_sentence(gate: ReportQualityGate) -> str:
    if not gate.failed_domains:
        return ""
    areas = sorted(gate.failed_domains.values())
    if len(areas) == 1:
        area_text = areas[0]
    else:
        area_text = ", ".join(areas[:-1]) + f", and {areas[-1]}"
    return f" Several assessment areas, including {area_text}, were inconclusive because scanner execution failed."


def safe_section_text(section_key: str, data: Any, gate: ReportQualityGate) -> str:
    findings = list(_get_attr(data, "findings", []) or [])
    counts = _severity_counts(findings)
    total = sum(counts.values())
    rate = _rate_limit_finding(findings)
    header_only = any(is_header_only_advisory_finding(f) for f in findings)
    weak_rate = rate is not None and str(_get_attr(rate, "evidence_quality", "") or "") == "weak"
    finding_phrase = (
        "one low-severity, unverified authentication control weakness related to possible missing rate limiting on the login endpoint"
        if total == 1 and rate is not None
        else (
            "one passive HTTP response security-header configuration observation"
            if total == 1 and header_only
            else f"{total} finding(s) with severity distribution critical={counts['critical']}, high={counts['high']}, medium={counts['medium']}, low={counts['low']}, info={counts['info']}"
        )
    )
    failed = _failed_area_sentence(gate)

    if section_key in {"executive_summary", "executive_summary_valhalla"}:
        if rate is not None:
            quality = (
                "Evidence quality is weak because testing observed rapid requests without HTTP 429, "
                "but did not validate full authentication flow behavior."
                if weak_rate
                else "Evidence is limited to the artifacts referenced in the finding table."
            )
            return (
                f"The assessment identified {finding_phrase}. {quality}"
                f"{failed} Therefore, the report should not be interpreted as a comprehensive security assessment."
            )
        if header_only:
            return (
                f"The assessment recorded {finding_phrase}. This is a passive configuration observation: "
                "no application compromise, authenticated impact, or exploit chain was demonstrated."
                f"{failed} Findings and limitations should be interpreted only within the tested scope."
            )
        return (
            f"The assessment recorded {finding_phrase}."
            f"{failed} Findings and limitations should be interpreted only within the tested scope."
        )

    if section_key == "business_risk":
        if rate is not None:
            return (
                "The observed authentication-control signal could increase susceptibility to brute-force "
                "or credential stuffing attempts if valid credentials are known or reused. Impact remains "
                "conditional because no account compromise, credential stuffing success, or authenticated "
                "business action was demonstrated."
            )
        if header_only:
            return (
                "Missing or incomplete HTTP response security headers could reduce browser-side defense-in-depth "
                "for affected responses. Business impact remains conditional because no application compromise, "
                "credential theft, account takeover, or authenticated business action was demonstrated."
            )
        return "Business impact is inconclusive beyond the validated findings and documented coverage limitations."

    if section_key in {"exploit_chains", "attack_scenarios"}:
        if rate is not None:
            return (
                "No validated exploit chain was demonstrated. The identified rate-limiting signal may "
                "contribute to credential attacks, but no account compromise, credential stuffing success, "
                "or authenticated impact was proven."
            )
        if header_only:
            return (
                "No validated exploit chain was demonstrated. Observations about HTTP response headers are "
                "passive configuration checks: they are not remote code execution, authentication bypass, "
                "or a demonstrated multi-step exploit without additional validated impact evidence."
            )
        return (
            "No validated exploit chain was demonstrated in the collected evidence. Multi-step chains require "
            "multiple validated findings with scope-appropriate impact where applicable."
        )

    if section_key == "zero_day_potential":
        if header_only:
            return (
                "Novel vulnerability indication: Not indicated. The finding is a common HTTP response header "
                "configuration weakness and no novel vulnerability class was observed."
            )
        return (
            "Novel vulnerability indication: Not indicated. The finding is a common authentication "
            "control weakness and no novel vulnerability class was observed."
        )

    if section_key in {
        "remediation_step",
        "remediation_stages",
        "prioritization_roadmap",
        "hardening_recommendations",
    }:
        if rate is not None:
            return (
                "Use stack-neutral authentication throttling controls until the technology stack is verified: "
                "application middleware, reverse proxy or WAF rules, and identity provider controls. Apply "
                "per-account and per-IP throttling, exponential backoff, lockout or CAPTCHA after a defined "
                "threshold, and monitoring with alerting for repeated failed attempts. Validate the fix with "
                "real login POST attempts, timestamps, and raw request/response evidence."
            )
        if header_only:
            return (
                "Harden transport and browser policy using modern header sets (avoid deprecated browser "
                "XSS filter headers). Set a strict Content-Security-Policy, X-Content-Type-Options: nosniff, "
                "frame control via Content-Security-Policy frame-ancestors (or X-Frame-Options as a stopgap), "
                "Referrer-Policy, a deliberate Permissions-Policy, Strict-Transport-Security on HTTPS, and "
                "(where appropriate) Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy. Verify with "
                "``curl -sS -D- -o /dev/null <url>`` (or equivalent) and review both redirect and final responses. "
                "Prefer controls at the reverse proxy, CDN, or application framework that matches your stack when known."
            )
        return (
            "Prioritize fixes using validated severity and business impact. When the technology stack is unknown, "
            "describe controls in a stack-neutral way: application middleware, reverse proxy or WAF, and identity "
            "provider settings where applicable. Verify each change with repeatable commands or test cases — without "
            "assuming a specific framework."
        )

    if section_key == "vulnerability_description":
        if rate is not None:
            return (
                "The finding describes possible missing or insufficient rate limiting on the login endpoint. "
                "Current evidence is weak: rapid login-path requests did not receive HTTP 429, but the test "
                "did not prove full authentication-flow behavior, per-account lockout, CAPTCHA, or throttling."
            )
        if header_only:
            return (
                "The finding describes missing or incomplete HTTP response security headers. This is a passive "
                "configuration observation, not proof of application compromise. Impact depends on affected "
                "responses, browser behavior, TLS deployment, and confirmed final-response headers."
            )
        return "No additional vulnerability narrative is available beyond the evidence-backed findings table."

    if section_key == "compliance_check":
        if header_only:
            return (
                "Customer-facing OWASP mapping for HTTP security-header configuration findings is A05:2021 "
                "Security Misconfiguration. Categories that were not tested must be treated as not assessed, "
                "not as clean or validated."
            )
        return (
            "Compliance mapping is limited to the validated finding and coverage gaps. OWASP categories "
            "without tested evidence must be treated as not assessed, not as clean."
        )

    return "No evidence-backed narrative is available for this section."


def _contains_forbidden_certainty(text: str) -> str | None:
    lower = (text or "").lower()
    for phrase in FORBIDDEN_CERTAINTY_PHRASES:
        if phrase in lower:
            return phrase
    if "zero-day potential" in lower and "not indicated" not in lower and "none" not in lower:
        return "zero-day potential"
    return None


_SECTIONS_WITH_SAFE_FALLBACK = frozenset(
    {
        "executive_summary",
        "executive_summary_valhalla",
        "business_risk",
        "exploit_chains",
        "attack_scenarios",
        "zero_day_potential",
        "remediation_step",
        "remediation_stages",
        "prioritization_roadmap",
        "hardening_recommendations",
        "vulnerability_description",
        "compliance_check",
    }
)


def sanitize_ai_sections_for_quality(
    texts: dict[str, str],
    data: Any,
    gate: ReportQualityGate,
    *,
    enforce_quality_gate: bool = True,
) -> tuple[dict[str, str], list[str]]:
    out = dict(texts)
    warnings: list[str] = []
    high_risk_gate = enforce_quality_gate and (
        gate.wstg_low_coverage
        or gate.critical_scanner_failed
        or gate.evidence_confidence in {"none", "weak"}
    )
    header_only_findings = any(
        is_header_only_advisory_finding(f) for f in list(_get_attr(data, "findings", []) or [])
    )
    for key, value in list(out.items()):
        phrase = _contains_forbidden_certainty(value)
        needs_safe = bool(phrase)
        if high_risk_gate and key in _SECTIONS_WITH_SAFE_FALLBACK:
            needs_safe = True
        if (
            header_only_findings
            and key in _SECTIONS_WITH_SAFE_FALLBACK
            and re.search(r"\bA02\b", value or "")
        ):
            needs_safe = True
            phrase = phrase or "customer-facing OWASP mapping must use A05:2021"
        if (
            key
            in {
                "remediation_step",
                "remediation_stages",
                "prioritization_roadmap",
                "hardening_recommendations",
            }
            and _technology_stack_unknown(data)
            and _mentions_specific_stack(value)
        ):
            needs_safe = True
            phrase = phrase or "stack-specific remediation without stack evidence"
        if needs_safe and key in _SECTIONS_WITH_SAFE_FALLBACK:
            out[key] = safe_section_text(key, data, gate)
            warnings.append(
                f"{key}: replaced unsupported certainty" + (f" ({phrase})" if phrase else "")
            )
        elif phrase:
            out[key] = _replace_forbidden_phrase(value)
            warnings.append(f"{key}: removed unsupported phrase ({phrase})")
    return out, warnings


def _technology_stack_unknown(data: Any) -> bool:
    vc = _get_attr(data, "valhalla_context")
    structured = _get_attr(vc, "tech_stack_structured")
    if structured is None:
        return True
    values = [
        _get_attr(structured, "web_server"),
        _get_attr(structured, "os"),
        _get_attr(structured, "cms"),
        _get_attr(structured, "frameworks"),
        _get_attr(structured, "js_libraries"),
    ]
    return not any(bool(v) for v in values)


def _mentions_specific_stack(text: str) -> bool:
    return bool(
        re.search(
            r"\b(express|nginx|django|next\.?js|node\.?js|spring|rails|laravel)\b", text or "", re.I
        )
    )


_POPULATED_MANDATORY_FOR_FULL: frozenset[str] = frozenset({"completed", "partial"})


def evaluate_valhalla_engagement_title_and_full(
    *,
    wstg_coverage_pct: float,
    mandatory_section_status: dict[str, str],
    findings: Iterable[Any],
    tool_error_rows: list[dict[str, str]] | None,
) -> tuple[str, bool]:
    """
    Single source of truth for Valhalla report title (without target suffix) and ``full_valhalla``.

    Full report only when WSTG ≥ 70%, mandatory recon sections are populated, no CVSS conflicts,
    no Docker/setup noise in tool error summaries, and every finding has non-none evidence quality.
    """
    from src.reports.valhalla_tool_health import any_docker_setup_noise_in_tool_rows

    title_partial = "Valhalla Security Assessment — Partial Coverage"
    title_full = "Valhalla Full Penetration Test Report"

    required_ids = (
        "tech_stack_structured",
        "ssl_tls_analysis",
        "security_headers_analysis",
        "port_exposure",
    )
    for sec in required_ids:
        st = (mandatory_section_status.get(sec) or "").strip().lower()
        if st not in _POPULATED_MANDATORY_FOR_FULL:
            return title_partial, False

    findings_list = list(findings)

    def _dict_xss(f: Any) -> bool:
        if isinstance(f, dict):
            t = f"{f.get('title', '')} {f.get('description', '')} {f.get('cwe', '')}".lower()
            return "xss" in t or "cwe-79" in t or f.get("cwe") in {"CWE-79", "79"}
        t = f"{_get_attr(f, 'title', '')} {_get_attr(f, 'description', '')} {_get_attr(f, 'cwe', '')}".lower()
        return "xss" in t or "cwe-79" in t

    if wstg_coverage_pct < 70.0:
        if any(_dict_xss(f) for f in findings_list):
            return (
                "Valhalla Security Assessment — Partial (active web/XSS-style findings present; "
                f"WSTG coverage {wstg_coverage_pct:.0f}%).",
                False,
            )
        return title_partial, False

    if any_docker_setup_noise_in_tool_rows(tool_error_rows):
        return title_partial, False

    for f in findings_list:
        if severity_cvss_band_mismatch_reason(f):
            return title_partial, False
        if cvss_conflict_reason(f):
            return title_partial, False
        if score_evidence_quality(f) == "none":
            return title_partial, False

    return title_full, True


def _replace_forbidden_phrase(text: str) -> str:
    out = text
    replacements = {
        "relatively stable": "inconclusive based on available evidence",
        "positive observation": "documented limitation",
        "absence of critical vulnerabilities": "no critical findings were validated in the available evidence",
        "no critical vulnerabilities": "no critical findings were validated in the available evidence",
        "no findings means secure": "missing findings do not prove security",
        "confirmed these findings without false positives": "validation status is limited to the cited evidence",
        "unauthorized transactions": "unauthorized actions",
        "regulatory fines": "compliance impact",
        "financial fraud": "financial impact",
        "data breach": "credential exposure signal",
        "significant vulnerability": "configuration observation",
        "critical http security headers": "HTTP security headers",
        "critical http headers": "HTTP security headers",
        "critical headers": "security headers",
        "could be exploited by attackers": "may increase risk only if a separate exploitable weakness exists",
        "attackers can exploit this directly": "direct exploitability was not demonstrated",
        "compromise the application": "increase browser-side risk in specific conditions",
        "gain unauthorized access": "attempt unauthorized access",
        "confirmed exploitability": "unverified exploitability",
        "exploitation is possible": "exploitability was not demonstrated",
        "severe consequences": "conditional impact",
        "financial losses": "business impact",
        "absence of effective rate limiting": "rate-limit signal",
        "does not implement rate limiting": "showed a possible rate-limit signal",
        "allowing attackers to perform rapid login attempts": "which may increase authentication attack risk if other controls are absent",
        "confirmed vulnerability": "unverified finding",
        "account compromise": "account attack risk",
        "brute force is possible as proven": "brute-force risk was not proven",
        "comprehensive penetration test": "automated assessment",
    }
    for phrase, repl in replacements.items():
        out = re.sub(re.escape(phrase), repl, out, flags=re.I)
    return out
