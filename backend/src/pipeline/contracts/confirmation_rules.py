"""Per-class confirmation rules + negative-control reading (R-5.4, prompt §15.2).

This is the lightweight, dependency-free home of the confirmation-class logic
(the keyword resolver, the per-class "what does NOT constitute confirmation"
table, and the canonical negative-control key reader). It lived in
``src.reports.poc_validation`` historically; it moved here so the evidence-tier
arbiter wiring (``src.orchestration.finding_adjudication``) can consume it
WITHOUT importing the heavy ``reports`` package (WeasyPrint et al.) — a runtime
failure of that package must never be able to disable tier adjudication.

``src.reports.poc_validation`` re-exports every public name here for backward
compatibility, so existing importers are unaffected.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

# Canonical negative-control keys are ``negative_control_url`` /
# ``negative_control_result`` (poc_schema.PROOF_OF_CONCEPT_KEYS — what the
# producers actually write). ``negative_control`` and ``baseline`` are accepted
# as DEPRECATED synonyms for a transition period (R-5.4, wave 3 etap 1). Reading
# only the old names is exactly the drift that kept IDOR/BOLA/AUTH_BYPASS
# unconfirmable regardless of what was collected.
_NEGATIVE_CONTROL_KEYS: tuple[str, ...] = (
    "negative_control_result",
    "negative_control_url",
    "negative_control",  # deprecated synonym
    "baseline",  # deprecated synonym
)


def _negative_control_value(root: dict[str, Any]) -> str | None:
    """First non-empty negative-control value across the canonical keys and the
    deprecated synonyms, or None."""
    if not isinstance(root, dict):
        return None
    for key in _NEGATIVE_CONTROL_KEYS:
        value = root.get(key)
        if value not in (None, ""):
            return str(value)
    return None


# ---------------------------------------------------------------------------
# Class confirmation rules (Part II, Phase J — prompt §15.2)
#
# Per-class table: what does NOT constitute confirmation vs. what does. A finding
# whose PoC does not meet its class bar is downgraded to ``observed`` (never
# ``confirmed_vulnerability``), and the downgrade is printed with its reason — a
# senior report never hides that something could not be proven.
# ---------------------------------------------------------------------------


class ConfirmationClass(StrEnum):
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    RCE = "rce"
    CMDI = "cmdi"
    IDOR = "idor"
    BOLA = "bola"
    AUTH_BYPASS = "auth_bypass"
    RATE_LIMITING = "rate_limiting"
    CVE_VERSION = "cve_version"
    TLS_HEADERS = "tls_headers"


@dataclass(frozen=True)
class ClassRuleResult:
    confirmation_class: ConfirmationClass
    confirmed: bool
    reason: str


def _poc_root(poc: dict[str, Any]) -> dict[str, Any]:
    return poc.get("proof_of_concept", poc) if isinstance(poc, dict) else {}


def _nonempty(*values: Any) -> bool:
    return any(bool(v) for v in values)


def _has_oast(root: dict[str, Any]) -> bool:
    return _nonempty(
        root.get("oast_callback"),
        root.get("oast"),
        root.get("interactsh"),
        root.get("out_of_band"),
    )


def _has_negative_control(root: dict[str, Any]) -> bool:
    return _negative_control_value(root) is not None


def _has_discriminator(root: dict[str, Any]) -> bool:
    return _nonempty(root.get("discriminator"), root.get("observed_impact"))


def _rule_xss(root: dict[str, Any]) -> bool:
    # Execution in a browser context (DOM/headless event) or OAST from the payload —
    # NOT mere reflection of the string.
    return _nonempty(
        root.get("verified_via_browser"),
        root.get("browser_alert_text"),
        root.get("dom_snapshot"),
    ) or _has_oast(root)


def _rule_sqli(root: dict[str, Any]) -> bool:
    # Boolean control with both branches, an identifiable DB error, or out-of-band —
    # NOT a bare timing difference without control.
    return _nonempty(
        root.get("boolean_true_response"),
        root.get("boolean_false_response"),
        root.get("db_error_signature"),
    ) or _has_oast(root)


def _rule_ssrf(root: dict[str, Any]) -> bool:
    # Interaction with a controlled OAST host with a unique canary subdomain —
    # NOT a 200 from the app.
    return _has_oast(root) and _nonempty(root.get("canary"), root.get("canary_subdomain"))


def _rule_rce(root: dict[str, Any]) -> bool:
    # Command execution with a unique marker in output or OAST.
    return _nonempty(root.get("controlled_output"), root.get("harmless_marker")) or _has_oast(root)


def _rule_idor(root: dict[str, Any]) -> bool:
    # Access to another owner's object under a lower-privilege role + own-object baseline.
    return _nonempty(root.get("cross_owner_access")) and _has_negative_control(root)


def _rule_auth_bypass(root: dict[str, Any]) -> bool:
    # Protected resource without a valid session + both controls (with/without session).
    return _nonempty(root.get("protected_resource_reached")) and _has_negative_control(root)


def _rule_rate_limiting(root: dict[str, Any]) -> bool:
    # A full auth cycle with a recorded attempt count and result, plus alt-path check.
    return _nonempty(root.get("attempts")) and _nonempty(root.get("result"))


def _rule_cve_version(root: dict[str, Any]) -> bool:
    # Confirmed exploitability, or an explicit "version-inferred, backport not checked" flag.
    return _nonempty(root.get("exploit_confirmed")) or _nonempty(root.get("version_inferred"))


def _rule_tls_headers(root: dict[str, Any]) -> bool:
    # Stored handshake / full header set naming the specific missing control.
    return _nonempty(root.get("handshake"), root.get("headers")) and _nonempty(
        root.get("missing_control")
    )


_CLASS_RULES: dict[ConfirmationClass, Callable[[dict[str, Any]], bool]] = {
    ConfirmationClass.XSS: _rule_xss,
    ConfirmationClass.SQLI: _rule_sqli,
    ConfirmationClass.SSRF: _rule_ssrf,
    ConfirmationClass.RCE: _rule_rce,
    ConfirmationClass.CMDI: _rule_rce,
    ConfirmationClass.IDOR: _rule_idor,
    ConfirmationClass.BOLA: _rule_idor,
    ConfirmationClass.AUTH_BYPASS: _rule_auth_bypass,
    ConfirmationClass.RATE_LIMITING: _rule_rate_limiting,
    ConfirmationClass.CVE_VERSION: _rule_cve_version,
    ConfirmationClass.TLS_HEADERS: _rule_tls_headers,
}

_NOT_CONFIRMATION_REASON: dict[ConfirmationClass, str] = {
    ConfirmationClass.XSS: "reflection of a string is not execution in a browser context",
    ConfirmationClass.SQLI: "a timing difference without a control is not SQLi",
    ConfirmationClass.SSRF: "a 200 from the app is not a controlled OAST interaction",
    ConfirmationClass.RCE: "a suspicious parameter is not command execution",
    ConfirmationClass.CMDI: "a suspicious parameter is not command execution",
    ConfirmationClass.IDOR: "access under your own role is not IDOR",
    ConfirmationClass.BOLA: "access under your own role is not BOLA",
    ConfirmationClass.AUTH_BYPASS: "HTTP 200 is not an authentication bypass",
    ConfirmationClass.RATE_LIMITING: "absence of 429 is not absence of rate limiting",
    ConfirmationClass.CVE_VERSION: "a version banner is not a confirmed CVE (backport unknown)",
    ConfirmationClass.TLS_HEADERS: "a scanner verdict is not a saved handshake/header proof",
}

#: Keyword → ConfirmationClass resolver (matches finding titles / CWE tokens).
_CLASS_KEYWORDS: tuple[tuple[str, ConfirmationClass], ...] = (
    ("xss", ConfirmationClass.XSS),
    ("cross-site scripting", ConfirmationClass.XSS),
    ("sql injection", ConfirmationClass.SQLI),
    ("sqli", ConfirmationClass.SQLI),
    ("ssrf", ConfirmationClass.SSRF),
    ("server-side request forgery", ConfirmationClass.SSRF),
    ("command injection", ConfirmationClass.CMDI),
    ("cmdi", ConfirmationClass.CMDI),
    ("remote code execution", ConfirmationClass.RCE),
    ("rce", ConfirmationClass.RCE),
    ("idor", ConfirmationClass.IDOR),
    ("insecure direct object", ConfirmationClass.IDOR),
    ("bola", ConfirmationClass.BOLA),
    ("broken object level", ConfirmationClass.BOLA),
    ("authentication bypass", ConfirmationClass.AUTH_BYPASS),
    ("auth bypass", ConfirmationClass.AUTH_BYPASS),
    ("rate limit", ConfirmationClass.RATE_LIMITING),
    ("tls", ConfirmationClass.TLS_HEADERS),
    ("security header", ConfirmationClass.TLS_HEADERS),
    ("outdated", ConfirmationClass.CVE_VERSION),
    ("cve", ConfirmationClass.CVE_VERSION),
)

#: Each keyword compiled to a whole-token matcher: not flanked by another
#: alphanumeric. Substring matching mis-classified common text — e.g. "source"
#: contains "rce", "details" could trip short tokens — which then drove the
#: wrong per-class gate during tier adjudication. Boundary matching fixes that
#: while still matching "CVE-2021", "TLS 1.2", "reflected XSS", etc.
_CLASS_KEYWORD_PATTERNS: tuple[tuple[re.Pattern[str], ConfirmationClass], ...] = tuple(
    (re.compile(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])"), cls)
    for keyword, cls in _CLASS_KEYWORDS
)


def resolve_confirmation_class(text: str) -> ConfirmationClass | None:
    """Best-effort resolve a finding title/CWE string to a confirmation class.

    Keywords match on token boundaries (not raw substrings) so e.g. "source"
    does not resolve to RCE.
    """
    low = (text or "").lower()
    for pattern, cls in _CLASS_KEYWORD_PATTERNS:
        if pattern.search(low):
            return cls
    return None


def evaluate_class_confirmation(
    confirmation_class: ConfirmationClass, poc: dict[str, Any]
) -> ClassRuleResult:
    """Return whether ``poc`` meets the confirmation bar for ``confirmation_class`` (§15.2).

    A finding that does not meet its class rule must be downgraded to ``observed``; the
    ``reason`` explains why, for printing in the report.
    """
    rule = _CLASS_RULES[confirmation_class]
    root = _poc_root(poc)
    confirmed = bool(rule(root))
    reason = "" if confirmed else _NOT_CONFIRMATION_REASON[confirmation_class]
    return ClassRuleResult(
        confirmation_class=confirmation_class, confirmed=confirmed, reason=reason
    )


__all__ = [
    "ClassRuleResult",
    "ConfirmationClass",
    "evaluate_class_confirmation",
    "resolve_confirmation_class",
]
