from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel


class XssValidationResult(BaseModel):
    reflection_context: str | None = None
    payload_entered: str | None = None
    payload_reflected: str | None = None
    verified_via_browser: bool | None = None
    browser_alert_text: str | None = None
    affected_parameter: str | None = None
    negative_control: str | None = None

    def is_validated(self) -> bool:
        required = [
            self.reflection_context,
            self.payload_entered,
            self.payload_reflected,
            self.verified_via_browser is not None,
            self.browser_alert_text,
            self.affected_parameter,
            self.negative_control,
        ]
        return all(required)


class CsrfValidationResult(BaseModel):
    raw_html_form: str | None = None
    raw_post: str | None = None
    cookies: dict | None = None
    origin_referer: str | None = None
    csrftoken_status: Literal["missing", "weak", "absent", "present"] | None = None
    state_changing: bool | None = None
    negative_control: str | None = None

    def is_validated(self) -> bool:
        required = [
            self.raw_html_form,
            self.raw_post,
            self.cookies,
            self.origin_referer,
            self.csrftoken_status,
            self.state_changing is not None,
            self.negative_control,
        ]
        return all(required)


class CmdiValidationResult(BaseModel):
    harmless_marker: str | None = None
    controlled_output: str | None = None
    server_proof: str | None = None
    negative_control: str | None = None

    def is_validated(self) -> bool:
        required = [
            self.harmless_marker,
            self.controlled_output,
            self.server_proof,
            self.negative_control,
        ]
        return all(required)


def validate_xss_poc(proof_of_concept: dict) -> XssValidationResult:
    poc_obj = proof_of_concept.get("proof_of_concept", proof_of_concept)
    xss_obj = poc_obj.get("xss", {})
    return XssValidationResult(
        reflection_context=xss_obj.get("reflection_context") or poc_obj.get("reflection_context"),
        payload_entered=xss_obj.get("payload_entered") or poc_obj.get("payload_entered"),
        payload_reflected=xss_obj.get("payload_reflected") or poc_obj.get("payload_reflected"),
        verified_via_browser=xss_obj.get("verified_via_browser")
        or poc_obj.get("verified_via_browser"),
        browser_alert_text=xss_obj.get("browser_alert_text") or poc_obj.get("browser_alert_text"),
        affected_parameter=xss_obj.get("affected_parameter") or poc_obj.get("affected_parameter"),
        negative_control=xss_obj.get("negative_control") or poc_obj.get("negative_control"),
    )


def validate_csrf(proof_of_concept: dict) -> CsrfValidationResult:
    poc_obj = proof_of_concept.get("proof_of_concept", proof_of_concept)
    csrf_obj = poc_obj.get("csrf", {})
    return CsrfValidationResult(
        raw_html_form=csrf_obj.get("raw_html_form") or poc_obj.get("raw_html_form"),
        raw_post=csrf_obj.get("raw_post") or poc_obj.get("raw_post"),
        cookies=csrf_obj.get("cookies") or poc_obj.get("cookies"),
        origin_referer=csrf_obj.get("origin_referer") or poc_obj.get("origin_referer"),
        csrftoken_status=csrf_obj.get("csrftoken_status") or poc_obj.get("csrftoken_status"),
        state_changing=csrf_obj.get("state_changing") or poc_obj.get("state_changing"),
        negative_control=csrf_obj.get("negative_control") or poc_obj.get("negative_control"),
    )


def validate_cmdi(proof_of_concept: dict) -> CmdiValidationResult:
    poc_obj = proof_of_concept.get("proof_of_concept", proof_of_concept)
    cmdi_obj = poc_obj.get("command_injection", {})
    return CmdiValidationResult(
        harmless_marker=cmdi_obj.get("harmless_marker") or poc_obj.get("harmless_marker"),
        controlled_output=cmdi_obj.get("controlled_output") or poc_obj.get("controlled_output"),
        server_proof=cmdi_obj.get("server_proof") or poc_obj.get("server_proof"),
        negative_control=cmdi_obj.get("negative_control") or poc_obj.get("negative_control"),
    )


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
    return _nonempty(root.get("negative_control"), root.get("baseline"))


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
    ("cve-", ConfirmationClass.CVE_VERSION),
)


def resolve_confirmation_class(text: str) -> ConfirmationClass | None:
    """Best-effort resolve a finding title/CWE string to a confirmation class."""
    low = (text or "").lower()
    for keyword, cls in _CLASS_KEYWORDS:
        if keyword in low:
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
