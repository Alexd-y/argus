"""Single versioned WSTG test-coverage registry (P7-WSTG-007, fix G-4).

This is the **one** source of truth for WSTG test-case coverage in ARGUS. The
former ``wstg_coverage_v2`` module (a competing, unused registry) was removed;
its ``build_wstg_coverage_v2`` entry point now lives here and delegates to
:func:`build_wstg_coverage` so there is no second registry to drift.

The registry targets a single, explicit standard version — :data:`WSTG_VERSION`
(OWASP WSTG v4.2). That version is surfaced in every coverage result so a report
can never present coverage against an ambiguous methodology revision.

Also includes the NIST SP 800-115 test-limitations builder for Valhalla reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Explicit OWASP WSTG methodology version this registry maps against. Surfaced
# in every coverage result (fix G-4: no version-ambiguous coverage output).
WSTG_VERSION: str = "4.2"


@dataclass
class WstgTestCase:
    """Single WSTG test case."""

    id: str
    name: str
    category: str
    tools_mapped: list[str] = field(default_factory=list)


@dataclass
class WstgCoverageResult:
    """Coverage analysis result."""

    total_tests: int
    covered: int
    partial: int
    not_covered: int
    coverage_percentage: float
    by_category: dict[str, Any] = field(default_factory=dict)
    tests: list[dict[str, Any]] = field(default_factory=list)
    auth_testing_enabled: bool = False
    not_covered_reasons: dict[str, str] = field(default_factory=dict)
    missing_artifacts: list[dict] = field(default_factory=list)
    # fix G-4 — explicit methodology version + additive scenario coverage.
    wstg_version: str = WSTG_VERSION
    scenario_coverage: dict[str, Any] | None = None


class WstgCoverageV2Result:
    """V2 coverage analysis with missing artifact tracking."""

    def __init__(
        self,
        total_tests: int,
        covered: int,
        partial: int,
        not_covered: int,
        coverage_percentage: float,
        by_category: dict[str, Any],
        tests: list[dict[str, Any]],
        missing_artifacts: list[dict],
        wstg_version: str = WSTG_VERSION,
    ):
        self.total_tests = total_tests
        self.covered = covered
        self.partial = partial
        self.not_covered = not_covered
        self.coverage_percentage = coverage_percentage
        self.by_category = by_category
        self.tests = tests
        self.missing_artifacts = missing_artifacts
        self.wstg_version = wstg_version


_WSTG_TESTS: list[WstgTestCase] = [
    # ── INFO (Information Gathering) ──────────────────────────────
    WstgTestCase("WSTG-INFO-01", "Conduct Search Engine Discovery Reconnaissance", "Information Gathering"),
    WstgTestCase("WSTG-INFO-02", "Fingerprint Web Server", "Information Gathering"),
    WstgTestCase("WSTG-INFO-03", "Review Webserver Metafiles for Information Leakage", "Information Gathering"),
    WstgTestCase("WSTG-INFO-04", "Enumerate Applications on Webserver", "Information Gathering"),
    WstgTestCase("WSTG-INFO-05", "Review Webpage Content for Information Leakage", "Information Gathering"),
    WstgTestCase("WSTG-INFO-06", "Identify Application Entry Points", "Information Gathering"),
    WstgTestCase("WSTG-INFO-07", "Map Execution Paths Through Application", "Information Gathering"),
    WstgTestCase("WSTG-INFO-08", "Fingerprint Web Application Framework", "Information Gathering"),
    WstgTestCase("WSTG-INFO-09", "Fingerprint Web Application", "Information Gathering"),
    WstgTestCase("WSTG-INFO-10", "Map Application Architecture", "Information Gathering"),
    # ── CONF (Configuration and Deployment) ───────────────────────
    WstgTestCase("WSTG-CONF-01", "Test Network Infrastructure Configuration", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-02", "Test Application Platform Configuration", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-03", "Test File Extensions Handling for Sensitive Information", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-04", "Review Old Backup and Unreferenced Files", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-05", "Enumerate Infrastructure and Application Admin Interfaces", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-06", "Test HTTP Methods", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-07", "Test HTTP Strict Transport Security", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-08", "Test RIA Cross Domain Policy", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-09", "Test File Permission", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-10", "Test for Subdomain Takeover", "Configuration and Deployment"),
    WstgTestCase("WSTG-CONF-11", "Test Cloud Storage", "Configuration and Deployment"),
    # ── IDNT (Identity Management) ────────────────────────────────
    WstgTestCase("WSTG-IDNT-01", "Test Role Definitions", "Identity Management"),
    WstgTestCase("WSTG-IDNT-02", "Test User Registration Process", "Identity Management"),
    WstgTestCase("WSTG-IDNT-03", "Test Account Provisioning Process", "Identity Management"),
    WstgTestCase("WSTG-IDNT-04", "Test for Account Enumeration and Guessable User Account", "Identity Management"),
    WstgTestCase("WSTG-IDNT-05", "Test for Weak or Unenforced Username Policy", "Identity Management"),
    # ── ATHN (Authentication) ─────────────────────────────────────
    WstgTestCase("WSTG-ATHN-01", "Test for Credentials Transported over an Encrypted Channel", "Authentication"),
    WstgTestCase("WSTG-ATHN-02", "Test for Default Credentials", "Authentication"),
    WstgTestCase("WSTG-ATHN-03", "Test for Weak Lock Out Mechanism", "Authentication"),
    WstgTestCase("WSTG-ATHN-04", "Test for Bypassing Authentication Schema", "Authentication"),
    WstgTestCase("WSTG-ATHN-05", "Test for Vulnerable Remember Password", "Authentication"),
    WstgTestCase("WSTG-ATHN-06", "Test for Browser Cache Weaknesses", "Authentication"),
    WstgTestCase("WSTG-ATHN-07", "Test for Weak Password Policy", "Authentication"),
    WstgTestCase("WSTG-ATHN-08", "Test for Weak Security Question Answer", "Authentication"),
    WstgTestCase("WSTG-ATHN-09", "Test for Weak Password Change or Reset Functionalities", "Authentication"),
    WstgTestCase("WSTG-ATHN-10", "Test for Weaker Authentication in Alternative Channel", "Authentication"),
    # ── ATHZ (Authorization) ──────────────────────────────────────
    WstgTestCase("WSTG-ATHZ-01", "Test Directory Traversal File Include", "Authorization"),
    WstgTestCase("WSTG-ATHZ-02", "Test for Bypassing Authorization Schema", "Authorization"),
    WstgTestCase("WSTG-ATHZ-03", "Test for Privilege Escalation", "Authorization"),
    WstgTestCase("WSTG-ATHZ-04", "Test for Insecure Direct Object References", "Authorization"),
    # ── SESS (Session Management) ─────────────────────────────────
    WstgTestCase("WSTG-SESS-01", "Test Session Management Schema", "Session Management"),
    WstgTestCase("WSTG-SESS-02", "Test Cookies Attributes", "Session Management"),
    WstgTestCase("WSTG-SESS-03", "Test for Session Fixation", "Session Management"),
    WstgTestCase("WSTG-SESS-04", "Test for Exposed Session Variables", "Session Management"),
    WstgTestCase("WSTG-SESS-05", "Test for Cross Site Request Forgery", "Session Management"),
    WstgTestCase("WSTG-SESS-06", "Test for Logout Functionality", "Session Management"),
    WstgTestCase("WSTG-SESS-07", "Test Session Timeout", "Session Management"),
    WstgTestCase("WSTG-SESS-08", "Test for Session Puzzling", "Session Management"),
    WstgTestCase("WSTG-SESS-09", "Test for Session Hijacking", "Session Management"),
    # ── INPV (Input Validation) ───────────────────────────────────
    WstgTestCase("WSTG-INPV-01", "Test for Reflected Cross Site Scripting", "Input Validation"),
    WstgTestCase("WSTG-INPV-02", "Test for Stored Cross Site Scripting", "Input Validation"),
    WstgTestCase("WSTG-INPV-03", "Test for HTTP Verb Tampering", "Input Validation"),
    WstgTestCase("WSTG-INPV-04", "Test for HTTP Parameter Pollution", "Input Validation"),
    WstgTestCase("WSTG-INPV-05", "Test for SQL Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-06", "Test for LDAP Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-07", "Test for XML Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-08", "Test for SSI Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-09", "Test for XPath Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-10", "Test for IMAP SMTP Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-11", "Test for Code Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-12", "Test for Command Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-13", "Test for Format String Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-14", "Test for Incubated Vulnerabilities", "Input Validation"),
    WstgTestCase("WSTG-INPV-15", "Test for HTTP Splitting Smuggling", "Input Validation"),
    WstgTestCase("WSTG-INPV-16", "Test for HTTP Incoming Requests", "Input Validation"),
    WstgTestCase("WSTG-INPV-17", "Test for Host Header Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-18", "Test for Server-Side Template Injection", "Input Validation"),
    WstgTestCase("WSTG-INPV-19", "Test for Server-Side Request Forgery", "Input Validation"),
    # ── ERRH (Error Handling) ─────────────────────────────────────
    WstgTestCase("WSTG-ERRH-01", "Test for Improper Error Handling", "Error Handling"),
    WstgTestCase("WSTG-ERRH-02", "Test for Stack Traces", "Error Handling"),
    # ── CRYP (Cryptography) ───────────────────────────────────────
    WstgTestCase("WSTG-CRYP-01", "Test for Weak Transport Layer Security", "Cryptography"),
    WstgTestCase("WSTG-CRYP-02", "Test for Padding Oracle", "Cryptography"),
    WstgTestCase("WSTG-CRYP-03", "Test for Sensitive Information Sent via Unencrypted Channels", "Cryptography"),
    WstgTestCase("WSTG-CRYP-04", "Test for Weak Encryption", "Cryptography"),
    # ── BUSL (Business Logic) ─────────────────────────────────────
    WstgTestCase("WSTG-BUSL-01", "Test Business Logic Data Validation", "Business Logic"),
    WstgTestCase("WSTG-BUSL-02", "Test Ability to Forge Requests", "Business Logic"),
    WstgTestCase("WSTG-BUSL-03", "Test Integrity Checks", "Business Logic"),
    WstgTestCase("WSTG-BUSL-04", "Test for Process Timing", "Business Logic"),
    WstgTestCase("WSTG-BUSL-05", "Test Number of Times a Function Can Be Used Limits", "Business Logic"),
    WstgTestCase("WSTG-BUSL-06", "Test for Circumvention of Work Flows", "Business Logic"),
    WstgTestCase("WSTG-BUSL-07", "Test Defenses Against Application Misuse", "Business Logic"),
    WstgTestCase("WSTG-BUSL-08", "Test Upload of Unexpected File Types", "Business Logic"),
    WstgTestCase("WSTG-BUSL-09", "Test Upload of Malicious Files", "Business Logic"),
    # ── CLNT (Client-Side) ────────────────────────────────────────
    WstgTestCase("WSTG-CLNT-01", "Test for DOM-Based Cross Site Scripting", "Client-Side"),
    WstgTestCase("WSTG-CLNT-02", "Test for JavaScript Execution", "Client-Side"),
    WstgTestCase("WSTG-CLNT-03", "Test for HTML Injection", "Client-Side"),
    WstgTestCase("WSTG-CLNT-04", "Test for Client-Side URL Redirect", "Client-Side"),
    WstgTestCase("WSTG-CLNT-05", "Test for CSS Injection", "Client-Side"),
    WstgTestCase("WSTG-CLNT-06", "Test for Client-Side Resource Manipulation", "Client-Side"),
    WstgTestCase("WSTG-CLNT-07", "Test Cross Origin Resource Sharing", "Client-Side"),
    WstgTestCase("WSTG-CLNT-08", "Test for Cross Site Flashing", "Client-Side"),
    WstgTestCase("WSTG-CLNT-09", "Test for Clickjacking", "Client-Side"),
    WstgTestCase("WSTG-CLNT-10", "Test WebSockets", "Client-Side"),
    WstgTestCase("WSTG-CLNT-11", "Test Web Messaging", "Client-Side"),
    WstgTestCase("WSTG-CLNT-12", "Test Browser Storage", "Client-Side"),
    WstgTestCase("WSTG-CLNT-13", "Test for Cross Site Script Inclusion", "Client-Side"),
]

_TOOL_TO_WSTG: dict[str, list[str]] = {
    "nmap": [
        "WSTG-INFO-01", "WSTG-INFO-02", "WSTG-INFO-04",
        "WSTG-CONF-01", "WSTG-CONF-06",
    ],
    "nikto": [
        "WSTG-CONF-01", "WSTG-CONF-02", "WSTG-CONF-03",
        "WSTG-CONF-04", "WSTG-CONF-06", "WSTG-ERRH-01",
    ],
    "nuclei": [
        "WSTG-INFO-08", "WSTG-CONF-02", "WSTG-CONF-07",
        "WSTG-INPV-01", "WSTG-INPV-02", "WSTG-INPV-05",
        "WSTG-INPV-18", "WSTG-INPV-19", "WSTG-CRYP-01",
        "WSTG-ERRH-01", "WSTG-ERRH-02",
    ],
    "dalfox": [
        "WSTG-INPV-01", "WSTG-INPV-02", "WSTG-CLNT-01",
    ],
    "sqlmap": [
        "WSTG-INPV-05",
    ],
    "testssl": [
        "WSTG-CRYP-01", "WSTG-CRYP-02", "WSTG-CRYP-03", "WSTG-CONF-07",
    ],
    "testssl.sh": [
        "WSTG-CRYP-01", "WSTG-CRYP-02", "WSTG-CRYP-03", "WSTG-CONF-07",
    ],
    "whatweb": [
        "WSTG-INFO-02", "WSTG-INFO-08", "WSTG-INFO-09",
    ],
    "httpx": [
        "WSTG-INFO-02", "WSTG-INFO-04", "WSTG-CONF-07",
    ],
    "gobuster": [
        "WSTG-CONF-03", "WSTG-CONF-04", "WSTG-CONF-05",
    ],
    "feroxbuster": [
        "WSTG-CONF-03", "WSTG-CONF-04", "WSTG-CONF-05",
    ],
    "dirsearch": [
        "WSTG-CONF-03", "WSTG-CONF-04", "WSTG-CONF-05",
    ],
    "ffuf": [
        "WSTG-CONF-03", "WSTG-CONF-04", "WSTG-CONF-05",
        "WSTG-INFO-06",
    ],
    "subfinder": [
        "WSTG-INFO-04", "WSTG-CONF-10",
    ],
    "amass": [
        "WSTG-INFO-04", "WSTG-CONF-10",
    ],
    "wpscan": [
        "WSTG-INFO-08", "WSTG-INFO-09", "WSTG-ATHN-02",
        "WSTG-IDNT-04",
    ],
    "sslyze": [
        "WSTG-CRYP-01", "WSTG-CRYP-02", "WSTG-CRYP-03", "WSTG-CRYP-04",
    ],
    "arjun": [
        "WSTG-INFO-06", "WSTG-ATHZ-02", "WSTG-ATHZ-04", "WSTG-INPV-05",
    ],
    "subjack": [
        "WSTG-CONF-10",
    ],
    "wafw00f": [
        "WSTG-INFO-10",
    ],
    "gitleaks": [
        "WSTG-CONF-04",
    ],
    "trufflehog": [
        "WSTG-CONF-04",
    ],
    "wappalyzer": [
        "WSTG-INFO-08", "WSTG-INFO-09", "WSTG-IDNT-01",
    ],
    "wappalyzer_cli": [
        "WSTG-INFO-08", "WSTG-INFO-09", "WSTG-IDNT-01",
    ],
    "webanalyze": [
        "WSTG-INFO-08", "WSTG-INFO-09", "WSTG-IDNT-01",
    ],
    "curl": [
        "WSTG-INFO-03", "WSTG-CONF-06",
    ],
    "theharvester": [
        "WSTG-INFO-01", "WSTG-INFO-05",
    ],
    "shodan": [
        "WSTG-INFO-01", "WSTG-INFO-04", "WSTG-INFO-10",
    ],
    "censys": [
        "WSTG-INFO-01", "WSTG-INFO-04",
    ],
    "dnsrecon": [
        "WSTG-INFO-04", "WSTG-CONF-10",
    ],
    "dig": [
        "WSTG-INFO-04",
    ],
    "commix": [
        "WSTG-INPV-11", "WSTG-INPV-12",
    ],
    "tplmap": [
        "WSTG-INPV-18",
    ],
    "jwt_tool": [
        "WSTG-SESS-01", "WSTG-SESS-02", "WSTG-SESS-03", "WSTG-ATHN-06",
    ],
    "burp": [
        "WSTG-INPV-01", "WSTG-INPV-02", "WSTG-INPV-05",
        "WSTG-SESS-01", "WSTG-SESS-02", "WSTG-SESS-05",
        "WSTG-ATHN-04", "WSTG-ATHZ-02", "WSTG-ATHZ-04",
    ],
    "zap": [
        "WSTG-INPV-01", "WSTG-INPV-02", "WSTG-INPV-05",
        "WSTG-SESS-01", "WSTG-SESS-02", "WSTG-SESS-05",
        "WSTG-CONF-06", "WSTG-ERRH-01",
    ],
    "retire.js": [
        "WSTG-CLNT-12", "WSTG-CLNT-13",
    ],
    "sslscan": [
        "WSTG-CRYP-01",
    ],
    "hydra": [
        "WSTG-ATHN-01", "WSTG-ATHN-02", "WSTG-ATHN-04", "WSTG-ATHN-07",
    ],
    "patator": [
        "WSTG-ATHN-01", "WSTG-ATHN-02", "WSTG-ATHN-04", "WSTG-ATHN-07",
    ],
    "rate_limit_signal": [
        "WSTG-ATHN-03",
    ],
    "trivy": [
        "WSTG-INFO-09", "WSTG-CONF-02",
    ],
    "xsstrike": [
        "WSTG-INPV-01", "WSTG-INPV-02", "WSTG-CLNT-01",
    ],
    "argus_recon": [
        "WSTG-INFO-01", "WSTG-INFO-02", "WSTG-INFO-04",
        "WSTG-INFO-05", "WSTG-INFO-06", "WSTG-INFO-08",
        "WSTG-INFO-09", "WSTG-INFO-10",
        "WSTG-CONF-07", "WSTG-CONF-10",
        "WSTG-CRYP-03",
    ],
    "argus_active_scan": [
        "WSTG-INPV-01", "WSTG-INPV-02", "WSTG-INPV-05",
        "WSTG-INPV-06", "WSTG-INPV-10", "WSTG-INPV-11",
        "WSTG-INPV-12", "WSTG-INPV-18", "WSTG-INPV-19",
        "WSTG-CLNT-01",
    ],
    "playwright": [
        "WSTG-CLNT-01", "WSTG-CLNT-02", "WSTG-CLNT-06", "WSTG-CLNT-07",
    ],
    "katana": [
        "WSTG-INFO-04", "WSTG-CONF-03", "WSTG-CONF-05",
    ],
    "waybackurls": [
        "WSTG-INFO-04", "WSTG-CONF-03",
    ],
    "gau": [
        "WSTG-INFO-04", "WSTG-CONF-03",
    ],
    "cookie_probe": [
        "WSTG-SESS-01", "WSTG-SESS-02", "WSTG-SESS-03", "WSTG-SESS-05",
    ],
    "httpx_tool": [
        "WSTG-INFO-02", "WSTG-INFO-04", "WSTG-CONF-07",
    ],
    "masscan": [
        "WSTG-INFO-04", "WSTG-CONF-01",
    ],
    "naabu": [
        "WSTG-INFO-04", "WSTG-CONF-01",
    ],
}

_TOOL_ALIASES: dict[str, str] = {
    "testssl.sh": "testssl",
    "owasp_zap": "zap",
    "owasp-zap": "zap",
    "zaproxy": "zap",
    "burpsuite": "burp",
    "burp_suite": "burp",
    "retirejs": "retire.js",
    "retire_js": "retire.js",
    "the_harvester": "theharvester",
    "the-harvester": "theharvester",
    "dns_recon": "dnsrecon",
    "dns-recon": "dnsrecon",
    "jwt-tool": "jwt_tool",
    "jwtool": "jwt_tool",
    "rate-limit-signal": "rate_limit_signal",
    "rate_limit": "rate_limit_signal",
    "git-leaks": "gitleaks",
    "git_leaks": "gitleaks",
    "truffle-hog": "trufflehog",
    "truffle_hog": "trufflehog",
    "waf_w00f": "wafw00f",
    "sub_finder": "subfinder",
    "sub-finder": "subfinder",
    "ferox_buster": "feroxbuster",
    "ferox-buster": "feroxbuster",
    "dir_search": "dirsearch",
    "dir-search": "dirsearch",
    "ssl_scan": "sslscan",
    "ssl-scan": "sslscan",
    "ssl_yze": "sslyze",
    "ssl-yze": "sslyze",
    "wp_scan": "wpscan",
    "wp-scan": "wpscan",
    "sub_jack": "subjack",
    "sub-jack": "subjack",
}

_TOOL_EVIDENCE_IDS: dict[str, str] = {
    "whatweb": "EV-TECH-001",
    "wappalyzer": "EV-TECH-001",
    "httpx": "EV-HDR-001",
    "curl": "EV-HDR-001",
    "nikto": "EV-HDR-001",
    "testssl": "EV-TLS-001",
    "testssl.sh": "EV-TLS-001",
    "sslscan": "EV-TLS-001",
    "sslyze": "EV-TLS-001",
    "nmap": "EV-PORT-001",
    "naabu": "EV-PORT-001",
    "masscan": "EV-PORT-001",
    "theharvester": "EV-EMAIL-001",
    "trivy": "EV-SCA-001",
    "rate_limit_signal": "EV-AUTH-001",
}

_MIN_TOOLS_FULL_COVERAGE = 2


def _normalize_tool_name(raw: str) -> str:
    """Lowercase + strip, then resolve aliases."""
    key = raw.strip().lower().replace(" ", "_")
    return _TOOL_ALIASES.get(key, key)


def _build_wstg_id_to_tests() -> dict[str, WstgTestCase]:
    return {t.id: t for t in _WSTG_TESTS}


def _determine_test_status(
    test_id: str,
    covering_tools: set[str],
    finding_wstg_ids: set[str],
) -> str:
    """Return 'covered' | 'partial' | 'not_covered' for a single test."""
    if test_id in finding_wstg_ids:
        return "covered"
    if len(covering_tools) >= _MIN_TOOLS_FULL_COVERAGE:
        return "covered"
    if covering_tools:
        return "partial"
    return "not_covered"


def _extract_wstg_ids_from_findings(findings: list[dict[str, Any]]) -> set[str]:
    """Pull WSTG-* references from finding tags, references, or descriptions."""
    result: set[str] = set()
    if not findings:
        return result
    for f in findings:
        for field_name in ("tags", "references", "ref", "wstg", "owasp_wstg"):
            val = f.get(field_name)
            if isinstance(val, list):
                for item in val:
                    s = str(item).upper()
                    if s.startswith("WSTG-"):
                        result.add(s)
            elif isinstance(val, str):
                for token in val.upper().replace(",", " ").split():
                    if token.startswith("WSTG-"):
                        result.add(token)
        desc = str(f.get("description") or "")
        title = str(f.get("title") or "")
        for text in (desc, title):
            for token in text.upper().replace(",", " ").split():
                if token.startswith("WSTG-") and len(token) <= 16:
                    result.add(token)
    return result


def build_wstg_coverage(
    tools_executed: list[str],
    findings: list[dict[str, Any]] | None = None,
    *,
    scenario_coverage: dict[str, Any] | None = None,
) -> WstgCoverageResult:
    """Calculate WSTG coverage based on executed tools and findings.

    ``scenario_coverage`` is an optional, additive block built by
    :mod:`src.reports.scenario_coverage` from executed playbook scenarios. When
    provided it is attached verbatim to the result (fix G-4: single coverage
    output, executed-scenario coverage layered on top of tool coverage).
    """
    normalized_tools = {_normalize_tool_name(t) for t in tools_executed if t}
    finding_wstg_ids = _extract_wstg_ids_from_findings(findings or [])

    wstg_to_covering_tools: dict[str, set[str]] = {}
    for tool_key in normalized_tools:
        mapped_ids = _TOOL_TO_WSTG.get(tool_key, [])
        for wstg_id in mapped_ids:
            wstg_to_covering_tools.setdefault(wstg_id, set()).add(tool_key)

    categories: dict[str, dict[str, int]] = {}
    category_evidence: dict[str, set[str]] = {}
    tests_output: list[dict[str, Any]] = []

    for tc in _WSTG_TESTS:
        covering = wstg_to_covering_tools.get(tc.id, set())
        status = _determine_test_status(tc.id, covering, finding_wstg_ids)

        cat_bucket = categories.setdefault(tc.category, {
            "covered": 0, "partial": 0, "not_covered": 0, "total": 0,
        })
        cat_bucket["total"] += 1
        cat_bucket[status] += 1
        if status != "not_covered":
            for tool in covering:
                evidence_id = _TOOL_EVIDENCE_IDS.get(tool)
                if evidence_id:
                    category_evidence.setdefault(tc.category, set()).add(evidence_id)

        tests_output.append({
            "id": tc.id,
            "name": tc.name,
            "category": tc.category,
            "status": status,
            "tools": sorted(covering),
        })

    total = len(_WSTG_TESTS)
    covered = sum(1 for t in tests_output if t["status"] == "covered")
    partial = sum(1 for t in tests_output if t["status"] == "partial")
    not_covered = total - covered - partial

    by_category: dict[str, dict[str, Any]] = {}
    for cat_name, counts in categories.items():
        cat_total = counts["total"]
        effective = counts["covered"] + counts["partial"] * 0.5
        by_category[cat_name] = {
            **counts,
            "percentage": (effective / cat_total * 100) if cat_total else 0.0,
            "evidence_ids": sorted(category_evidence.get(cat_name, set())),
        }

    effective_total = covered + partial * 0.5
    coverage_pct = (effective_total / total * 100) if total else 0.0

    return WstgCoverageResult(
        total_tests=total,
        covered=covered,
        partial=partial,
        not_covered=not_covered,
        coverage_percentage=coverage_pct,
        by_category=by_category,
        tests=tests_output,
        wstg_version=WSTG_VERSION,
        scenario_coverage=scenario_coverage,
    )


def build_test_limitations(
    scan_config: dict[str, Any],
    scan_results: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Build NIST SP 800-115 test limitations section.

    Returns list of limitation dicts with keys: category, description, impact.
    """
    limitations: list[dict[str, str]] = [
        {
            "category": "scope",
            "description": "Testing limited to authorized targets only",
            "impact": "medium",
        },
        {
            "category": "time",
            "description": "Time-limited testing window",
            "impact": "medium",
        },
        {
            "category": "scope",
            "description": (
                "Destructive testing and denial-of-service attacks were not performed"
            ),
            "impact": "high",
        },
        {
            "category": "tool",
            "description": (
                "Primary reliance on automated tools; "
                "manual verification performed for critical findings"
            ),
            "impact": "medium",
        },
    ]

    results = scan_results or {}
    config = scan_config or {}

    waf_detected = _check_waf_detected(results, config)
    if waf_detected:
        limitations.append({
            "category": "network",
            "description": (
                "Web Application Firewall (WAF) detected; "
                "testing accuracy may be affected by WAF rules"
            ),
            "impact": "high",
        })

    scan_perspective = str(config.get("scan_perspective", "external")).lower()
    if scan_perspective in ("external", "ext", "outside"):
        limitations.append({
            "category": "access",
            "description": (
                "Testing performed from external perspective only; "
                "internal network not assessed"
            ),
            "impact": "high",
        })

    has_creds = bool(
        config.get("credentials")
        or config.get("auth_token")
        or config.get("authenticated")
        or config.get("auth_testing_enabled")
    )
    if not has_creds:
        limitations.append({
            "category": "access",
            "description": (
                "Authenticated testing not performed; "
                "coverage limited to unauthenticated access. "
                "Business logic flaws, IDOR, privilege escalation, and "
                "authenticated access control issues were NOT tested."
            ),
            "impact": "high",
        })

    missing_tools = results.get("missing_tools") or config.get("missing_tools")
    if isinstance(missing_tools, list) and missing_tools:
        limitations.append({
            "category": "tool",
            "description": (
                "Some tools were unavailable in the testing environment"
            ),
            "impact": "medium",
        })

    scan_mode = str(config.get("scan_mode", "")).lower()
    if scan_mode in ("quick", "fast", "light"):
        limitations.append({
            "category": "time",
            "description": (
                "Quick scan mode used; "
                "reduced coverage compared to deep scan"
            ),
            "impact": "high",
        })

    rate_limited = (
        results.get("rate_limited")
        or results.get("rate_limiting_detected")
    )
    if rate_limited:
        limitations.append({
            "category": "network",
            "description": (
                "Rate limiting detected on target; "
                "some tests may have incomplete results"
            ),
            "impact": "medium",
        })

    ssl_errors = results.get("ssl_errors") or results.get("tls_errors")
    if ssl_errors:
        limitations.append({
            "category": "network",
            "description": (
                "TLS/SSL certificate errors encountered; "
                "some HTTPS tests may be incomplete"
            ),
            "impact": "low",
        })

    return limitations


def _check_waf_detected(
    results: dict[str, Any],
    config: dict[str, Any],
) -> bool:
    """Detect WAF presence from results or config."""
    if results.get("waf_detected"):
        return True
    if config.get("waf_detected"):
        return True
    wafw00f = results.get("wafw00f")
    if isinstance(wafw00f, dict) and wafw00f.get("detected"):
        return True
    if isinstance(wafw00f, str) and wafw00f.strip():
        return True
    tools_results = results.get("tool_results") or {}
    if isinstance(tools_results, dict):
        waf_output = tools_results.get("wafw00f")
        if isinstance(waf_output, dict) and waf_output.get("detected"):
            return True
        if isinstance(waf_output, str) and "is behind" in waf_output.lower():
            return True
    return False


def build_wstg_coverage_v2(
    tools_executed: list[str],
    findings: list[dict[str, Any]] | None = None,
    evidence_inventory: list[dict[str, Any]] | None = None,
) -> WstgCoverageV2Result:
    """WSTG coverage with missing-artifact tracking.

    Kept as a thin alias over :func:`build_wstg_coverage` (fix G-4: one
    registry). It adds a ``missing_artifacts`` view for ``not_covered`` tests
    that also lack a matching evidence artifact.
    """
    result = build_wstg_coverage(tools_executed, findings)
    
    evidence_set = set()
    if evidence_inventory:
        for ev in evidence_inventory:
            if isinstance(ev, dict) and ev.get("test_id"):
                evidence_set.add(ev["test_id"])
    
    missing_artifacts = []
    for test in result.tests:
        if test["status"] == "not_covered" and test["id"] not in evidence_set:
            missing_artifacts.append({
                "test_id": test["id"],
                "category": test["category"],
                "tool_hint": f"tool_{test['tools'][0]}_stdout" if test["tools"] else "unknown",
                "artifact_hint": f"Not assessed: missing artifact for {test['id']}",
            })
    
    return WstgCoverageV2Result(
        total_tests=result.total_tests,
        covered=result.covered,
        partial=result.partial,
        not_covered=result.not_covered,
        coverage_percentage=result.coverage_percentage,
        by_category=result.by_category,
        tests=result.tests,
        missing_artifacts=missing_artifacts,
        wstg_version=result.wstg_version,
    )
