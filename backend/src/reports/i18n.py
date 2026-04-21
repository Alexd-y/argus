"""Report i18n — English-only translation layer.

Currently supports only English. The language parameter is preserved for future
multi-language support. Russian data in OWASP/scanner output is handled at the
data layer, not the i18n layer.
"""

from __future__ import annotations

_EN: dict[str, str] = {
    "table_of_contents": "Table of Contents",
    "executive_summary": "Executive Summary",
    "scope_and_objectives": "Scope and Objectives",
    "methodology": "Methodology",
    "findings_overview": "Findings Overview",
    "detailed_findings": "Detailed Findings",
    "risk_assessment": "Risk Assessment",
    "recommendations": "Recommendations",
    "remediation_plan": "Remediation Plan",
    "appendix": "Appendix",
    "severity": "Severity",
    "finding": "Finding",
    "description": "Description",
    "impact": "Impact",
    "remediation": "Remediation",
    "evidence": "Evidence",
    "affected_asset": "Affected Asset",
    "cvss_score": "CVSS Score",
    "cvss_vector": "CVSS Vector",
    "cwe_id": "CWE ID",
    "confidence": "Confidence",
    "status": "Status",
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "test_limitations": "Test Limitations",
    "wstg_coverage": "WSTG Test Coverage",
    "coverage_percentage": "Coverage",
    "covered": "Covered",
    "not_covered": "Not Covered",
    "partial": "Partial",
    "category": "Category",
    "limitation": "Limitation",
    "disclaimer": "Disclaimer",
    "confidential": "Confidential",
    "prepared_for": "Prepared for",
    "prepared_by": "Prepared by",
    "date": "Date",
    "version": "Version",
}

TRANSLATIONS: dict[str, dict[str, str]] = {"en": _EN}

SUPPORTED_LANGUAGES: frozenset[str] = frozenset({"en"})


def get_translations(language: str = "en") -> dict[str, str]:  # noqa: ARG001
    """Return the English translation dict. ``language`` param kept for backward compat."""
    return _EN


def t(key: str, language: str = "en") -> str:  # noqa: ARG001
    """Look up a single translation key. Always returns English. Falls back to the key itself."""
    return _EN.get(key, key)
