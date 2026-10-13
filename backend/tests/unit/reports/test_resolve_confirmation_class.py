"""resolve_confirmation_class must match on token boundaries, not raw substrings.

Regression guard for the wave-3 adjudication wiring: substring matching made
"source" resolve to RCE (contains "rce"), which then drove the wrong per-class
gate when the arbiter adjudicated a finding's tier.
"""

from __future__ import annotations

import pytest
from src.reports.poc_validation import ConfirmationClass, resolve_confirmation_class


@pytest.mark.parametrize(
    "text",
    [
        "Source code disclosure via .git",
        "Resource exhaustion in parser",
        "Outsourcing review of the module",
    ],
)
def test_source_like_text_does_not_resolve_to_rce(text: str) -> None:
    assert resolve_confirmation_class(text) is not ConfirmationClass.RCE


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Reflected XSS in q", ConfirmationClass.XSS),
        ("Blind SQL injection in id", ConfirmationClass.SQLI),
        ("Remote Code Execution via upload", ConfirmationClass.RCE),
        ("IDOR on /api/orders/{id}", ConfirmationClass.IDOR),
        ("Missing security header (TLS 1.2)", ConfirmationClass.TLS_HEADERS),
        ("Outdated jQuery 1.7 (CVE-2020-11022)", ConfirmationClass.CVE_VERSION),
        ("SSRF to metadata endpoint", ConfirmationClass.SSRF),
    ],
)
def test_real_classes_still_resolve(text: str, expected: ConfirmationClass) -> None:
    assert resolve_confirmation_class(text) is expected


def test_unrelated_text_resolves_to_none() -> None:
    assert resolve_confirmation_class("Verbose error message in response") is None
