"""Email harvesting for DWM breach lookups must decode escape/entity wrappers.

Regression: a JSON-escaped ``>`` (``\\u003e``) or HTML ``&gt;`` immediately before
an address leaked into the captured local-part (``u003einfo@svalbard.ca``), so the
dark-web breach lookup queried a malformed selector and would miss a real leak for
the true address.
"""

from __future__ import annotations

from src.orchestration.handlers import _harvest_emails


def _tr(stdout: str) -> dict:
    return {"whois": {"stdout": stdout}}


def test_decodes_json_escaped_bracket() -> None:
    out = _harvest_emails(_tr(r"contact: >info@svalbard.ca<"), "svalbard.ca")
    assert out == ["info@svalbard.ca"]


def test_decodes_html_entity_bracket() -> None:
    out = _harvest_emails(_tr("&gt;admin@svalbard.ca&lt; &#62;ops@svalbard.ca"), "svalbard.ca")
    assert out == ["admin@svalbard.ca", "ops@svalbard.ca"]


def test_only_in_scope_domain() -> None:
    out = _harvest_emails(_tr("x@other.com y@svalbard.ca z@mail.svalbard.ca"), "svalbard.ca")
    assert out == ["y@svalbard.ca", "z@mail.svalbard.ca"]


def test_clean_email_unchanged() -> None:
    assert _harvest_emails(_tr("mail: info@svalbard.ca"), "svalbard.ca") == ["info@svalbard.ca"]
