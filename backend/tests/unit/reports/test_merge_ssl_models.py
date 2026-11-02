"""§3 SSL-parser consolidation: _merge_ssl_models field-wise primary-wins merge.

Locks in the behaviour the two hand-rolled merge blocks in _vh_build_ssl had:
the testssl-JSON/structured source wins per field, the gap-filler supplies only
what the primary left empty.
"""

from __future__ import annotations

from src.reports.valhalla_report_context import (
    _SSL_MERGE_FIELDS,
    SslTlsAnalysisModel,
    _merge_ssl_models,
)


def test_primary_wins_fallback_fills_gaps() -> None:
    primary = SslTlsAnalysisModel(issuer="Let's Encrypt", subject="", protocols=["TLS 1.3"])
    fallback = SslTlsAnalysisModel(
        issuer="Other CA", subject="CN=svalbard.ca", protocols=["TLS 1.2"], hsts="max-age=1"
    )
    merged = _merge_ssl_models(primary, fallback)
    # primary non-empty field wins
    assert merged.issuer == "Let's Encrypt"
    assert merged.protocols == ["TLS 1.3"]
    # primary empty field -> fallback fills it
    assert merged.subject == "CN=svalbard.ca"
    assert merged.hsts == "max-age=1"


def test_merge_covers_the_declared_field_set() -> None:
    # Every merged field must exist on the model (guards a typo in the tuple).
    model_fields = set(SslTlsAnalysisModel.model_fields)
    assert set(_SSL_MERGE_FIELDS) <= model_fields
    # And the key certificate/protocol fields the reports render are all merged.
    for f in ("issuer", "subject", "san", "valid_from", "valid_to", "protocols"):
        assert f in _SSL_MERGE_FIELDS
