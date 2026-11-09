"""SSL/TLS protocol-support cells: no "unknown" — confirmed yes/no from a real probe.

Regression: a modern site (TLS 1.2/1.3 only) ran testssl, which reported
``TLS 1.0 not offered`` / ``TLS 1.1 not offered``, but the authoritative negatives
were dropped (the model carried no ``not_offered`` field and the JSON parser
conflated not-offered entries into the offered/weak lists). The report then showed
"unknown" for the TLS 1.0 / TLS 1.1 columns instead of a confirmed "no".
"""

from __future__ import annotations

from src.reports.valhalla_report_context import (
    SslTlsAnalysisModel,
    _ssl_from_testssl_json,
    _tls_version_cell,
    build_ssl_tls_table_rows,
)

# testssl.sh --jsonfile-pretty scanResult for a hardened Vercel/Let's Encrypt host:
# only TLS 1.2 / 1.3 are offered; the legacy versions are explicitly "not offered".
_TESTSSL_JSON = {
    "scanResult": [
        {"id": "SSLv2", "severity": "OK", "finding": "not offered (OK)"},
        {"id": "SSLv3", "severity": "OK", "finding": "not offered (OK)"},
        {"id": "TLS1", "severity": "OK", "finding": "not offered"},
        {"id": "TLS1_1", "severity": "OK", "finding": "not offered"},
        {"id": "TLS1_2", "severity": "OK", "finding": "offered (OK)"},
        {"id": "TLS1_3", "severity": "OK", "finding": "offered (OK): final"},
        {"id": "HSTS", "severity": "OK", "finding": "HSTS max-age=63072000"},
    ]
}


def test_json_parser_records_not_offered_and_offered() -> None:
    ssl = _ssl_from_testssl_json(_TESTSSL_JSON)
    # offered versions are the modern ones, as display labels
    assert "TLS 1.2" in ssl.protocols
    assert "TLS 1.3" in ssl.protocols
    # the legacy versions are authoritative negatives, NOT weaknesses
    assert set(ssl.not_offered) == {"sslv2", "sslv3", "tls 1.0", "tls 1.1"}
    assert ssl.weak_protocols == []  # not-offered weak versions are never "weak"


def test_cell_confirmed_no_for_not_offered() -> None:
    # testssl probed and said "not offered" -> a confirmed "no", never "unknown".
    assert _tls_version_cell(["TLS 1.2", "TLS 1.3"], "1.0", ["tls 1.0", "tls 1.1"]) == "no"
    assert _tls_version_cell(["TLS 1.2", "TLS 1.3"], "1.1", ["tls 1.0", "tls 1.1"]) == "no"


def test_cell_yes_for_offered() -> None:
    assert _tls_version_cell(["TLS 1.2", "TLS 1.3"], "1.2", []) == "yes (see scan)"
    assert _tls_version_cell(["TLS 1.2", "TLS 1.3"], "1.3", []) == "yes (see scan)"


def test_cell_never_emits_unknown() -> None:
    # Probe ran (offered list present) but a version is in neither list: honest
    # "not tested" — NEVER "unknown", and NEVER a fabricated "no"/secure claim.
    out = _tls_version_cell(["TLS 1.2"], "1.0", [])
    assert out == "not tested"
    assert out != "unknown"


def test_cell_na_when_no_probe_at_all() -> None:
    assert _tls_version_cell([], "1.0", []) == "n/a"
    assert _tls_version_cell([], "1.0", None) == "n/a"


def test_table_rows_show_no_not_unknown_for_hardened_host() -> None:
    ssl = _ssl_from_testssl_json(_TESTSSL_JSON)
    recon = {
        "ssl_certs": {
            "svalbard.ca": [
                {
                    "common_name": "*.svalbard.ca",
                    "issuer": "Let's Encrypt",
                    "validity_not_before": "2026-10-16",
                    "validity_not_after": "2027-01-14",
                }
            ]
        }
    }
    rows = build_ssl_tls_table_rows(recon, ssl, target_hint="svalbard.ca")
    assert rows, "expected at least one SSL/TLS row"
    r = rows[0]
    assert r.tls_1_0 == "no"
    assert r.tls_1_1 == "no"
    assert r.tls_1_2 == "yes (see scan)"
    assert r.tls_1_3 == "yes (see scan)"
    for cell in (r.tls_1_0, r.tls_1_1, r.tls_1_2, r.tls_1_3):
        assert cell != "unknown"


def test_not_offered_survives_model_roundtrip() -> None:
    m = SslTlsAnalysisModel(protocols=["TLS 1.2"], not_offered=["tls 1.0"])
    dumped = m.model_dump(mode="json")
    assert dumped["not_offered"] == ["tls 1.0"]
