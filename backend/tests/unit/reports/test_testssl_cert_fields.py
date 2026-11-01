"""parse_testssl_cert_fields: extract issuer/subject/SAN/validity from testssl text.

Regression: the openssl-oriented matcher missed testssl's column layout and its
greedy Issuer regex captured the CAA commentary line (`match with "Issuer" below`)
instead of the real Issuer field, so reports showed issuer='" below' and empty
subject/SAN/validity for a perfectly valid Let's Encrypt certificate.
"""

from __future__ import annotations

from src.reports.tls_parser_v2 import parse_testssl_cert_fields

# Trimmed real testssl output for svalbard.ca (Vercel / Let's Encrypt), including
# the stray `}` line prefixes and the CAA commentary that fooled the old parser.
_TESTSSL = """\
} DNS CAA RR (experimental)    available - please check for match with "Issuer" below
 Issuer                       YR1 (Let's Encrypt from US)
} Common Name (CN)             *.svalbard.ca ,{
} subjectAltName (SAN)         *.svalbard.ca svalbard.ca
 Certificate Validity (UTC)   75 >= 30 days (2026-10-16 03:22 --> 2027-01-14 03:22)
"""


def test_testssl_issuer_is_the_field_not_the_caa_comment() -> None:
    cf = parse_testssl_cert_fields(_TESTSSL)
    assert cf["issuer"] == "YR1 (Let's Encrypt from US)"
    assert "below" not in cf["issuer"].lower()


def test_testssl_subject_san_and_validity() -> None:
    cf = parse_testssl_cert_fields(_TESTSSL)
    assert cf["subject"] == "*.svalbard.ca"
    assert cf["san"] == ["*.svalbard.ca", "svalbard.ca"]
    assert cf["valid_from"].startswith("2026-10-16")
    assert cf["valid_to"].startswith("2027-01-14")
    assert "2026-10-16" in cf["validity"] and "2027-01-14" in cf["validity"]


def test_openssl_fallback_forms() -> None:
    cf = parse_testssl_cert_fields(
        "issuer=C = US, O = Let's Encrypt, CN = R3\n"
        "subject=CN = example.com\n"
        "notBefore=Jan  1 00:00:00 2026 GMT\n"
        "notAfter=Apr  1 00:00:00 2026 GMT\n"
    )
    assert "Let's Encrypt" in cf["issuer"]
    assert cf["valid_from"].startswith("Jan")
    assert cf["valid_to"].startswith("Apr")


def test_empty_text_is_safe() -> None:
    cf = parse_testssl_cert_fields("")
    assert cf == {
        "issuer": "",
        "subject": "",
        "san": [],
        "valid_from": "",
        "valid_to": "",
        "validity": "",
    }
