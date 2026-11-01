"""parse_testssl_cert_fields: extract issuer/subject/SAN/validity from testssl text.

Regression: the openssl-oriented matcher missed testssl's column layout and its
greedy Issuer regex captured the CAA commentary line (`match with "Issuer" below`)
instead of the real Issuer field, so reports showed issuer='" below' and empty
subject/SAN/validity for a perfectly valid Let's Encrypt certificate.
"""

from __future__ import annotations

from src.reports.tls_parser_v2 import (
    canon_tls_version,
    parse_testssl_cert_fields,
    reconcile_tls_protocols,
)

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
        "protocols": [],
        "weak_protocols": [],
        "not_offered": [],
    }


def test_protocols_are_offered_only_and_record_negatives() -> None:
    # testssl reports each version's offered status; not-offered legacy versions
    # must NOT appear (regression: SSLv2 / TLS 1.1 were falsely listed as present),
    # and the explicit negatives are recorded for the reconcile step.
    text = (
        " SSLv2      not offered (OK)\n"
        " SSLv3      not offered (OK)\n"
        " TLS 1      not offered\n"
        " TLS 1.1    not offered\n"
        " TLS 1.2    offered (OK)\n"
        " TLS 1.3    offered (OK)\n"
    )
    cf = parse_testssl_cert_fields(text)
    assert cf["protocols"] == ["TLS 1.2", "TLS 1.3"]
    assert cf["weak_protocols"] == []
    assert set(cf["not_offered"]) == {"sslv2", "sslv3", "tls 1.0", "tls 1.1"}


def test_offered_weak_protocol_flagged() -> None:
    cf = parse_testssl_cert_fields(" TLS 1.1    offered\n TLS 1.2    offered (OK)\n")
    assert "TLS 1.1" in cf["protocols"]
    assert cf["weak_protocols"] == ["TLS 1.1"]


def test_canon_tls_version_forms() -> None:
    assert canon_tls_version("TLSv1.1") == "tls 1.1"
    assert canon_tls_version("TLS1.1") == "tls 1.1"
    assert canon_tls_version("tls 1") == "tls 1.0"
    assert canon_tls_version("tlsv1.0") == "tls 1.0"
    assert canon_tls_version("SSLv2") == "sslv2"
    assert canon_tls_version("http/2") == ""


def test_reconcile_no_fail_open() -> None:
    # A legacy-detected weak protocol that the column parse did NOT explicitly mark
    # 'not offered' must be KEPT, not dropped (no fail-open). Differently-cased
    # forms normalise to the same version.
    cf = {"protocols": ["TLS 1.2"], "weak_protocols": [], "not_offered": ["sslv2"]}
    protocols, weak = reconcile_tls_protocols(["SSLv2", "TLS1.1"], ["SSLv2", "TLS1.1"], cf)
    # SSLv2 explicitly not-offered -> removed; TLS1.1 not contradicted -> kept weak
    assert "SSLv2" not in protocols and "SSLv2" not in weak
    assert "TLS1.1" in protocols and "TLS1.1" in weak
    assert "TLS 1.2" in protocols


def test_reconcile_positive_evidence_wins_over_negative() -> None:
    # Same version reported BOTH offered and not-offered (e.g. two testssl IP
    # sections): the offered (positive) evidence must win — it stays weak.
    cf = {
        "protocols": ["TLS 1.1"],
        "weak_protocols": ["TLS 1.1"],
        "not_offered": ["tls 1.1"],
    }
    protocols, weak = reconcile_tls_protocols([], [], cf)
    assert "TLS 1.1" in protocols
    assert "TLS 1.1" in weak  # never erased by the conflicting negative
