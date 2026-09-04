"""Block 2.5 — breach / credential-exposure analyzer tests."""

from __future__ import annotations

from src.recon.dns_security.data_exposure import analyze_breach_exposure, mask_email

D = "alleksy.com"


class TestMaskEmail:
    def test_long_local(self):
        assert mask_email("john.doe@alleksy.com") == "j******e@alleksy.com"

    def test_short_local(self):
        assert mask_email("ab@alleksy.com") == "a*@alleksy.com"

    def test_invalid(self):
        assert mask_email("notanemail") == "***"


class TestAnalyzeBreach:
    def test_no_breaches_no_finding(self):
        assert analyze_breach_exposure(D, {"a@alleksy.com": []}) == []

    def test_empty_input(self):
        assert analyze_breach_exposure(D, {}) == []

    def test_breach_without_passwords_is_low(self):
        results = {
            "sd@alleksy.com": [{"Name": "Collection1", "DataClasses": ["Email addresses"]}]
        }
        f = analyze_breach_exposure(D, results)
        assert len(f) == 1
        assert f[0]["severity"] == "low"
        assert "Collection1" in f[0]["evidence"]

    def test_breach_with_passwords_is_medium(self):
        results = {
            "sd@alleksy.com": [
                {"Name": "LinkedIn", "DataClasses": ["Email addresses", "Passwords"]}
            ]
        }
        f = analyze_breach_exposure(D, results)
        assert f[0]["severity"] == "medium"

    def test_emails_masked_and_no_password_values(self):
        results = {
            "john.doe@alleksy.com": [{"Name": "X", "DataClasses": ["Passwords"]}]
        }
        f = analyze_breach_exposure(D, results)
        evidence = f[0]["evidence"]
        assert "j******e@alleksy.com" in evidence
        assert "john.doe@alleksy.com" not in evidence

    def test_multiple_emails_and_sources_aggregated(self):
        results = {
            "a@alleksy.com": [{"Name": "BreachA", "DataClasses": ["Email addresses"]}],
            "b@alleksy.com": [{"Name": "BreachB", "DataClasses": ["Passwords"]}],
        }
        f = analyze_breach_exposure(D, results)
        assert "2 email address(es)" in f[0]["description"]
        assert "BreachA" in f[0]["evidence"] and "BreachB" in f[0]["evidence"]
