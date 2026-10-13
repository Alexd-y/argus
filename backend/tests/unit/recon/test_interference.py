"""Wave 3 / etap 6 — unified interference signal."""

from __future__ import annotations

from src.recon.vulnerability_analysis.interference import (
    InterferenceSignal,
    detect_interference,
)


def test_clean_observation_has_no_interference() -> None:
    sig = detect_interference(status_code=200, body="<html>ok</html>", headers={"Server": "nginx"})
    assert sig.observed is False
    assert sig.reasons() == ()


def test_rate_limit_from_429_or_retry_after() -> None:
    assert detect_interference(status_code=429).rate_limited is True
    assert detect_interference(status_code=200, headers={"Retry-After": "30"}).rate_limited is True


def test_waf_marker_in_body_or_server() -> None:
    assert detect_interference(status_code=403, body="This request has been blocked").waf_blocked
    assert detect_interference(status_code=200, headers={"Server": "cloudflare"}).waf_blocked
    # A bare 403 without a marker is NOT assumed to be a WAF.
    assert detect_interference(status_code=403, body="Forbidden").waf_blocked is False


def test_unreachable_and_fingerprint_change() -> None:
    assert detect_interference(connection_error=True).target_unreachable is True
    assert (
        detect_interference(baseline_fingerprint="a", current_fingerprint="b").fingerprint_changed
        is True
    )
    assert (
        detect_interference(baseline_fingerprint="a", current_fingerprint="a").fingerprint_changed
        is False
    )


def test_observed_and_reasons_aggregate() -> None:
    sig = detect_interference(
        status_code=429, body="web application firewall", connection_error=True
    )
    assert sig.observed is True
    assert set(sig.reasons()) == {"waf_blocked", "rate_limited", "target_unreachable"}


def test_merge_ors_signals() -> None:
    a = InterferenceSignal(rate_limited=True)
    b = InterferenceSignal(waf_blocked=True)
    merged = a.merge(b)
    assert merged.rate_limited and merged.waf_blocked
    assert set(merged.reasons()) == {"rate_limited", "waf_blocked"}
