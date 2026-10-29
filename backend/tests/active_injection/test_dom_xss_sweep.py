"""DOM-XSS sweep candidate-URL builder (headless-browser DOM sink probing).

The browser navigation itself needs Playwright + a live target and is covered by
the live validation; here we lock in the pure candidate-URL construction that
decides WHICH client-side sinks get probed — the part that made OWASP Juice Shop's
``/#/search?q=`` DOM XSS reachable.
"""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.xss_verifier import (
    build_dom_xss_candidate_urls,
)

_PAYLOAD = '<iframe src="javascript:alert(`c`)">'


def test_candidates_cover_spa_hash_route_and_plain_query() -> None:
    urls = build_dom_xss_candidate_urls(
        "http://shop.example/", ["search"], ["q"], _PAYLOAD, max_urls=16
    )
    # SPA client route (the Juice-Shop form) AND the plain query form.
    assert any(u.startswith("http://shop.example/#/search?q=") for u in urls)
    assert any(u.startswith("http://shop.example/search?q=") for u in urls)


def test_candidates_are_url_encoded_and_same_origin() -> None:
    urls = build_dom_xss_candidate_urls(
        "http://shop.example/", ["search"], ["q"], _PAYLOAD, max_urls=16
    )
    assert urls, "expected candidate URLs"
    for u in urls:
        assert u.startswith("http://shop.example/"), f"off-origin candidate: {u}"
        # payload must be percent-encoded (no raw angle brackets / spaces leak in)
        assert "<" not in u and ">" not in u and " " not in u


def test_defaults_injected_without_hints() -> None:
    # Even with no discovered routes/params, the common SPA sink (search?q) is probed.
    urls = build_dom_xss_candidate_urls("http://x.test/", [], [], _PAYLOAD, max_urls=8)
    assert any("/#/search?q=" in u for u in urls)


def test_bounded_by_max_urls() -> None:
    urls = build_dom_xss_candidate_urls(
        "http://x.test/", ["a", "b", "c"], ["p1", "p2", "p3"], _PAYLOAD, max_urls=5
    )
    assert 0 < len(urls) <= 5


def test_non_http_scheme_rejected() -> None:
    assert build_dom_xss_candidate_urls("ftp://x/", ["a"], ["b"], _PAYLOAD) == []
    assert build_dom_xss_candidate_urls("", ["a"], ["b"], _PAYLOAD) == []


def test_default_sink_survives_many_discovered_hints() -> None:
    # Regression: a long discovered route/param list (route-major loop) must not
    # crowd the common search?q DOM sink out of the max_urls budget — the defaults
    # are prepended so /#/search?q= is always probed (OWASP Juice Shop's sink).
    routes = [
        "login", "whoami", "products", "user", "basket",
        "feedback", "cards", "orders", "profile", "admin",
    ]
    params = [
        "email", "password", "username", "id", "userId",
        "key", "coupon", "orderId", "token", "name",
    ]
    urls = build_dom_xss_candidate_urls("http://shop.example/", routes, params, _PAYLOAD, max_urls=16)
    assert any(u.startswith("http://shop.example/#/search?q=") for u in urls), (
        "search?q sink was crowded out by discovered hints"
    )
