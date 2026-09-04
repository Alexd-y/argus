"""Block 1.1 — unified AttackSurface builder."""

from __future__ import annotations

from src.recon.attack_surface import build_attack_surface


def test_open_ports_deduped_and_sorted():
    surface = build_attack_surface(open_ports=[443, 80, 443, 22])
    assert surface.open_ports == [22, 80, 443]


def test_urls_collected_from_assets_and_params():
    surface = build_attack_surface(
        assets=["https://alleksy.com", "nginx 1.25 (not a url)"],
        urls=["https://alleksy.com/login"],
        params=[{"url": "https://alleksy.com/search", "param": "q"}],
    )
    assert "https://alleksy.com" in surface.urls
    assert "https://alleksy.com/login" in surface.urls
    assert "https://alleksy.com/search" in surface.urls
    assert "nginx 1.25 (not a url)" not in surface.urls


def test_endpoints_strip_query():
    surface = build_attack_surface(
        params=[{"url": "https://alleksy.com/search?q=1", "param": "q"}]
    )
    assert "https://alleksy.com/search" in surface.endpoints


def test_injection_points_from_query_params():
    surface = build_attack_surface(
        params=[{"url": "https://alleksy.com/item", "param": "id", "method": "get"}]
    )
    assert surface.injection_points == [
        {"url": "https://alleksy.com/item", "parameter": "id", "method": "GET", "location": "query"}
    ]


def test_injection_points_from_form_inputs():
    surface = build_attack_surface(
        forms=[
            {
                "action": "https://alleksy.com/login",
                "method": "post",
                "inputs": [{"name": "user"}, {"name": "pass"}],
            }
        ]
    )
    params = {p["parameter"] for p in surface.injection_points}
    assert params == {"user", "pass"}
    assert all(p["location"] == "body" and p["method"] == "POST" for p in surface.injection_points)


def test_empty_surface_is_valid():
    surface = build_attack_surface()
    assert surface.assets == []
    assert surface.injection_points == []
