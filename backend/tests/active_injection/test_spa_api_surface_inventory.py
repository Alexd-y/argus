"""SPA/API route extraction feeds active injection planning."""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.injection_planner import (
    ActiveInjectionPlannerFlags,
    build_injection_plan,
)
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    build_input_surface_inventory,
)
from src.recon.vulnerability_analysis.active_scan.spa_api_surface import (
    extract_script_urls_from_html,
    extract_spa_api_surfaces,
)
from src.orchestration.handlers import (
    _collect_recon_surface_artifacts,
    _normalize_scan_mode_for_va,
)


def test_next_vercel_bundle_routes_feed_endpoint_inventory() -> None:
    html = '<html><script src="/_next/static/chunks/app.js"></script></html>'
    js = """
    fetch('/api/login', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({email: email, password: password})
    })
    axios.get('/api/users?userId=1')
    """
    scripts = extract_script_urls_from_html("https://app.example/", html)
    assert scripts == ["https://app.example/_next/static/chunks/app.js"]

    surfaces = extract_spa_api_surfaces(
        "https://app.example/",
        html_text=html,
        script_bodies={scripts[0]: js},
    )
    endpoints = surfaces.endpoint_inventory
    assert any(r["url"] == "https://app.example/api/login" and r["method"] == "POST" for r in endpoints)
    login = next(r for r in endpoints if r["url"] == "https://app.example/api/login")
    assert login["content_type"] == "application/json"
    assert {"email", "password"}.issubset(set(login["json_fields"]))
    assert login["confirmed"] is True
    users = next(r for r in endpoints if r["url"].startswith("https://app.example/api/users"))
    assert users["query_params"] == ["userId"]


def test_recon_context_urls_and_js_feed_spa_extractor() -> None:
    urls, scripts = _collect_recon_surface_artifacts(
        {
            "url_history_urls": {"urls": ["https://app.example/api/users?userId=1"]},
            "js_analysis": {
                "stdout": "fetch('/api/profile', { method: 'POST', body: JSON.stringify({displayName: name}) })"
            },
        },
        target="https://app.example/",
    )
    surfaces = extract_spa_api_surfaces(
        "https://app.example/",
        discovered_urls=urls,
        script_bodies=scripts,
    )
    assert any(r["url"].startswith("https://app.example/api/users") for r in surfaces.endpoint_inventory)
    assert any(r["url"] == "https://app.example/api/profile" and r["method"] == "POST" for r in surfaces.endpoint_inventory)


def test_scan_mode_prefers_canonical_scan_mode_over_legacy_scan_type() -> None:
    assert _normalize_scan_mode_for_va({"scanType": "quick", "scan_mode": "deep"}) == "deep"
    assert _normalize_scan_mode_for_va({"scanType": "light"}) == "standard"


def test_endpoint_inventory_creates_confirmed_injection_surfaces() -> None:
    inv = build_input_surface_inventory(
        {
            "endpoint_inventory": [
                {
                    "url": "https://app.example/api/login",
                    "method": "POST",
                    "content_type": "application/json",
                    "json_fields": ["email", "password"],
                    "confirmed": True,
                },
                {
                    "url": "https://app.example/api/users?userId=1",
                    "method": "GET",
                    "query_params": ["userId"],
                    "auth_context": "authenticated",
                    "confirmed": True,
                },
            ],
            "route_inventory": [
                {
                    "url": "https://app.example/api/orders/{orderId}",
                    "method": "GET",
                    "auth_context": "authenticated",
                }
            ],
        }
    )
    by_param = {(item.location, item.param_name, item.method) for item in inv.items}
    assert ("json", "email", "POST") in by_param
    assert ("json", "password", "POST") in by_param
    assert ("query", "userId", "GET") in by_param
    assert ("path", "orderId", "GET") in by_param


def test_hidden_post_body_uses_conservative_field_hints() -> None:
    surfaces = extract_spa_api_surfaces(
        "https://app.example/",
        script_bodies={
            "bundle.js": "fetch('/api/login', { method: 'POST', body: credentials })",
        },
    )
    login = next(r for r in surfaces.endpoint_inventory if r["url"] == "https://app.example/api/login")
    assert login["method"] == "POST"
    assert {"email", "username", "password"}.issubset(set(login["json_fields"]))
    inv = build_input_surface_inventory({"endpoint_inventory": surfaces.endpoint_inventory})
    assert any(item.location == "json" and item.param_name == "password" for item in inv.items)


def test_numeric_api_path_segments_create_idor_surface() -> None:
    surfaces = extract_spa_api_surfaces(
        "https://app.example/",
        discovered_urls=["/api/users/123"],
    )
    inv = build_input_surface_inventory({"endpoint_inventory": surfaces.endpoint_inventory})
    assert any(item.location == "path" and item.param_name in {"id", "userId"} for item in inv.items)


def test_deep_plan_covers_sqli_xss_ssrf_ssti_xxe_idor_for_confirmed_surfaces() -> None:
    inv = build_input_surface_inventory(
        {
            "endpoint_inventory": [
                {
                    "url": "https://app.example/api/profile",
                    "method": "POST",
                    "content_type": "application/json",
                    "json_fields": ["userId", "displayName", "xml"],
                    "auth_context": "authenticated",
                    "confirmed": True,
                }
            ]
        }
    )
    steps = build_injection_plan(
        inv,
        mode="deep",
        flags=ActiveInjectionPlannerFlags(
            lab_destructive_execution_allowed=False,
            oast_enabled=True,
            destructive_tool_ids=frozenset({"sqlmap"}),
        ),
    )
    runnable = {s.family for s in steps if not s.not_assessed_reason}
    assert {"xss", "sqli", "ssrf", "ssti", "xxe", "idor"}.issubset(runnable)
    assert any(s.family == "sqli" and s.tool == "sqlmap" for s in steps)
    assert any(s.family == "idor" and s.param == "userId" for s in steps if not s.not_assessed_reason)
