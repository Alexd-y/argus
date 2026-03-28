"""WhatWeb VA adapter: NDJSON / JSON array merge (VHQ-001)."""

from __future__ import annotations

import json

from src.recon.vulnerability_analysis.active_scan.whatweb_va_adapter import (
    merge_whatweb_json_roots,
    parse_whatweb_stdout,
    parse_whatweb_text_fallback,
    parse_whatweb_to_tech_stack,
)


def test_parse_whatweb_stdout_single_object() -> None:
    obj = {"target": "http://x/", "plugins": {"HTTPServer": {"string": "nginx"}}}
    out = parse_whatweb_stdout(json.dumps(obj))
    assert out == obj


def test_parse_whatweb_stdout_ndjson_merges_plugins() -> None:
    a = {"target": "http://x/", "plugins": {"HTTPServer": {"string": "nginx"}}}
    b = {"plugins": {"WordPress": {"version": "6"}}}
    text = json.dumps(a) + "\n" + json.dumps(b) + "\n"
    out = parse_whatweb_stdout(text)
    assert out is not None
    plugs = out.get("plugins")
    assert isinstance(plugs, dict)
    assert "HTTPServer" in plugs and "WordPress" in plugs
    assert out.get("target") == "http://x/"


def test_parse_whatweb_stdout_json_array() -> None:
    roots = [
        {"plugins": {"Apache": {"version": "2.4"}}},
        {"plugins": {"jQuery": {"string": "3.6.0"}}},
    ]
    out = parse_whatweb_stdout(json.dumps(roots))
    assert out is not None
    plugs = out["plugins"]
    assert "Apache" in plugs and "jQuery" in plugs


def test_merge_whatweb_json_roots_empty() -> None:
    assert merge_whatweb_json_roots([]) is None


def test_parse_whatweb_text_fallback_bracket_plugins() -> None:
    line = "https://ex.example [200 OK] HTTPServer[nginx 1.22], WordPress[6.2]"
    root = parse_whatweb_text_fallback(line)
    assert root is not None
    assert "plugins" in root
    plugs = root["plugins"]
    assert "HTTPServer" in plugs or "WordPress" in plugs
    merged = merge_whatweb_json_roots([root])
    assert merged is not None
    ts = parse_whatweb_to_tech_stack(merged)
    assert ts.get("web_server") or ts.get("cms")


def test_parse_whatweb_to_tech_stack_from_merged() -> None:
    merged = merge_whatweb_json_roots(
        [
            {"plugins": {"HTTPServer": {"string": "nginx/1.20"}}},
            {"plugins": {"WordPress": {"version": "6.4"}}},
        ]
    )
    assert merged is not None
    ts = parse_whatweb_to_tech_stack(merged)
    assert "nginx" in (ts.get("web_server") or "").lower()
    assert "wordpress" in (ts.get("cms") or "").lower()
