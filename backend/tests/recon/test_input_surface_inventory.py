"""Unit tests for :mod:`src.recon.vulnerability_analysis.active_scan.input_surface_inventory`."""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
    InputSurfaceItem,
    build_input_surface_inventory,
    normalize_path_template,
)


def test_build_empty_bundle() -> None:
    inv = build_input_surface_inventory({})
    assert inv.items == []


def test_query_param_minimal() -> None:
    inv = build_input_surface_inventory(
        {
            "params_inventory": [
                {
                    "param": "q",
                    "full_url": "https://api.example.com/search?q=test",
                    "method": "GET",
                }
            ]
        }
    )
    assert len(inv.items) == 1
    it = inv.items[0]
    assert it.param_name == "q"
    assert it.location == "query"
    assert it.method == "GET"
    assert "example.com" in it.url


def test_json_body_fields_minimal() -> None:
    inv = build_input_surface_inventory(
        {
            "endpoint_inventory": [
                {
                    "url": "https://api.example.com/v1/user",
                    "method": "POST",
                    "json_fields": ["profile.bio"],
                    "content_type": "application/json",
                }
            ]
        }
    )
    assert len(inv.items) == 1
    it = inv.items[0]
    assert it.location == "json"
    assert it.param_name == "profile.bio"
    assert it.content_type == "application/json"


def test_graphql_variables_minimal() -> None:
    inv = build_input_surface_inventory(
        {
            "graphql": {
                "endpoint": "https://api.example.com/graphql",
                "variables": ["id"],
            }
        }
    )
    assert len(inv.items) == 1
    it = inv.items[0]
    assert it.location == "graphql"
    assert it.param_name == "id"
    assert it.method == "POST"


def test_dedup_same_method_path_param_location() -> None:
    row = {"param": "a", "full_url": "https://dup.example/path?a=1", "method": "GET"}
    inv = build_input_surface_inventory({"params_inventory": [row, row]})
    assert len(inv.items) == 1


def test_scope_url_substring_filter() -> None:
    inv = build_input_surface_inventory(
        {
            "params_inventory": [
                {"param": "x", "full_url": "https://keep.example/a?x=1"},
                {"param": "y", "full_url": "https://other.example/b?y=1"},
            ]
        },
        scope="keep.example",
    )
    assert len(inv.items) == 1
    assert inv.items[0].param_name == "x"


def test_nested_vulnerability_analysis_input_merge() -> None:
    inv = build_input_surface_inventory(
        {
            "vulnerability_analysis_input": {
                "params_inventory": [
                    {"param": "token", "full_url": "https://nested.test/cb?token=1"}
                ]
            },
            "extra": 1,
        }
    )
    assert len(inv.items) == 1
    assert inv.items[0].param_name == "token"


def test_inventory_deduplicated_method() -> None:
    a = InputSurfaceItem(
        surface_id="s1",
        url="https://z.com/x?p=1",
        method="get",
        param_name="p",
        location="query",
    )
    b = InputSurfaceItem(
        surface_id="s2",
        url="https://z.com/x?q=2",
        method="GET",
        param_name="p",
        location="query",
    )
    inv = InputSurfaceInventory(items=[a, b])
    d = inv.deduplicated()
    assert len(d.items) == 1


def test_normalize_path_template_strips_query() -> None:
    assert normalize_path_template("HTTPS://Host.COM/Path/?q=1") == "host.com/path"
