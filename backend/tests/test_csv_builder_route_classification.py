"""Tests for route_classification CSV builder."""

from __future__ import annotations

import csv
import io

from src.recon.reporting.csv_builder import (
    _derive_classification_from_path,
    build_route_classification_from_inventory,
)


def _csv_rows(content: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(content)))


def test_derive_classification_from_path() -> None:
    """Path patterns map correctly: /login -> login_flow, /admin -> admin_flow."""
    assert _derive_classification_from_path("/login") == "login_flow"
    assert _derive_classification_from_path("/signin") == "login_flow"
    assert _derive_classification_from_path("/admin") == "admin_flow"
    assert _derive_classification_from_path("https://example.com/reset-password") == "password_reset_flow"
    assert _derive_classification_from_path("/contact") == "contact_flow"
    assert _derive_classification_from_path("/") == "public_page"
    assert _derive_classification_from_path("/robots.txt") == "public_page"


def test_build_route_classification_from_inventory_uses_existing_classification() -> None:
    """When route_inventory has classification column, it is preserved."""
    rows = [
        {
            "route_path": "/login",
            "url": "https://example.com/login",
            "host": "example.com",
            "classification": "auth_custom",
            "discovery_source": "mcp_fetch",
            "evidence_ref": "mcp_fetch:https://example.com/login",
        },
    ]
    csv_content = build_route_classification_from_inventory(rows)
    out = _csv_rows(csv_content)
    assert len(out) == 1
    assert out[0]["route"] == "/login"
    assert out[0]["host"] == "example.com"
    assert out[0]["classification"] == "auth_custom"
    assert out[0]["discovery_source"] == "mcp_fetch"
    assert out[0]["evidence_ref"] == "mcp_fetch:https://example.com/login"


def test_build_route_classification_from_inventory_derives_classification_when_missing() -> None:
    """When route_inventory has no classification column, derive from path."""
    rows = [
        {
            "route_path": "/login",
            "url": "https://example.com/login",
            "host": "example.com",
            "classification": "",
            "discovery_source": "unknown",
            "evidence_ref": "",
        },
        {
            "route_path": "",
            "url": "https://example.com/admin",
            "host": "example.com",
            "classification": "",
            "discovery_source": "route_inventory",
            "evidence_ref": "route_inventory.csv:1",
        },
    ]
    csv_content = build_route_classification_from_inventory(rows)
    out = _csv_rows(csv_content)
    assert len(out) == 2
    assert out[0]["classification"] == "login_flow"
    assert out[1]["classification"] == "admin_flow"
    assert out[1]["route"] == "/admin"


def test_build_route_classification_from_inventory_columns() -> None:
    """Output has ROUTE_CLASSIFICATION_CSV_COLUMNS: route, host, classification, discovery_source, evidence_ref."""
    rows = [
        {
            "route_path": "/",
            "url": "https://example.com/",
            "host": "example.com",
            "classification": "public_page",
            "discovery_source": "mcp_fetch",
            "evidence_ref": "mcp_fetch:https://example.com/",
        },
    ]
    csv_content = build_route_classification_from_inventory(rows)
    out = _csv_rows(csv_content)
    expected_cols = {"route", "host", "classification", "discovery_source", "evidence_ref"}
    assert expected_cols.issubset(out[0].keys())


def test_build_route_classification_from_inventory_deduplicates() -> None:
    """Same (route, host) appears only once."""
    rows = [
        {"route_path": "/login", "url": "https://a.com/login", "host": "a.com", "classification": "login_flow", "discovery_source": "x", "evidence_ref": "1"},
        {"route_path": "/login", "url": "https://a.com/login", "host": "a.com", "classification": "login_flow", "discovery_source": "y", "evidence_ref": "2"},
    ]
    csv_content = build_route_classification_from_inventory(rows)
    out = _csv_rows(csv_content)
    assert len(out) == 1
