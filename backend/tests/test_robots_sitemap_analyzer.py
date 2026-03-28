"""VDF-010 — Unit tests for robots/sitemap parsing helpers (no HTTP)."""

from __future__ import annotations

from src.recon.robots_sitemap_analyzer import (
    _loc_urls_from_sitemap,
    _origin_from_url,
    _parse_robots_rules,
    _sensitive_hints_from_paths,
)


def test_origin_from_url_valid_and_invalid() -> None:
    assert _origin_from_url("https://example.com/path?q=1") == "https://example.com"
    assert _origin_from_url("  http://a.test  ") == "http://a.test"
    assert _origin_from_url("") is None
    assert _origin_from_url("ftp://x") is None
    assert _origin_from_url("/relative") is None


def test_parse_robots_rules_disallow_allow_sitemap_comments() -> None:
    text = """# top comment
User-agent: *
Disallow: /admin/
Allow: /public
Sitemap: https://ex.example/s1.xml
disallow: /tmp
"""
    disallow, allow, sitemaps = _parse_robots_rules(text)
    assert "/admin/" in disallow
    assert "/tmp" in disallow
    assert "/public" in allow
    assert "https://ex.example/s1.xml" in sitemaps


def test_parse_robots_rules_ignores_empty_directives() -> None:
    disallow, allow, sitemaps = _parse_robots_rules("Disallow:\nAllow:  \nSitemap:\n")
    assert disallow == []
    assert allow == []
    assert sitemaps == []


def test_loc_urls_from_sitemap_merges_and_trims() -> None:
    xml = """<?xml version="1.0"?>
<urlset>
  <url><loc>  https://a.test/one  </loc></url>
  <url><LOC>https://a.test/two</LOC></url>
</urlset>"""
    locs = _loc_urls_from_sitemap(xml)
    assert locs == ["https://a.test/one", "https://a.test/two"]


def test_sensitive_hints_from_paths_merged_order() -> None:
    paths = ["/wp-admin/", "https://x/api/v1", "/backup/old.zip"]
    hints = _sensitive_hints_from_paths(paths)
    assert "wp-admin" in hints
    assert "api" in hints
    assert "backup" in hints
