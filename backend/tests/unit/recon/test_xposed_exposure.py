"""XposedOrNot exposure analyzer + injectable collector (offline)."""

from __future__ import annotations

import asyncio

from src.core.config import settings
from src.recon.dns_security.xposed_exposure import (
    analyze_xposed_exposure,
    collect_xposed_exposure,
)


def test_analyze_no_breaches_yields_nothing():
    assert analyze_xposed_exposure("example.com", {}) == []
    assert analyze_xposed_exposure("example.com", {"a@example.com": []}) == []


def test_analyze_builds_masked_low_severity_finding():
    findings = analyze_xposed_exposure(
        "example.com",
        {"john.doe@example.com": ["Collection1", "LinkedIn"]},
    )
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "low"
    assert f["source_tool"] == "xposedornot"
    # email masked, breach names present, no raw local-part leak
    assert "john.doe@example.com" not in f["evidence"]
    assert "Collection1" in f["evidence"]
    assert "LinkedIn" in f["evidence"]


def test_collect_disabled_by_default_returns_empty():
    async def _fetch(_email):
        return ["ShouldNotBeUsed"]

    out = asyncio.run(
        collect_xposed_exposure("example.com", ["a@example.com"], fetch=_fetch)
    )
    assert out == []  # gate off by default


def test_collect_enabled_with_injected_fetch(monkeypatch):
    monkeypatch.setattr(settings, "xposedornot_enabled", True)

    async def _fetch(email):
        return ["BreachX"] if email == "hit@example.com" else []

    out = asyncio.run(
        collect_xposed_exposure(
            "example.com", ["hit@example.com", "clean@example.com"], fetch=_fetch
        )
    )
    assert len(out) == 1
    assert "BreachX" in out[0]["evidence"]


def test_collect_degrades_when_fetch_raises(monkeypatch):
    monkeypatch.setattr(settings, "xposedornot_enabled", True)

    async def _fetch(_email):
        raise RuntimeError("network down")

    out = asyncio.run(
        collect_xposed_exposure("example.com", ["a@example.com"], fetch=_fetch)
    )
    assert out == []  # never raises, no finding


def test_collect_dedups_and_skips_non_emails(monkeypatch):
    monkeypatch.setattr(settings, "xposedornot_enabled", True)
    calls: list[str] = []

    async def _fetch(email):
        calls.append(email)
        return ["B"]

    asyncio.run(
        collect_xposed_exposure(
            "example.com", ["a@example.com", "a@example.com", "not-an-email"], fetch=_fetch
        )
    )
    assert calls == ["a@example.com"]  # deduped + non-email skipped
