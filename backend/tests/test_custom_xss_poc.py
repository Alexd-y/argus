"""Custom XSS PoC (httpx) — mocked (XSS-PLAN-001)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.recon.exploitation.custom_xss_poc import (
    collect_xss_payloads,
    resolve_xss_payload_file_path,
    run_custom_xss_poc,
)


def test_resolve_xss_payload_file_exists() -> None:
    p = resolve_xss_payload_file_path()
    assert p is not None
    assert p.is_file()


def test_collect_xss_non_aggressive_caps() -> None:
    rows = collect_xss_payloads(aggressive=False, max_payloads=200)
    assert len(rows) <= 40
    assert "alert(1)" in rows


def test_collect_xss_aggressive_caps() -> None:
    quiet = collect_xss_payloads(aggressive=False, max_payloads=200)
    loud = collect_xss_payloads(aggressive=True, max_payloads=200)
    assert len(loud) <= 80
    assert len(quiet) <= 40
    assert len(loud) >= len(quiet)


@pytest.mark.asyncio
async def test_run_custom_xss_poc_finds_reflection(tmp_path) -> None:
    wl = tmp_path / "p.txt"
    wl.write_text("<script>alert(1)</script>\n", encoding="utf-8")

    params = [
        {"url": "https://ex.test/page?p=1", "param": "p", "method": "GET"},
    ]

    mock_resp = MagicMock()
    mock_resp.text = "hello <script>alert(1)</script> world"

    with (
        patch(
            "src.recon.exploitation.custom_xss_poc.resolve_xss_payload_file_path",
            return_value=wl,
        ),
        patch("httpx.AsyncClient") as client_cls,
    ):
        inst = MagicMock()
        client_cls.return_value.__aenter__.return_value = inst
        inst.get = AsyncMock(return_value=mock_resp)

        rows = await run_custom_xss_poc(
            "https://ex.test/page?p=1",
            params,
            [],
            timeout=5.0,
            max_payloads=5,
        )

    assert rows
    d = rows[0].get("data") or {}
    assert d.get("cwe") == "CWE-79"
    assert d.get("poc_curl")
    assert rows[0].get("source_tool") == "custom_xss_poc"


@pytest.mark.asyncio
async def test_run_custom_xss_script_context_alert1_high_cvss() -> None:
    """Payload alert(1) reflected inside <script>: CWE-79, CVSS >= 7, high."""
    params = [{"url": "https://ex.test/page?world=1", "param": "world", "method": "GET"}]
    mock_resp = MagicMock()
    mock_resp.text = (
        "<!doctype html><script>\n"
        "// reflected probe\n"
        "alert(1)\n"
        "</script>"
    )

    with patch("httpx.AsyncClient") as client_cls:
        inst = MagicMock()
        client_cls.return_value.__aenter__.return_value = inst
        inst.get = AsyncMock(return_value=mock_resp)

        rows = await run_custom_xss_poc(
            "https://ex.test/page?world=1",
            params,
            [],
            timeout=5.0,
            max_payloads=15,
            aggressive=False,
        )

    assert rows, "expected finding for script-context reflection"
    d = rows[0].get("data") or {}
    assert d.get("cwe") == "CWE-79"
    assert float(d.get("cvss_score") or 0) >= 7.0
    assert (d.get("severity") or "").lower() == "high"
    assert "curl" in (d.get("poc_curl") or "").lower()


@pytest.mark.asyncio
async def test_run_custom_xss_script_breakout_high_cvss() -> None:
    """Closing script + new script: treated as script-context high."""
    params = [{"url": "https://ex.test/page?p=1", "param": "p", "method": "GET"}]
    breakout = "</script><script>alert(1)</script>"
    mock_resp = MagicMock()
    mock_resp.text = f"<div>x</div>{breakout}<footer></footer>"

    with patch("httpx.AsyncClient") as client_cls:
        inst = MagicMock()
        client_cls.return_value.__aenter__.return_value = inst
        inst.get = AsyncMock(return_value=mock_resp)

        rows = await run_custom_xss_poc(
            "https://ex.test/page?p=1",
            params,
            [],
            timeout=5.0,
            max_payloads=20,
        )

    assert rows
    d = rows[0].get("data") or {}
    assert d.get("cwe") == "CWE-79"
    assert float(d.get("cvss_score") or 0) >= 7.0


@pytest.mark.asyncio
async def test_run_custom_xss_poc_no_reflection(tmp_path) -> None:
    wl = tmp_path / "p.txt"
    wl.write_text("uniquemarker123\n", encoding="utf-8")
    params = [{"url": "https://ex.test/page?p=1", "param": "p", "method": "GET"}]
    mock_resp = MagicMock()
    mock_resp.text = "no payload here"

    with (
        patch(
            "src.recon.exploitation.custom_xss_poc.resolve_xss_payload_file_path",
            return_value=wl,
        ),
        patch("httpx.AsyncClient") as client_cls,
    ):
        inst = MagicMock()
        client_cls.return_value.__aenter__.return_value = inst
        inst.get = AsyncMock(return_value=mock_resp)

        rows = await run_custom_xss_poc(
            "https://ex.test/page?p=1",
            params,
            [],
            timeout=5.0,
            max_payloads=5,
        )

    assert rows == []
