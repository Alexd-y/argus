"""Offline test for §8.1 — the browser pool slot is keyed by scan id.

The hardening doc specifies ``pool_slot("browser", scan_id)`` so the per-scan
concurrent browser-session cap is enforced. This verifies the adapter passes the
scan id (not the session id) as the pool key, with a session-id fallback for
legacy callers. ``apool_slot`` is stubbed — no Redis required.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from src.sandbox import playwright_adapter as pw


class _FakeRunner:
    def execute(self, *_args, **_kwargs):
        return type("_R", (), {"stdout": '{"success": true, "url": "u"}'})()


def _install_key_capture(monkeypatch) -> dict[str, object]:
    captured: dict[str, object] = {}

    @asynccontextmanager
    async def _fake_apool_slot(pool_type, key, **_kwargs):
        captured["pool_type"] = pool_type
        captured["key"] = key
        yield None

    monkeypatch.setattr(pw, "apool_slot", _fake_apool_slot)
    return captured


async def test_browser_pool_keyed_by_scan_id(monkeypatch):
    captured = _install_key_capture(monkeypatch)
    adapter = pw.PlaywrightAdapter(
        sandbox_runner=_FakeRunner(), session_id="sess", scan_id="scan-42"
    )

    await adapter._run_in_sandbox(
        Path("x.js"), pw.BrowserRequest(action="navigate", url="http://t")
    )

    assert captured["pool_type"] == "browser"
    assert captured["key"] == "scan-42"


async def test_browser_pool_falls_back_to_session_id(monkeypatch):
    captured = _install_key_capture(monkeypatch)
    adapter = pw.PlaywrightAdapter(sandbox_runner=_FakeRunner(), session_id="sess-only")

    await adapter._run_in_sandbox(
        Path("x.js"), pw.BrowserRequest(action="navigate", url="http://t")
    )

    assert captured["key"] == "sess-only"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
