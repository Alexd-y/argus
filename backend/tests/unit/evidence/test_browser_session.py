"""Wave 2a (etap 1-2) — browser-context wrapper.

Two guarantees are under test:

* **Explicit unavailability** — a missing Playwright/Chromium raises
  :class:`BrowserUnavailable`, never a silent ``None``. Verified offline by
  patching ``playwright_available`` to False.
* **Mid-crash HAR is valid** — the context is closed in a ``finally`` so
  Playwright finalises the HAR even when the scenario raises mid-way. Verified
  with a real browser; skipped cleanly when Playwright/Chromium is absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from src.evidence.browser_session import (
    BrowserCaptureSpec,
    BrowserUnavailable,
    _prepare_context,
    browser_context,
    browser_context_sync,
    playwright_available,
)

# Real-browser tests are opt-in on the runtime having Playwright. In the sandbox
# e2e image (playwright + chromium installed) they run; everywhere else they
# skip — a recorded skip, never a false pass.
requires_browser = pytest.mark.skipif(
    not playwright_available(), reason="playwright not installed in this runtime"
)


class _Boom(RuntimeError):
    """Sentinel mid-scenario crash."""


def test_prepare_context_wires_requested_recordings(tmp_path: Path) -> None:
    artifacts, kwargs = _prepare_context(
        tmp_path / "wd", BrowserCaptureSpec(record_har=True, record_video=True)
    )
    assert kwargs["viewport"] == {"width": 1280, "height": 720}
    assert str(kwargs["record_har_path"]).endswith("session.har")
    assert "record_video_dir" in kwargs
    assert artifacts.har_path is not None and artifacts.har_path.name == "session.har"
    assert artifacts.video_dir is not None and artifacts.video_dir.is_dir()


def test_prepare_context_omits_unrequested_recordings(tmp_path: Path) -> None:
    artifacts, kwargs = _prepare_context(tmp_path / "wd", BrowserCaptureSpec())
    assert "record_har_path" not in kwargs
    assert "record_video_dir" not in kwargs
    assert artifacts.har_path is None
    assert artifacts.video_dir is None


async def test_async_wrapper_raises_when_playwright_missing(tmp_path: Path) -> None:
    with (
        patch("src.evidence.browser_session.playwright_available", return_value=False),
        pytest.raises(BrowserUnavailable),
    ):
        async with browser_context(workdir=tmp_path, spec=BrowserCaptureSpec()):
            pass  # pragma: no cover — entry raises before the body


def test_sync_wrapper_raises_when_playwright_missing(tmp_path: Path) -> None:
    with (
        patch("src.evidence.browser_session.playwright_available", return_value=False),
        pytest.raises(BrowserUnavailable),
        browser_context_sync(workdir=tmp_path, spec=BrowserCaptureSpec()),
    ):
        pass  # pragma: no cover — entry raises before the body


@requires_browser
async def test_mid_crash_har_is_valid_async(tmp_path: Path) -> None:
    """A crash inside the scenario must still leave a finalised, valid HAR."""
    har_path: Path | None = None
    try:
        with pytest.raises(_Boom):
            async with browser_context(
                workdir=tmp_path, spec=BrowserCaptureSpec(record_har=True)
            ) as (context, artifacts):
                har_path = artifacts.har_path
                page = await context.new_page()
                await page.goto("data:text/html,<h1>argus</h1>")
                raise _Boom("mid-scenario crash")
    except BrowserUnavailable:
        pytest.skip("chromium not installed in this runtime")

    assert har_path is not None and har_path.is_file()
    # If the context had NOT been closed in finally, the HAR would be missing or
    # truncated. A parseable HAR envelope proves finalisation despite the crash.
    doc = json.loads(har_path.read_text(encoding="utf-8"))
    assert "log" in doc and isinstance(doc["log"].get("entries"), list)


@requires_browser
def test_mid_crash_har_is_valid_sync(tmp_path: Path) -> None:
    """Sync twin of the mid-crash HAR guarantee."""
    har_path: Path | None = None
    try:
        with (
            pytest.raises(_Boom),
            browser_context_sync(workdir=tmp_path, spec=BrowserCaptureSpec(record_har=True)) as (
                context,
                artifacts,
            ),
        ):
            har_path = artifacts.har_path
            page = context.new_page()
            page.goto("data:text/html,<h1>argus</h1>")
            raise _Boom("mid-scenario crash")
    except BrowserUnavailable:
        pytest.skip("chromium not installed in this runtime")

    assert har_path is not None and har_path.is_file()
    doc = json.loads(har_path.read_text(encoding="utf-8"))
    assert "log" in doc and isinstance(doc["log"].get("entries"), list)
