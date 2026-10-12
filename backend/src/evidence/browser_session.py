"""Browser-context wrapper for evidence capture (wave 2a, etap 1–2, 3, 5).

Architecture decision A (``docs/architecture-decisions.md``): browser evidence
is produced in the sandbox. This module is the single place that launches a
Playwright **browser context** (not a bare page) configured to record the
evidence kinds the caller asks for — HAR (``record_har_path``), video
(``record_video_dir``), and screenshots — and that closes the context in a
``finally`` so Playwright finalises the HAR / video files even when the scenario
raises mid-way (the most common way these artifacts end up empty/corrupt).

Unavailability is explicit, never silent (etap 1): when Playwright or Chromium
is missing, callers get :class:`BrowserUnavailable` and record a
"browser evidence unavailable" state so the arbiter caps the reachable level
rather than reading the absence as "no vulnerability".
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

_logger = logging.getLogger(__name__)

_DEFAULT_VIEWPORT = (1280, 720)


class BrowserUnavailable(RuntimeError):
    """Raised when Playwright / Chromium is not installed in this runtime."""


@dataclass
class BrowserCaptureSpec:
    """What the caller wants recorded for a browser scenario."""

    record_har: bool = False
    record_video: bool = False
    viewport_width: int = _DEFAULT_VIEWPORT[0]
    viewport_height: int = _DEFAULT_VIEWPORT[1]


@dataclass
class BrowserArtifacts:
    """Files produced by a browser session (populated after the context closes)."""

    workdir: Path
    har_path: Path | None = None
    video_dir: Path | None = None
    screenshot_paths: list[Path] = field(default_factory=list)

    def video_paths(self) -> list[Path]:
        if self.video_dir is None or not self.video_dir.is_dir():
            return []
        return sorted(p for p in self.video_dir.glob("*.webm") if p.is_file())


def playwright_available() -> bool:
    """True when the Playwright Python package can be imported."""
    try:
        import playwright.async_api  # noqa: F401

        return True
    except Exception:
        return False


@asynccontextmanager
async def browser_context(
    *,
    workdir: Path,
    spec: BrowserCaptureSpec,
) -> AsyncIterator[tuple[object, BrowserArtifacts]]:
    """Yield ``(context, artifacts)`` for a recording Playwright browser context.

    The context is created with ``record_har_path`` / ``record_video_dir`` per
    ``spec`` and is ALWAYS closed in ``finally`` so the HAR / video are
    finalised even if the caller raises. Raises :class:`BrowserUnavailable` if
    Playwright/Chromium is missing — the caller must surface that as an explicit
    state, not swallow it.
    """
    if not playwright_available():
        raise BrowserUnavailable("playwright is not installed in this runtime")

    from playwright.async_api import async_playwright

    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    artifacts = BrowserArtifacts(workdir=workdir)
    context_kwargs: dict[str, object] = {
        "viewport": {"width": spec.viewport_width, "height": spec.viewport_height},
    }
    if spec.record_har:
        artifacts.har_path = workdir / "session.har"
        context_kwargs["record_har_path"] = str(artifacts.har_path)
    if spec.record_video:
        artifacts.video_dir = workdir / "video"
        artifacts.video_dir.mkdir(parents=True, exist_ok=True)
        context_kwargs["record_video_dir"] = str(artifacts.video_dir)

    pw = await async_playwright().start()
    browser = None
    context = None
    try:
        try:
            browser = await pw.chromium.launch()
        except Exception as exc:
            raise BrowserUnavailable(f"chromium failed to launch: {type(exc).__name__}") from exc
        context = await browser.new_context(**context_kwargs)
        yield context, artifacts
    finally:
        # Order matters: closing the CONTEXT flushes HAR + finalises video.
        if context is not None:
            with _suppress("context.close"):
                await context.close()
        if browser is not None:
            with _suppress("browser.close"):
                await browser.close()
        with _suppress("playwright.stop"):
            await pw.stop()


class _suppress:
    """Log-and-swallow context manager for best-effort teardown steps."""

    def __init__(self, what: str) -> None:
        self._what = what

    def __enter__(self) -> _suppress:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if exc_type is not None:
            _logger.warning(
                "browser_session.teardown_failed",
                extra={"event": "argus.browser.teardown_failed", "step": self._what},
            )
        return True


__all__ = [
    "BrowserArtifacts",
    "BrowserCaptureSpec",
    "BrowserUnavailable",
    "browser_context",
    "playwright_available",
]
