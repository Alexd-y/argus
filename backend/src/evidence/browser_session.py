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
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
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


def _prepare_context(workdir: Path, spec: BrowserCaptureSpec) -> tuple[BrowserArtifacts, dict]:
    """Shared setup: make the workdir, build the ``new_context`` kwargs, and
    record where each recorded artifact will land. Used by both the async and
    sync context managers so the two twins cannot drift."""
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
    return artifacts, context_kwargs


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

    artifacts, context_kwargs = _prepare_context(workdir, spec)

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


@contextmanager
def browser_context_sync(
    *,
    workdir: Path,
    spec: BrowserCaptureSpec,
) -> Iterator[tuple[object, BrowserArtifacts]]:
    """Synchronous twin of :func:`browser_context`.

    For call-sites that run under ``asyncio.to_thread`` or a plain sync entry
    point (Playwright's sync API cannot be driven from a running event loop).
    Identical guarantees: the context is created with ``record_har_path`` /
    ``record_video_dir`` and is ALWAYS closed in ``finally`` so HAR / video are
    finalised even if the caller raises. Raises :class:`BrowserUnavailable` when
    Playwright/Chromium is missing — surface it explicitly, never swallow it.
    """
    if not playwright_available():
        raise BrowserUnavailable("playwright is not installed in this runtime")

    from playwright.sync_api import sync_playwright

    artifacts, context_kwargs = _prepare_context(workdir, spec)

    pw = sync_playwright().start()
    browser = None
    context = None
    try:
        try:
            browser = pw.chromium.launch()
        except Exception as exc:
            raise BrowserUnavailable(f"chromium failed to launch: {type(exc).__name__}") from exc
        context = browser.new_context(**context_kwargs)
        yield context, artifacts
    finally:
        # Order matters: closing the CONTEXT flushes HAR + finalises video.
        if context is not None:
            with _suppress("context.close"):
                context.close()
        if browser is not None:
            with _suppress("browser.close"):
                browser.close()
        with _suppress("playwright.stop"):
            pw.stop()


def _redacted_har_bytes(raw: bytes) -> tuple[bytes, bool]:
    """Structurally redact a recorded HAR by round-tripping it through the
    redacting exporter. Returns ``(har_bytes, pipeline_redact)``: on success the
    bytes are already redacted (``pipeline_redact=False``); if the HAR cannot be
    parsed, the raw bytes are returned with ``pipeline_redact=True`` so the
    generic byte redactor still runs as a fallback layer."""
    try:
        from src.evidence.har_export import export_har
        from src.web_workbench.imports.har import import_har

        exchanges = import_har(raw.decode("utf-8", errors="replace"))
        # Structural redaction (headers/cookies/query) here, AND keep the generic
        # byte redactor on at persist time as defense-in-depth — it catches
        # secrets in bodies / arbitrary text that structural rules miss. HAR is
        # text, so the extra pass is cheap.
        return export_har(exchanges, redact=True).encode("utf-8"), True
    except Exception:
        return raw, True


async def persist_browser_artifacts(
    artifacts: BrowserArtifacts,
    *,
    pipeline: object,
    tenant_id: object,
    scan_id: object,
    confirmed: bool,
    finding_id: object = None,
) -> dict[str, int]:
    """Bridge recorded browser artifacts into the evidence pipeline (wave 2a).

    * **HAR** (the raw request/response exchange) is persisted whenever present —
      it is the basis for CONFIRMED.
    * **VIDEO** (the achieved effect) is persisted ONLY when ``confirmed`` (an
      EXPLOITED-tier scenario); otherwise the recordings are DELETED. A video of
      a scenario that did not fire is not kept (etap 5 policy) — unless a later
      wave treats it as evidence of interference.

    Best-effort: a per-artifact failure is logged, never raised, so evidence
    capture can never break the verification that produced it. Returns the count
    persisted per kind.
    """
    from src.pipeline.contracts.finding_dto import EvidenceKind

    counts = {"har": 0, "video": 0}

    har = artifacts.har_path
    if har is not None and har.is_file() and har.stat().st_size > 0:
        try:
            # Playwright records a RAW HAR (full headers, cookies, query); re-
            # serialise it through the redacting exporter so secrets in those
            # STRUCTURED fields are scrubbed (the generic byte redactor alone
            # cannot reliably see them). Fall back to the raw bytes under the
            # generic redactor if the HAR cannot be parsed.
            har_bytes, har_redact = _redacted_har_bytes(har.read_bytes())
            await pipeline.persist(  # type: ignore[attr-defined]
                tenant_id=tenant_id,
                scan_id=scan_id,
                finding_id=finding_id,
                kind=EvidenceKind.HAR,
                raw_data=har_bytes,
                content_type="application/json",
                redact=har_redact,
            )
            counts["har"] += 1
        except Exception as exc:
            _logger.info(
                "browser_har_persist_skipped",
                extra={"event": "argus.browser.har_persist_skipped", "error": type(exc).__name__},
            )

    videos = artifacts.video_paths()
    if confirmed:
        for video in videos:
            try:
                await pipeline.persist(  # type: ignore[attr-defined]
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    finding_id=finding_id,
                    kind=EvidenceKind.VIDEO,
                    raw_data=video.read_bytes(),
                    content_type="video/webm",
                    # Binary media: the text-oriented redactor would only waste
                    # cycles / corrupt bytes, so skip it.
                    redact=False,
                )
                counts["video"] += 1
            except Exception as exc:
                _logger.info(
                    "browser_video_persist_skipped",
                    extra={
                        "event": "argus.browser.video_persist_skipped",
                        "error": type(exc).__name__,
                    },
                )
    else:
        # Delete-on-unconfirmed: a recording of a scenario that did not fire is
        # not worth the storage (etap 5).
        for video in videos:
            with _suppress("video.unlink"):
                video.unlink()
    return counts


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
    "browser_context_sync",
    "persist_browser_artifacts",
    "playwright_available",
]
