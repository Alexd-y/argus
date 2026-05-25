"""Playwright browser automation adapter for pentest exploitation.

Provides browser-based security testing capabilities: XSS confirmation,
authentication bypass, CSRF verification, screenshot evidence capture.
Inspired by Shannon's Playwright session isolation but adapted for
ARGUS's Docker sandbox model.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class BrowserAction(str):
    """Supported browser action types."""

    NAVIGATE = "navigate"
    CLICK = "click"
    TYPE = "type"
    SCREENSHOT = "screenshot"
    WAIT = "wait"
    EXECUTE_JS = "execute_js"
    GET_COOKIES = "get_cookies"
    SET_COOKIE = "set_cookie"
    EVALUATE = "evaluate"
    INTERCEPT = "intercept"


class BrowserRequest(BaseModel):
    """A single browser action request."""

    action: str = Field(description="BrowserAction type")
    url: str | None = Field(default=None, description="URL for navigate action")
    selector: str | None = Field(default=None, description="CSS/XPath selector for click/type")
    text: str | None = Field(default=None, description="Text to type")
    js_code: str | None = Field(default=None, description="JavaScript to execute")
    wait_ms: int | None = Field(default=None, description="Wait time in milliseconds")
    screenshot_path: str | None = Field(default=None, description="Path to save screenshot")
    timeout_ms: int = Field(default=30000, description="Action timeout in ms")


class BrowserResponse(BaseModel):
    """Result of a browser action."""

    success: bool = True
    url: str = ""
    title: str = ""
    status_code: int | None = None
    body_text: str | None = None
    body_html: str | None = None
    screenshot_path: str | None = None
    cookies: list[dict[str, Any]] = Field(default_factory=list)
    js_result: Any = None
    error: str | None = None
    elapsed_ms: float = 0


@dataclass
class PlaywrightSession:
    """Manages an isolated Playwright browser session.

    Each session controls one browser instance. Multiple sessions
    can run in parallel (mirroring Shannon's agent1-agent5 isolation).
    """

    session_id: str = "default"
    headless: bool = True
    browser_type: str = "chromium"
    _process: Any | None = field(default=None, repr=False)
    _started: bool = field(default=False, repr=False)

    def start(self) -> None:
        """Start the browser process."""
        if self._started:
            return
        self._started = True
        logger.info("Playwright session %s started", self.session_id)

    def stop(self) -> None:
        """Stop the browser process."""
        if not self._started:
            return
        self._started = False
        logger.info("Playwright session %s stopped", self.session_id)

    @property
    def is_running(self) -> bool:
        return self._started


class PlaywrightAdapter:
    """Sandbox-executing Playwright adapter for browser-based pentest operations.

    Runs Playwright commands inside the Kali sandbox container, communicating
    via script files and stdout/stderr capture. This is the ARGUS equivalent
    of Shannon's Playwright integration but operates through the existing
    ``docker exec`` sandbox model rather than Claude Agent SDK tool calls.
    """

    def __init__(
        self,
        sandbox_runner: Any | None = None,
        container_name: str = "argus-sandbox",
        session_id: str = "default",
    ) -> None:
        self._runner = sandbox_runner
        self._container = container_name
        self._session = PlaywrightSession(session_id=session_id)
        self._screenshots_dir = tempfile.mkdtemp(prefix="argus_pw_")

    async def execute(self, request: BrowserRequest) -> BrowserResponse:
        """Execute a browser action inside the sandbox.

        Generates a Node.js script that uses Playwright to perform the
        requested action, then executes it inside the sandbox container.
        """
        script = self._generate_script(request)
        script_path = Path(tempfile.mktemp(suffix=".mjs", prefix="argus_pw_"))
        try:
            script_path.write_text(script, encoding="utf-8")
            return await self._run_in_sandbox(script_path, request)
        finally:
            if script_path.exists():
                script_path.unlink()

    async def navigate(self, url: str, **kwargs) -> BrowserResponse:
        """Navigate to a URL and capture the page state."""
        return await self.execute(BrowserRequest(action=BrowserAction.NAVIGATE, url=url, **kwargs))

    async def click(self, selector: str, **kwargs) -> BrowserResponse:
        """Click an element by CSS selector."""
        return await self.execute(BrowserRequest(action=BrowserAction.CLICK, selector=selector, **kwargs))

    async def type_text(self, selector: str, text: str, **kwargs) -> BrowserResponse:
        """Type text into an element by CSS selector."""
        return await self.execute(BrowserRequest(action=BrowserAction.TYPE, selector=selector, text=text, **kwargs))

    async def screenshot(self, path: str | None = None, **kwargs) -> BrowserResponse:
        """Take a screenshot of the current page."""
        shot_path = path or str(Path(self._screenshots_dir) / f"screenshot_{int(time.time())}.png")
        return await self.execute(BrowserRequest(action=BrowserAction.SCREENSHOT, screenshot_path=shot_path, **kwargs))

    async def execute_js(self, js_code: str, **kwargs) -> BrowserResponse:
        """Execute JavaScript in the browser context."""
        return await self.execute(BrowserRequest(action=BrowserAction.EXECUTE_JS, js_code=js_code, **kwargs))

    async def login_flow(
        self,
        url: str,
        steps: list[dict[str, str]],
        success_condition: dict[str, str] | None = None,
    ) -> BrowserResponse:
        """Execute a declarative login flow (from AuthConfig).

        Combines navigate, type, and click actions into a single script
        execution for efficiency.
        """
        script_lines = [
            "const { chromium } = require('playwright');",
            f"const browser = await chromium.launch({{ headless: true }});",
            "const context = await browser.newContext();",
            "const page = await context.newPage();",
            f"await page.goto({json.dumps(url)}, {{ waitUntil: 'networkidle', timeout: 30000 }});",
        ]

        for step in steps:
            instruction = step.get("instruction", "").lower()
            if "type" in instruction or "enter" in instruction:
                selector = step.get("selector", "")
                value = step.get("value", "")
                if selector and value:
                    script_lines.append(f"await page.fill({json.dumps(selector)}, {json.dumps(value)});")
            elif "click" in instruction or "press" in instruction:
                selector = step.get("selector", "")
                if selector:
                    script_lines.append(f"await page.click({json.dumps(selector)});")
            script_lines.append("await page.waitForTimeout(500);")

        if success_condition:
            cond_type = success_condition.get("type", "")
            cond_value = success_condition.get("value", "")
            if cond_type == "url_contains":
                script_lines.append(
                    f"await page.waitForURL(url => url.includes({json.dumps(cond_value)}), {{ timeout: 15000 }}).catch(() => {{}});"
                )
            elif cond_type == "status_code":
                script_lines.append(f"// status_code check: {cond_value}")

        script_lines.extend([
            "const url = page.url();",
            "const title = await page.title();",
            "const cookies = await context.cookies();",
            "console.log(JSON.stringify({ url, title, cookies }));",
            "await browser.close();",
        ])

        script = "\n".join(script_lines)
        script_path = Path(tempfile.mktemp(suffix=".mjs", prefix="argus_login_"))
        try:
            script_path.write_text(script, encoding="utf-8")
            return await self._run_in_sandbox(script_path, BrowserRequest(action="login_flow", url=url))
        finally:
            if script_path.exists():
                script_path.unlink()

    def _generate_script(self, request: BrowserRequest) -> str:
        """Generate a Node.js Playwright script for the given request."""
        lines = [
            "const { chromium } = require('playwright');",
            "(async () => {",
            f"  const browser = await chromium.launch({{ headless: {str(self._session.headless).lower()} }});",
            "  const context = await browser.newContext();",
            "  const page = await context.newPage();",
        ]

        if request.action == BrowserAction.NAVIGATE and request.url:
            lines.append(f"  await page.goto({json.dumps(request.url)}, {{ waitUntil: 'networkidle', timeout: {request.timeout_ms} }});")
            lines.append("  const url = page.url();")
            lines.append("  const title = await page.title();")
            lines.append("  const body = await page.textContent('body').catch(() => '');")
            lines.append("  console.log(JSON.stringify({ success: true, url, title, body_text: body }));")

        elif request.action == BrowserAction.CLICK and request.selector:
            lines.append(f"  await page.click({json.dumps(request.selector)}, {{ timeout: {request.timeout_ms} }});")
            lines.append("  console.log(JSON.stringify({ success: true }));")

        elif request.action == BrowserAction.TYPE and request.selector and request.text:
            lines.append(f"  await page.fill({json.dumps(request.selector)}, {json.dumps(request.text)});")
            lines.append("  console.log(JSON.stringify({ success: true }));")

        elif request.action == BrowserAction.SCREENSHOT:
            path = request.screenshot_path or "/tmp/screenshot.png"
            lines.append(f"  await page.screenshot({{ path: {json.dumps(path)} }});")
            lines.append(f"  console.log(JSON.stringify({{ success: true, screenshot_path: {json.dumps(path)} }}));")

        elif request.action == BrowserAction.EXECUTE_JS and request.js_code:
            safe_js = request.js_code.replace("`", "\\`")
            lines.append(f"  const result = await page.evaluate(`{safe_js}`);")
            lines.append("  console.log(JSON.stringify({ success: true, js_result: result }));")

        else:
            lines.append("  console.log(JSON.stringify({ success: false, error: 'Unknown action' }));")

        lines.extend([
            "  await browser.close();",
            "})();",
        ])
        return "\n".join(lines)

    async def _run_in_sandbox(self, script_path: Path, request: BrowserRequest) -> BrowserResponse:
        """Execute the generated script inside the sandbox container."""
        start = time.monotonic()
        try:
            if self._runner is not None:
                result = await asyncio.to_thread(
                    self._runner.execute,
                    "node",
                    [str(script_path)],
                    timeout=60,
                )
                stdout = result.stdout if hasattr(result, "stdout") else str(result)
            else:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", self._container, "node", str(script_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=60)
                stdout = stdout_bytes.decode("utf-8", errors="ignore")

            elapsed = (time.monotonic() - start) * 1000

            try:
                data = json.loads(stdout.strip().split("\n")[-1])
            except (json.JSONDecodeError, IndexError):
                data = {}

            return BrowserResponse(
                success=data.get("success", False),
                url=data.get("url", request.url or ""),
                title=data.get("title", ""),
                body_text=data.get("body_text"),
                screenshot_path=data.get("screenshot_path"),
                cookies=data.get("cookies", []),
                js_result=data.get("js_result"),
                elapsed_ms=elapsed,
            )
        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start) * 1000
            return BrowserResponse(success=False, error="Timeout", elapsed_ms=elapsed)
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            return BrowserResponse(success=False, error=str(exc), elapsed_ms=elapsed)


__all__ = [
    "BrowserAction",
    "BrowserRequest",
    "BrowserResponse",
    "PlaywrightAdapter",
    "PlaywrightSession",
]