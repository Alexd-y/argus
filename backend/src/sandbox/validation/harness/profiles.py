"""Validation harnesses for different target profiles.

Each harness implements execute() for its specific environment type:
WebApp, API, CLI, Library, Binary.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

logger = logging.getLogger(__name__)


class BaseHarness(ABC):
    """Abstract harness — all profiles implement this."""

    @abstractmethod
    async def execute(
        self,
        reproducer: dict[str, Any],
        environment: dict[str, Any],
        *,
        timeout: int = 300,
        capture_syscalls: bool = True,
        capture_network: bool = False,
    ) -> dict[str, Any]:
        """Execute reproducer in environment, return raw results."""


class WebAppHarness(BaseHarness):
    """Validates web application vulnerabilities (XSS, SQLi, CSRF, SSRF, ...)."""

    async def execute(
        self,
        reproducer: dict[str, Any],
        environment: dict[str, Any],
        *,
        timeout: int = 300,
        capture_syscalls: bool = True,
        capture_network: bool = False,
    ) -> dict[str, Any]:
        import httpx

        url = reproducer.get("target_url", "")
        method = reproducer.get("method", "GET").upper()
        payload = reproducer.get("payload", "")
        headers = dict(reproducer.get("headers", {}) or {})
        param = reproducer.get("param", "")

        logs: list[str] = []
        result = {"stdout": "", "stderr": "", "exit_code": -1, "logs": logs, "syscalls": []}

        if not url:
            result["stderr"] = "No target URL"
            return result

        effective_url = url
        request_params: dict[str, str] = {}
        request_data: dict[str, str] = {}

        if payload and param:
            if method in ("GET", "HEAD", "DELETE"):
                request_params[param] = payload
            else:
                request_data[param] = payload
        elif payload and method == "GET":
            effective_url = f"{url}{'&' if '?' in url else '?'}{payload}"

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(min(timeout, 60)),
                verify=False,
                follow_redirects=True,
                max_redirects=5,
            ) as client:
                if method == "GET":
                    resp = await client.get(effective_url, params=request_params, headers=headers)
                elif method == "POST":
                    resp = await client.post(effective_url, params=request_params, data=request_data, headers=headers)
                elif method == "PUT":
                    resp = await client.put(effective_url, params=request_params, json=request_data, headers=headers)
                elif method == "DELETE":
                    resp = await client.delete(effective_url, params=request_params, headers=headers)
                else:
                    resp = await client.request(method, effective_url, params=request_params, data=request_data, headers=headers)

                result["exit_code"] = 0 if resp.status_code < 500 else 1
                body_preview = resp.text[:10000]
                result["stdout"] = f"HTTP {resp.status_code}\n{body_preview}"
                logs.append(f"[{resp.status_code}] {method} {resp.url}")
                logs.append(f"Content-Length: {len(resp.content)}")
                for k, v in resp.headers.items():
                    if k.lower() in ("content-type", "server", "x-powered-by", "set-cookie", "location"):
                        logs.append(f"{k}: {v[:200]}")
        except httpx.TimeoutException:
            result["exit_code"] = 124
            result["stderr"] = "Request timeout"
            logs.append("TIMEOUT")
        except Exception as exc:
            result["exit_code"] = 1
            result["stderr"] = str(exc)
            logs.append(f"ERROR: {exc}")

        return result


class ApiHarness(BaseHarness):
    """Validates API vulnerabilities — similar to WebApp but with structured request/response."""

    async def execute(
        self,
        reproducer: dict[str, Any],
        environment: dict[str, Any],
        *,
        timeout: int = 300,
        capture_syscalls: bool = True,
        capture_network: bool = False,
    ) -> dict[str, Any]:
        # API harness uses same HTTP logic as WebApp
        web = WebAppHarness()
        result = await web.execute(reproducer, environment, timeout=timeout)
        result["profile"] = "api"
        return result


class CliHarness(BaseHarness):
    """Validates CLI vulnerabilities — executes command and captures output."""

    async def execute(
        self,
        reproducer: dict[str, Any],
        environment: dict[str, Any],
        *,
        timeout: int = 300,
        capture_syscalls: bool = True,
        capture_network: bool = False,
    ) -> dict[str, Any]:
        command = reproducer.get("payload", "")
        logs: list[str] = []

        if not command:
            return {"stdout": "", "stderr": "No command", "exit_code": -1, "logs": logs}

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=min(timeout, 120)
            )
            return {
                "stdout": (stdout or b"").decode("utf-8", errors="replace")[:50000],
                "stderr": (stderr or b"").decode("utf-8", errors="replace")[:10000],
                "exit_code": proc.returncode or 0,
                "logs": [f"[CLI] exit={proc.returncode}"],
                "syscalls": [],
            }
        except TimeoutError:
            return {"stdout": "", "stderr": "Command timeout", "exit_code": 124, "logs": ["TIMEOUT"]}
        except Exception as exc:
            return {"stdout": "", "stderr": str(exc), "exit_code": 1, "logs": [f"ERROR: {exc}"]}


class LibraryHarness(BaseHarness):
    """Validates library vulnerabilities — function calls in isolation."""

    async def execute(
        self,
        reproducer: dict[str, Any],
        environment: dict[str, Any],
        *,
        timeout: int = 300,
        capture_syscalls: bool = True,
        capture_network: bool = False,
    ) -> dict[str, Any]:
        code = reproducer.get("payload", "")
        if not code:
            return {"stdout": "", "stderr": "No code to execute", "exit_code": -1, "logs": []}

        with TemporaryDirectory() as tmp:
            script = Path(tmp) / "test_harness.py"
            script.write_text(code, encoding="utf-8")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "python3", str(script),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=min(timeout, 60)
                )
                return {
                    "stdout": (stdout or b"").decode("utf-8", errors="replace")[:10000],
                    "stderr": (stderr or b"").decode("utf-8", errors="replace")[:5000],
                    "exit_code": proc.returncode or 0,
                    "logs": [f"[LIB] exit={proc.returncode}"],
                    "syscalls": [],
                }
            except TimeoutError:
                return {"stdout": "", "stderr": "Library execution timeout", "exit_code": 124, "logs": []}
            except Exception as exc:
                return {"stdout": "", "stderr": str(exc), "exit_code": 1, "logs": [f"ERROR: {exc}"]}


class BinaryHarness(BaseHarness):
    """Validates binary/malware samples — metadata extraction and controlled sandbox execution."""

    async def execute(
        self,
        reproducer: dict[str, Any],
        environment: dict[str, Any],
        *,
        timeout: int = 300,
        capture_syscalls: bool = True,
        capture_network: bool = False,
    ) -> dict[str, Any]:
        sample_path = reproducer.get("payload", "")
        logs: list[str] = []
        result = {"stdout": "", "stderr": "", "exit_code": -1, "logs": logs, "syscalls": []}

        if not sample_path:
            result["stderr"] = "No binary sample path"
            return result

        commands = []
        if not Path(sample_path).exists():
            logs.append(f"[BIN] Sample not found: {sample_path}")
            return result

        checks: list[tuple[str, list[str]]] = [
            ("File type", ["file", sample_path]),
            ("Strings (suspicious)", ["strings", sample_path]),
        ]

        for label, cmd in checks:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                output = (out or b"").decode("utf-8", errors="replace")[:5000]
                logs.append(f"[BIN] {label}:\n{output}")
                result["stdout"] += f"\n--- {label} ---\n{output}"
                result["exit_code"] = 0
            except Exception as exc:
                logs.append(f"[BIN] {label} failed: {exc}")

        return result
