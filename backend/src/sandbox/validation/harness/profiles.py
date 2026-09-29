"""Validation harnesses for different target profiles.

Each harness implements execute() for its specific environment type:
WebApp, API, CLI, Library, Binary.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from src.core.config import settings
from src.sandbox.docker_gateway import DockerGatewayError, exec_in

logger = logging.getLogger(__name__)

# F-H01: message returned when a harness would otherwise execute an
# attacker-influenceable reproducer on the host but the sandbox is unavailable.
_SANDBOX_REQUIRED_MSG = (
    "reproducer execution requires the argus-sandbox (SANDBOX_ENABLED=true); "
    "refusing to run untrusted reproducer payload on the host"
)


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
        environment: dict[str, Any],  # noqa: ARG002 - ValidationProfile.execute interface signature
        *,
        timeout: int = 300,
        capture_syscalls: bool = True,  # noqa: ARG002 - ValidationProfile.execute interface signature
        capture_network: bool = False,  # noqa: ARG002 - ValidationProfile.execute interface signature
    ) -> dict[str, Any]:
        import httpx

        url = reproducer.get("target_url", "")
        method = reproducer.get("method", "GET").upper()
        payload = reproducer.get("payload", "")
        headers = dict(reproducer.get("headers", {}) or {})
        param = reproducer.get("param", "")

        logs: list[str] = []
        result = {
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "logs": logs,
            "syscalls": [],
        }

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
                    resp = await client.post(
                        effective_url,
                        params=request_params,
                        data=request_data,
                        headers=headers,
                    )
                elif method == "PUT":
                    resp = await client.put(
                        effective_url,
                        params=request_params,
                        json=request_data,
                        headers=headers,
                    )
                elif method == "DELETE":
                    resp = await client.delete(
                        effective_url, params=request_params, headers=headers
                    )
                else:
                    resp = await client.request(
                        method,
                        effective_url,
                        params=request_params,
                        data=request_data,
                        headers=headers,
                    )

                result["exit_code"] = 0 if resp.status_code < 500 else 1
                body_preview = resp.text[:10000]
                result["stdout"] = f"HTTP {resp.status_code}\n{body_preview}"
                logs.append(f"[{resp.status_code}] {method} {resp.url}")
                logs.append(f"Content-Length: {len(resp.content)}")
                for k, v in resp.headers.items():
                    if k.lower() in (
                        "content-type",
                        "server",
                        "x-powered-by",
                        "set-cookie",
                        "location",
                    ):
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
        capture_syscalls: bool = True,  # noqa: ARG002 - ValidationProfile.execute interface signature
        capture_network: bool = False,  # noqa: ARG002 - ValidationProfile.execute interface signature
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
        environment: dict[str, Any],  # noqa: ARG002 - ValidationProfile.execute interface signature
        *,
        timeout: int = 300,
        capture_syscalls: bool = True,  # noqa: ARG002 - ValidationProfile.execute interface signature
        capture_network: bool = False,  # noqa: ARG002 - ValidationProfile.execute interface signature
    ) -> dict[str, Any]:
        command = reproducer.get("payload", "")
        logs: list[str] = []

        if not command:
            return {"stdout": "", "stderr": "No command", "exit_code": -1, "logs": logs}

        # F-H01: the CLI reproducer `payload` is an attacker-influenceable shell
        # command (derived from findings / LLM output). It MUST NOT run on the
        # host. Execute it inside the segmented, unprivileged argus-sandbox via the
        # single Docker gateway. `sh -c <command>` preserves legitimate pipe /
        # redirect reproducer semantics, while the whole command is carried as ONE
        # argv element — it cannot inject arguments into the `docker exec` itself.
        # If the sandbox is unavailable we fail closed rather than fall back to the
        # host shell (that fallback WAS the vulnerability).
        if not settings.sandbox_enabled:
            return {
                "stdout": "",
                "stderr": _SANDBOX_REQUIRED_MSG,
                "exit_code": -1,
                "logs": ["[CLI] sandbox disabled — fail-closed"],
            }
        try:
            result = await exec_in(
                settings.sandbox_container_name,
                ["sh", "-c", command],
                timeout=float(min(timeout, 120)),
            )
        except DockerGatewayError as exc:
            return {
                "stdout": "",
                "stderr": f"sandbox exec rejected: {exc}",
                "exit_code": 1,
                "logs": [f"ERROR: {exc}"],
            }
        return {
            "stdout": result.stdout[:50000],
            "stderr": result.stderr[:10000],
            "exit_code": result.exit_code,
            "logs": [f"[CLI] exit={result.exit_code} (sandbox)"],
            "syscalls": [],
        }


class LibraryHarness(BaseHarness):
    """Validates library vulnerabilities — function calls in isolation."""

    async def execute(
        self,
        reproducer: dict[str, Any],
        environment: dict[str, Any],  # noqa: ARG002 - ValidationProfile.execute interface signature
        *,
        timeout: int = 300,
        capture_syscalls: bool = True,  # noqa: ARG002 - ValidationProfile.execute interface signature
        capture_network: bool = False,  # noqa: ARG002 - ValidationProfile.execute interface signature
    ) -> dict[str, Any]:
        code = reproducer.get("payload", "")
        if not code:
            return {
                "stdout": "",
                "stderr": "No code to execute",
                "exit_code": -1,
                "logs": [],
            }

        # F-H01: the library reproducer `payload` is attacker-influenceable Python.
        # Previously it was written to a temp file and run with host `python3` —
        # arbitrary code execution on the host. Run it inside the argus-sandbox via
        # the gateway instead (`python3 -c <code>`; code carried as one argv
        # element). Fail closed when the sandbox is unavailable.
        if not settings.sandbox_enabled:
            return {
                "stdout": "",
                "stderr": _SANDBOX_REQUIRED_MSG,
                "exit_code": -1,
                "logs": ["[LIB] sandbox disabled — fail-closed"],
            }
        try:
            result = await exec_in(
                settings.sandbox_container_name,
                ["python3", "-c", code],
                timeout=float(min(timeout, 60)),
            )
        except DockerGatewayError as exc:
            return {
                "stdout": "",
                "stderr": f"sandbox exec rejected: {exc}",
                "exit_code": 1,
                "logs": [f"ERROR: {exc}"],
            }
        return {
            "stdout": result.stdout[:10000],
            "stderr": result.stderr[:5000],
            "exit_code": result.exit_code,
            "logs": [f"[LIB] exit={result.exit_code} (sandbox)"],
            "syscalls": [],
        }


class BinaryHarness(BaseHarness):
    """Validates binary/malware samples — metadata extraction and controlled sandbox execution."""

    async def execute(
        self,
        reproducer: dict[str, Any],
        environment: dict[str, Any],  # noqa: ARG002 - ValidationProfile.execute interface signature
        *,
        timeout: int = 300,  # noqa: ARG002 - ValidationProfile.execute interface signature
        capture_syscalls: bool = True,  # noqa: ARG002 - ValidationProfile.execute interface signature
        capture_network: bool = False,  # noqa: ARG002 - ValidationProfile.execute interface signature
    ) -> dict[str, Any]:
        sample_path = reproducer.get("payload", "")
        logs: list[str] = []
        result = {
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "logs": logs,
            "syscalls": [],
        }

        if not sample_path:
            result["stderr"] = "No binary sample path"
            return result

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
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                output = (out or b"").decode("utf-8", errors="replace")[:5000]
                logs.append(f"[BIN] {label}:\n{output}")
                result["stdout"] += f"\n--- {label} ---\n{output}"
                result["exit_code"] = 0
            except Exception as exc:
                logs.append(f"[BIN] {label} failed: {exc}")

        return result
