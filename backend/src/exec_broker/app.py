"""F-H01 Stage 4 — argus-exec-broker FastAPI application.

Run with (inside the broker container, which is the only socket holder):

    uvicorn src.exec_broker.app:app --host 0.0.0.0 --port 8080

Security model
--------------
* **Single narrow verb.** The only mutating operation is "exec a tool in an
  allowlisted container". There is no create / start / commit / pull / build /
  volume / network endpoint. ``POST /containers/create`` is not *denied* — it is
  simply not implemented, so it is unreachable by construction, not by allowlist.
* **Server-side re-validation.** The broker never trusts the caller:
  - ``container`` must be in a static allowlist.
  - ``argv`` must be a non-empty list of strings.
  - ``argv[0]`` (the tool) must be in the existing ``ALLOWED_TOOLS`` set.
  - ``timeout`` is clamped to a hard ceiling.
  - stdout/stderr are truncated past a byte cap.
* **Exec via the single gateway.** The broker container runs with
  ``DOCKER_TRANSPORT=socket``, so :func:`docker_gateway.exec_in_sync` runs the
  ``docker exec`` through the CLI (``shell=False``, list argv). Using the CLI
  means the daemon handles the hijacked exec stream / stdout-stderr demux — the
  broker does not have to proxy a raw upgraded socket connection.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.core.config import settings
from src.sandbox.docker_gateway import DockerGatewayError, exec_in_sync
from src.tools.guardrails.command_parser import ALLOWED_TOOLS

logger = logging.getLogger(__name__)

# Static container allowlist. Derived from settings where available so a renamed
# sandbox still works, plus the canonical kali-runner name.
_ALLOWED_CONTAINERS: frozenset[str] = frozenset(
    {
        settings.sandbox_container_name,
        settings.lab_runner_container_name,
        "argus-kali-runner",
    }
)

app = FastAPI(title="argus-exec-broker", version="1.0.0")


class ExecRequest(BaseModel):
    container: str
    argv: list[str] = Field(min_length=1)
    workdir: str | None = None
    timeout: float = Field(default=120.0, gt=0)
    env: dict[str, str] | None = None


class ExecResponse(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    truncated: bool


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _reject(status_code: int, reason: str) -> None:
    logger.warning(
        "exec_broker_rejected",
        extra={"event": "exec_broker_rejected", "status": status_code, "reason": reason},
    )
    raise HTTPException(status_code=status_code, detail=reason)


def _truncate(text: str, cap: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= cap:
        return text, False
    return encoded[:cap].decode("utf-8", errors="replace"), True


@app.post("/v1/exec", response_model=ExecResponse)
def exec_endpoint(req: ExecRequest) -> ExecResponse:
    # 1. Container allowlist.
    if req.container not in _ALLOWED_CONTAINERS:
        _reject(403, f"container not allowed: {req.container!r}")
    # 2. argv shape.
    if not req.argv or not all(isinstance(a, str) for a in req.argv):
        _reject(400, "argv must be a non-empty list of strings")
    # 3. Tool allowlist (argv[0]).
    tool = req.argv[0]
    if tool not in ALLOWED_TOOLS:
        _reject(403, f"tool not allowed: {tool!r}")
    # 4. Clamp timeout to the hard ceiling.
    timeout = min(float(req.timeout), float(settings.exec_broker_max_timeout_sec))

    try:
        result = exec_in_sync(
            req.container,
            req.argv,
            workdir=req.workdir,
            timeout=timeout,
            env=req.env,
        )
    except DockerGatewayError as exc:
        _reject(400, f"invalid exec request: {exc}")

    cap = int(settings.exec_broker_max_output_bytes)
    stdout, t_out = _truncate(result.stdout, cap)
    stderr, t_err = _truncate(result.stderr, cap)
    return ExecResponse(
        exit_code=result.exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_s=result.duration_s,
        truncated=t_out or t_err,
    )
