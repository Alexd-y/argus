"""WB-E2E — Web Workbench Intruder + Sessions contract tests (live stack).

These cases run against the live ``infra/docker-compose.e2e.yml`` stack
(OWASP Juice Shop + full ARGUS) and are opt-in via ``-m requires_docker_e2e``.
They close the infra-gated loop for two vertical slices whose *engines* are
already offline-verified (MockTransport unit tests):

Intruder (WB-P4b) — full lifecycle against a real target:
  1.  Create a workbench project scoped to juice-shop (HOST rule).
  2.  Create a ``sniper`` attack whose payloads reference the signed
      ``sqli_safe`` registry family (SI-5 — no raw payload bytes in the API).
  3.  Start the attack; it dispatches to the ``argus.intruder.highvol`` pool.
  4.  Poll to a terminal status within the timeout.
  5.  At least one request is forwarded through the ForwardGate (scope) and
      recorded; result rows are metadata-only (no raw request/response body).
  6.  Kill-switch: pausing the project rejects a fresh start with 409.

Sessions (WB-P6b) — persistence + split-plane invariant on the live API:
  7.  Create a login macro (secret referenced by ``secret_ref`` placeholder).
  8.  Create owner + attacker principals (``secrets_ref`` handle only).
  9.  No raw credential is ever echoed back by the API (SI-3).
  10. Optimistic locking rejects a stale macro update with 409.

The live owner/attacker *replay run* (authorization analysis) has no HTTP
trigger yet — its engine (``AuthorizationReplayRunner``) is exercised offline
via MockTransport; wiring a replay-run endpoint is the remaining WB-P6b step.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

pytestmark = pytest.mark.requires_docker_e2e


BASE_URL: str = os.environ.get("E2E_BACKEND_URL", "http://localhost:8000")
TARGET: str = os.environ.get("E2E_TARGET", "http://juice-shop:3000")
TARGET_HOST: str = os.environ.get("E2E_TARGET_HOST", "juice-shop")
TARGET_PORT: int = int(os.environ.get("E2E_TARGET_PORT", "3000"))
TOKEN: str = os.environ.get("E2E_TOKEN", "e2e-api-key-not-for-production")
ATTACK_TIMEOUT_SECONDS: int = int(os.environ.get("E2E_WB_ATTACK_TIMEOUT_SECONDS", "300"))
MAX_REQUESTS: int = int(os.environ.get("E2E_WB_MAX_REQUESTS", "16"))

HTTP_TIMEOUT_SECONDS: float = 30.0
POLL_INTERVAL_SECONDS: float = 3.0

_TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled"})


def _request(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    """Zero-dep stdlib HTTP wrapper (mirrors the scan-lifecycle suite)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {TOKEN}",
            "User-Agent": "argus-wb-e2e/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:  # noqa: S310
            payload = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        payload = exc.read() if exc.fp else b""
        status = exc.code
    if not payload:
        return status, None
    try:
        return status, json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return status, payload.decode("utf-8", errors="replace")


def _build_attack_template() -> tuple[str, list[dict[str, int]]]:
    """Return ``(base64_template, positions)`` for a sniper GET with one marker.

    The payload is injected byte-exact over the ``§INJECT§`` span, so the
    position offsets are computed against the raw bytes of the template.
    """
    marker = "§INJECT§".encode()
    prefix = b"GET /rest/products/search?q="
    suffix = (
        f" HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}:{TARGET_PORT}\r\n"
        f"Accept: application/json\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    raw = prefix + marker + suffix
    start = len(prefix)
    end = start + len(marker)
    template_b64 = base64.b64encode(raw).decode("ascii")
    return template_b64, [{"start": start, "end": end}]


# ── shared project fixture (created ACTIVE, scoped to juice-shop) ─────────


@dataclass
class WbProject:
    project_id: str
    version: int


@pytest.fixture(scope="module")
def wb_project() -> Iterator[WbProject]:
    """Create a workbench project scoped to the juice-shop host, then archive it."""
    suffix = str(int(time.time()))
    payload = {
        "name": f"e2e-wb-{suffix}",
        "description": "WB E2E — intruder + sessions",
        "scope_rules": [{"kind": "host", "pattern": TARGET_HOST}],
    }
    status, body = _request("POST", "/api/v1/wb/projects", body=payload)
    assert status == 201, f"failed to create wb project: status={status} body={body}"
    assert isinstance(body, dict) and body.get("id"), f"no project id in {body}"
    assert body.get("status") == "active", f"project not active on create: {body}"
    project = WbProject(project_id=str(body["id"]), version=int(body["version"]))
    try:
        yield project
    finally:
        # Best-effort teardown — archive so the tenant list stays clean.
        s, cur = _request("GET", f"/api/v1/wb/projects/{project.project_id}")
        if s == 200 and isinstance(cur, dict):
            _request(
                "PATCH",
                f"/api/v1/wb/projects/{project.project_id}",
                body={"expected_version": int(cur["version"]), "status": "archived"},
            )


# ── Intruder lifecycle ───────────────────────────────────────────────────


@dataclass
class WbAttack:
    attack_id: str
    version: int


@pytest.fixture(scope="module")
def created_attack(wb_project: WbProject) -> WbAttack:
    template_b64, positions = _build_attack_template()
    payload = {
        "name": f"e2e-sqli-{int(time.time())}",
        "attack_type": "sniper",
        "raw_request_template_base64": template_b64,
        "positions": positions,
        "payload_config": {
            "sets": [
                {
                    "family_id": "sqli_safe",
                    "correlation_key": "e2e-wb-intruder",
                    "max_payloads": MAX_REQUESTS,
                }
            ]
        },
        "config": {"max_requests": MAX_REQUESTS},
    }
    status, body = _request(
        "POST",
        f"/api/v1/wb/projects/{wb_project.project_id}/intruder/attacks",
        body=payload,
    )
    assert status == 201, f"failed to create attack: status={status} body={body}"
    assert isinstance(body, dict)
    assert body.get("status") not in _TERMINAL_STATUSES, body.get("status")
    return WbAttack(attack_id=str(body["id"]), version=int(body["version"]))


def test_intruder_attack_created_with_payload_reference(created_attack: WbAttack) -> None:
    status, body = _request("GET", f"/api/v1/wb/intruder/attacks/{created_attack.attack_id}")
    assert status == 200
    assert isinstance(body, dict)
    # SI-5 — the API stores payload *references*, never raw bytes.
    cfg = body.get("payload_config") or {}
    assert cfg.get("sets"), f"payload_config lost its references: {cfg}"
    assert cfg["sets"][0]["family_id"] == "sqli_safe"


@pytest.fixture(scope="module")
def completed_attack(created_attack: WbAttack) -> dict[str, Any]:
    status, body = _request(
        "POST",
        f"/api/v1/wb/intruder/attacks/{created_attack.attack_id}/start",
        body={"expected_version": created_attack.version},
    )
    assert status == 200, f"start failed: status={status} body={body}"
    deadline = time.monotonic() + ATTACK_TIMEOUT_SECONDS
    final: dict[str, Any] = {}
    while time.monotonic() < deadline:
        s, cur = _request("GET", f"/api/v1/wb/intruder/attacks/{created_attack.attack_id}")
        if s == 200 and isinstance(cur, dict):
            final = cur
            if cur.get("status") in _TERMINAL_STATUSES:
                return final
        time.sleep(POLL_INTERVAL_SECONDS)
    raise TimeoutError(f"attack {created_attack.attack_id} did not finish within timeout: {final}")


def test_intruder_attack_reaches_terminal_state(completed_attack: dict[str, Any]) -> None:
    assert completed_attack.get("status") in _TERMINAL_STATUSES
    # A ``sniper`` run against an in-scope host must have attempted requests.
    assert int(completed_attack.get("requests_completed", 0)) > 0


def test_intruder_requests_recorded_metadata_only(
    created_attack: WbAttack, completed_attack: dict[str, Any]
) -> None:
    _ = completed_attack
    status, body = _request(
        "GET", f"/api/v1/wb/intruder/attacks/{created_attack.attack_id}/requests?limit=100"
    )
    assert status == 200
    assert isinstance(body, dict)
    items = body.get("items") or []
    assert items, "no intruder requests were recorded"
    forwarded = [r for r in items if r.get("forward_outcome") == "forwarded"]
    assert forwarded, "no request passed the ForwardGate (scope) to the target"
    # Result rows are metadata-only — never a raw request/response body.
    for row in items:
        assert "raw_request" not in row
        assert "raw_response" not in row
        assert "response_body" not in row
        assert "payload_value" not in row
        # A forwarded row carries a response fingerprint, not the body.
        if row.get("forward_outcome") == "forwarded" and row.get("status_code") is not None:
            assert row.get("response_sha256"), f"forwarded row missing sha256: {row}"


def test_intruder_kill_switch_blocks_start_when_project_paused(
    wb_project: WbProject, created_attack: WbAttack, completed_attack: dict[str, Any]
) -> None:
    _ = created_attack, completed_attack
    # Pause the project (kill-switch), then a fresh attack start must be refused.
    s, cur = _request("GET", f"/api/v1/wb/projects/{wb_project.project_id}")
    assert s == 200 and isinstance(cur, dict)
    s2, _ = _request(
        "PATCH",
        f"/api/v1/wb/projects/{wb_project.project_id}",
        body={"expected_version": int(cur["version"]), "status": "paused"},
    )
    assert s2 == 200, "failed to pause project"
    try:
        template_b64, positions = _build_attack_template()
        s3, created = _request(
            "POST",
            f"/api/v1/wb/projects/{wb_project.project_id}/intruder/attacks",
            body={
                "name": f"e2e-killswitch-{int(time.time())}",
                "attack_type": "sniper",
                "raw_request_template_base64": template_b64,
                "positions": positions,
                "payload_config": {"sets": [{"family_id": "sqli_safe", "max_payloads": 4}]},
                "config": {"max_requests": 4},
            },
        )
        assert s3 == 201, f"attack create failed: {created}"
        s4, blocked = _request(
            "POST",
            f"/api/v1/wb/intruder/attacks/{created['id']}/start",
            body={"expected_version": int(created["version"])},
        )
        assert s4 == 409, f"kill-switch did not block start on paused project: {s4} {blocked}"
    finally:
        # Restore active so module teardown archive succeeds cleanly.
        s5, cur2 = _request("GET", f"/api/v1/wb/projects/{wb_project.project_id}")
        if s5 == 200 and isinstance(cur2, dict):
            _request(
                "PATCH",
                f"/api/v1/wb/projects/{wb_project.project_id}",
                body={"expected_version": int(cur2["version"]), "status": "active"},
            )


# ── Sessions persistence + split-plane invariant ─────────────────────────

_RAW_SECRET_SENTINEL = "sup3r-s3cret-e2e-password"


@pytest.fixture(scope="module")
def session_macro(wb_project: WbProject) -> dict[str, Any]:
    body = {
        "name": f"e2e-login-{int(time.time())}",
        "steps": [
            {
                "method": "POST",
                "path": "/rest/user/login",
                "headers": {"Content-Type": "application/json"},
                "body": '{"email":"owner@juice-sh.op","password":"{{secret_ref:owner_pw}}"}',
            }
        ],
        "match_rules": {"set_cookie": "token", "status": 200},
        "config": {"note": "split-plane: password via secret_ref only"},
    }
    status, created = _request(
        "POST",
        f"/api/v1/wb/projects/{wb_project.project_id}/sessions/macros",
        body=body,
    )
    assert status == 201, f"macro create failed: status={status} body={created}"
    assert isinstance(created, dict) and created.get("id")
    return created


def test_session_macro_does_not_echo_raw_secret(session_macro: dict[str, Any]) -> None:
    blob = json.dumps(session_macro)
    assert _RAW_SECRET_SENTINEL not in blob
    # A secret_ref placeholder is allowed; a resolved raw value is not.
    assert "{{secret_ref:owner_pw}}" in blob


def test_session_principals_split_plane(
    wb_project: WbProject, session_macro: dict[str, Any]
) -> None:
    for role in ("owner", "attacker", "anonymous"):
        body: dict[str, Any] = {"name": f"e2e-{role}-{int(time.time())}", "role": role}
        if role != "anonymous":
            body["secrets_ref"] = f"vault://wb/e2e/{role}"
            body["macro_id"] = session_macro["id"]
        status, created = _request(
            "POST",
            f"/api/v1/wb/projects/{wb_project.project_id}/sessions/principals",
            body=body,
        )
        assert status == 201, f"{role} principal create failed: {status} {created}"
        assert isinstance(created, dict)
        assert created.get("role") == role
        # Only the handle is stored/echoed — never a raw credential.
        assert _RAW_SECRET_SENTINEL not in json.dumps(created)
        if role != "anonymous":
            assert created.get("secrets_ref", "").startswith("vault://")


def test_session_macro_optimistic_lock(session_macro: dict[str, Any]) -> None:
    stale_version = int(session_macro["version"])
    # First update bumps the version.
    status, updated = _request(
        "PATCH",
        f"/api/v1/wb/sessions/macros/{session_macro['id']}",
        body={"expected_version": stale_version, "name": f"renamed-{int(time.time())}"},
    )
    assert status == 200, f"first macro update failed: {status} {updated}"
    # A second update with the now-stale version must be rejected (409).
    status2, conflict = _request(
        "PATCH",
        f"/api/v1/wb/sessions/macros/{session_macro['id']}",
        body={"expected_version": stale_version, "name": "should-conflict"},
    )
    assert status2 == 409, f"optimistic lock not enforced: {status2} {conflict}"
