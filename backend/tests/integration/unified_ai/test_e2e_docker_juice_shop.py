"""Gated live Docker e2e against the ARGUS stack (master prompt §22).

Skipped unless E2E_BACKEND_URL is reachable. This is not a Juice Shop HTTP ping:
it issues a LAB lease and executes a real lab script through the live API.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

pytestmark = pytest.mark.requires_docker_e2e

_BACKEND = os.environ.get("E2E_BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
_TOKEN = os.environ.get("E2E_TOKEN", "e2e-api-key-not-for-production")
_TENANT = os.environ.get("E2E_TENANT_ID", "00000000-0000-0000-0000-000000000001")
_TARGET = os.environ.get("ARGUS_E2E_TARGET", "http://juice-shop:3000")


def _request(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        f"{_BACKEND}{path}",
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {_TOKEN}",
            "X-Tenant-Id": _TENANT,
            "X-User-Id": "e2e-operator",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw else {}
            return int(resp.status), parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"detail": raw}
        return int(exc.code), parsed
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        pytest.skip(f"e2e backend not reachable at {_BACKEND}")


def test_live_stack_lab_lease_and_script_execute() -> None:
    status, _ = _request("GET", "/health")
    if status >= 500:
        pytest.skip(f"e2e backend unhealthy: {status}")

    mode_status, _ = _request(
        "POST",
        "/api/v1/engagements/e2e-lab/execution-mode",
        {"mode": "lab_unrestricted"},
    )
    if mode_status in {401, 403, 404}:
        pytest.skip(f"execution-mode API not available ({mode_status})")
    assert mode_status in {200, 201}

    scope_status, _ = _request(
        "POST",
        "/api/v1/engagements/e2e-lab/lab-scope",
        {
            "cidrs": ["10.90.0.0/16", "172.16.0.0/12"],
            "dns_suffixes": ["juice-shop", "localhost"],
            "k8s_namespace": os.environ.get("ARGUS_LAB_K8S_NAMESPACE", "argus-lab"),
            "capture_full": True,
        },
    )
    assert scope_status == 201, scope_status

    lease_status, lease = _request(
        "POST",
        "/api/v1/engagements/e2e-lab/lab-lease",
        {"target": _TARGET, "kill_switch_cleared": True},
    )
    if lease_status == 403:
        pytest.skip("live target outside lab boundary")
    assert lease_status == 201, lease
    lease_id = lease["lease_id"]

    script_status, script = _request(
        "POST",
        "/api/v1/lab/scripts",
        {"language": "python", "source": "print('e2e-lab-ok')", "lease_id": lease_id},
    )
    assert script_status == 201, script
    exec_status, executed = _request(
        "POST",
        f"/api/v1/lab/scripts/{script['script_id']}/execute",
    )
    assert exec_status == 200, executed
    assert executed["requires_approval"] is False
    assert executed["status"] == "completed"
    assert "e2e-lab-ok" in executed["stdout"]
    assert executed.get("runner") != "argus-sandbox"
