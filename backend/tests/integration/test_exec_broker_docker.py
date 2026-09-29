"""F-H01 Stage 4 — argus-exec-broker end-to-end against a real Docker daemon.

Marked ``requires_docker`` (skipped by default; run with ``pytest -m requires_docker``).

Verifies the two acceptance conditions:
  1. A whitelisted tool exec through the broker reaches a real container and
     returns its output (the `docker exec` hot path still works).
  2. The broker exposes NO container-create surface — the escape primitive that
     survives the Tecnativa proxy is unreachable by construction.

The test drives the broker's endpoint in-process (socket transport) against a
throwaway container, so it does not require the full compose stack — only a
reachable Docker daemon.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid

import pytest
from fastapi.testclient import TestClient
from src.exec_broker import app as broker_app

pytestmark = pytest.mark.requires_docker

_IMAGE = "alpine:3.19"


@pytest.fixture()
def throwaway_container():
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    name = f"argus-broker-itest-{uuid.uuid4().hex[:8]}"
    subprocess.run(["docker", "pull", _IMAGE], check=True, capture_output=True, timeout=120)
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, _IMAGE, "sleep", "120"],
        check=True,
        capture_output=True,
        timeout=60,
    )
    try:
        yield name
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


def test_exec_through_broker_reaches_real_container(
    throwaway_container: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Allow our throwaway container + a tool that exists in alpine.
    monkeypatch.setattr(
        broker_app, "_ALLOWED_CONTAINERS", frozenset({throwaway_container}), raising=False
    )
    monkeypatch.setattr(broker_app, "ALLOWED_TOOLS", frozenset({"echo"}), raising=False)
    monkeypatch.setattr(broker_app.settings, "docker_transport", "socket", raising=False)

    client = TestClient(broker_app.app)
    resp = client.post(
        "/v1/exec",
        json={"container": throwaway_container, "argv": ["echo", "argus-broker-ok"], "timeout": 30},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["exit_code"] == 0
    assert "argus-broker-ok" in body["stdout"]


def test_broker_has_no_create_or_run_endpoint() -> None:
    client = TestClient(broker_app.app)
    # None of the escape endpoints exist -> 404, regardless of daemon state.
    for path in ("/containers/create", "/v1/containers/create", "/v1/run", "/v1/start", "/build"):
        assert client.post(path, json={}).status_code == 404
