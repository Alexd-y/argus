"""F-H01 Stage 4 — argus-exec-broker policy tests (no Docker daemon).

Uses FastAPI's TestClient and stubs the gateway exec so the server-side policy
(container allowlist, tool allowlist, timeout clamp, output truncation) and the
*absence* of any create/start surface are verified without a real daemon.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from src.exec_broker import app as broker_app
from src.sandbox.docker_gateway import ExecResult


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    captured: dict = {}

    def _fake_exec(container, argv, *, workdir=None, timeout, env=None):  # noqa: ANN001
        captured["container"] = container
        captured["argv"] = argv
        captured["timeout"] = timeout
        return ExecResult(0, "tool-output", "", 0.01)

    monkeypatch.setattr(broker_app, "exec_in_sync", _fake_exec)
    tc = TestClient(broker_app.app)
    tc._captured = captured  # type: ignore[attr-defined]
    return tc


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_allowed_tool_in_allowed_container_execs(client: TestClient) -> None:
    resp = client.post(
        "/v1/exec",
        json={"container": "argus-sandbox", "argv": ["nuclei", "-version"], "timeout": 30},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["exit_code"] == 0
    assert body["stdout"] == "tool-output"
    assert client._captured["argv"] == ["nuclei", "-version"]  # type: ignore[attr-defined]


def test_disallowed_container_rejected(client: TestClient) -> None:
    resp = client.post(
        "/v1/exec",
        json={"container": "postgres", "argv": ["nuclei", "-version"], "timeout": 30},
    )
    assert resp.status_code == 403
    assert "container not allowed" in resp.json()["detail"]


def test_disallowed_tool_rejected(client: TestClient) -> None:
    resp = client.post(
        "/v1/exec",
        json={"container": "argus-sandbox", "argv": ["bash", "-c", "id"], "timeout": 30},
    )
    assert resp.status_code == 403
    assert "tool not allowed" in resp.json()["detail"]


def test_empty_argv_rejected(client: TestClient) -> None:
    resp = client.post("/v1/exec", json={"container": "argus-sandbox", "argv": [], "timeout": 30})
    # pydantic min_length=1 -> 422 before our handler.
    assert resp.status_code in (400, 422)


def test_timeout_clamped_to_ceiling(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(broker_app.settings, "exec_broker_max_timeout_sec", 60.0, raising=False)
    resp = client.post(
        "/v1/exec",
        json={"container": "argus-sandbox", "argv": ["nuclei"], "timeout": 99999},
    )
    assert resp.status_code == 200
    assert client._captured["timeout"] == 60.0  # type: ignore[attr-defined]


def test_output_truncated_past_cap(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    big = "A" * 10000

    def _big_exec(container, argv, *, workdir=None, timeout, env=None):  # noqa: ANN001
        return ExecResult(0, big, "", 0.01)

    monkeypatch.setattr(broker_app, "exec_in_sync", _big_exec)
    monkeypatch.setattr(broker_app.settings, "exec_broker_max_output_bytes", 100, raising=False)
    resp = client.post(
        "/v1/exec",
        json={"container": "argus-sandbox", "argv": ["nuclei"], "timeout": 30},
    )
    body = resp.json()
    assert body["truncated"] is True
    assert len(body["stdout"].encode("utf-8")) <= 100


def test_no_container_create_surface(client: TestClient) -> None:
    """The broker exposes only /v1/exec + /health — the escape endpoints do not
    exist by construction, not by allowlist."""
    routes = {r.path for r in broker_app.app.routes if hasattr(r, "path")}
    assert "/v1/exec" in routes
    for forbidden in ("/containers/create", "/v1/containers/create", "/v1/run", "/v1/start"):
        assert forbidden not in routes
    # And a live probe returns 404 (no such route).
    assert client.post("/containers/create", json={}).status_code == 404
