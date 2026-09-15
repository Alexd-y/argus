"""Real-Docker tests for :class:`DockerLifecycleSandboxAdapter` (§8.2).

Marked ``requires_docker`` — needs a live Docker daemon (mounted socket) and the
sandbox image. Run, e.g.:

    $env:ARGUS_TEST_SANDBOX_IMAGE = "argus-sandbox"
    pytest tests/integration/sandbox/test_docker_sandbox_adapter.py -m requires_docker -p no:cacheprovider

Must run where a real Docker socket is available (e.g. ECS-on-EC2, not Fargate).
Exercises the verifiable create → exec → collect → destroy lifecycle end to end
and owner-scoped orphan cleanup.
"""

from __future__ import annotations

import os
import uuid

import pytest
from src.orchestration.sandbox_lifecycle import (
    SandboxStatus,
    cleanup_orphans,
    run_in_sandbox,
)
from src.sandbox.docker_sandbox_adapter import DockerLifecycleSandboxAdapter

pytestmark = pytest.mark.requires_docker

_IMAGE = os.environ.get("ARGUS_TEST_SANDBOX_IMAGE", "argus-sandbox")


@pytest.fixture(scope="module")
def _docker_client():
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"docker daemon unavailable: {exc}")
    try:
        client.images.get(_IMAGE)
    except Exception:  # noqa: BLE001
        pytest.skip(f"sandbox image {_IMAGE!r} not present")
    return client


@pytest.fixture
def _adapter(_docker_client):
    return DockerLifecycleSandboxAdapter(client=_docker_client, image=_IMAGE)


async def test_lifecycle_runs_id_and_cleans_up(_adapter, _docker_client):
    labels = {"argus.owner": f"itest-{uuid.uuid4().hex[:8]}"}
    result = await run_in_sandbox(
        _adapter, f"t-{uuid.uuid4().hex[:8]}", ["id"], owner_labels=labels
    )
    assert result.status == SandboxStatus.SUCCEEDED
    assert result.exit_code == 0
    assert result.container_id
    # Cleanup on success: the container must be gone.
    remaining = _docker_client.containers.list(
        all=True, filters={"label": [f"argus.owner={labels['argus.owner']}"]}
    )
    assert remaining == []


async def test_exec_echo_captures_stdout(_adapter):
    labels = {"argus.owner": f"itest-{uuid.uuid4().hex[:8]}"}
    cid = await _adapter.create(f"t-{uuid.uuid4().hex[:8]}", labels)
    try:
        result = await _adapter.exec(cid, ["echo", "argus-sandbox-ok"])
        assert result.exit_code == 0
        assert "argus-sandbox-ok" in result.stdout
    finally:
        await _adapter.destroy(cid)


async def test_orphan_cleanup_only_touches_owned(_adapter, _docker_client):
    owner = f"itest-{uuid.uuid4().hex[:8]}"
    labels = {"argus.owner": owner}
    cid = await _adapter.create(f"t-{uuid.uuid4().hex[:8]}", labels)
    try:
        # max_age_seconds=0 → our freshly-created, owner-labelled container is an
        # orphan candidate and is removed; nothing else is.
        removed = await cleanup_orphans(_adapter, labels, max_age_seconds=0.0)
        assert removed >= 1
        remaining = _docker_client.containers.list(
            all=True, filters={"label": [f"argus.owner={owner}"]}
        )
        assert remaining == []
    finally:
        await _adapter.destroy(cid)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v", "-m", "requires_docker"]))
