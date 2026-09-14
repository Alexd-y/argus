"""Real-cluster tests for K8sLifecycleSandboxAdapter (section 8.2 K8s variant).

Marked ``requires_kind`` (auto-tagged by ``tests/integration/k8s/conftest.py``)
- needs the ``kubernetes`` SDK, ``kubectl`` on PATH, and ``KIND_CLUSTER_NAME``
set (the ``kev-hpa-kind.yml`` CI workflow provisions all three). Skipped by
default in dev. Run, e.g.::

    $env:KIND_CLUSTER_NAME = "argus-kind"
    $env:ARGUS_TEST_K8S_NAMESPACE = "argus-sandbox"
    $env:ARGUS_TEST_SANDBOX_IMAGE = "argus-sandbox"
    pytest tests/integration/k8s/test_k8s_lifecycle_adapter.py -m requires_kind

Exercises the verifiable create -> exec -> collect -> destroy lifecycle end to
end against a live cluster and owner-scoped orphan cleanup.
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
from src.sandbox.k8s_lifecycle_adapter import K8sLifecycleSandboxAdapter

pytestmark = pytest.mark.requires_kind

_NAMESPACE = os.environ.get("ARGUS_TEST_K8S_NAMESPACE", "argus-sandbox")
_IMAGE = os.environ.get("ARGUS_TEST_SANDBOX_IMAGE", "argus-sandbox")


@pytest.fixture(scope="module")
def _core_v1():
    pytest.importorskip("kubernetes")
    from kubernetes import client, config

    try:
        config.load_kube_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"kubeconfig unavailable: {exc}")
    return client.CoreV1Api()


@pytest.fixture
def _adapter(_core_v1):
    return K8sLifecycleSandboxAdapter(core_v1=_core_v1, namespace=_NAMESPACE, image=_IMAGE)


async def test_lifecycle_runs_id_and_cleans_up(_adapter, _core_v1):
    labels = {"argus.owner": f"itest-{uuid.uuid4().hex[:8]}"}
    result = await run_in_sandbox(_adapter, f"t-{uuid.uuid4().hex[:8]}", ["id"], owner_labels=labels)
    assert result.status == SandboxStatus.SUCCEEDED
    assert result.exit_code == 0
    assert result.container_id
    selector = ",".join(f"{k}={v}" for k, v in labels.items())
    remaining = _core_v1.list_namespaced_pod(namespace=_NAMESPACE, label_selector=selector)
    assert list(getattr(remaining, "items", []) or []) == []


async def test_exec_echo_captures_stdout(_adapter):
    labels = {"argus.owner": f"itest-{uuid.uuid4().hex[:8]}"}
    pod = await _adapter.create(f"t-{uuid.uuid4().hex[:8]}", labels)
    try:
        result = await _adapter.exec(pod, ["echo", "argus-sandbox-ok"])
        assert result.exit_code == 0
        assert "argus-sandbox-ok" in result.stdout
    finally:
        await _adapter.destroy(pod)


async def test_orphan_cleanup_only_touches_owned(_adapter, _core_v1):
    owner = f"itest-{uuid.uuid4().hex[:8]}"
    labels = {"argus.owner": owner}
    pod = await _adapter.create(f"t-{uuid.uuid4().hex[:8]}", labels)
    try:
        removed = await cleanup_orphans(_adapter, labels, max_age_seconds=0.0)
        assert removed >= 1
        selector = ",".join(f"{k}={v}" for k, v in labels.items())
        remaining = _core_v1.list_namespaced_pod(namespace=_NAMESPACE, label_selector=selector)
        assert list(getattr(remaining, "items", []) or []) == []
    finally:
        await _adapter.destroy(pod)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v", "-m", "requires_kind"]))
