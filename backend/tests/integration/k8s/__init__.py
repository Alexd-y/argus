"""Kubernetes integration tests (kind-cluster gated).

Tests under this package require a live ``kind`` cluster reachable via a
``kubectl`` configured against the cluster's kubeconfig. They are skipped
by default (auto-discovered as ``requires_kind`` by ``conftest.py``) and
opt-in via the ``KIND_CLUSTER_NAME`` environment variable, which the CI
workflow ``.github/workflows/kev-hpa-kind.yml`` exports after the cluster
is provisioned.
"""
