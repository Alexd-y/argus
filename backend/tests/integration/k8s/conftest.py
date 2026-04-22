"""Kind-cluster gating + shared fixtures for ``backend/tests/integration/k8s``.

Tests in this package require:

* the ``kubectl`` binary on ``PATH`` (auto-installed by ``helm/kind-action``
  in the CI workflow), AND
* the ``KIND_CLUSTER_NAME`` environment variable to be set (the CI workflow
  ``kev-hpa-kind.yml`` exports it after the cluster comes up).

When EITHER prerequisite is missing the entire suite is skipped at
collection time. This mirrors the ``requires_postgres`` / ``requires_redis``
pattern in the parent ``backend/tests/conftest.py`` and keeps the local
``pytest -q`` feedback loop clean for developers without a kind binary.

The skip is implemented as a module-level ``pytestmark`` on each test
file PLUS a fallback ``pytest_collection_modifyitems`` hook here so a
test author who forgets the marker still gets the right behaviour in
dev. The hook also tags each item with ``requires_kind`` so CI can opt
INTO the suite via ``pytest -m requires_kind``.
"""

from __future__ import annotations

import os
import shutil

import pytest


def _kubectl_available() -> bool:
    """Return True when ``kubectl`` is on PATH AND ``KIND_CLUSTER_NAME`` is set."""
    if not os.environ.get("KIND_CLUSTER_NAME"):
        return False
    return shutil.which("kubectl") is not None


KIND_AVAILABLE: bool = _kubectl_available()

# Module-level skipif used as the default `pytestmark` import target. Test
# files import this name and assign it to `pytestmark` for clarity.
skip_if_no_kind = pytest.mark.skipif(
    not KIND_AVAILABLE,
    reason=(
        "kind cluster prerequisites missing: requires KIND_CLUSTER_NAME env "
        "variable AND kubectl on PATH (CI workflow .github/workflows/"
        "kev-hpa-kind.yml provides both)"
    ),
)


def pytest_configure(config: pytest.Config) -> None:
    """Register the ``requires_kind`` marker so CI can opt-in via ``-m``."""
    config.addinivalue_line(
        "markers",
        "requires_kind: needs a live kind cluster + kubectl on PATH "
        "(skipped by default; opt-in via KIND_CLUSTER_NAME env or "
        "pytest -m requires_kind)",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,  # noqa: ARG001 — pytest hook signature
    items: list[pytest.Item],
) -> None:
    """Tag every item in this package with ``requires_kind`` and skip when missing."""
    for item in items:
        item.add_marker(pytest.mark.requires_kind)
        if not KIND_AVAILABLE:
            item.add_marker(skip_if_no_kind)
