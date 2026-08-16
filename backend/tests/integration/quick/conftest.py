"""Quick integration tests are mock-based and must not pull FastAPI/main.app."""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        item.add_marker(pytest.mark.no_auth_override)
