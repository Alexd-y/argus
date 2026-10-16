"""Quick integration tests are mock-based and must not pull FastAPI/main.app."""

from __future__ import annotations

import pathlib

import pytest

_QUICK_DIR = pathlib.Path(__file__).resolve().parent


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    # A conftest's ``pytest_collection_modifyitems`` receives EVERY collected item in the
    # session, not just this package's — marking all of them would leak ``no_auth_override``
    # onto unrelated router tests (e.g. tests/unit/api/*), whose auth override would then be
    # skipped, 401-ing them in the full run. Scope the marker to this package's own items.
    for item in items:
        try:
            pathlib.Path(str(item.path)).resolve().relative_to(_QUICK_DIR)
        except (ValueError, OSError):
            continue
        item.add_marker(pytest.mark.no_auth_override)
