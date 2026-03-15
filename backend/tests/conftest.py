"""Pytest fixtures for ARGUS backend tests (ARGUS-003, ARGUS-004)."""

import sys
from pathlib import Path

import pytest

# Ensure backend is on path when running from ARGUS root
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# pytest-asyncio: async tests run without explicit event loop
pytest_plugins = ["pytest_asyncio"]


@pytest.fixture(scope="module")
def app():
    """FastAPI app instance."""
    from main import app as _app
    return _app


@pytest.fixture
def client(app):
    """TestClient for FastAPI app (uses httpx via starlette)."""
    from starlette.testclient import TestClient
    return TestClient(app)
