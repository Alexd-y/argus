"""Conftest for the MCP integration suite.

The MCP server module imports ``src.db.session`` (transitively, via the
service layer) which expects a Postgres-shaped DSN. The default
integration conftest sets ``DATABASE_URL=sqlite+aiosqlite:///:memory:``;
we hard-override it here BEFORE any ``src.*`` import so the engine
constructor does not blow up.

The override is safe because no real connection is opened at import time
— SQLAlchemy lazily resolves the DSN on the first ``begin()`` call, and
the smoke tests in this folder never reach that point.
"""

from __future__ import annotations

import os

os.environ["DATABASE_URL"] = (
    "postgresql+asyncpg://mcp-int-test:no-password@localhost:5432/mcp_int_test"
)
