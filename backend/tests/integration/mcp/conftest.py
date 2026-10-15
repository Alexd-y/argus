"""Conftest for the MCP integration suite.

Historically this set ``DATABASE_URL`` to a fake *postgres* DSN "so the engine constructor
does not blow up". That is stale — ``src.db.session`` imports and constructs its async
engine fine on the sqlite default (verified), and no real connection is opened at import
time. The fake postgres DSN was actively harmful: being a module-level ``os.environ[...]=``
it leaked a postgres URL into every *later* suite in the same session, so the migration
round-trip tests (which read ``DATABASE_URL`` at collection) saw "postgres is available",
tried to connect to an unreachable host, hung/errored, and corrupted the shared async /
logging state — the root of the full-suite "passes in isolation, fails in aggregate"
cascade. We keep an explicit, deterministic sqlite value (identical to the parent default)
so the MCP suite is self-contained without poisoning the rest of the run.
"""

from __future__ import annotations

import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
