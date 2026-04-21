"""Backend root pytest conftest.

Pure ``sys.path`` insertion so ``from src.X import Y`` (the project-wide
convention used by every module in ``backend/src/*`` and every test in
``backend/tests/*``) resolves correctly regardless of where ``pytest`` is
invoked from:

  * ``cd backend && pytest …`` — works because ``backend/`` is cwd.
  * ``pytest backend/tests/…`` from project root — also works because of
    ``backend/tests/conftest.py`` (already inserts ``BACKEND_DIR``).
  * Edge cases (running pytest against paths under ``backend/`` that do NOT
    descend into ``backend/tests/``, e.g. doctests for ``backend/src/…`` or
    ad-hoc plugins) would otherwise miss the path injection. This file
    closes that gap with zero side effects.

Intentionally minimal:

* No fixtures (parent conftests in ``tests/`` and ``tests/unit/`` own those).
* No imports of ``src.*`` — keeps mypy / collection startup cheap.
* No environment variable manipulation — that lives in
  ``backend/tests/unit/conftest.py`` where it belongs (scoped to the unit
  subtree so integration tests still see the real env).

Do NOT add behaviour here; if a fixture is needed, put it in the closest
``tests/**/conftest.py`` so its scope is explicit.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent
_BACKEND_DIR_STR = str(_BACKEND_DIR)
if _BACKEND_DIR_STR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR_STR)
