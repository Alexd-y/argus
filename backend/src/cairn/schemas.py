"""Shared Cairn constants and lightweight schema primitives.

Full API request/response Pydantic models (ported from
``_external/Cairn/cairn/src/cairn/server/models.py``) are added in Phase 3. This
module holds the small, cross-phase primitives that Phase 1/2 already need so they
have a single source of truth.
"""

from __future__ import annotations

from typing import Final

#: Special fact refs created together with the project.
ORIGIN_REF: Final[str] = "origin"
GOAL_REF: Final[str] = "goal"

#: Creator string used for the dispatcher-created bootstrap intent (upstream D-04).
BOOTSTRAP_CREATOR: Final[str] = "dispatcher.bootstrap"
BOOTSTRAP_DESCRIPTION: Final[str] = "bootstrap"
