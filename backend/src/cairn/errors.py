"""Cairn domain errors.

These map the HTTP status semantics of the upstream Cairn protocol
(``cairn/src/cairn/server/services.py``) onto ARGUS. The API router (Phase 3)
translates them into ``HTTPException`` responses; the service layer (Phase 2)
raises them so business logic stays framework-agnostic and unit-testable.
"""

from __future__ import annotations


class CairnError(Exception):
    """Base class for all Cairn domain errors.

    ``status_code`` mirrors the HTTP status the upstream Cairn server returns for
    the equivalent condition, so the router can translate 1:1.
    """

    status_code: int = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CairnNotFoundError(CairnError):
    """Project / fact / intent / hint not found (404)."""

    status_code = 404


class CairnValidationError(CairnError):
    """Request violates a protocol invariant that is not a conflict (400)."""

    status_code = 400


class CairnForbiddenError(CairnError):
    """Operation not allowed in the current project state (403)."""

    status_code = 403


class CairnConflictError(CairnError):
    """Concurrency / state conflict — claimed by another worker, already
    concluded, stale fence token, etc. (409)."""

    status_code = 409
