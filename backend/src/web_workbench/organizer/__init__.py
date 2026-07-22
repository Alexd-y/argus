"""Web Workbench — Organizer: collections + saved items (WB-P3c).

Tenant-scoped persistence for saving, tagging and searching requests/notes.
"""

from src.web_workbench.organizer.repository import (
    CollectionNameConflictError,
    CollectionNotFoundError,
    ItemNotFoundError,
    OptimisticLockError,
    OrganizerRepository,
    OrganizerRepositoryError,
    ProjectNotFoundError,
)

__all__ = [
    "CollectionNameConflictError",
    "CollectionNotFoundError",
    "ItemNotFoundError",
    "OptimisticLockError",
    "OrganizerRepository",
    "OrganizerRepositoryError",
    "ProjectNotFoundError",
]
