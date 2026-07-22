"""Web Workbench domain contracts (Pydantic, strict, ``extra="forbid"``).

These are the API / service contracts for the workbench foundation. They are
intentionally decoupled from SQLAlchemy models but reuse the shared policy
primitives (:class:`src.policy.scope.ScopeRule`) so scope semantics have a
single source of truth.
"""

from src.web_workbench.contracts.project import (
    EapAttachRequest,
    ProjectStatus,
    WorkbenchEapView,
    WorkbenchProjectCreate,
    WorkbenchProjectDTO,
    WorkbenchProjectListResponse,
    WorkbenchProjectUpdate,
)

__all__ = [
    "EapAttachRequest",
    "ProjectStatus",
    "WorkbenchEapView",
    "WorkbenchProjectCreate",
    "WorkbenchProjectDTO",
    "WorkbenchProjectListResponse",
    "WorkbenchProjectUpdate",
]
