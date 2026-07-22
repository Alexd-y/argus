"""Web Workbench — Repeater: scope-gated byte-exact replay (WB-P3b).

Every replay passes the mandatory forward gate (scope + optional full preflight)
before any byte leaves the process; a blocked replay never touches the sender.
"""

from src.web_workbench.repeater.engine import (
    HttpSender,
    RawResponse,
    ReplayResult,
    RepeaterService,
)
from src.web_workbench.repeater.repository import (
    ExchangeNotFoundError,
    OptimisticLockError,
    ProjectNotFoundError,
    RepeaterRepository,
    RepeaterRepositoryError,
    TabNotFoundError,
)
from src.web_workbench.repeater.sender import HttpxSender

__all__ = [
    "ExchangeNotFoundError",
    "HttpSender",
    "HttpxSender",
    "OptimisticLockError",
    "ProjectNotFoundError",
    "RawResponse",
    "ReplayResult",
    "RepeaterRepository",
    "RepeaterRepositoryError",
    "RepeaterService",
    "TabNotFoundError",
]
