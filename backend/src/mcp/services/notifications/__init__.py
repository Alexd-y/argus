"""MCP webhook notification adapters and dispatcher (ARG-035).

Public surface:

* :class:`NotificationEvent` / :class:`NotificationSeverity` /
  :class:`AdapterResult` — wire-contract schemas (see :mod:`schemas`).
* :class:`NotificationDispatcher` / :class:`NotifierProtocol` — the
  fan-out facade (see :mod:`dispatcher`).
* :class:`SlackNotifier` / :class:`LinearAdapter` / :class:`JiraAdapter`
  — concrete adapters (see :mod:`slack`, :mod:`linear`, :mod:`jira`).
* :class:`CircuitBreaker`, :func:`hash_target`,
  :func:`compute_backoff_seconds` — shared helpers exposed for tests.

The whole subsystem is gated by ``MCP_NOTIFICATIONS_ENABLED`` (default
``false``); see ``docs/mcp-server.md`` for the operator runbook.
"""

from src.mcp.services.notifications._base import (
    DEFAULT_BACKOFF_BASE_SECONDS,
    DEFAULT_BACKOFF_CAP_SECONDS,
    DEFAULT_BACKOFF_FACTOR,
    DEFAULT_CIRCUIT_COOLDOWN_SECONDS,
    DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
    DEFAULT_DEDUP_CAPACITY,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TIMEOUT_SECONDS,
    TARGET_REDACTED_LEN,
    CircuitBreaker,
    NotifierBase,
    compute_backoff_seconds,
    hash_target,
)
from src.mcp.services.notifications.dispatcher import (
    ENABLE_ENV,
    NotificationDispatcher,
    NotifierProtocol,
    is_globally_enabled_via_env,
)
from src.mcp.services.notifications.jira import (
    DEFAULT_FINDING_FIELD_ID,
    JIRA_API_TOKEN_ENV,
    JIRA_FINDING_FIELD_ENV,
    JIRA_PROJECT_KEY_ENV,
    JIRA_SITE_URL_ENV,
    JIRA_USER_EMAIL_ENV,
    JiraAdapter,
    build_jira_payload,
)
from src.mcp.services.notifications.linear import (
    DEFAULT_LINEAR_API_URL,
    LINEAR_API_KEY_ENV,
    LINEAR_API_URL_ENV,
    LINEAR_DEFAULT_TEAM_ENV,
    LINEAR_TEAM_MAP_ENV,
    LinearAdapter,
    build_linear_payload,
)
from src.mcp.services.notifications.schemas import (
    NOTIFICATION_EVENT_TYPES,
    AdapterResult,
    CircuitState,
    NotificationEvent,
    NotificationSeverity,
)
from src.mcp.services.notifications.slack import (
    SLACK_WEBHOOK_URL_ENV,
    SlackNotifier,
    build_slack_payload,
)

__all__ = [
    "DEFAULT_BACKOFF_BASE_SECONDS",
    "DEFAULT_BACKOFF_CAP_SECONDS",
    "DEFAULT_BACKOFF_FACTOR",
    "DEFAULT_CIRCUIT_COOLDOWN_SECONDS",
    "DEFAULT_CIRCUIT_FAILURE_THRESHOLD",
    "DEFAULT_DEDUP_CAPACITY",
    "DEFAULT_FINDING_FIELD_ID",
    "DEFAULT_LINEAR_API_URL",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_TIMEOUT_SECONDS",
    "ENABLE_ENV",
    "JIRA_API_TOKEN_ENV",
    "JIRA_FINDING_FIELD_ENV",
    "JIRA_PROJECT_KEY_ENV",
    "JIRA_SITE_URL_ENV",
    "JIRA_USER_EMAIL_ENV",
    "LINEAR_API_KEY_ENV",
    "LINEAR_API_URL_ENV",
    "LINEAR_DEFAULT_TEAM_ENV",
    "LINEAR_TEAM_MAP_ENV",
    "NOTIFICATION_EVENT_TYPES",
    "SLACK_WEBHOOK_URL_ENV",
    "TARGET_REDACTED_LEN",
    "AdapterResult",
    "CircuitBreaker",
    "CircuitState",
    "JiraAdapter",
    "LinearAdapter",
    "NotificationDispatcher",
    "NotificationEvent",
    "NotificationSeverity",
    "NotifierBase",
    "NotifierProtocol",
    "SlackNotifier",
    "build_jira_payload",
    "build_linear_payload",
    "build_slack_payload",
    "compute_backoff_seconds",
    "hash_target",
    "is_globally_enabled_via_env",
]
