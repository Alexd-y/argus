"""Signed-engagement model + FAIL-CLOSED scope enforcement (legitimate governance).

An :class:`Engagement` is the authorization envelope for a pentest: the targets,
tenants and actions permitted, inside a time window, at a bounded rate. The gate
:func:`assert_in_scope` **denies by default** — it raises :class:`ScopeViolation`
unless the action is explicitly inside a live engagement's scope.

This is the correct, defensive governance posture. The ARTEX "fail-open" inversion
(allow-by-default, cross-tenant traversal, egress to arbitrary sinks) is deliberately
NOT implemented — crossing into a tenant/target the engagement does not list is a
violation here, not a feature.

Pure module: no DB/LLM/network. Persistence (the ``engagements`` table + its DAO) and
the per-phase/per-node call sites wrap this pure predicate.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime

__all__ = ["Engagement", "ScopeViolation", "assert_in_scope", "host_of"]


class ScopeViolation(RuntimeError):
    """Raised when an action is not explicitly permitted by a live engagement."""


@dataclass(frozen=True)
class Engagement:
    """Immutable authorization envelope for one engagement."""

    engagement_id: str
    allowed_targets: tuple[str, ...] = ()
    allowed_tenants: tuple[str, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    window_start: datetime | None = None
    window_end: datetime | None = None
    max_rate_per_target: int | None = None
    revoked: bool = False
    metadata: dict = field(default_factory=dict)

    def is_active(self, now: datetime) -> bool:
        """True only inside the (optional) time window; a revoked engagement is never active."""
        if self.revoked:
            return False
        if self.window_start is not None and now < self.window_start:
            return False
        return not (self.window_end is not None and now > self.window_end)


def host_of(value: str) -> str:
    """Extract the host from a URL / authority / host:port string (lowercased).

    Uses the SAME standard parser the scanners use (``urllib.parse.urlsplit``) and
    returns only the parsed hostname, to avoid scope/allowlist bypasses from
    parser-differential inputs. Returns ``""`` (→ the caller denies, fail-closed) when
    the value carries a backslash, fragment, whitespace/control char or a userinfo
    component — vectors that let a hand-rolled parser disagree with the HTTP client
    about which host is actually contacted.
    """
    raw = str(value).strip()
    if not raw:
        return ""
    # Reject differential vectors outright (fail-closed → caller denies).
    if "\\" in raw or "#" in raw:
        return ""
    if any(ch.isspace() or ord(ch) < 0x20 for ch in raw):
        return ""
    candidate = raw if "://" in raw else "//" + raw
    try:
        parts = urllib.parse.urlsplit(candidate)
    except ValueError:
        return ""
    # Embedded credentials are ambiguous/suspicious for a scope check → deny.
    if parts.username or parts.password:
        return ""
    return (parts.hostname or "").rstrip(".").lower()


def _target_allowed(target: str, allowed_targets: tuple[str, ...]) -> bool:
    host = host_of(target)
    if not host:
        return False
    for allowed in allowed_targets:
        a = host_of(allowed)
        if not a:
            continue
        if host == a or host.endswith("." + a):
            return True
    return False


def assert_in_scope(
    target: str,
    action: str,
    engagement: Engagement | None,
    *,
    tenant_id: str | None = None,
    now: datetime | None = None,
) -> None:
    """Fail-closed scope gate. Returns ``None`` when permitted, else raises.

    Denies unless EVERY condition holds: a non-revoked engagement, inside its window,
    the target within ``allowed_targets`` (host or subdomain), the action within
    ``allowed_actions``, and — when a ``tenant_id`` is supplied — that tenant within
    ``allowed_tenants``. A missing engagement denies everything.
    """
    if engagement is None:
        raise ScopeViolation("no engagement in context — fail-closed deny")
    now = now or datetime.now(UTC)
    if engagement.revoked:
        raise ScopeViolation(f"engagement {engagement.engagement_id!r} is revoked")
    if not engagement.is_active(now):
        raise ScopeViolation(
            f"engagement {engagement.engagement_id!r} is outside its testing window"
        )
    if tenant_id is not None and tenant_id not in engagement.allowed_tenants:
        raise ScopeViolation(
            f"tenant {tenant_id!r} is not in engagement {engagement.engagement_id!r} scope"
        )
    if not _target_allowed(target, engagement.allowed_targets):
        raise ScopeViolation(f"target {target!r} is out of engagement scope")
    if action not in engagement.allowed_actions:
        raise ScopeViolation(f"action {action!r} is not permitted by the engagement")
    return None
