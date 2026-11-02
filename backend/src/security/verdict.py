"""Canonical allow/deny verdict for security gates (§8).

A single, dependency-free shape for "may this proceed?" decisions so every gate
logs and serialises its outcome the same way instead of each inventing its own
``(bool, reason, status)`` tuple. Fail-closed by construction: the only way to get
an allowing verdict is :meth:`SecurityVerdict.allow`; everything else denies.

This does NOT replace richer, domain-specific DTOs (e.g.
``ToolPolicyDecision``) — it is the small common denominator for the many
one-off ``allowed: bool`` decisions, and new gates should return it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class SecurityVerdict:
    """Outcome of a security gate.

    ``allowed`` — whether the action may proceed.
    ``code``    — stable machine code (``""`` when allowed; a SCREAMING_SNAKE deny
                  code otherwise), safe for metrics/log correlation.
    ``reason``  — short human-readable explanation (no secrets, no PII).
    ``detail``  — optional structured context for logs (no secrets).
    """

    allowed: bool
    code: str = ""
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allow(cls, reason: str = "allowed", **detail: Any) -> SecurityVerdict:
        return cls(allowed=True, code="", reason=reason, detail=dict(detail))

    @classmethod
    def deny(cls, code: str, reason: str = "", **detail: Any) -> SecurityVerdict:
        return cls(allowed=False, code=code, reason=reason or code, detail=dict(detail))

    def __bool__(self) -> bool:  # lets callers write ``if verdict:`` / ``not verdict``
        return self.allowed

    def log_extra(self, event: str) -> dict[str, Any]:
        """Structured-log ``extra`` dict for this verdict under ``event``."""
        return {
            "event": event,
            "allowed": self.allowed,
            "code": self.code,
            "reason": self.reason,
            **self.detail,
        }


__all__ = ["SecurityVerdict"]
