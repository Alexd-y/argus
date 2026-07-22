"""Declarative interception rule engine for the workbench proxy (WB-P2a).

Pure, deterministic matching: given an ordered rule set and a request's
normalized metadata, decide whether the proxy should hold the request for
manual editing (``INTERCEPT``), pass it through untouched (``PASS``) or drop it
(``DROP``). This is an *ergonomics* gate only — it is NOT a security control.
The mandatory security gate is :class:`~src.web_workbench.proxy.forward_gate.
ForwardGate` (scope + preflight), which runs regardless of the intercept
decision.

First-match-wins over the ordered rule list; if no rule matches, the configured
``default_action`` applies. Matching is case-insensitive for method/host and
uses substring/glob-free prefix semantics for the path to keep the engine
predictable and injection-free.
"""

from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.web_workbench.proxy.transport import NormalizedRequest


class InterceptAction(StrEnum):
    """What the proxy should do with a matched request."""

    INTERCEPT = "intercept"
    PASS = "pass"
    DROP = "drop"


class InterceptRule(BaseModel):
    """One interception rule. Empty match fields are treated as wildcards.

    * ``methods`` — set of upper-cased HTTP methods (empty = any).
    * ``host_suffix`` — case-insensitive host suffix (empty = any).
    * ``path_prefix`` — case-sensitive request-path prefix (empty = any).
    * ``content_type_contains`` — case-insensitive substring of the request's
      ``Content-Type`` (empty = any).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: InterceptAction
    methods: frozenset[str] = Field(default_factory=frozenset)
    host_suffix: StrictStr = Field(default="", max_length=255)
    path_prefix: StrictStr = Field(default="", max_length=2048)
    content_type_contains: StrictStr = Field(default="", max_length=128)

    def matches(self, request: NormalizedRequest) -> bool:
        if self.methods and request.method.upper() not in {m.upper() for m in self.methods}:
            return False
        if self.host_suffix:
            host = (request.host_header() or "").lower()
            if not host.endswith(self.host_suffix.lower()):
                return False
        if self.path_prefix and not _request_path(request).startswith(self.path_prefix):
            return False
        if self.content_type_contains:
            ctype = (request.header("Content-Type") or "").lower()
            if self.content_type_contains.lower() not in ctype:
                return False
        return True


def _request_path(request: NormalizedRequest) -> str:
    """Return the request path (origin-form target or path of absolute-form)."""
    target = request.target
    if target.startswith(("http://", "https://")):
        return urlsplit(target).path or "/"
    return target.split("?", 1)[0]


class InterceptRuleSet(BaseModel):
    """An ordered rule set with a default action (first-match-wins)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: tuple[InterceptRule, ...] = Field(default_factory=tuple)
    default_action: InterceptAction = InterceptAction.PASS

    def decide(self, request: NormalizedRequest) -> InterceptAction:
        """Return the action for ``request`` (first matching rule, else default)."""
        for rule in self.rules:
            if rule.matches(request):
                return rule.action
        return self.default_action


__all__ = [
    "InterceptAction",
    "InterceptRule",
    "InterceptRuleSet",
]
