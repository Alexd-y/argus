"""Session macro replay — establish an authenticated session (WB-P6b).

Replays a login / session-setup macro (an ordered list of request steps) through
the mandatory forward gate to obtain a live session (cookie jar) for
authenticated testing. Invariants:

* **Gate first (SI-WB-1).** Every step is evaluated by
  :class:`~src.web_workbench.proxy.forward_gate.ForwardGate` before a byte
  leaves the process; a blocked step aborts the macro fail-closed (no partial
  session is trusted).
* **Split-plane secrets (SI-3).** Steps carry ``secret_ref`` placeholders, never
  raw credentials. The injected :data:`SecretResolver` resolves each ref to a
  value in-process at replay time; resolved values are substituted into the raw
  request bytes and are **never logged**.
* **Byte-fidelity where it matters.** Placeholder substitution and cookie
  injection rewrite only the affected bytes; the rest of each request head/body
  is preserved.

Network egress is delegated to an injected :class:`~src.web_workbench.repeater.
engine.HttpSender`, so the runner is offline-testable with a stub sender.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from src.web_workbench.message_editor.engine import RawHttpMessage
from src.web_workbench.proxy.forward_gate import ForwardGate
from src.web_workbench.proxy.transport import (
    HttpMessageError,
    NormalizedRequest,
    NormalizedResponse,
)
from src.web_workbench.repeater.engine import HttpSender
from src.web_workbench.sessions.cookies import (
    cookie_header_value,
    inject_cookie_header,
    parse_set_cookies,
)

#: Resolves a ``secret_ref`` placeholder to its value from the secret plane.
SecretResolver = Callable[[str], str]


class MacroError(Exception):
    """Raised on a malformed macro step definition (fail-closed)."""


@dataclass(frozen=True)
class MacroStep:
    """One replay step: byte-exact raw request + placeholder→secret_ref map."""

    raw_request: bytes
    secret_refs: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EstablishedSession:
    """Result of replaying a macro: the session cookie jar + auth verdict."""

    cookies: dict[str, str]
    authenticated: bool
    steps_run: int
    blocked: bool
    block_reason: str | None = None

    def cookie_header(self) -> str:
        """Render the ``Cookie`` header value to attach to authenticated requests."""
        return cookie_header_value(self.cookies)


def parse_steps(raw_steps: Sequence[Any] | None) -> list[MacroStep]:
    """Parse persisted macro ``steps`` JSON into :class:`MacroStep` objects.

    Each step must be a mapping with a base64 ``raw_request_base64`` and an
    optional ``secret_refs`` map. Raises :class:`MacroError` on any malformed
    entry (fail-closed — a broken macro must not silently no-op).
    """
    if not raw_steps:
        raise MacroError("macro has no steps")
    steps: list[MacroStep] = []
    for position, entry in enumerate(raw_steps):
        if not isinstance(entry, dict):
            raise MacroError(f"step {position} is not an object")
        encoded = entry.get("raw_request_base64")
        if not isinstance(encoded, str) or not encoded:
            raise MacroError(f"step {position} missing raw_request_base64")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise MacroError(f"step {position} raw_request_base64 is not valid base64") from exc
        refs_raw = entry.get("secret_refs") or {}
        if not isinstance(refs_raw, dict):
            raise MacroError(f"step {position} secret_refs must be an object")
        secret_refs = {str(k): str(v) for k, v in refs_raw.items()}
        steps.append(MacroStep(raw_request=raw, secret_refs=secret_refs))
    return steps


def _substitute_secrets(raw: bytes, secret_refs: dict[str, str], resolver: SecretResolver) -> bytes:
    """Replace each placeholder token in ``raw`` with its resolved secret value."""
    out = raw
    for placeholder, secret_ref in secret_refs.items():
        value = resolver(secret_ref)
        out = out.replace(placeholder.encode("latin-1"), value.encode("latin-1"))
    return out


def _matches(response: NormalizedResponse, body: bytes, rules: dict[str, Any] | None) -> bool:
    """Evaluate ``match_rules`` against a response (all present rules must hold)."""
    if not rules:
        # No explicit rule → treat any successful (2xx/3xx) response as authed.
        return 200 <= response.status_code < 400
    statuses = rules.get("status")
    if isinstance(statuses, (list, tuple)) and response.status_code not in {
        int(s) for s in statuses
    }:
        return False
    body_contains = rules.get("body_contains")
    if isinstance(body_contains, str) and body_contains:
        if body_contains.encode("latin-1") not in body:
            return False
    header_contains = rules.get("header_contains")
    if isinstance(header_contains, dict):
        for name, needle in header_contains.items():
            value = response.header(str(name)) or ""
            if str(needle).lower() not in value.lower():
                return False
    cookie_present = rules.get("cookie_present")
    if isinstance(cookie_present, str) and cookie_present:
        if cookie_present not in parse_set_cookies(response):
            return False
    return True


class MacroRunner:
    """Replays a session macro to establish an authenticated cookie jar."""

    def __init__(self, gate: ForwardGate, sender: HttpSender) -> None:
        self._gate = gate
        self._sender = sender

    def establish(
        self,
        steps: Sequence[MacroStep],
        match_rules: dict[str, Any] | None,
        resolver: SecretResolver,
    ) -> EstablishedSession:
        """Replay ``steps`` in order, carrying cookies, and judge auth success."""
        if not steps:
            raise MacroError("macro has no steps")
        jar: dict[str, str] = {}
        last_response: NormalizedResponse | None = None
        last_body = b""
        steps_run = 0

        for step in steps:
            raw = _substitute_secrets(step.raw_request, step.secret_refs, resolver)
            if jar:
                raw = inject_cookie_header(raw, cookie_header_value(jar))
            try:
                request = NormalizedRequest.parse(raw)
            except HttpMessageError as exc:
                raise MacroError("macro step produced a malformed request") from exc

            decision = self._gate.evaluate(request)
            if not decision.allowed:
                return EstablishedSession(
                    cookies=jar,
                    authenticated=False,
                    steps_run=steps_run,
                    blocked=True,
                    block_reason=decision.reason,
                )

            body = RawHttpMessage.from_bytes(raw).body
            raw_response = self._sender.send(request, body).raw
            response = NormalizedResponse.parse(raw_response)
            jar.update(parse_set_cookies(response))
            last_response = response
            last_body = RawHttpMessage.from_bytes(raw_response).body
            steps_run += 1

        authenticated = (
            _matches(last_response, last_body, match_rules) if last_response is not None else False
        )
        return EstablishedSession(
            cookies=jar,
            authenticated=authenticated,
            steps_run=steps_run,
            blocked=False,
        )


__all__ = [
    "EstablishedSession",
    "MacroError",
    "MacroRunner",
    "MacroStep",
    "SecretResolver",
    "parse_steps",
]
