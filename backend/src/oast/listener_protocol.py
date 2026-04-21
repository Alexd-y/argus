"""Listener protocols and a deterministic fake for unit/integration tests.

Production deployments host three independent OAST listeners:

* a DNS server (UDP / TCP, RFC 1035) that captures qname queries against
  the OAST base domain;
* an HTTPS reverse proxy that captures GET/POST hits against
  ``oast.argus.local/p/<path_token>``;
* an SMTP MX listener that captures RCPT TO lines for blind email-based
  callbacks (XXE, SSRF, password-reset oracle).

Each listener implementation MUST adhere to :class:`OASTListenerProtocol`
so the orchestrator can swap backends (in-cluster, Burp Collaborator,
interactsh) without touching the validator code path.

The :class:`FakeOASTListener` shipped here is the in-process backend used
by unit tests and the ``DRY_RUN`` sandbox. It implements the protocol with
a tiny bookkeeping dict and a thin queue wrapper so tests can simulate
listener traffic without spinning up real network sockets.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from src.oast.correlator import (
    InteractionKind,
    OASTCorrelator,
    OASTInteraction,
)
from src.oast.provisioner import OASTToken


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Listener protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class OASTListenerProtocol(Protocol):
    """Contract every OAST listener implementation must respect.

    Listeners are network endpoints in production but unit tests inject
    a deterministic fake (:class:`FakeOASTListener`) so we can drive the
    correlator without sockets. The protocol therefore deliberately
    omits any I/O lifecycle methods (``start``, ``stop``); those belong
    on concrete adapters, not the integration contract.
    """

    def register(self, token: OASTToken) -> None:
        """Notify the listener about a freshly issued ``token``.

        Listeners use this to pre-populate any internal lookup tables
        (e.g. a path-token → token-id index) so they can resolve incoming
        callbacks in O(1).
        """

    def unregister(self, token_id: UUID) -> None:
        """Forget ``token_id`` — called after revocation or expiry."""

    def deliver(self, interaction: OASTInteraction) -> None:
        """Forward ``interaction`` into the correlator pipeline.

        Production implementations push the interaction into an async
        queue so the network thread does not block on consumer logic;
        :class:`FakeOASTListener` performs the call synchronously.
        """


# ---------------------------------------------------------------------------
# Fake listener
# ---------------------------------------------------------------------------


class FakeOASTListener:
    """Deterministic in-process listener used by unit + integration tests.

    The fake holds a reference to a :class:`OASTCorrelator` and forwards
    every :meth:`deliver` straight into the correlator's ``ingest``. It
    is intentionally simple: the goal is to exercise the surrounding
    contracts (correlator, provisioner, canary fallback), not to mimic a
    full DNS/HTTPS listener.

    Tests can use the convenience helpers :meth:`emit_dns_query`,
    :meth:`emit_http_request`, and :meth:`emit_smtp_rcpt` to simulate
    incoming traffic against an issued token without crafting full
    :class:`OASTInteraction` instances by hand.
    """

    def __init__(
        self,
        correlator: OASTCorrelator,
        *,
        id_factory: Callable[[], UUID] | None = None,
    ) -> None:
        self._correlator = correlator
        self._registered: dict[UUID, OASTToken] = {}
        self._id_factory: Callable[[], UUID] = id_factory or uuid4
        self._lock = threading.Lock()

    # -- protocol surface ----------------------------------------------------

    def register(self, token: OASTToken) -> None:
        with self._lock:
            self._registered[token.id] = token

    def unregister(self, token_id: UUID) -> None:
        with self._lock:
            self._registered.pop(token_id, None)

    def deliver(self, interaction: OASTInteraction) -> None:
        self._correlator.ingest(interaction)

    # -- test helpers --------------------------------------------------------

    def is_registered(self, token_id: UUID) -> bool:
        with self._lock:
            return token_id in self._registered

    def registered_tokens(self) -> Iterable[OASTToken]:
        with self._lock:
            return list(self._registered.values())

    def emit_dns_query(
        self,
        token: OASTToken,
        *,
        kind: InteractionKind = InteractionKind.DNS_A,
        source_ip: str = "203.0.113.10",
        qname: str | None = None,
    ) -> OASTInteraction:
        """Simulate a DNS query against ``token`` and forward it."""
        if kind not in {
            InteractionKind.DNS_A,
            InteractionKind.DNS_AAAA,
            InteractionKind.DNS_TXT,
            InteractionKind.DNS_ANY,
        }:
            raise ValueError(f"kind {kind!r} is not a DNS interaction")
        qname_value = qname or token.subdomain
        raw_bytes = f"{kind.value}:{qname_value}".encode("utf-8")
        interaction = OASTInteraction.build(
            id=self._id_factory(),
            token_id=token.id,
            kind=kind,
            source_ip=source_ip,
            raw_request_bytes=raw_bytes,
            metadata={"qname": qname_value},
        )
        self.deliver(interaction)
        return interaction

    def emit_http_request(
        self,
        token: OASTToken,
        *,
        method: str = "GET",
        path: str | None = None,
        source_ip: str = "203.0.113.20",
        user_agent: str | None = None,
        scheme: str = "https",
    ) -> OASTInteraction:
        """Simulate an HTTP / HTTPS hit against ``token`` and forward it."""
        scheme_normalised = scheme.lower()
        if scheme_normalised not in {"http", "https"}:
            raise ValueError(f"scheme must be http or https (got {scheme!r})")
        kind = (
            InteractionKind.HTTPS_REQUEST
            if scheme_normalised == "https"
            else InteractionKind.HTTP_REQUEST
        )
        path_value = path or f"/p/{token.path_token}"
        method_normalised = method.upper()
        raw_bytes = f"{method_normalised} {path_value} HTTP/1.1".encode("utf-8")
        metadata = {
            "method": method_normalised,
            "path": path_value,
            "scheme": scheme_normalised,
        }
        if user_agent is not None:
            metadata["user_agent"] = user_agent
        interaction = OASTInteraction.build(
            id=self._id_factory(),
            token_id=token.id,
            kind=kind,
            source_ip=source_ip,
            raw_request_bytes=raw_bytes,
            metadata=metadata,
        )
        self.deliver(interaction)
        return interaction

    def emit_smtp_rcpt(
        self,
        token: OASTToken,
        *,
        envelope_from: str = "scanner@example.com",
        source_ip: str = "203.0.113.30",
    ) -> OASTInteraction:
        """Simulate an SMTP RCPT TO arriving for ``token``."""
        rcpt = f"argus@{token.subdomain}"
        raw_bytes = f"MAIL FROM:<{envelope_from}>\r\nRCPT TO:<{rcpt}>".encode("utf-8")
        interaction = OASTInteraction.build(
            id=self._id_factory(),
            token_id=token.id,
            kind=InteractionKind.SMTP_RCPT,
            source_ip=source_ip,
            raw_request_bytes=raw_bytes,
            metadata={
                "envelope_from": envelope_from,
                "rcpt_to": rcpt,
            },
        )
        self.deliver(interaction)
        return interaction


# ---------------------------------------------------------------------------
# Burp Collaborator client stub
# ---------------------------------------------------------------------------


class BurpCollaboratorClientStub:
    """Placeholder client matching the Burp Collaborator REST surface.

    The real client (out of scope for ARG-007) talks to the Collaborator
    REST API to poll for interactions. This stub documents the methods
    the orchestrator will eventually use and raises :class:`NotImplementedError`
    so any accidental call in production fails loudly.

    The stub still exposes the pollable contract because the listener
    protocol module is the canonical place for "everything that talks to
    an external OAST backend", and downstream code can depend on the
    type without importing the future implementation.
    """

    backend_name: str = "burp_collaborator"

    def __init__(
        self, *, biid: str | None = None, server_url: str | None = None
    ) -> None:
        # ``biid`` is the Collaborator authentication token; the real
        # client validates it before issuing requests. We accept it now so
        # the constructor signature stays stable when the implementation
        # lands.
        self._biid = biid
        self._server_url = server_url

    def poll(self, *, since_token: str | None = None) -> list[OASTInteraction]:
        """Fetch new interactions since ``since_token`` (Collaborator cursor)."""
        del since_token
        raise NotImplementedError(
            "Burp Collaborator polling is not implemented in this milestone; "
            "swap in the production client when the listener team ships it."
        )

    def register(self, token: OASTToken) -> None:
        del token
        raise NotImplementedError(
            "Burp Collaborator registration is not implemented in this milestone."
        )

    def unregister(self, token_id: UUID) -> None:
        del token_id
        raise NotImplementedError(
            "Burp Collaborator unregistration is not implemented in this milestone."
        )

    def deliver(self, interaction: OASTInteraction) -> None:
        del interaction
        raise NotImplementedError(
            "Burp Collaborator delivery is server-driven, not client-driven."
        )


__all__ = [
    "BurpCollaboratorClientStub",
    "FakeOASTListener",
    "OASTListenerProtocol",
]
