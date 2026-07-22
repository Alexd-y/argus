"""Concrete httpx-backed :class:`HttpSender` for the Repeater (WB-P3b-2).

This performs the real, infra-gated upstream send for a replay that has already
passed the mandatory :class:`~src.web_workbench.proxy.forward_gate.ForwardGate`
(scope + preflight) inside :class:`RepeaterService`. It is *never* reached for a
blocked replay, so egress only ever targets an in-scope host.

Security / robustness invariants:

* **Bounded response** — the body is streamed and read up to a hard cap; larger
  responses are truncated (``truncated`` recorded) rather than buffered without
  bound ("no unbounded in-memory bodies").
* **No implicit redirects** — the operator inspects the single response
  (``follow_redirects=False``); a redirect is a response, not a new request.
* **Hop-by-hop headers stripped** — connection-management headers that httpx
  must own are dropped; ``Content-Length`` is recomputed by httpx from the body.
* TLS verification is opt-in (``verify``); it defaults to *off* because
  authorized in-scope pentest targets routinely present invalid certificates —
  this is intentional and scope-gated, not a fail-open on an arbitrary host.
"""

from __future__ import annotations

import time

import httpx

from src.web_workbench.proxy.transport import NormalizedRequest
from src.web_workbench.repeater.engine import RawResponse

#: Default hard cap on the response bytes read into memory (5 MiB).
DEFAULT_MAX_RESPONSE_BYTES: int = 5 * 1024 * 1024
#: Default overall request timeout (seconds).
DEFAULT_TIMEOUT_SECONDS: float = 30.0

#: Headers httpx must own; forwarding them verbatim corrupts the send.
_HOP_BY_HOP = frozenset({"host", "content-length", "transfer-encoding", "connection", "keep-alive"})


class HttpxSender:
    """Sends an allowed replay upstream via httpx and captures the raw response.

    A caller may inject a preconfigured :class:`httpx.Client` (e.g. one built on
    ``httpx.MockTransport`` for offline tests); otherwise a client is created per
    send with the configured timeout / TLS verification.
    """

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        verify: bool = False,
    ) -> None:
        if max_response_bytes < 0:
            raise ValueError("max_response_bytes must be non-negative")
        self._client = client
        self._timeout = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._verify = verify

    def _forward_headers(self, request: NormalizedRequest) -> list[tuple[str, str]]:
        return [(name, value) for name, value in request.headers if name.lower() not in _HOP_BY_HOP]

    def send(self, request: NormalizedRequest, body: bytes) -> RawResponse:
        target, _port = request.to_target_spec()
        url = target.url
        assert url is not None  # to_target_spec always yields a URL-kind spec
        headers = self._forward_headers(request)

        client = self._client
        owns_client = client is None
        if client is None:
            client = httpx.Client(timeout=self._timeout, verify=self._verify)

        started = time.monotonic()
        try:
            with client.stream(
                request.method,
                url,
                headers=headers,
                content=body,
                follow_redirects=False,
            ) as response:
                raw_body, truncated = self._read_bounded(response)
                raw = self._serialize(response, raw_body)
                duration_ms = int((time.monotonic() - started) * 1000)
                return RawResponse(
                    status_code=response.status_code,
                    raw=raw,
                    duration_ms=duration_ms,
                    truncated=truncated,
                )
        finally:
            if owns_client:
                client.close()

    def _read_bounded(self, response: httpx.Response) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        for chunk in response.iter_bytes():
            remaining = self._max_response_bytes - total
            if len(chunk) >= remaining:
                chunks.append(chunk[:remaining])
                total += remaining
                truncated = len(chunk) > remaining or total >= self._max_response_bytes
                if truncated:
                    break
            else:
                chunks.append(chunk)
                total += len(chunk)
        return b"".join(chunks), truncated

    @staticmethod
    def _serialize(response: httpx.Response, body: bytes) -> bytes:
        version = response.http_version or "HTTP/1.1"
        reason = response.reason_phrase or ""
        status_line = f"{version} {response.status_code} {reason}".rstrip()
        lines = [status_line]
        lines.extend(f"{name}: {value}" for name, value in response.headers.multi_items())
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        return head + body


__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "HttpxSender",
]
