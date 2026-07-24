"""Live intercepting-proxy daemon — mitmproxy addon (WB-P2b-2).

The infra-gated MITM daemon that ties the offline proxy primitives (WB-P2a) to a
real interception loop. Every flow is subjected to the mandatory, fail-closed
:class:`~src.web_workbench.proxy.forward_gate.ForwardGate` (scope, then the
optional preflight hook) BEFORE it is forwarded upstream (SI-WB-1); an
out-of-scope flow is answered with a synthetic 403 and never leaves the box.
Interception ergonomics (hold / pass / drop) are a separate, non-security gate
via :class:`~src.web_workbench.proxy.intercept_rules.InterceptRuleSet`.

Design for testability and safe optional-dependency handling:

* The **security + capture core** (:class:`ProxyFlowProcessor`) is pure and has
  no mitmproxy dependency, so the gate/intercept/capture behaviour is unit
  tested offline (``httpx``/fixtures) exactly like the Repeater.
* ``mitmproxy`` is an optional dependency (the ``web-proxy`` image/profile). It
  is imported guarded at module load so importing this module never fails when
  mitmproxy is absent; the addon + :func:`main` raise a clear error if invoked
  without it.
* The per-listener MITM **CA** (sealed at rest, WB-P2b-1) is unsealed once at
  boot and handed to mitmproxy's certstore, which mints per-host leaves from it
  — reusing our CA private key without duplicating TLS leaf logic. The private
  key is written only to the daemon's private confdir and never logged.

Bodies are bounded on capture ("no unbounded in-memory bodies"): each direction
is read up to a hard cap before persistence spills/inlines/drops it.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from src.web_workbench.proxy.forward_gate import (
    REASON_OUT_OF_SCOPE,
    ForwardDecision,
    ForwardGate,
    ForwardOutcome,
)
from src.web_workbench.proxy.intercept_rules import InterceptAction, InterceptRuleSet
from src.web_workbench.proxy.repository import CaptureInput
from src.web_workbench.proxy.transport import (
    DEFAULT_MAX_CAPTURE_BYTES,
    HttpMessageError,
    NormalizedRequest,
    NormalizedResponse,
)

try:  # optional dependency — only present in the web-proxy image/profile.
    from mitmproxy import http as _mitm_http  # type: ignore[import-not-found]

    _MITMPROXY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only where mitmproxy is absent
    _mitm_http = None
    _MITMPROXY_AVAILABLE = False

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mitmproxy import http

logger = logging.getLogger(__name__)

_SOURCE_PROXY = "proxy"


@dataclass(frozen=True)
class ProxyIdentity:
    """The tenant/project/listener a running proxy instance serves."""

    tenant_id: str
    project_id: str
    listener_id: str | None = None


class TrafficSink(Protocol):
    """Persists a captured flow. Implemented by the repository-backed sink."""

    async def record(self, capture: CaptureInput) -> None: ...


class ProxyFlowProcessor:
    """Pure security + capture core for a single proxy instance (no mitmproxy).

    Holds the mandatory forward gate, the (non-security) intercept rule set, and
    the traffic sink. The mitmproxy addon is a thin adapter over this class; all
    gate/intercept/capture decisions are made here and are unit-testable offline.
    """

    def __init__(
        self,
        gate: ForwardGate,
        *,
        identity: ProxyIdentity,
        sink: TrafficSink,
        intercept_rules: InterceptRuleSet | None = None,
        intercept_enabled: bool = False,
        max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    ) -> None:
        if max_capture_bytes < 0:
            raise ValueError("max_capture_bytes must be non-negative")
        self._gate = gate
        self._identity = identity
        self._sink = sink
        self._rules = intercept_rules
        self._intercept_enabled = intercept_enabled
        self._max_capture = max_capture_bytes

    @property
    def max_capture_bytes(self) -> int:
        return self._max_capture

    def evaluate(self, request: NormalizedRequest) -> ForwardDecision:
        """Run the mandatory forward gate for ``request``."""
        return self._gate.evaluate(request)

    def intercept_action(self, request: NormalizedRequest) -> InterceptAction:
        """Return the (ergonomic, non-security) intercept action for ``request``."""
        if not self._intercept_enabled or self._rules is None:
            return InterceptAction.PASS
        return self._rules.decide(request)

    def build_capture(
        self,
        *,
        request: NormalizedRequest,
        decision: ForwardDecision,
        request_body: bytes | None,
        response: NormalizedResponse | None,
        response_body: bytes | None,
    ) -> CaptureInput:
        """Build the persistence payload for a (forwarded or blocked) flow.

        Raises :class:`HttpMessageError` if the request target cannot be resolved
        (an unresolvable target is never persisted as in-scope).
        """
        target, port = request.to_target_spec()
        url = target.url or ""
        scheme, _, rest = url.partition("://")
        authority, _, path_and_query = rest.partition("/")
        host = authority.split(":", 1)[0]
        path, _, query = ("/" + path_and_query).partition("?")
        in_scope = decision.reason != REASON_OUT_OF_SCOPE
        return CaptureInput(
            method=request.method,
            scheme=scheme or "https",
            host=host,
            port=port,
            path=path or "/",
            query=query or None,
            http_version=request.http_version,
            forward_outcome=str(decision.outcome.value),
            in_scope=in_scope,
            source=_SOURCE_PROXY,
            listener_id=self._identity.listener_id,
            status_code=response.status_code if response is not None else None,
            request_headers=request.headers,
            response_headers=response.headers if response is not None else None,
            request_body=request_body,
            response_body=response_body,
            request_content_type=request.header("Content-Type"),
            response_content_type=(
                response.header("Content-Type") if response is not None else None
            ),
            block_reason=decision.reason,
        )

    async def record(self, capture: CaptureInput) -> None:
        """Persist a built capture through the injected sink."""
        await self._sink.record(capture)


# ---------------------------------------------------------------------------
# mitmproxy addon (thin adapter — infra-gated, exercised in E2E, not unit tests)
# ---------------------------------------------------------------------------


class WorkbenchProxyAddon:
    """mitmproxy addon wiring flows through :class:`ProxyFlowProcessor`.

    On ``request`` the flow is gated: an out-of-scope / preflight-denied flow is
    answered with a synthetic 403 and its blocked outcome persisted immediately
    (the sender is never reached). An in-scope flow may be held for manual edit
    (intercept) or passed. On ``response`` the forwarded flow's bounded bodies
    are captured and persisted.
    """

    def __init__(self, processor: ProxyFlowProcessor) -> None:
        if not _MITMPROXY_AVAILABLE:  # pragma: no cover - guarded at construction
            raise RuntimeError("mitmproxy is not installed; the web-proxy image is required")
        self._processor = processor

    def _normalized(self, flow: "http.HTTPFlow") -> NormalizedRequest:  # pragma: no cover - e2e
        headers = tuple(
            (name.decode("latin-1"), value.decode("latin-1"))
            for name, value in flow.request.headers.fields
        )
        # Absolute target so the gate resolves the real scheme/host/port.
        return NormalizedRequest(
            method=flow.request.method,
            target=flow.request.url,
            http_version=flow.request.http_version,
            headers=headers,
        )

    async def request(self, flow: "http.HTTPFlow") -> None:  # pragma: no cover - e2e
        try:
            request = self._normalized(flow)
        except HttpMessageError:
            flow.response = _mitm_http.Response.make(400, b"malformed request")
            return

        decision = self._processor.evaluate(request)
        if not decision.allowed:
            # SI-WB-1: an out-of-scope/denied flow is never forwarded.
            flow.response = _mitm_http.Response.make(403, b"blocked by scope policy")
            capture = self._processor.build_capture(
                request=request,
                decision=decision,
                request_body=self._bounded(flow.request.raw_content),
                response=None,
                response_body=None,
            )
            await self._processor.record(capture)
            flow.metadata["wb_blocked"] = True
            return

        flow.metadata["wb_request"] = request
        if self._processor.intercept_action(request) is InterceptAction.DROP:
            flow.kill()
        elif self._processor.intercept_action(request) is InterceptAction.INTERCEPT:
            flow.intercept()

    async def response(self, flow: "http.HTTPFlow") -> None:  # pragma: no cover - e2e
        if flow.metadata.get("wb_blocked"):
            return
        request = flow.metadata.get("wb_request")
        if request is None or flow.response is None:
            return
        response = NormalizedResponse(
            http_version=flow.response.http_version,
            status_code=flow.response.status_code,
            reason=flow.response.reason or "",
            headers=tuple(
                (name.decode("latin-1"), value.decode("latin-1"))
                for name, value in flow.response.headers.fields
            ),
        )
        decision = ForwardDecision(outcome=ForwardOutcome.FORWARD, reason=None)
        capture = self._processor.build_capture(
            request=request,
            decision=decision,
            request_body=self._bounded(flow.request.raw_content),
            response=response,
            response_body=self._bounded(flow.response.raw_content),
        )
        await self._processor.record(capture)

    def _bounded(self, data: bytes | None) -> bytes | None:  # pragma: no cover - e2e
        if data is None:
            return None
        cap = self._processor.max_capture_bytes
        return data if len(data) <= cap else data[:cap]


# ---------------------------------------------------------------------------
# Repository-backed sink + daemon bootstrap (infra-gated)
# ---------------------------------------------------------------------------


class RepositoryTrafficSink:  # pragma: no cover - requires a live DB
    """Persists captures via :class:`~src.web_workbench.proxy.repository.ProxyRepository`.

    Each record opens its own tenant-scoped transaction (RLS via
    ``set_session_tenant``) so a slow persist never holds a connection across
    flows.
    """

    def __init__(
        self,
        repository,
        session_factory,
        *,
        identity: ProxyIdentity,
        object_store,
    ) -> None:
        self._repo = repository
        self._session_factory = session_factory
        self._identity = identity
        self._object_store = object_store

    async def record(self, capture: CaptureInput) -> None:
        # Deferred: importing src.db.session at module top builds a DB engine as
        # an import-time side effect, which would defeat offline import of the
        # pure ProxyFlowProcessor. This sink is infra-gated (needs a live DB).
        from src.db.session import set_session_tenant  # noqa: PLC0415

        async with self._session_factory() as session, session.begin():
            await set_session_tenant(session, self._identity.tenant_id)
            await self._repo.persist_message(
                session,
                self._identity.tenant_id,
                self._identity.project_id,
                capture,
                object_store=self._object_store,
            )


_DEFAULT_CONFDIR = "/tmp/argus-wb-proxy"
_MITM_CA_FILENAME = "mitmproxy-ca.pem"
_MITM_CA_CERT_FILENAME = "mitmproxy-ca-cert.pem"


def _require_env(name: str) -> str:  # pragma: no cover - bootstrap glue
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required environment variable {name} is not set")
    return value


def _resolve_listen_endpoint() -> tuple[str, int]:
    """Resolve the proxy bind host/port from env (pure; unit-tested).

    ``WB_PROXY_LISTEN_HOST`` (default ``0.0.0.0``) / ``WB_PROXY_LISTEN_PORT``
    (default ``8080``). Raises ``RuntimeError`` on an invalid port.
    """
    host = (os.environ.get("WB_PROXY_LISTEN_HOST") or "0.0.0.0").strip() or "0.0.0.0"
    raw = (os.environ.get("WB_PROXY_LISTEN_PORT") or "8080").strip()
    try:
        port = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"invalid WB_PROXY_LISTEN_PORT: {raw!r}") from exc
    if not (1 <= port <= 65535):
        raise RuntimeError(f"WB_PROXY_LISTEN_PORT out of range: {port}")
    return host, port


def _write_ca_material(
    confdir: str, *, private_key_pem: bytes, certificate_pem: bytes
) -> str:
    """Write the unsealed CA as ``mitmproxy-ca.pem`` so mitmproxy mints leaves
    from OUR per-listener CA instead of generating its own (pure filesystem;
    unit-tested).

    The private key lands only in the daemon's private confdir (dir ``0700``,
    file ``0600``) and is never logged. Returns the written bundle path.
    """
    os.makedirs(confdir, mode=0o700, exist_ok=True)
    try:
        os.chmod(confdir, 0o700)
    except OSError:  # pragma: no cover - platform-dependent (e.g. Windows)
        pass

    # mitmproxy's certstore reads a combined KEY-then-CERT PEM bundle.
    material = (
        private_key_pem.rstrip(b"\n") + b"\n" + certificate_pem.rstrip(b"\n") + b"\n"
    )
    bundle_path = os.path.join(confdir, _MITM_CA_FILENAME)
    fd = os.open(bundle_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, material)
    finally:
        os.close(fd)

    # Public cert only — safe to distribute to clients for trust import.
    with open(os.path.join(confdir, _MITM_CA_CERT_FILENAME), "wb") as fh:
        fh.write(certificate_pem)
    return bundle_path


async def _run() -> None:  # pragma: no cover - infra-gated (needs mitmproxy + live DB)
    """Async daemon body: load the listener's scope + sealed CA, then run mitmproxy."""
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster
    from sqlalchemy import select

    from src.db.models_web_workbench import WbProxyListener
    from src.db.session import create_task_engine_and_session, set_session_tenant
    from src.web_workbench.contracts.proxy import ProxyListenerStatus
    from src.web_workbench.projects.repository import WorkbenchProjectRepository
    from src.web_workbench.projects.service import ProjectScopeService
    from src.web_workbench.proxy.body_store import S3BodyObjectStore
    from src.web_workbench.proxy.ca_lifecycle import build_sealer_from_settings, load_ca
    from src.web_workbench.proxy.repository import ProxyRepository

    sealer = build_sealer_from_settings()
    if sealer is None:
        # Fail-closed: never run the MITM CA without a configured KEK.
        raise RuntimeError(
            "WB_CA_SEALING_KEY is not set; refusing to start the proxy (fail-closed)"
        )

    tenant_id = _require_env("DEFAULT_TENANT_ID")
    listener_id = (os.environ.get("WB_PROXY_LISTENER_ID") or "").strip() or None
    host, port = _resolve_listen_endpoint()
    confdir = (os.environ.get("WB_PROXY_CONFDIR") or _DEFAULT_CONFDIR).strip() or _DEFAULT_CONFDIR

    engine, session_factory = create_task_engine_and_session()
    try:
        async with session_factory() as session:
            await set_session_tenant(session, tenant_id)
            stmt = select(WbProxyListener).where(WbProxyListener.tenant_id == tenant_id)
            if listener_id:
                stmt = stmt.where(WbProxyListener.id == listener_id)
            else:
                stmt = stmt.where(
                    WbProxyListener.status == ProxyListenerStatus.ACTIVE.value,
                    WbProxyListener.ca_sealed_key.isnot(None),
                ).order_by(WbProxyListener.created_at, WbProxyListener.id)
            listener = (await session.execute(stmt)).scalars().first()
            if listener is None:
                raise RuntimeError(
                    "no active proxy listener with an issued CA found for tenant "
                    f"{tenant_id}; create + enable a listener and issue its CA via the API first"
                )
            if not listener.ca_cert_pem or not listener.ca_sealed_key:
                raise RuntimeError(
                    f"listener {listener.id} has no issued CA; issue one via the API first"
                )
            project = await WorkbenchProjectRepository().get(
                session, tenant_id, listener.project_id
            )
            if project is None:
                raise RuntimeError(
                    f"project {listener.project_id} not found for listener {listener.id}"
                )
            identity = ProxyIdentity(
                tenant_id=tenant_id,
                project_id=listener.project_id,
                listener_id=listener.id,
            )
            scope_rules = tuple(project.scope_rules)
            ca = load_ca(
                sealer,
                certificate_pem=listener.ca_cert_pem,
                sealed_key=listener.ca_sealed_key,
            )

        _write_ca_material(
            confdir,
            private_key_pem=ca.export_private_key_pem(),
            certificate_pem=ca.certificate_pem,
        )

        gate = ForwardGate(ProjectScopeService(scope_rules))
        sink = RepositoryTrafficSink(
            ProxyRepository(),
            session_factory,
            identity=identity,
            object_store=S3BodyObjectStore(),
        )
        # Interception (hold) needs the workbench UI to resume flows; a headless
        # daemon has no resume consumer, so run in capture+gate mode (no hold).
        processor = ProxyFlowProcessor(
            gate, identity=identity, sink=sink, intercept_enabled=False
        )

        logger.info(
            "wb_proxy_starting",
            extra={
                "event": "wb_proxy_starting",
                "listener_id": identity.listener_id,
                "project_id": identity.project_id,
                "listen_host": host,
                "listen_port": port,
                "scope_rule_count": len(scope_rules),
                "ca_fingerprint": ca.fingerprint_sha256,
            },
        )

        opts = Options(
            listen_host=host,
            listen_port=port,
            confdir=confdir,
            ssl_insecure=True,  # upstream cert validation off — this is an audit proxy
        )
        master = DumpMaster(opts, with_termlog=True, with_dumper=False)
        master.addons.add(WorkbenchProxyAddon(processor))
        await master.run()
    finally:
        await engine.dispose()


def main() -> None:  # pragma: no cover - infra-gated live entrypoint
    """Console entrypoint (``python -m src.web_workbench.proxy.service``).

    Bootstraps a mitmproxy ``DumpMaster`` with the workbench addon for a single
    persisted, CA-issued listener. Requires mitmproxy + a live DB + the CA
    sealing key (``WB_CA_SEALING_KEY``). End-to-end behaviour is covered by the
    E2E suite; the pure helpers (:func:`_resolve_listen_endpoint`,
    :func:`_write_ca_material`) and the processor/addon core are unit-tested.
    """
    if not _MITMPROXY_AVAILABLE:
        raise RuntimeError("mitmproxy is not installed; the web-proxy image is required")
    logging.basicConfig(
        level=(os.environ.get("LOG_LEVEL") or "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    main()


__all__ = [
    "ProxyFlowProcessor",
    "ProxyIdentity",
    "RepositoryTrafficSink",
    "TrafficSink",
    "WorkbenchProxyAddon",
    "main",
]
