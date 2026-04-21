"""Unit tests for :mod:`src.oast.listener_protocol` (ARG-007).

Covers the deterministic in-process :class:`FakeOASTListener` and the
:class:`BurpCollaboratorClientStub` placeholder.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from src.oast.correlator import (
    InteractionKind,
    OASTCorrelator,
)
from src.oast.listener_protocol import (
    BurpCollaboratorClientStub,
    FakeOASTListener,
    OASTListenerProtocol,
)
from src.oast.provisioner import InternalOASTProvisioner


_TENANT = UUID("11111111-1111-1111-1111-111111111111")
_SCAN = UUID("22222222-2222-2222-2222-222222222222")


class TestFakeOASTListener:
    def test_satisfies_protocol(self, listener: FakeOASTListener) -> None:
        assert isinstance(listener, OASTListenerProtocol)

    def test_register_unregister_round_trip(
        self,
        listener: FakeOASTListener,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        listener.register(token)
        assert listener.is_registered(token.id) is True
        listener.unregister(token.id)
        assert listener.is_registered(token.id) is False

    def test_emit_dns_query_pushes_to_correlator(
        self,
        listener: FakeOASTListener,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        listener.register(token)
        interaction = listener.emit_dns_query(token)
        assert interaction.kind is InteractionKind.DNS_A
        observed = correlator.list_interactions(token.id)
        assert len(observed) == 1
        assert observed[0].metadata["qname"] == token.subdomain

    def test_emit_dns_query_rejects_non_dns_kind(
        self,
        listener: FakeOASTListener,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        listener.register(token)
        with pytest.raises(ValueError):
            listener.emit_dns_query(token, kind=InteractionKind.HTTP_REQUEST)

    def test_emit_http_request_uses_https_kind_by_default(
        self,
        listener: FakeOASTListener,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        listener.register(token)
        interaction = listener.emit_http_request(token)
        assert interaction.kind is InteractionKind.HTTPS_REQUEST
        # Path defaults to /p/<token>; method defaults to GET
        assert interaction.metadata["method"] == "GET"
        assert interaction.metadata["scheme"] == "https"

    def test_emit_http_request_validates_scheme(
        self,
        listener: FakeOASTListener,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        listener.register(token)
        with pytest.raises(ValueError):
            listener.emit_http_request(token, scheme="ftp")

    def test_emit_http_request_with_custom_user_agent(
        self,
        listener: FakeOASTListener,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        listener.register(token)
        interaction = listener.emit_http_request(token, user_agent="argus-test-bot/1.0")
        assert interaction.metadata["user_agent"] == "argus-test-bot/1.0"

    def test_emit_smtp_rcpt_records_envelope(
        self,
        listener: FakeOASTListener,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        listener.register(token)
        interaction = listener.emit_smtp_rcpt(token)
        assert interaction.kind is InteractionKind.SMTP_RCPT
        assert interaction.metadata["envelope_from"] == "scanner@example.com"
        assert "@" in interaction.metadata["rcpt_to"]
        observed = correlator.list_interactions(token.id)
        assert len(observed) == 1


class TestBurpCollaboratorClientStub:
    def test_poll_raises_not_implemented(self) -> None:
        client = BurpCollaboratorClientStub(biid="test-biid")
        with pytest.raises(NotImplementedError):
            client.poll()

    def test_register_raises_not_implemented(
        self,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        client = BurpCollaboratorClientStub()
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        with pytest.raises(NotImplementedError):
            client.register(token)

    def test_unregister_raises_not_implemented(self) -> None:
        client = BurpCollaboratorClientStub()
        with pytest.raises(NotImplementedError):
            client.unregister(uuid4())
