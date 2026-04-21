"""Unit tests for :mod:`src.policy.ownership`.

Covers challenge issuance, the in-memory store, dry-run mode, the closed
failure taxonomy, URL / DNS host extraction helpers, and verification
paths via mocked ``httpx`` / ``dns.asyncresolver`` so the test suite never
touches a real network or DNS resolver.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

from src.policy.audit import AuditEventType, AuditLogger, InMemoryAuditSink
from src.policy.ownership import (
    OWNERSHIP_FAILURE_REASONS,
    InMemoryOwnershipProofStore,
    OwnershipChallenge,
    OwnershipMethod,
    OwnershipProof,
    OwnershipVerificationError,
    OwnershipVerifier,
    _build_http_url,
    _constant_time_equals,
    _extract_dns_host,
)


# ---------------------------------------------------------------------------
# OwnershipChallenge / OwnershipProof model contracts
# ---------------------------------------------------------------------------


class TestOwnershipModels:
    def test_challenge_token_must_be_43_chars(self, tenant_id: UUID) -> None:
        now = datetime.now(tz=timezone.utc)
        with pytest.raises(ValidationError):
            OwnershipChallenge(
                tenant_id=tenant_id,
                target="example.com",
                method=OwnershipMethod.DNS_TXT,
                token="too-short",
                expires_at=now + timedelta(hours=1),
            )

    def test_challenge_naive_datetime_rejected(self, tenant_id: UUID) -> None:
        with pytest.raises(ValidationError):
            OwnershipChallenge(
                tenant_id=tenant_id,
                target="example.com",
                method=OwnershipMethod.DNS_TXT,
                token="A" * 43,
                issued_at=datetime(2026, 4, 17, 12, 0, 0),
                expires_at=datetime(2026, 4, 17, 13, 0, 0),
            )

    def test_proof_extra_fields_forbidden(self, tenant_id: UUID) -> None:
        now = datetime.now(tz=timezone.utc)
        with pytest.raises(ValidationError):
            OwnershipProof.model_validate(
                {
                    "challenge_id": "00000000-0000-0000-0000-000000000000",
                    "tenant_id": str(tenant_id),
                    "target": "example.com",
                    "method": "dns_txt",
                    "verified_at": now.isoformat(),
                    "valid_until": (now + timedelta(hours=1)).isoformat(),
                    "extra": "nope",
                }
            )


# ---------------------------------------------------------------------------
# Challenge issuance
# ---------------------------------------------------------------------------


class TestIssueChallenge:
    def test_token_is_43_chars(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.DNS_TXT,
        )
        assert len(challenge.token) == 43
        assert "=" not in challenge.token

    def test_default_ttl_is_long(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.HTTP_HEADER,
        )
        delta = challenge.expires_at - challenge.issued_at
        assert delta >= timedelta(hours=24)

    def test_blank_target_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        with pytest.raises(ValueError):
            verifier.issue_challenge(
                tenant_id=tenant_id,
                target="   ",
                method=OwnershipMethod.HTTP_HEADER,
            )

    def test_zero_ttl_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        with pytest.raises(ValueError):
            verifier.issue_challenge(
                tenant_id=tenant_id,
                target="example.com",
                method=OwnershipMethod.HTTP_HEADER,
                ttl=timedelta(0),
            )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"dns_timeout_s": 0},
            {"dns_timeout_s": 61},
            {"http_timeout_s": 0},
            {"http_timeout_s": 61},
        ],
    )
    def test_constructor_validates_timeouts(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        kwargs: dict[str, Any],
    ) -> None:
        with pytest.raises(ValueError):
            OwnershipVerifier(
                store=ownership_store, audit_logger=audit_logger, **kwargs
            )


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


class TestDryRun:
    def test_dry_run_records_proof_and_skips_network(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_sink: InMemoryAuditSink,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(
            store=ownership_store, audit_logger=audit_logger, dry_run=True
        )
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.DNS_TXT,
        )
        proof = asyncio.run(verifier.verify(challenge))
        assert proof.notes == "dry-run"
        assert ownership_store.get(tenant_id=tenant_id, target="example.com") == proof
        events = list(audit_sink.iter_events(tenant_id=tenant_id))
        assert len(events) == 1
        assert events[0].event_type is AuditEventType.OWNERSHIP_VERIFY
        assert events[0].decision_allowed is True


# ---------------------------------------------------------------------------
# Expired challenge short-circuits
# ---------------------------------------------------------------------------


class TestExpiry:
    def test_expired_challenge_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        # Build an *already-expired* challenge directly without going
        # through ``issue_challenge`` so the test is deterministic.
        now = datetime.now(tz=timezone.utc)
        challenge = OwnershipChallenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.HTTP_HEADER,
            token="A" * 43,
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(seconds=1),
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier.verify(challenge))
        assert exc_info.value.summary == "ownership_proof_expired"


# ---------------------------------------------------------------------------
# HTTP header verification
# ---------------------------------------------------------------------------


def _stub_http_client(response: httpx.Response | Exception) -> httpx.AsyncClient:
    """Build an ``httpx.AsyncClient`` whose ``get`` returns ``response``."""
    client = MagicMock(spec=httpx.AsyncClient)
    if isinstance(response, Exception):
        client.get = AsyncMock(side_effect=response)
    else:
        client.get = AsyncMock(return_value=response)
    client.aclose = AsyncMock()
    return client


def _make_response(
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: str = "",
) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        headers=headers or {},
        content=body.encode("utf-8"),
        request=httpx.Request("GET", "https://example.com/"),
    )


class TestHttpHeader:
    def test_header_match_grants_proof(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.HTTP_HEADER,
        )
        response = _make_response(headers={"X-Argus-Ownership": challenge.token})
        client = _stub_http_client(response)
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        proof = asyncio.run(verifier_with_client.verify(challenge))
        assert proof.method is OwnershipMethod.HTTP_HEADER
        assert proof.tenant_id == tenant_id

    def test_missing_header_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.HTTP_HEADER,
        )
        response = _make_response()
        client = _stub_http_client(response)
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier_with_client.verify(challenge))
        assert exc_info.value.summary == "ownership_header_missing"

    def test_wrong_token_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.HTTP_HEADER,
        )
        response = _make_response(headers={"X-Argus-Ownership": "B" * 43})
        client = _stub_http_client(response)
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier_with_client.verify(challenge))
        assert exc_info.value.summary == "ownership_token_mismatch"

    def test_4xx_status_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.HTTP_HEADER,
        )
        response = _make_response(status=503)
        client = _stub_http_client(response)
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier_with_client.verify(challenge))
        assert exc_info.value.summary == "ownership_http_status"

    def test_timeout_propagates_taxonomy(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.HTTP_HEADER,
        )
        client = _stub_http_client(httpx.ReadTimeout("slow"))
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier_with_client.verify(challenge))
        assert exc_info.value.summary == "ownership_http_timeout"

    def test_generic_http_error_maps_to_taxonomy(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.HTTP_HEADER,
        )
        client = _stub_http_client(httpx.ConnectError("refused"))
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier_with_client.verify(challenge))
        assert exc_info.value.summary == "ownership_http_error"


# ---------------------------------------------------------------------------
# Webroot verification
# ---------------------------------------------------------------------------


class TestWebroot:
    def test_token_in_body_grants(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.WEBROOT,
        )
        response = _make_response(body=challenge.token + "\n")
        client = _stub_http_client(response)
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        proof = asyncio.run(verifier_with_client.verify(challenge))
        assert proof.method is OwnershipMethod.WEBROOT

    def test_non_200_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.WEBROOT,
        )
        response = _make_response(status=404)
        client = _stub_http_client(response)
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier_with_client.verify(challenge))
        assert exc_info.value.summary == "ownership_http_status"

    def test_wrong_body_token_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.WEBROOT,
        )
        response = _make_response(body="other-token-entirely")
        client = _stub_http_client(response)
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier_with_client.verify(challenge))
        assert exc_info.value.summary == "ownership_token_mismatch"

    def test_timeout_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.WEBROOT,
        )
        client = _stub_http_client(httpx.ReadTimeout("slow"))
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier_with_client.verify(challenge))
        assert exc_info.value.summary == "ownership_http_timeout"

    def test_generic_http_error_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.WEBROOT,
        )
        client = _stub_http_client(httpx.ConnectError("refused"))
        verifier_with_client = OwnershipVerifier(
            store=ownership_store,
            audit_logger=audit_logger,
            http_client=client,
        )
        with pytest.raises(OwnershipVerificationError) as exc_info:
            asyncio.run(verifier_with_client.verify(challenge))
        assert exc_info.value.summary == "ownership_http_error"


# ---------------------------------------------------------------------------
# DNS verification (lazily mocked)
# ---------------------------------------------------------------------------


class TestDnsTxt:
    def test_token_match_grants(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.DNS_TXT,
        )
        with patch.object(
            verifier, "_resolve_dns", new=AsyncMock(return_value=[challenge.token])
        ):
            proof = asyncio.run(verifier.verify(challenge))
        assert proof.method is OwnershipMethod.DNS_TXT

    def test_no_matching_record_rejected(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.DNS_TXT,
        )
        with patch.object(
            verifier, "_resolve_dns", new=AsyncMock(return_value=["unrelated"])
        ):
            with pytest.raises(OwnershipVerificationError) as exc_info:
                asyncio.run(verifier.verify(challenge))
        assert exc_info.value.summary == "ownership_token_mismatch"

    def test_dns_timeout_maps_to_taxonomy(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.DNS_TXT,
        )
        with patch.object(
            verifier,
            "_resolve_dns",
            new=AsyncMock(
                side_effect=OwnershipVerificationError("ownership_dns_timeout")
            ),
        ):
            with pytest.raises(OwnershipVerificationError) as exc_info:
                asyncio.run(verifier.verify(challenge))
        assert exc_info.value.summary == "ownership_dns_timeout"

    def test_dns_nxdomain_maps_to_taxonomy(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.DNS_TXT,
        )
        with patch.object(
            verifier,
            "_resolve_dns",
            new=AsyncMock(
                side_effect=OwnershipVerificationError("ownership_dns_nxdomain")
            ),
        ):
            with pytest.raises(OwnershipVerificationError) as exc_info:
                asyncio.run(verifier.verify(challenge))
        assert exc_info.value.summary == "ownership_dns_nxdomain"

    def test_dns_generic_error_maps_to_taxonomy(
        self,
        ownership_store: InMemoryOwnershipProofStore,
        audit_logger: AuditLogger,
        tenant_id: UUID,
    ) -> None:
        verifier = OwnershipVerifier(store=ownership_store, audit_logger=audit_logger)
        challenge = verifier.issue_challenge(
            tenant_id=tenant_id,
            target="example.com",
            method=OwnershipMethod.DNS_TXT,
        )
        with patch.object(
            verifier,
            "_resolve_dns",
            new=AsyncMock(
                side_effect=OwnershipVerificationError("ownership_dns_error")
            ),
        ):
            with pytest.raises(OwnershipVerificationError) as exc_info:
                asyncio.run(verifier.verify(challenge))
        assert exc_info.value.summary == "ownership_dns_error"


# ---------------------------------------------------------------------------
# In-memory proof store
# ---------------------------------------------------------------------------


class TestInMemoryStore:
    def test_save_and_get_round_trip(self, tenant_id: UUID) -> None:
        store = InMemoryOwnershipProofStore()
        now = datetime.now(tz=timezone.utc)
        proof = OwnershipProof(
            challenge_id=UUID("00000000-0000-0000-0000-000000000001"),
            tenant_id=tenant_id,
            target="Example.com",
            method=OwnershipMethod.HTTP_HEADER,
            valid_until=now + timedelta(hours=1),
        )
        store.save(proof)
        # Lookup is case-insensitive (stores normalise to lowercase).
        assert store.get(tenant_id=tenant_id, target="EXAMPLE.com") == proof

    def test_get_returns_none_when_missing(self, tenant_id: UUID) -> None:
        store = InMemoryOwnershipProofStore()
        assert store.get(tenant_id=tenant_id, target="anything") is None


# ---------------------------------------------------------------------------
# URL / DNS helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    @pytest.mark.parametrize(
        ("target", "expected"),
        [
            ("https://example.com/path", "example.com"),
            ("api.example.com", "api.example.com"),
            ("api.example.com:8080", "api.example.com"),
            ("api.example.com/sub", "api.example.com"),
        ],
    )
    def test_extract_dns_host(self, target: str, expected: str) -> None:
        assert _extract_dns_host(target) == expected

    def test_extract_dns_host_blank_rejected(self) -> None:
        with pytest.raises(OwnershipVerificationError):
            _extract_dns_host("")

    def test_build_http_url_upgrades_bare_host(self) -> None:
        url = _build_http_url("example.com")
        assert url.startswith("https://example.com")

    def test_build_http_url_preserves_scheme(self) -> None:
        url = _build_http_url("http://example.com/some/path")
        assert url.startswith("http://example.com/")

    def test_build_http_url_path_override(self) -> None:
        url = _build_http_url(
            "https://example.com/old", path="/.well-known/argus-ownership.txt"
        )
        assert url.endswith("/.well-known/argus-ownership.txt")

    def test_constant_time_equals_equal(self) -> None:
        assert _constant_time_equals("abc", "abc") is True

    def test_constant_time_equals_unequal(self) -> None:
        assert _constant_time_equals("abc", "abd") is False

    def test_failure_taxonomy_is_closed(self) -> None:
        for summary in OWNERSHIP_FAILURE_REASONS:
            assert isinstance(summary, str)
            assert summary.startswith("ownership_")
