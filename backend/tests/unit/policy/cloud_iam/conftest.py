"""Shared fixtures for the cloud_iam ownership unit tests (ARG-043)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.policy.ownership import (
    OwnershipChallenge,
    OwnershipMethod,
)


@pytest.fixture()
def cloud_audit_sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture()
def cloud_audit_logger(cloud_audit_sink: InMemoryAuditSink) -> AuditLogger:
    return AuditLogger(cloud_audit_sink)


@pytest.fixture()
def aws_challenge_token() -> str:
    """43-char URL-safe token (matches OwnershipChallenge.token contract)."""
    return "AwsExternalIdAwsExternalIdAwsExternalIdAwsa"


@pytest.fixture()
def gcp_challenge_token() -> str:
    """43-char URL-safe token embedded as ``argus_token`` in the JWT."""
    return "GcpArgusTokenGcpArgusTokenGcpArgusTokenGcpA"


@pytest.fixture()
def azure_challenge_token() -> str:
    """43-char client-request-id ARGUS includes in the IMDS exchange."""
    return "AzureClientReqIdAzureClientReqIdAzureClient"


def make_challenge(
    *,
    method: OwnershipMethod,
    target: str,
    token: str,
    tenant_id: UUID | None = None,
    issued_at: datetime | None = None,
    ttl: timedelta = timedelta(hours=1),
) -> OwnershipChallenge:
    issued = issued_at or datetime.now(tz=timezone.utc)
    return OwnershipChallenge(
        challenge_id=uuid4(),
        tenant_id=tenant_id or UUID("11111111-1111-4111-8111-111111111111"),
        target=target,
        method=method,
        token=token,
        issued_at=issued,
        expires_at=issued + ttl,
    )
