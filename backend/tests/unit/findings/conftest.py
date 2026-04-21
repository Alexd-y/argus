"""Shared fixtures for ``tests/unit/findings``.

Exposes:

* :func:`make_finding` — minimal but valid :class:`FindingDTO` builder used
  across prioritizer / correlator tests.
* :class:`FakeRedis` — synchronous stand-in for the production Redis client.
* :class:`FakeHttpResponse` / :class:`FakeHttpClient` — implement
  :class:`HttpClientProtocol` so EPSS / KEV tests run without network I/O.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

import pytest

from src.findings.epss_client import HttpClientProtocol, HttpResponse, RedisLike
from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    SSVCDecision,
)


# ---------------------------------------------------------------------------
# FindingDTO builder
# ---------------------------------------------------------------------------


@pytest.fixture
def make_finding() -> Callable[..., FindingDTO]:
    """Return a builder that emits a valid :class:`FindingDTO`."""

    def _factory(
        *,
        finding_id: UUID | None = None,
        tenant_id: UUID | None = None,
        scan_id: UUID | None = None,
        asset_id: UUID | None = None,
        tool_run_id: UUID | None = None,
        category: FindingCategory = FindingCategory.INFO,
        cwe: list[int] | None = None,
        cvss_v3_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cvss_v3_score: float = 0.0,
        epss_score: float | None = None,
        kev_listed: bool = False,
        ssvc_decision: SSVCDecision = SSVCDecision.TRACK,
        confidence: ConfidenceLevel = ConfidenceLevel.SUSPECTED,
        status: FindingStatus = FindingStatus.NEW,
        mitre_attack: list[str] | None = None,
    ) -> FindingDTO:
        return FindingDTO(
            id=finding_id or uuid4(),
            tenant_id=tenant_id or uuid4(),
            scan_id=scan_id or uuid4(),
            asset_id=asset_id or uuid4(),
            tool_run_id=tool_run_id or uuid4(),
            category=category,
            cwe=cwe if cwe is not None else [200],
            cvss_v3_vector=cvss_v3_vector,
            cvss_v3_score=cvss_v3_score,
            epss_score=epss_score,
            kev_listed=kev_listed,
            ssvc_decision=ssvc_decision,
            confidence=confidence,
            status=status,
            mitre_attack=mitre_attack or [],
        )

    return _factory


# ---------------------------------------------------------------------------
# Fake Redis
# ---------------------------------------------------------------------------


@dataclass
class FakeRedis:
    """In-memory Redis stand-in honouring :class:`RedisLike`."""

    store: dict[str, str] = field(default_factory=dict)
    raise_on_get: bool = False
    raise_on_set: bool = False

    def get(self, key: str) -> str | None:
        if self.raise_on_get:
            raise RuntimeError("simulated redis failure")
        return self.store.get(key)

    def setex(self, key: str, seconds: int, value: str) -> None:
        if self.raise_on_set:
            raise RuntimeError("simulated redis failure")
        if seconds <= 0:
            raise ValueError("ttl must be positive")
        self.store[key] = value


@pytest.fixture
def fake_redis() -> FakeRedis:
    """Empty :class:`FakeRedis` instance."""
    return FakeRedis()


# Type-check the duck-typed FakeRedis at fixture import time so a regression in
# the protocol (e.g. renaming ``setex``) breaks the test boot, not random tests.
def _typecheck_fake_redis() -> RedisLike:
    return FakeRedis()


_typecheck_fake_redis()


# ---------------------------------------------------------------------------
# Fake HTTP
# ---------------------------------------------------------------------------


@dataclass
class FakeHttpResponse:
    """Minimal :class:`HttpResponse` implementation for tests."""

    status_code: int = 200
    json_payload: object = field(default_factory=dict)
    text_body: str = ""
    raise_on_json: bool = False
    headers: dict[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        if self.raise_on_json:
            raise ValueError("invalid JSON")
        return self.json_payload

    @property
    def text(self) -> str:
        return self.text_body


@dataclass
class FakeHttpClient:
    """:class:`HttpClientProtocol` that returns scripted responses."""

    response: FakeHttpResponse | None = None
    responses: list[FakeHttpResponse] = field(default_factory=list)
    calls: list[tuple[str, float]] = field(default_factory=list)
    headers_calls: list[dict[str, str]] = field(default_factory=list)
    raise_exception: type[BaseException] | None = None

    async def get(
        self,
        url: str,
        *,
        timeout: float,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        self.calls.append((url, timeout))
        self.headers_calls.append(dict(headers or {}))
        if self.raise_exception is not None:
            raise self.raise_exception("simulated http failure")
        if self.responses:
            return self.responses.pop(0)
        if self.response is not None:
            return self.response
        raise RuntimeError("no scripted response")


@pytest.fixture
def fake_http() -> FakeHttpClient:
    """Empty :class:`FakeHttpClient`."""
    return FakeHttpClient()


def _typecheck_fake_http() -> HttpClientProtocol:
    return FakeHttpClient()


_typecheck_fake_http()
