"""Unit tests for :mod:`src.findings.kev_client`."""

from __future__ import annotations

import json
import logging
from datetime import date

import pytest

from src.findings.kev_client import KevClient
from src.findings.kev_persistence import KevRecord
from tests.unit.findings.conftest import FakeHttpClient, FakeHttpResponse, FakeRedis


_SAMPLE_CATALOG: dict[str, object] = {
    "vulnerabilities": [
        {"cveID": "CVE-2024-1001"},
        {"cveID": "CVE-2024-1002"},
        {"cveID": "CVE-2023-9999"},
        {"cveID": "CVE-2025-0001"},
        {"cveID": "CVE-2024-2222"},
    ]
}


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_construction_rejects_non_positive_ttl(fake_http: FakeHttpClient) -> None:
    with pytest.raises(ValueError):
        KevClient(fake_http, ttl_seconds=0)


def test_construction_rejects_non_positive_timeout(fake_http: FakeHttpClient) -> None:
    with pytest.raises(ValueError):
        KevClient(fake_http, timeout_s=0)


# ---------------------------------------------------------------------------
# is_listed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cve", ["", "not-a-cve", "CVE-2024", "cve-2024-12345"])
async def test_invalid_cve_returns_false(
    fake_http: FakeHttpClient, fake_redis: FakeRedis, cve: str
) -> None:
    client = KevClient(fake_http, fake_redis)
    assert await client.is_listed(cve) is False
    assert fake_http.calls == []


async def test_cache_miss_fetches_and_caches(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=_SAMPLE_CATALOG)
    client = KevClient(fake_http, fake_redis)
    assert await client.is_listed("CVE-2024-1001") is True
    assert await client.is_listed("CVE-9999-0000") is False
    assert "argus:kev:catalog" in fake_redis.store
    decoded = json.loads(fake_redis.store["argus:kev:catalog"])
    assert "CVE-2024-1001" in decoded


async def test_cache_hit_skips_http(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_redis.store["argus:kev:catalog"] = json.dumps(["CVE-2024-7777"])
    client = KevClient(fake_http, fake_redis)
    assert await client.is_listed("CVE-2024-7777") is True
    assert await client.is_listed("CVE-2024-1001") is False
    assert fake_http.calls == []


async def test_no_redis_works_without_caching(fake_http: FakeHttpClient) -> None:
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=_SAMPLE_CATALOG)
    client = KevClient(fake_http, redis_client=None)
    assert await client.is_listed("CVE-2024-1001") is True


async def test_http_failure_returns_false(fake_redis: FakeRedis) -> None:
    fake_http = FakeHttpClient(raise_exception=TimeoutError)
    client = KevClient(fake_http, fake_redis)
    assert await client.is_listed("CVE-2024-1001") is False


async def test_http_non_200_returns_false(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(status_code=503)
    client = KevClient(fake_http, fake_redis)
    assert await client.is_listed("CVE-2024-1001") is False


@pytest.mark.parametrize(
    "payload",
    [
        "wrong",
        {"vulnerabilities": "wrong"},
        {"no_vulns": True},
        {"vulnerabilities": [{"cveID": "not-a-cve"}]},
        {"vulnerabilities": [None]},
    ],
)
async def test_malformed_payloads_yield_empty_catalog(
    fake_http: FakeHttpClient, fake_redis: FakeRedis, payload: object
) -> None:
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=payload)
    client = KevClient(fake_http, fake_redis)
    assert await client.is_listed("CVE-2024-1001") is False


async def test_malformed_json_returns_false(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(status_code=200, raise_on_json=True)
    client = KevClient(fake_http, fake_redis)
    assert await client.is_listed("CVE-2024-1001") is False


async def test_cache_corrupt_value_falls_through(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_redis.store["argus:kev:catalog"] = "not-json"
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=_SAMPLE_CATALOG)
    client = KevClient(fake_http, fake_redis)
    assert await client.is_listed("CVE-2024-1001") is True


# ---------------------------------------------------------------------------
# refresh
# ---------------------------------------------------------------------------


async def test_refresh_returns_count(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=_SAMPLE_CATALOG)
    client = KevClient(fake_http, fake_redis)
    count = await client.refresh()
    assert count == 5


async def test_refresh_failure_returns_zero(
    fake_redis: FakeRedis,
) -> None:
    fake_http = FakeHttpClient(raise_exception=TimeoutError)
    client = KevClient(fake_http, fake_redis)
    assert await client.refresh() == 0


async def test_redis_get_failure_falls_through(
    fake_http: FakeHttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis(raise_on_get=True)
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=_SAMPLE_CATALOG)
    client = KevClient(fake_http, redis)
    with caplog.at_level(logging.WARNING, logger="src.findings.kev_client"):
        assert await client.is_listed("CVE-2024-1001") is True
    assert any(
        "kev_cache_get_failed" in r.message or "kev.cache_get_failed" in r.message
        for r in caplog.records
    )


async def test_invalid_cve_logs_warning(
    fake_http: FakeHttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    client = KevClient(fake_http)
    with caplog.at_level(logging.WARNING, logger="src.findings.kev_client"):
        assert await client.is_listed("not-a-cve") is False
    assert any(
        "kev_invalid_cve" in r.message or "kev.invalid_cve" in r.message
        for r in caplog.records
    )


# ---------------------------------------------------------------------------
# ARG-044 — air-gap mode
# ---------------------------------------------------------------------------


async def test_airgap_mode_skips_http_for_is_listed(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """In air-gap mode ``is_listed`` MUST NOT touch the network."""
    client = KevClient(fake_http, fake_redis, airgap=True)
    assert await client.is_listed("CVE-2024-1001") is False
    assert fake_http.calls == []


async def test_airgap_mode_skips_fetch_kev_catalog(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """In air-gap mode ``fetch_kev_catalog`` returns ``None`` and skips HTTP."""
    client = KevClient(fake_http, fake_redis, airgap=True)
    assert await client.fetch_kev_catalog() is None
    assert fake_http.calls == []


async def test_airgap_mode_refresh_returns_zero(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    client = KevClient(fake_http, fake_redis, airgap=True)
    assert await client.refresh() == 0
    assert fake_http.calls == []


# ---------------------------------------------------------------------------
# ARG-044 — fetch_kev_catalog (structured records for Postgres persistence)
# ---------------------------------------------------------------------------


_FULL_CATALOG: dict[str, object] = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-1001",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Acme Widget Auth Bypass",
            "dateAdded": "2024-08-15",
            "shortDescription": "Authentication bypass via crafted token.",
            "requiredAction": "Apply patch.",
            "dueDate": "2024-09-05",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://example.com/advisory",
        },
        {
            "cveID": "cve-2025-0001",  # lower-case → must be normalised
            "vendorProject": "Beta",
            "product": "Tool",
            "vulnerabilityName": "Beta Tool RCE",
            "dateAdded": "2025-01-10",
            "shortDescription": "Remote code execution.",
            "requiredAction": "Upgrade to 2.0.",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "INVALID",  # malformed — must be dropped
            "dateAdded": "2025-01-10",
        },
        {
            "cveID": "CVE-2024-2222",
            "dateAdded": "not-a-date",  # invalid date — must be dropped
        },
    ]
}


async def test_fetch_kev_catalog_returns_structured_records(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(
        status_code=200,
        json_payload=_FULL_CATALOG,
        headers={"ETag": '"v1-abcd"'},
    )
    client = KevClient(fake_http, fake_redis)
    records = await client.fetch_kev_catalog()
    assert records is not None
    assert len(records) == 2
    by_cve = {r.cve_id: r for r in records}
    assert "CVE-2024-1001" in by_cve
    assert "CVE-2025-0001" in by_cve
    record = by_cve["CVE-2024-1001"]
    assert isinstance(record, KevRecord)
    assert record.vendor_project == "Acme"
    assert record.product == "Widget"
    assert record.date_added == date(2024, 8, 15)
    assert record.due_date == date(2024, 9, 5)
    assert record.known_ransomware_use is True
    assert record.notes == "https://example.com/advisory"
    # Lower-case "cve-..." must be upper-cased to canonical CVE-YYYY-NNNN.
    assert by_cve["CVE-2025-0001"].known_ransomware_use is False


async def test_fetch_kev_catalog_persists_etag_to_redis(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(
        status_code=200,
        json_payload=_FULL_CATALOG,
        headers={"ETag": '"v1-abcd"'},
    )
    client = KevClient(fake_http, fake_redis)
    await client.fetch_kev_catalog()
    assert fake_redis.store.get("argus:kev:etag") == '"v1-abcd"'


async def test_fetch_kev_catalog_sends_if_none_match_header(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """A cached ETag MUST be sent back as ``If-None-Match`` on the next poll."""
    fake_redis.store["argus:kev:etag"] = '"cached-etag"'
    fake_http.response = FakeHttpResponse(
        status_code=200,
        json_payload=_FULL_CATALOG,
        headers={"ETag": '"new-etag"'},
    )
    client = KevClient(fake_http, fake_redis)
    await client.fetch_kev_catalog()
    assert fake_http.headers_calls
    assert fake_http.headers_calls[0].get("If-None-Match") == '"cached-etag"'


async def test_fetch_kev_catalog_handles_304_not_modified(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """On 304 Not Modified, return ``None`` and do not overwrite cached state."""
    fake_redis.store["argus:kev:etag"] = '"v1-abcd"'
    fake_http.response = FakeHttpResponse(status_code=304)
    client = KevClient(fake_http, fake_redis)
    assert await client.fetch_kev_catalog() is None
    # ETag cache survives the 304.
    assert fake_redis.store["argus:kev:etag"] == '"v1-abcd"'


async def test_fetch_kev_catalog_handles_http_error(
    fake_redis: FakeRedis,
) -> None:
    fake_http = FakeHttpClient(raise_exception=TimeoutError)
    client = KevClient(fake_http, fake_redis)
    assert await client.fetch_kev_catalog() is None


async def test_fetch_kev_catalog_handles_non_200(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(status_code=502)
    client = KevClient(fake_http, fake_redis)
    assert await client.fetch_kev_catalog() is None


async def test_fetch_kev_catalog_handles_malformed_json(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(
        status_code=200, raise_on_json=True
    )
    client = KevClient(fake_http, fake_redis)
    assert await client.fetch_kev_catalog() is None


async def test_fetch_kev_catalog_returns_empty_for_missing_vulnerabilities(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(
        status_code=200, json_payload={"otherKey": []}
    )
    client = KevClient(fake_http, fake_redis)
    records = await client.fetch_kev_catalog()
    assert records is None or records == []


async def test_fetch_kev_catalog_drops_invalid_entries(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """Non-dict entries / missing CVE IDs / bad dates MUST be silently dropped."""
    payload = {
        "vulnerabilities": [
            None,
            {"cveID": "CVE-2024-1001", "dateAdded": "2024-08-15"},
            {"cveID": "not-a-cve", "dateAdded": "2024-08-15"},
            {"dateAdded": "2024-08-15"},  # missing cveID
        ]
    }
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=payload)
    client = KevClient(fake_http, fake_redis)
    records = await client.fetch_kev_catalog()
    assert records is not None
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-1001"


async def test_construction_rejects_negative_timeout(
    fake_http: FakeHttpClient,
) -> None:
    with pytest.raises(ValueError):
        KevClient(fake_http, timeout_s=-5)
