"""Unit tests for :mod:`src.findings.epss_client`."""

from __future__ import annotations

import logging

import pytest

from src.findings.epss_client import EpssClient
from tests.unit.findings.conftest import FakeHttpClient, FakeHttpResponse, FakeRedis


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_construction_rejects_non_positive_ttl(fake_http: FakeHttpClient) -> None:
    with pytest.raises(ValueError):
        EpssClient(fake_http, ttl_seconds=0)
    with pytest.raises(ValueError):
        EpssClient(fake_http, ttl_seconds=-1)


def test_construction_rejects_non_positive_timeout(fake_http: FakeHttpClient) -> None:
    with pytest.raises(ValueError):
        EpssClient(fake_http, timeout_s=0)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cve",
    [
        "",
        "not-a-cve",
        "CVE-2024",
        "CVE-2024-12",
        "CVE-2024-1234567890",
    ],
)
async def test_invalid_cve_returns_none(
    fake_http: FakeHttpClient, fake_redis: FakeRedis, cve: str
) -> None:
    client = EpssClient(fake_http, fake_redis)
    assert await client.get(cve) is None
    assert fake_http.calls == []


async def test_lowercase_cve_normalised_to_upper_for_cache(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """Cache key must be canonical (uppercase) regardless of caller casing."""
    fake_http.response = FakeHttpResponse(
        status_code=200,
        json_payload={"data": [{"epss": "0.42"}]},
    )
    client = EpssClient(fake_http, fake_redis)

    assert await client.get("cve-2024-12345") == 0.42
    assert "argus:epss:CVE-2024-12345" in fake_redis.store
    assert "argus:epss:cve-2024-12345" not in fake_redis.store

    fake_http.calls.clear()
    assert await client.get("CVE-2024-12345") == 0.42
    assert fake_http.calls == []


# ---------------------------------------------------------------------------
# Cache hit / miss
# ---------------------------------------------------------------------------


async def test_cache_hit_skips_http(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_redis.store["argus:epss:CVE-2024-12345"] = "0.42"
    client = EpssClient(fake_http, fake_redis)
    assert await client.get("CVE-2024-12345") == 0.42
    assert fake_http.calls == []


async def test_cache_miss_fetches_and_caches(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(
        status_code=200,
        json_payload={"data": [{"cve": "CVE-2024-12345", "epss": "0.85"}]},
    )
    client = EpssClient(fake_http, fake_redis)
    result = await client.get("CVE-2024-12345")
    assert result == 0.85
    assert "argus:epss:CVE-2024-12345" in fake_redis.store
    assert fake_redis.store["argus:epss:CVE-2024-12345"].startswith("0.85")
    assert len(fake_http.calls) == 1
    assert "cve=CVE-2024-12345" in fake_http.calls[0][0]


async def test_cache_returns_bytes(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_redis.store["argus:epss:CVE-2024-12345"] = "0.7"

    class BytesRedis(FakeRedis):
        def get(self, key: str) -> bytes | None:  # type: ignore[override]
            value = self.store.get(key)
            return value.encode("utf-8") if value is not None else None

    redis = BytesRedis(store=dict(fake_redis.store))
    client = EpssClient(fake_http, redis)
    assert await client.get("CVE-2024-12345") == 0.7


async def test_cache_corrupt_value_falls_through(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_redis.store["argus:epss:CVE-2024-12345"] = "not-a-float"
    fake_http.response = FakeHttpResponse(
        status_code=200,
        json_payload={"data": [{"epss": "0.42"}]},
    )
    client = EpssClient(fake_http, fake_redis)
    assert await client.get("CVE-2024-12345") == 0.42


async def test_cache_out_of_range_value_falls_through(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_redis.store["argus:epss:CVE-2024-12345"] = "1.5"
    fake_http.response = FakeHttpResponse(
        status_code=200,
        json_payload={"data": [{"epss": "0.42"}]},
    )
    client = EpssClient(fake_http, fake_redis)
    assert await client.get("CVE-2024-12345") == 0.42


async def test_no_redis_works_without_caching(fake_http: FakeHttpClient) -> None:
    fake_http.response = FakeHttpResponse(
        status_code=200, json_payload={"data": [{"epss": "0.5"}]}
    )
    client = EpssClient(fake_http, redis_client=None)
    assert await client.get("CVE-2024-12345") == 0.5


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


async def test_http_timeout_returns_none(fake_redis: FakeRedis) -> None:
    fake_http = FakeHttpClient(raise_exception=TimeoutError)
    client = EpssClient(fake_http, fake_redis)
    assert await client.get("CVE-2024-12345") is None


async def test_http_non_200_returns_none(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(status_code=503)
    client = EpssClient(fake_http, fake_redis)
    assert await client.get("CVE-2024-12345") is None
    assert "argus:epss:CVE-2024-12345" not in fake_redis.store


async def test_malformed_json_returns_none(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(status_code=200, raise_on_json=True)
    client = EpssClient(fake_http, fake_redis)
    assert await client.get("CVE-2024-12345") is None


@pytest.mark.parametrize(
    "payload",
    [
        "not a dict",
        {"data": []},
        {"data": "wrong"},
        {"data": [{"epss": None}]},
        {"data": [{"epss": "not-a-float"}]},
        {"data": [{"epss": "1.5"}]},
        {"data": [{"epss": "-0.1"}]},
        {"data": [{"no_epss": "0.5"}]},
        {"no_data": True},
        {"data": [None]},
    ],
)
async def test_malformed_payload_returns_none(
    fake_http: FakeHttpClient, fake_redis: FakeRedis, payload: object
) -> None:
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=payload)
    client = EpssClient(fake_http, fake_redis)
    assert await client.get("CVE-2024-12345") is None


async def test_redis_get_failure_falls_through(
    fake_http: FakeHttpClient,
) -> None:
    redis = FakeRedis(raise_on_get=True)
    fake_http.response = FakeHttpResponse(
        status_code=200, json_payload={"data": [{"epss": "0.3"}]}
    )
    client = EpssClient(fake_http, redis)
    assert await client.get("CVE-2024-12345") == 0.3


async def test_redis_set_failure_does_not_raise(
    fake_http: FakeHttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    redis = FakeRedis(raise_on_set=True)
    fake_http.response = FakeHttpResponse(
        status_code=200, json_payload={"data": [{"epss": "0.6"}]}
    )
    client = EpssClient(fake_http, redis)
    with caplog.at_level(logging.WARNING, logger="src.findings.epss_client"):
        assert await client.get("CVE-2024-12345") == 0.6
    assert any(
        "epss_cache_put_failed" in r.message or "epss.cache_put_failed" in r.message
        for r in caplog.records
    )


async def test_invalid_cve_logs_warning(
    fake_http: FakeHttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    client = EpssClient(fake_http)
    with caplog.at_level(logging.WARNING, logger="src.findings.epss_client"):
        assert await client.get("not-a-cve") is None
    assert any(
        "epss_invalid_cve" in r.message or "epss.invalid_cve" in r.message
        for r in caplog.records
    )


# ---------------------------------------------------------------------------
# ARG-044 — air-gap mode
# ---------------------------------------------------------------------------


async def test_airgap_mode_skips_remote_get(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    client = EpssClient(fake_http, fake_redis, airgap=True)
    assert await client.get("CVE-2024-12345") is None
    assert fake_http.calls == []


async def test_airgap_mode_returns_cached_value(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """Air-gap mode still reads from the local Redis cache (offline bundle)."""
    fake_redis.store["argus:epss:CVE-2024-12345"] = "0.7"
    client = EpssClient(fake_http, fake_redis, airgap=True)
    assert await client.get("CVE-2024-12345") == 0.7
    assert fake_http.calls == []


async def test_airgap_mode_short_circuits_fetch_epss_batch(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    client = EpssClient(fake_http, fake_redis, airgap=True)
    rows = await client.fetch_epss_batch(["CVE-2024-12345", "CVE-2024-67890"])
    assert rows == {}
    assert fake_http.calls == []


# ---------------------------------------------------------------------------
# ARG-044 — fetch_epss_batch
# ---------------------------------------------------------------------------


async def test_fetch_epss_batch_returns_entries(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    payload = {
        "data": [
            {
                "cve": "CVE-2024-12345",
                "epss": "0.42",
                "percentile": "0.97",
                "date": "2024-08-15",
            },
            {
                "cve": "CVE-2024-67890",
                "epss": "0.10",
                "percentile": "0.55",
                "date": "2024-08-15",
            },
        ]
    }
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=payload)
    client = EpssClient(fake_http, fake_redis)
    rows = await client.fetch_epss_batch(["CVE-2024-12345", "CVE-2024-67890"])
    assert set(rows) == {"CVE-2024-12345", "CVE-2024-67890"}
    assert rows["CVE-2024-12345"].epss_score == 0.42
    assert rows["CVE-2024-12345"].epss_percentile == 0.97
    assert str(rows["CVE-2024-12345"].model_date) == "2024-08-15"


async def test_fetch_epss_batch_chunks_requests(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """``chunk_size`` controls how many CVEs go in each request."""
    payload = {
        "data": [
            {
                "cve": "CVE-2024-00001",
                "epss": "0.10",
                "percentile": "0.50",
                "date": "2024-01-01",
            },
            {
                "cve": "CVE-2024-00002",
                "epss": "0.20",
                "percentile": "0.55",
                "date": "2024-01-01",
            },
            {
                "cve": "CVE-2024-00003",
                "epss": "0.30",
                "percentile": "0.60",
                "date": "2024-01-01",
            },
        ]
    }
    # The batch endpoint returns the union of every chunk's response;
    # the fake serves the same payload for each chunk so we can count.
    fake_http.responses = [
        FakeHttpResponse(status_code=200, json_payload=payload),
        FakeHttpResponse(status_code=200, json_payload=payload),
        FakeHttpResponse(status_code=200, json_payload=payload),
    ]
    client = EpssClient(fake_http, fake_redis)
    rows = await client.fetch_epss_batch(
        [
            "CVE-2024-00001",
            "CVE-2024-00002",
            "CVE-2024-00003",
        ],
        chunk_size=1,
    )
    # Three separate HTTP calls, one per chunk.
    assert len(fake_http.calls) == 3
    assert set(rows) == {"CVE-2024-00001", "CVE-2024-00002", "CVE-2024-00003"}


async def test_fetch_epss_batch_filters_invalid_cves(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(
        status_code=200, json_payload={"data": []}
    )
    client = EpssClient(fake_http, fake_redis)
    rows = await client.fetch_epss_batch(
        ["", "not-a-cve", "CVE-99999", "CVE-2024-12345"]
    )
    # Only the one valid CVE survives the validator + reaches the batch fetch.
    assert rows == {}
    assert len(fake_http.calls) == 1
    assert "CVE-2024-12345" in fake_http.calls[0][0]


async def test_fetch_epss_batch_dedupes_inputs(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.response = FakeHttpResponse(
        status_code=200, json_payload={"data": []}
    )
    client = EpssClient(fake_http, fake_redis)
    await client.fetch_epss_batch(
        ["CVE-2024-12345", "cve-2024-12345", "CVE-2024-12345"]
    )
    # Single chunk, single CVE.
    assert len(fake_http.calls) == 1
    url = fake_http.calls[0][0]
    assert url.count("CVE-2024-12345") == 1


async def test_fetch_epss_batch_empty_input_returns_empty_dict(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    client = EpssClient(fake_http, fake_redis)
    assert await client.fetch_epss_batch([]) == {}
    assert fake_http.calls == []


async def test_fetch_epss_batch_rejects_non_positive_chunk_size(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    client = EpssClient(fake_http, fake_redis)
    with pytest.raises(ValueError):
        await client.fetch_epss_batch(["CVE-2024-12345"], chunk_size=0)


async def test_fetch_epss_batch_retries_on_5xx(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """Batch endpoint MUST retry transient 5xx with exponential backoff."""
    payload = {
        "data": [
            {
                "cve": "CVE-2024-12345",
                "epss": "0.42",
                "percentile": "0.97",
                "date": "2024-08-15",
            }
        ]
    }
    fake_http.responses = [
        FakeHttpResponse(status_code=503),  # first attempt — retryable.
        FakeHttpResponse(status_code=503),  # second attempt — still failing.
        FakeHttpResponse(status_code=200, json_payload=payload),  # third — succeeds.
    ]
    client = EpssClient(
        fake_http,
        fake_redis,
        max_retries=3,
        backoff_base_s=0.0,  # disable real sleeping in tests.
        backoff_cap_s=0.0,
    )
    rows = await client.fetch_epss_batch(["CVE-2024-12345"])
    assert "CVE-2024-12345" in rows
    assert len(fake_http.calls) == 3


async def test_fetch_epss_batch_gives_up_after_max_retries(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    fake_http.responses = [
        FakeHttpResponse(status_code=503),
        FakeHttpResponse(status_code=503),
    ]
    client = EpssClient(
        fake_http,
        fake_redis,
        max_retries=1,
        backoff_base_s=0.0,
        backoff_cap_s=0.0,
    )
    rows = await client.fetch_epss_batch(["CVE-2024-12345"])
    assert rows == {}


async def test_fetch_epss_batch_drops_invalid_rows(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    """Rows missing a percentile / date / CVE MUST be dropped silently."""
    payload = {
        "data": [
            {"cve": "CVE-2024-12345", "epss": "0.4"},  # missing percentile
            {"epss": "0.4", "percentile": "0.5", "date": "2024-08-15"},  # missing CVE
            {
                "cve": "CVE-2024-67890",
                "epss": "0.4",
                "percentile": "0.5",
                "date": "not-a-date",
            },
        ]
    }
    fake_http.response = FakeHttpResponse(status_code=200, json_payload=payload)
    client = EpssClient(fake_http, fake_redis)
    rows = await client.fetch_epss_batch(["CVE-2024-12345", "CVE-2024-67890"])
    assert rows == {}


async def test_fetch_epss_batch_air_gap_returns_empty(
    fake_http: FakeHttpClient, fake_redis: FakeRedis
) -> None:
    client = EpssClient(fake_http, fake_redis, airgap=True)
    rows = await client.fetch_epss_batch(["CVE-2024-12345"])
    assert rows == {}
    assert fake_http.calls == []
