"""Security regression tests for endpoint inventory builder."""

from __future__ import annotations

import csv
import io

from src.recon.reporting.endpoint_builder import ENDPOINT_PATHS, build_endpoint_inventory


def _csv_rows(content: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(content)))


def test_endpoint_builder_fail_closed_when_mcp_unavailable_and_no_httpx_fallback(
    monkeypatch,
) -> None:
    def _raise(_url: str, _timeout: float) -> dict:
        raise RuntimeError("token=super-secret internal failure details")

    def _httpx_should_not_run(_url: str, _timeout: float = 10.0) -> dict:
        raise AssertionError("httpx fallback must not run when use_mcp=True")

    monkeypatch.setattr("src.recon.mcp.client._fetch_via_mcp_sync", _raise)
    monkeypatch.setattr(
        "src.recon.reporting.endpoint_builder._fetch_endpoint_httpx",
        _httpx_should_not_run,
    )

    csv_content = build_endpoint_inventory(
        live_hosts=["https://example.com"],
        use_mcp=True,
        timeout=1.0,
    )
    rows = _csv_rows(csv_content)

    assert len(rows) == len(ENDPOINT_PATHS)
    assert all(row["exists"] == "no" for row in rows)
    assert all(row["notes"] == "mcp_fetch_failed" for row in rows)
    assert "super-secret" not in csv_content
