"""Scan OAST traces go through the correlator."""

from __future__ import annotations

from uuid import uuid4

from src.oast.scan_traces import (
    get_oast_provisioner,
    list_scan_oast_traces,
    record_scan_oast_trace,
    reset_scan_oast_traces,
)


def setup_function() -> None:
    reset_scan_oast_traces()


def test_missing_token_is_uncorrelated() -> None:
    row = record_scan_oast_trace(scan_id="s-1", protocol="dns")
    assert row["correlation_status"] == "uncorrelated"
    assert list_scan_oast_traces("s-1")


def test_unknown_uuid_token_is_unknown_token() -> None:
    row = record_scan_oast_trace(
        scan_id="s-1",
        protocol="dns",
        token_id=str(uuid4()),
    )
    assert row["correlation_status"] == "unknown_token"


def test_issued_token_correlates() -> None:
    token = get_oast_provisioner().issue(tenant_id=uuid4(), scan_id=uuid4())
    row = record_scan_oast_trace(
        scan_id=str(token.scan_id),
        protocol="dns",
        token_id=str(token.id),
    )
    assert row["correlation_status"] == "correlated"
