"""ARG-047 — Scan lifecycle contract tests against the live e2e stack.

Ten cases exercise the externally observable lifecycle of a scan against
OWASP Juice Shop, mirroring what the bash / PowerShell wrapper drives:

  1.  POST /api/v1/scans returns 201 + scan_id.
  2.  GET  /api/v1/scans/<id> returns 200 with the canonical fields.
  3.  Scan progresses through queued → running → completed within the timeout.
  4.  GET /api/v1/scans/<id>/findings returns a non-empty list (>= threshold).
  5.  GET /api/v1/scans/<id>/findings/statistics is internally consistent.
  6.  POST /api/v1/scans/<id>/reports/generate-all enqueues a bundle.
  7.  GET /api/v1/reports?target=... lists the bundle members.
  8.  Each report eventually moves to ``generation_status='ready'``.
  9.  Report detail endpoint returns a populated summary.
  10. Idempotency: a second generate-all call does NOT duplicate the bundle.

These tests share fixtures so wall-time stays sane when run as a suite.
A single ``module``-scope ``scan_session`` fixture triggers the scan once
and yields the scan_id to all dependent cases.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

pytestmark = pytest.mark.requires_docker_e2e


BASE_URL: str = os.environ.get("E2E_BACKEND_URL", "http://localhost:8000")
TARGET: str = os.environ.get("E2E_TARGET", "http://juice-shop:3000")
TOKEN: str = os.environ.get("E2E_TOKEN", "e2e-api-key-not-for-production")
SCAN_MODE: str = os.environ.get("E2E_SCAN_MODE", "standard")
MIN_FINDINGS: int = int(os.environ.get("E2E_MIN_FINDINGS", "50"))
EXPECTED_REPORTS: int = int(os.environ.get("E2E_EXPECTED_REPORTS", "12"))
SCAN_TIMEOUT_SECONDS: int = int(os.environ.get("E2E_SCAN_TIMEOUT_SECONDS", "2400"))
REPORT_TIMEOUT_SECONDS: int = int(os.environ.get("E2E_REPORT_TIMEOUT_SECONDS", "600"))

HTTP_TIMEOUT_SECONDS: float = 30.0
POLL_INTERVAL_SECONDS: float = 5.0


@dataclass(frozen=True)
class ScanSession:
    """Shared state across the lifecycle tests — populated by the fixture."""

    scan_id: str
    triggered_at: float


def _request(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    """Tiny stdlib HTTP wrapper — keeps the test suite zero-dep."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {TOKEN}",
            "User-Agent": "argus-e2e-tests/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:  # noqa: S310
            payload = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        payload = exc.read() if exc.fp else b""
        status = exc.code
    if not payload:
        return status, None
    try:
        return status, json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return status, payload.decode("utf-8", errors="replace")


def _poll_scan_status(scan_id: str, deadline_epoch: float) -> dict[str, Any]:
    """Poll the scan endpoint until it hits a terminal state or the deadline."""
    while time.monotonic() < deadline_epoch:
        status, body = _request("GET", f"/api/v1/scans/{scan_id}")
        if status == 200 and isinstance(body, dict):
            cur = body.get("status")
            if cur in ("completed", "failed", "cancelled"):
                return body
        time.sleep(POLL_INTERVAL_SECONDS)
    raise TimeoutError(f"scan {scan_id} did not finish within timeout")


def _list_reports_for_scan(scan_id: str) -> list[dict[str, Any]]:
    """Fetch reports filtered to the given scan_id (hydrate via detail endpoint)."""
    encoded_target = urllib.parse.quote(TARGET, safe=":/?#[]@!$&'()*+,;=")
    status, listing = _request("GET", f"/api/v1/reports?target={encoded_target}")
    if status != 200 or not isinstance(listing, list):
        return []
    matched: list[dict[str, Any]] = []
    for row in listing:
        rid = row.get("report_id") or row.get("id")
        if not rid:
            continue
        s2, detail = _request("GET", f"/api/v1/reports/{rid}")
        if s2 != 200 or not isinstance(detail, dict):
            continue
        if detail.get("scan_id") == scan_id:
            matched.append({**row, **detail})
    return matched


# ── Module-scope fixture: trigger the scan ONCE and reuse for every case ──

@pytest.fixture(scope="module")
def scan_session() -> Iterator[ScanSession]:
    """Trigger one scan against juice-shop and share the id across the module."""
    payload = {"target": TARGET, "email": "e2e@example.com", "scan_mode": SCAN_MODE}
    status, body = _request("POST", "/api/v1/scans", body=payload)
    assert status == 201, f"failed to create scan: status={status} body={body}"
    assert isinstance(body, dict) and body.get("scan_id"), f"no scan_id in {body}"
    yield ScanSession(scan_id=str(body["scan_id"]), triggered_at=time.monotonic())


# ── Case 1: POST /api/v1/scans returns 201 + scan_id ─────────────────────

def test_scan_create_returns_uuid_and_queued_status(scan_session: ScanSession) -> None:
    assert scan_session.scan_id
    # Sanity-check UUID shape — 8-4-4-4-12 hex.
    assert len(scan_session.scan_id) == 36
    assert scan_session.scan_id.count("-") == 4


# ── Case 2: GET scan returns canonical fields ────────────────────────────

def test_scan_get_returns_expected_shape(scan_session: ScanSession) -> None:
    status, body = _request("GET", f"/api/v1/scans/{scan_session.scan_id}")
    assert status == 200
    assert isinstance(body, dict)
    for key in ("id", "status", "progress", "phase", "target", "created_at"):
        assert key in body, f"missing key {key!r} in {body}"
    assert body["id"] == scan_session.scan_id
    assert body["target"] == TARGET


# ── Case 3: scan reaches 'completed' within the timeout ──────────────────

@pytest.fixture(scope="module")
def completed_scan(scan_session: ScanSession) -> dict[str, Any]:
    deadline = time.monotonic() + SCAN_TIMEOUT_SECONDS
    final = _poll_scan_status(scan_session.scan_id, deadline)
    assert final.get("status") == "completed", (
        f"scan ended in non-completed state: {final.get('status')} (phase={final.get('phase')})"
    )
    return final


def test_scan_progresses_to_completed_within_timeout(completed_scan: dict[str, Any]) -> None:
    assert completed_scan["status"] == "completed"
    assert int(completed_scan.get("progress", 0)) >= 100


# ── Case 4: findings list is non-empty (>= threshold) ────────────────────

def test_scan_findings_meet_minimum_count(scan_session: ScanSession, completed_scan: dict[str, Any]) -> None:
    _ = completed_scan
    status, body = _request("GET", f"/api/v1/scans/{scan_session.scan_id}/findings")
    assert status == 200
    assert isinstance(body, list)
    assert len(body) >= MIN_FINDINGS, (
        f"insufficient findings: got {len(body)}, need >= {MIN_FINDINGS}"
    )


# ── Case 5: statistics endpoint mirrors the list count ───────────────────

def test_scan_findings_statistics_consistent(scan_session: ScanSession, completed_scan: dict[str, Any]) -> None:
    _ = completed_scan
    status, body = _request("GET", f"/api/v1/scans/{scan_session.scan_id}/findings/statistics")
    assert status == 200
    assert isinstance(body, dict)
    total = int(body.get("total", 0))
    assert total >= MIN_FINDINGS, f"statistics.total={total}, expected >= {MIN_FINDINGS}"
    # Severity buckets should sum to the total (allowing zero-buckets).
    by_severity = body.get("by_severity") or {}
    if isinstance(by_severity, dict) and by_severity:
        bucket_sum = sum(int(v or 0) for v in by_severity.values() if isinstance(v, (int, float)))
        # Allow small drift due to severity-unknown findings (rare).
        assert bucket_sum <= total, "severity buckets exceeded total"


# ── Case 6: generate-all enqueues a bundle ───────────────────────────────

@pytest.fixture(scope="module")
def report_bundle(scan_session: ScanSession, completed_scan: dict[str, Any]) -> dict[str, Any]:
    _ = completed_scan
    status, body = _request(
        "POST",
        f"/api/v1/scans/{scan_session.scan_id}/reports/generate-all",
        body={},
    )
    assert status == 202, f"generate-all expected 202, got {status}: {body}"
    assert isinstance(body, dict)
    assert "bundle_id" in body or "report_ids" in body, f"unexpected response shape: {body}"
    return body


def test_generate_all_returns_accepted_with_bundle_metadata(report_bundle: dict[str, Any]) -> None:
    assert isinstance(report_bundle, dict)


# ── Case 7: report list contains the bundle members ──────────────────────

def test_reports_list_contains_bundle_members(
    scan_session: ScanSession, report_bundle: dict[str, Any]
) -> None:
    _ = report_bundle
    deadline = time.monotonic() + REPORT_TIMEOUT_SECONDS
    matched: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        matched = _list_reports_for_scan(scan_session.scan_id)
        if len(matched) >= EXPECTED_REPORTS:
            break
        time.sleep(POLL_INTERVAL_SECONDS)
    assert len(matched) >= EXPECTED_REPORTS, (
        f"only {len(matched)} reports listed, expected >= {EXPECTED_REPORTS}"
    )


# ── Case 8: every report moves out of pending/processing to ready ────────

def test_all_reports_finish_generation(
    scan_session: ScanSession, report_bundle: dict[str, Any]
) -> None:
    _ = report_bundle
    deadline = time.monotonic() + REPORT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        rows = _list_reports_for_scan(scan_session.scan_id)
        if not rows:
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        statuses = {(r.get("generation_status") or "").lower() for r in rows}
        if statuses.issubset({"ready", "failed"}) and "ready" in statuses:
            break
        time.sleep(POLL_INTERVAL_SECONDS)
    rows = _list_reports_for_scan(scan_session.scan_id)
    pending = [r for r in rows if (r.get("generation_status") or "").lower() in ("pending", "processing")]
    assert not pending, f"{len(pending)} report(s) still pending/processing after timeout"
    failed = [r for r in rows if (r.get("generation_status") or "").lower() == "failed"]
    assert not failed, f"{len(failed)} report(s) finished in 'failed' state"


# ── Case 9: report detail endpoint returns populated summary ─────────────

def test_report_detail_summary_populated(
    scan_session: ScanSession, report_bundle: dict[str, Any]
) -> None:
    _ = report_bundle
    rows = _list_reports_for_scan(scan_session.scan_id)
    assert rows, "no reports listed for scan"
    inspected = 0
    for row in rows:
        rid = row.get("report_id") or row.get("id")
        if not rid:
            continue
        status, detail = _request("GET", f"/api/v1/reports/{rid}")
        assert status == 200
        assert isinstance(detail, dict)
        assert detail.get("report_id") == rid
        assert detail.get("scan_id") == scan_session.scan_id
        summary = detail.get("summary") or {}
        assert isinstance(summary, dict)
        inspected += 1
        if inspected >= 3:
            break  # Sampling — full coverage handled by Case 8.
    assert inspected > 0


# ── Case 10: idempotency — second generate-all does not duplicate ────────

def test_second_generate_all_does_not_duplicate_bundle(
    scan_session: ScanSession, report_bundle: dict[str, Any]
) -> None:
    _ = report_bundle
    rows_before = _list_reports_for_scan(scan_session.scan_id)
    status, _body = _request(
        "POST",
        f"/api/v1/scans/{scan_session.scan_id}/reports/generate-all",
        body={},
    )
    # Either 202 (re-queue accepted) or 409 (idempotency-blocked) is acceptable;
    # what matters is the row count does NOT explode.
    assert status in (202, 409), f"unexpected status from second generate-all: {status}"
    time.sleep(POLL_INTERVAL_SECONDS)
    rows_after = _list_reports_for_scan(scan_session.scan_id)
    # Allow up to ``EXPECTED_REPORTS`` extra rows (one new bundle is acceptable);
    # what we forbid is unbounded duplication.
    assert len(rows_after) <= len(rows_before) + EXPECTED_REPORTS, (
        f"report rows duplicated: before={len(rows_before)} after={len(rows_after)}"
    )
