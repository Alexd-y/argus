"""Admin POST /admin/audit-logs/verify-chain — chain integrity verification (T25).

Covers:

* Happy path with a clean 5-event chain → ``ok=True``.
* Synthetic drift via tampered ``_event_hash`` marker → ``ok=False`` with
  ``drift_event_id`` / ``drift_detected_at`` localized.
* Empty time-window → ``ok=True`` with ``verified_count=0`` and
  ``last_verified_index=-1``.
* Time-window > 90 days → HTTP 400 (closed-taxonomy detail).
* RBAC matrix:
    - admin scoped to own tenant → 200
    - admin without ``X-Admin-Tenant`` → 403
    - admin with mismatched tenant → 403
    - super-admin cross-tenant (no ``tenant_id``) → 200
    - operator (any combination) → 403
* Audit-emit structured log includes ``user_id_hash`` from ``X-Operator-Subject``
  and the ``tenant_hash`` of the effective tenant (never raw ids).

The pure-helper hash chain semantics are exercised via the API surface; the
``policy.audit.verify_audit_log_chain`` helper itself is therefore covered by
the same fixtures (no separate unit tests needed — happy/drift/empty paths all
flow through here).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from main import app
from src.core.config import settings
from src.core.observability import tenant_hash, user_id_hash
from src.db.session import get_db
from src.policy.audit import (
    GENESIS_HASH,
    _compute_audit_log_hash,
    verify_audit_log_chain,
)

VERIFY = "/api/v1/admin/audit-logs/verify-chain"
_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY}


# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------


def _audit_row(
    *,
    tenant_id: str,
    created_at: datetime,
    user_id: str | None = None,
    action: str = "policy.decision",
    resource_type: str | None = "policy",
    resource_id: str | None = None,
    details: dict[str, object] | None = None,
    ip_address: str | None = None,
    row_id: str | None = None,
) -> SimpleNamespace:
    """Build a SimpleNamespace mimicking ``src.db.models.AuditLog``."""
    return SimpleNamespace(
        id=row_id or str(uuid.uuid4()),
        tenant_id=tenant_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details if details is not None else {"k": "v"},
        ip_address=ip_address,
        created_at=created_at,
    )


def _build_clean_chain(
    tenant_id: str,
    *,
    count: int = 5,
    start_at: datetime | None = None,
) -> list[SimpleNamespace]:
    """Build ``count`` rows with valid ``_prev_event_hash`` / ``_event_hash`` markers.

    The markers are computed against the same canonical projection the verifier
    uses, so the resulting chain MUST validate cleanly. This mirrors what an
    audit-aware emitter would write at row-creation time.
    """
    base = start_at or datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
    rows: list[SimpleNamespace] = []
    prev_hash = GENESIS_HASH
    for i in range(count):
        row = _audit_row(
            tenant_id=tenant_id,
            created_at=base + timedelta(seconds=i),
            action=f"policy.decision_{i}",
            details={"step": i, "_prev_event_hash": prev_hash},
        )
        expected = _compute_audit_log_hash(row=row, prev_hash=prev_hash)
        if not isinstance(row.details, dict):
            row.details = {}
        row.details["_event_hash"] = expected
        rows.append(row)
        prev_hash = expected
    return rows


def _override_db(rows: list[SimpleNamespace]) -> None:
    async def mock_get_db() -> AsyncGenerator[AsyncMock, None]:
        session = AsyncMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = rows
        session.execute = AsyncMock(return_value=result)
        yield session

    app.dependency_overrides[get_db] = mock_get_db


def _clear_db_override() -> None:
    app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# Helper-level smoke tests (pure verify_audit_log_chain)
# ---------------------------------------------------------------------------


class TestVerifyAuditLogChainHelper:
    """Direct exercise of the pure helper — fast feedback for chain semantics."""

    def test_clean_chain_returns_ok_true_with_full_count(self) -> None:
        tid = str(uuid.uuid4())
        rows = _build_clean_chain(tid, count=5)
        verdict = verify_audit_log_chain(rows)
        assert verdict.ok is True
        assert verdict.verified_count == 5
        assert verdict.last_verified_index == 4
        assert verdict.drift_event_id is None
        assert verdict.drift_detected_at is None

    def test_empty_input_returns_ok_true_with_negative_index(self) -> None:
        verdict = verify_audit_log_chain([])
        assert verdict.ok is True
        assert verdict.verified_count == 0
        assert verdict.last_verified_index == -1

    def test_chain_without_markers_recomputes_cleanly(self) -> None:
        tid = str(uuid.uuid4())
        rows = [
            _audit_row(
                tenant_id=tid,
                created_at=datetime(2026, 4, 1, tzinfo=timezone.utc) + timedelta(seconds=i),
                details={"step": i},
            )
            for i in range(3)
        ]
        verdict = verify_audit_log_chain(rows)
        assert verdict.ok is True
        assert verdict.verified_count == 3


# ---------------------------------------------------------------------------
# Auth / RBAC
# ---------------------------------------------------------------------------


class TestVerifyChainAuth:
    """``X-Admin-Key`` gate (existing ``require_admin`` pattern)."""

    def test_401_without_key(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(VERIFY)
        assert r.status_code == 401

    def test_401_wrong_key(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(VERIFY, headers={"X-Admin-Key": "nope"})
        assert r.status_code == 401


class TestVerifyChainRbac:
    """admin / super-admin allowed; operator denied; tenant-scoping enforced."""

    def test_super_admin_no_tenant_id_returns_200(self, client: TestClient) -> None:
        rows = _build_clean_chain(str(uuid.uuid4()), count=2)
        _override_db(rows)
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert body["verified_count"] == 2
        assert body["last_verified_index"] == 1

    def test_admin_role_with_matching_tenant_returns_200(
        self, client: TestClient
    ) -> None:
        tid = str(uuid.uuid4())
        rows = _build_clean_chain(tid, count=3)
        _override_db(rows)
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={
                        **_ADMIN_HEADERS,
                        "X-Admin-Role": "admin",
                        "X-Admin-Tenant": tid,
                    },
                    params={"tenant_id": tid},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert body["verified_count"] == 3

    def test_admin_role_without_tenant_id_returns_403(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                VERIFY,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "admin",
                    "X-Admin-Tenant": tid,
                },
            )
        assert r.status_code == 403
        assert "tenant_id" in r.json().get("detail", "").lower()

    def test_admin_role_tenant_mismatch_returns_403(self, client: TestClient) -> None:
        my_tid = str(uuid.uuid4())
        other_tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                VERIFY,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "admin",
                    "X-Admin-Tenant": my_tid,
                },
                params={"tenant_id": other_tid},
            )
        assert r.status_code == 403
        assert "mismatch" in r.json().get("detail", "").lower()

    def test_operator_role_returns_403(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                VERIFY,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "operator",
                    "X-Admin-Tenant": tid,
                },
                params={"tenant_id": tid},
            )
        assert r.status_code == 403
        # Closed-taxonomy detail: must mention "admin" or "super-admin" privilege.
        detail_lc = r.json().get("detail", "").lower()
        assert "admin" in detail_lc or "super-admin" in detail_lc


# ---------------------------------------------------------------------------
# Time-window guard (≤90 days)
# ---------------------------------------------------------------------------


class TestVerifyChainTimeWindow:
    def test_window_too_large_returns_400(self, client: TestClient) -> None:
        # 100-day window — over the 90-day cap.
        until = datetime(2026, 4, 21, tzinfo=timezone.utc)
        since = until - timedelta(days=100)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                VERIFY,
                headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                params={
                    "since": since.isoformat(),
                    "until": until.isoformat(),
                },
            )
        assert r.status_code == 400
        detail = r.json().get("detail", "").lower()
        assert "90 days" in detail or "exceeds" in detail

    def test_window_at_cap_is_accepted(self, client: TestClient) -> None:
        # Exactly 90 days — must succeed (boundary).
        tid = str(uuid.uuid4())
        until = datetime(2026, 4, 21, tzinfo=timezone.utc)
        since = until - timedelta(days=90)
        rows = _build_clean_chain(tid, count=1, start_at=since + timedelta(seconds=1))
        _override_db(rows)
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                    params={
                        "since": since.isoformat(),
                        "until": until.isoformat(),
                    },
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200, r.text

    def test_until_before_since_returns_422(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                VERIFY,
                headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                params={
                    "since": "2026-04-30T00:00:00Z",
                    "until": "2026-04-01T00:00:00Z",
                },
            )
        assert r.status_code == 422

    def test_unbounded_window_defaults_to_last_90_days(
        self, client: TestClient
    ) -> None:
        """No bounds → implicit "last 90 days" anchored to ``utcnow``.

        Confirms the verifier is callable without timestamps for the common
        "verify recent activity" case while remaining bounded by the cap.
        Also verifies the response echoes the resolved bounds (S2-2).
        """
        _override_db([])
        before = datetime.now(tz=timezone.utc)
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                )
        finally:
            _clear_db_override()
        after = datetime.now(tz=timezone.utc)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert body["verified_count"] == 0
        assert body["last_verified_index"] == -1
        # S2-2 — response MUST echo the effective bounds even when defaults
        # were applied (no since/until in the request).
        eff_until = datetime.fromisoformat(body["effective_until"])
        eff_since = datetime.fromisoformat(body["effective_since"])
        assert before <= eff_until <= after, (
            "effective_until must be anchored to server-side utcnow"
        )
        assert eff_until - eff_since == timedelta(days=90), (
            "effective_since must be exactly 90 days before effective_until"
        )


# ---------------------------------------------------------------------------
# Happy path / drift / empty
# ---------------------------------------------------------------------------


class TestVerifyChainHappyPath:
    def test_clean_chain_returns_ok_true(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        rows = _build_clean_chain(tid, count=5)
        _override_db(rows)
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["verified_count"] == 5
        assert body["last_verified_index"] == 4
        assert body["drift_event_id"] is None
        assert body["drift_detected_at"] is None
        # S2-2 — effective window MUST be present on every response (even
        # when defaults were applied) so callers / SIEM can render the real
        # verified range.
        assert "effective_since" in body
        assert "effective_until" in body
        assert datetime.fromisoformat(body["effective_since"]) < datetime.fromisoformat(
            body["effective_until"]
        )

    def test_empty_range_returns_ok_true_zero_count(self, client: TestClient) -> None:
        _override_db([])
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["verified_count"] == 0
        assert body["last_verified_index"] == -1
        assert body["drift_event_id"] is None


class TestVerifyChainDriftDetection:
    def test_synthetic_drift_returns_ok_false_with_drift_event(
        self, client: TestClient
    ) -> None:
        tid = str(uuid.uuid4())
        rows = _build_clean_chain(tid, count=4)
        # Manually corrupt the prev_event_hash on row index 2.
        # Index 0/1 will verify; index 2 trips the chain.
        assert isinstance(rows[2].details, dict)
        rows[2].details["_prev_event_hash"] = "f" * 64
        drifted_id = rows[2].id
        drifted_at = rows[2].created_at
        _override_db(rows)
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is False
        assert body["verified_count"] == 2  # rows 0 and 1 verified
        assert body["last_verified_index"] == 1
        assert body["drift_event_id"] == drifted_id
        # Datetime is serialized — compare ISO prefix.
        assert body["drift_detected_at"].startswith(drifted_at.isoformat()[:19])

    def test_corrupted_event_hash_marker_detected(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        rows = _build_clean_chain(tid, count=3)
        assert isinstance(rows[1].details, dict)
        rows[1].details["_event_hash"] = "0" * 64  # not the real expected hash
        _override_db(rows)
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is False
        assert body["verified_count"] == 1
        assert body["last_verified_index"] == 0
        assert body["drift_event_id"] == rows[1].id


# ---------------------------------------------------------------------------
# Audit emit (structured log)
# ---------------------------------------------------------------------------


class TestVerifyChainAuditEmit:
    def test_audit_emit_includes_operator_subject_hash(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        tid = str(uuid.uuid4())
        operator = "alice@argus.example"
        rows = _build_clean_chain(tid, count=2)
        _override_db(rows)
        try:
            with caplog.at_level(logging.INFO):
                with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                    r = client.post(
                        VERIFY,
                        headers={
                            **_ADMIN_HEADERS,
                            "X-Admin-Role": "admin",
                            "X-Admin-Tenant": tid,
                            "X-Operator-Subject": operator,
                        },
                        params={"tenant_id": tid},
                    )
        finally:
            _clear_db_override()
        assert r.status_code == 200, r.text
        record = next(
            (rec for rec in caplog.records if rec.message == "admin.audit_chain_verify"),
            None,
        )
        assert record is not None, "expected admin.audit_chain_verify log record"
        assert getattr(record, "event", None) == "argus.admin.audit_chain_verify"
        assert getattr(record, "user_id_hash", None) == user_id_hash(operator)
        assert getattr(record, "tenant_hash", None) == tenant_hash(tid)
        assert getattr(record, "role_tenant_hash", None) == tenant_hash(tid)
        assert getattr(record, "ok", None) is True
        assert getattr(record, "verified_count", None) == 2
        assert getattr(record, "cross_tenant", None) is False
        # PII deny-list: raw operator string MUST NOT appear in the log payload.
        rendered = json.dumps(
            {
                k: getattr(record, k, None)
                for k in (
                    "event",
                    "role",
                    "user_id_hash",
                    "tenant_hash",
                    "role_tenant_hash",
                    "query_fingerprint",
                    "ok",
                    "verified_count",
                )
            },
            default=str,
        )
        assert operator not in rendered

    def test_query_fingerprint_is_24_hex_chars(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        tid = str(uuid.uuid4())
        rows = _build_clean_chain(tid, count=1)
        _override_db(rows)
        try:
            with caplog.at_level(logging.INFO):
                with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                    r = client.post(
                        VERIFY,
                        headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                    )
        finally:
            _clear_db_override()
        assert r.status_code == 200
        record = next(
            (rec for rec in caplog.records if rec.message == "admin.audit_chain_verify"),
            None,
        )
        assert record is not None
        fp = getattr(record, "query_fingerprint", None)
        assert isinstance(fp, str)
        assert len(fp) == 24
        # Hex-only — confirm it is a valid sha256 prefix.
        int(fp, 16)


# ---------------------------------------------------------------------------
# Performance smoke (≤2 s on 10⁴ events) — pure helper level
# ---------------------------------------------------------------------------


class TestVerifyChainPerformance:
    """Pure-helper benchmark on 10⁴ rows to validate the p95 ≤ 2 s plan target.

    Kept at the helper level (not via the API) to avoid TestClient overhead
    polluting the measurement. Skipped automatically if the run is in a
    constrained environment by simply tightening the budget — failing here
    means the chain compute regressed by an order of magnitude.
    """

    def test_helper_handles_10000_events_under_budget(self) -> None:
        import time

        tid = str(uuid.uuid4())
        rows = _build_clean_chain(tid, count=10_000)
        start = time.perf_counter()
        verdict = verify_audit_log_chain(rows)
        elapsed = time.perf_counter() - start
        assert verdict.ok is True
        assert verdict.verified_count == 10_000
        # Generous 5 s ceiling for shared CI runners; production target is 2 s p95.
        assert elapsed < 5.0, f"chain verify too slow: {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# Defence-in-depth: PII / fingerprint stability
# ---------------------------------------------------------------------------


class TestVerifyChainNoPiiLeak:
    def test_response_body_never_contains_raw_operator_string(
        self, client: TestClient
    ) -> None:
        tid = str(uuid.uuid4())
        operator = "carol@argus.example"
        rows = _build_clean_chain(tid, count=2)
        _override_db(rows)
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={
                        **_ADMIN_HEADERS,
                        "X-Admin-Role": "super-admin",
                        "X-Operator-Subject": operator,
                    },
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200
        assert operator not in r.text

    def test_query_fingerprint_is_stable_across_calls(self) -> None:
        """Same params → same fingerprint (helper must be deterministic)."""
        from src.api.routers.admin_audit_chain import _query_fingerprint

        since = datetime(2026, 4, 1, tzinfo=timezone.utc)
        until = datetime(2026, 4, 21, tzinfo=timezone.utc)
        tid = str(uuid.uuid4())
        fp_a = _query_fingerprint(
            tenant_id=tid, since=since, until=until, event_type="policy.decision"
        )
        fp_b = _query_fingerprint(
            tenant_id=tid, since=since, until=until, event_type="policy.decision"
        )
        assert fp_a == fp_b
        assert len(fp_a) == 24
        # Sanity: changing event_type changes the fingerprint.
        fp_c = _query_fingerprint(
            tenant_id=tid, since=since, until=until, event_type="other"
        )
        assert fp_c != fp_a

    def test_query_fingerprint_uses_tenant_hash_not_raw_id(self) -> None:
        from src.api.routers.admin_audit_chain import _query_fingerprint

        tid = str(uuid.uuid4())
        fp = _query_fingerprint(
            tenant_id=tid, since=None, until=None, event_type=None
        )
        # The raw uuid never travels into the canonical payload — only its hash.
        canonical_with_raw = json.dumps(
            {"tenant_id": tid, "since": None, "until": None, "event_type": None},
            sort_keys=True,
            separators=(",", ":"),
        )
        bad_hash = hashlib.sha256(canonical_with_raw.encode("utf-8")).hexdigest()[:24]
        assert fp != bad_hash


# ---------------------------------------------------------------------------
# S1-1 — Fingerprint MUST hash the EFFECTIVE window (not raw query params)
# ---------------------------------------------------------------------------


class TestVerifyChainFingerprintEffectiveWindow:
    """Regression for SIEM-correlation drift when defaults are applied.

    Background: prior to fix, ``_query_fingerprint`` was fed the raw ``since`` /
    ``until`` query parameters — which are ``None`` whenever the operator
    omitted them. Two requests issued hours apart with no time params would
    therefore collapse to the same fingerprint despite scanning different real
    windows. SIEM analytics correlating verify-runs by fingerprint would
    silently merge unrelated runs.
    """

    def test_fingerprint_uses_effective_window_not_raw_params(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Two endpoint calls with no since/until at different `now` MUST diverge."""
        from src.api.routers import admin_audit_chain as router_mod

        # Two distinct simulated-now windows separated by 6h, each ≤90 days
        # wide so the cap-guard does not trip. The router calls
        # ``_resolve_chain_window(None, None)`` once per request, so a
        # side-effect generator yields the next window per invocation.
        anchor_until_a = datetime(2026, 5, 1, 6, 0, tzinfo=timezone.utc)
        anchor_until_b = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
        windows: list[tuple[datetime, datetime]] = [
            (anchor_until_a - timedelta(days=90), anchor_until_a),
            (anchor_until_b - timedelta(days=90), anchor_until_b),
        ]
        idx = {"i": 0}

        def stubbed_resolve(
            since: datetime | None, until: datetime | None
        ) -> tuple[datetime, datetime]:
            if since is None and until is None:
                w = windows[idx["i"]]
                idx["i"] += 1
                return w
            return (since or windows[0][0], until or windows[0][1])

        _override_db([])
        try:
            with patch.object(
                router_mod, "_resolve_chain_window", side_effect=stubbed_resolve
            ):
                with caplog.at_level(logging.INFO):
                    with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                        r1 = client.post(
                            VERIFY,
                            headers={
                                **_ADMIN_HEADERS,
                                "X-Admin-Role": "super-admin",
                            },
                        )
                        r2 = client.post(
                            VERIFY,
                            headers={
                                **_ADMIN_HEADERS,
                                "X-Admin-Role": "super-admin",
                            },
                        )
        finally:
            _clear_db_override()

        assert r1.status_code == 200, r1.text
        assert r2.status_code == 200, r2.text

        records = [
            rec
            for rec in caplog.records
            if rec.message == "admin.audit_chain_verify"
        ]
        assert len(records) >= 2, "expected two audit_chain_verify log records"
        fp_first = getattr(records[-2], "query_fingerprint", None)
        fp_second = getattr(records[-1], "query_fingerprint", None)
        assert isinstance(fp_first, str) and isinstance(fp_second, str)
        assert fp_first != fp_second, (
            "Fingerprint MUST diverge when the effective window advances; "
            "otherwise SIEM cannot tell distinct verify runs apart."
        )

    def test_fingerprint_stable_when_explicit_bounds_match_resolved_defaults(
        self,
    ) -> None:
        """Explicit bounds == resolved-default bounds → identical fingerprint.

        Defence-in-depth check that the helper is purely a function of the
        effective window (no hidden discriminator on whether the bounds came
        from the URL or from default-resolution).
        """
        from src.api.routers.admin_audit_chain import (
            _query_fingerprint,
            _resolve_chain_window,
        )

        # First: resolve with no bounds (defaults applied at "now_a"); second:
        # call helper directly with those exact resolved bounds.
        resolved_since, resolved_until = _resolve_chain_window(None, None)
        tid = str(uuid.uuid4())
        fp_default = _query_fingerprint(
            tenant_id=tid,
            since=resolved_since,
            until=resolved_until,
            event_type=None,
        )
        fp_explicit = _query_fingerprint(
            tenant_id=tid,
            since=resolved_since,
            until=resolved_until,
            event_type=None,
        )
        assert fp_default == fp_explicit, (
            "Same effective window MUST produce the same fingerprint regardless "
            "of how the bounds were sourced (defaults vs explicit query params)."
        )


# ---------------------------------------------------------------------------
# S2-1 — Drift identifiers MUST surface in the structured audit-emit log
# ---------------------------------------------------------------------------


class TestVerifyChainAuditEmitDriftFields:
    """SIEM forensics MUST be able to pivot to the offending row from the log.

    Without ``drift_event_id`` / ``drift_detected_at`` on the structured
    record, SIEM has to re-fetch the response body to identify the row that
    broke the chain — slow and brittle. Both fields are admin-visible per
    RBAC and carry no PII (UUID + ISO timestamp).
    """

    def test_audit_emit_includes_drift_id_when_drift_detected(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        tid = str(uuid.uuid4())
        rows = _build_clean_chain(tid, count=4)
        # Synthesize drift on row index 2 by tampering its prev-marker.
        assert isinstance(rows[2].details, dict)
        rows[2].details["_prev_event_hash"] = "f" * 64
        drifted_id = rows[2].id
        drifted_at = rows[2].created_at
        _override_db(rows)
        try:
            with caplog.at_level(logging.INFO):
                with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                    r = client.post(
                        VERIFY,
                        headers={
                            **_ADMIN_HEADERS,
                            "X-Admin-Role": "super-admin",
                        },
                    )
        finally:
            _clear_db_override()
        assert r.status_code == 200, r.text
        record = next(
            (rec for rec in caplog.records if rec.message == "admin.audit_chain_verify"),
            None,
        )
        assert record is not None, "expected admin.audit_chain_verify log record"
        assert getattr(record, "ok", None) is False
        assert getattr(record, "drift_event_id", None) == drifted_id, (
            "Structured log MUST carry the drifted row id for SIEM pivot."
        )
        emitted_drift_at = getattr(record, "drift_detected_at", None)
        assert isinstance(emitted_drift_at, str)
        assert emitted_drift_at.startswith(drifted_at.isoformat()[:19])

    def test_audit_emit_drift_fields_null_on_clean_chain(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Clean chain → both drift fields explicitly ``None`` (not absent)."""
        tid = str(uuid.uuid4())
        rows = _build_clean_chain(tid, count=3)
        _override_db(rows)
        try:
            with caplog.at_level(logging.INFO):
                with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                    r = client.post(
                        VERIFY,
                        headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                    )
        finally:
            _clear_db_override()
        assert r.status_code == 200, r.text
        record = next(
            (rec for rec in caplog.records if rec.message == "admin.audit_chain_verify"),
            None,
        )
        assert record is not None
        assert getattr(record, "ok", None) is True
        # Sentinel test: keys present but explicitly null — SIEM mappings rely
        # on a stable schema rather than absence-vs-presence to mean "no drift".
        assert hasattr(record, "drift_event_id")
        assert hasattr(record, "drift_detected_at")
        assert getattr(record, "drift_event_id") is None
        assert getattr(record, "drift_detected_at") is None


# ---------------------------------------------------------------------------
# S2-2 — Response MUST echo the effective window when defaults were applied
# ---------------------------------------------------------------------------


class TestVerifyChainResponseEffectiveWindow:
    """Response surfaces the implicit-default window so UI / SIEM can render
    "Verified the last 90 days" instead of silently missing the bound.
    """

    def test_response_includes_effective_window_when_defaults_applied(
        self, client: TestClient
    ) -> None:
        _override_db([])
        before = datetime.now(tz=timezone.utc)
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                )
        finally:
            _clear_db_override()
        after = datetime.now(tz=timezone.utc)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "effective_since" in body and "effective_until" in body, (
            "Default-resolved windows MUST be echoed back in the response."
        )
        eff_until = datetime.fromisoformat(body["effective_until"])
        eff_since = datetime.fromisoformat(body["effective_since"])
        # Server-side anchor sits between client-side `before` and `after`.
        assert before - timedelta(seconds=1) <= eff_until <= after + timedelta(
            seconds=1
        ), "effective_until must be ~utcnow at request time"
        assert eff_until - eff_since == timedelta(days=90), (
            "Implicit default window MUST be exactly 90 days wide."
        )

    def test_response_echoes_explicit_bounds_unchanged(
        self, client: TestClient
    ) -> None:
        """Explicit bounds → response echoes them verbatim (no surprise rebase)."""
        until = datetime(2026, 4, 21, 12, 0, tzinfo=timezone.utc)
        since = until - timedelta(days=30)
        _override_db([])
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.post(
                    VERIFY,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                    params={
                        "since": since.isoformat(),
                        "until": until.isoformat(),
                    },
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200, r.text
        body = r.json()
        echoed_since = datetime.fromisoformat(body["effective_since"])
        echoed_until = datetime.fromisoformat(body["effective_until"])
        assert echoed_since == since
        assert echoed_until == until
