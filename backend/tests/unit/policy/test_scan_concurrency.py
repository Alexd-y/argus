"""Unit tests for :mod:`src.policy.scan_concurrency`."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.policy.scan_concurrency import (
    ScanConcurrencyError,
    _ACTIVE_STATUSES,
    _DEFAULT_MAX_CONCURRENT,
    check_scan_concurrency,
)


@pytest.fixture
def mock_session() -> AsyncMock:
    session = AsyncMock()
    session.execute = AsyncMock()
    return session


class TestActiveStatuses:
    def test_active_statuses_include_queued_running_awaiting(self) -> None:
        assert "queued" in _ACTIVE_STATUSES
        assert "running" in _ACTIVE_STATUSES
        assert "awaiting_approval" in _ACTIVE_STATUSES

    def test_default_max_concurrent_is_three(self) -> None:
        assert _DEFAULT_MAX_CONCURRENT == 3


class TestCheckScanConcurrency:
    @pytest.mark.asyncio
    async def test_allows_scan_when_below_limit(
        self, mock_session: AsyncMock
    ) -> None:
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 1
        mock_session.execute.return_value = mock_result

        await check_scan_concurrency(mock_session, "tenant-1", max_concurrent=3)

        mock_session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rejects_scan_at_limit(
        self, mock_session: AsyncMock
    ) -> None:
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 3
        mock_session.execute.return_value = mock_result

        with pytest.raises(ScanConcurrencyError) as exc_info:
            await check_scan_concurrency(mock_session, "tenant-1", max_concurrent=3)

        assert exc_info.value.active_count == 3
        assert exc_info.value.max_concurrent == 3

    @pytest.mark.asyncio
    async def test_rejects_scan_over_limit(
        self, mock_session: AsyncMock
    ) -> None:
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 5
        mock_session.execute.return_value = mock_result

        with pytest.raises(ScanConcurrencyError) as exc_info:
            await check_scan_concurrency(mock_session, "tenant-1", max_concurrent=3)

        assert exc_info.value.active_count == 5
        assert exc_info.value.max_concurrent == 3

    @pytest.mark.asyncio
    async def test_allows_two_concurrent_scans(
        self, mock_session: AsyncMock
    ) -> None:
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 2
        mock_session.execute.return_value = mock_result

        await check_scan_concurrency(mock_session, "tenant-1", max_concurrent=3)

    @pytest.mark.asyncio
    async def test_fail_open_on_db_error(self, mock_session: AsyncMock) -> None:
        mock_session.execute.side_effect = Exception("DB connection lost")

        await check_scan_concurrency(
            mock_session, "tenant-1", max_concurrent=3, fail_open=True
        )

    @pytest.mark.asyncio
    async def test_fail_closed_on_db_error(self, mock_session: AsyncMock) -> None:
        mock_session.execute.side_effect = Exception("DB connection lost")

        with pytest.raises(Exception, match="DB connection lost"):
            await check_scan_concurrency(
                mock_session, "tenant-1", max_concurrent=3, fail_open=False
            )

    @pytest.mark.asyncio
    async def test_uses_settings_default_max_concurrent(
        self, mock_session: AsyncMock
    ) -> None:
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 0
        mock_session.execute.return_value = mock_result

        with patch(
            "src.policy.scan_concurrency.settings"
        ) as mock_settings:
            mock_settings.scan_max_concurrent = 5
            await check_scan_concurrency(mock_session, "tenant-1")

    @pytest.mark.asyncio
    async def test_zero_active_scans_allows_creation(
        self, mock_session: AsyncMock
    ) -> None:
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 0
        mock_session.execute.return_value = mock_result

        await check_scan_concurrency(mock_session, "tenant-1", max_concurrent=3)


class TestScanConcurrencyError:
    def test_error_message_contains_counts(self) -> None:
        exc = ScanConcurrencyError(
            tenant_id="t-1", active_count=3, max_concurrent=3
        )
        assert "3" in str(exc)
        assert "3" in str(exc)
        assert "t-1" in str(exc)

    def test_error_attributes(self) -> None:
        exc = ScanConcurrencyError(
            tenant_id="t-1", active_count=5, max_concurrent=3
        )
        assert exc.tenant_id == "t-1"
        assert exc.active_count == 5
        assert exc.max_concurrent == 3