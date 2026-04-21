"""Unit tests for :class:`NotificationDispatcher` (ARG-035)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

import pytest

from src.mcp.services.notifications import (
    AdapterResult,
    ENABLE_ENV,
    NotificationDispatcher,
    NotificationEvent,
    NotificationSeverity,
    NotifierProtocol,
    is_globally_enabled_via_env,
)
from tests.unit.mcp.services.notifications.conftest import make_event


class _StubNotifier:
    """Minimal in-process notifier used for dispatcher unit tests."""

    def __init__(
        self,
        name: str,
        *,
        delivered: bool = True,
        side_effect: Callable[[NotificationEvent, str], Awaitable[AdapterResult]]
        | None = None,
        raise_with: BaseException | None = None,
    ) -> None:
        self.name = name
        self.calls: list[tuple[str, NotificationEvent]] = []
        self._delivered = delivered
        self._side_effect = side_effect
        self._raise_with = raise_with
        self.closed = False

    async def send_with_retry(
        self, event: NotificationEvent, *, tenant_id: str
    ) -> AdapterResult:
        self.calls.append((tenant_id, event))
        if self._raise_with is not None:
            raise self._raise_with
        if self._side_effect is not None:
            return await self._side_effect(event, tenant_id)
        return AdapterResult(
            adapter_name=self.name,
            event_id=event.event_id,
            delivered=self._delivered,
            attempts=1 if self._delivered else 3,
            target_redacted="abc123def456",
            status_code=200 if self._delivered else 503,
            error_code=None if self._delivered else "http_5xx",
        )

    async def aclose(self) -> None:
        self.closed = True


def _build_dispatcher(
    *,
    adapters: list[NotifierProtocol],
    enabled: bool = True,
    audit_logger: object | None = None,
    per_tenant_disabled: dict[str, frozenset[str]] | None = None,
    enabled_adapters: set[str] | None = None,
) -> NotificationDispatcher:
    disp = NotificationDispatcher(
        adapters=adapters,
        enabled=enabled,
        audit_logger=audit_logger,  # type: ignore[arg-type]
        per_tenant_disabled_adapters=per_tenant_disabled,
    )
    targets = (
        enabled_adapters if enabled_adapters is not None else {a.name for a in adapters}
    )
    for a in adapters:
        disp.set_adapter_enabled(a.name, a.name in targets)
    return disp


class TestDispatcherDisabled:
    def test_globally_disabled_returns_empty(self) -> None:
        slack = _StubNotifier("slack")
        disp = _build_dispatcher(adapters=[slack], enabled=False)
        result = asyncio.run(disp.dispatch(make_event()))
        assert result == []
        assert slack.calls == []

    def test_per_adapter_disabled_skipped(self) -> None:
        slack = _StubNotifier("slack")
        linear = _StubNotifier("linear")
        disp = _build_dispatcher(
            adapters=[slack, linear],
            enabled_adapters={"linear"},
        )
        result = asyncio.run(
            disp.dispatch(make_event(severity=NotificationSeverity.HIGH))
        )
        names = {r.adapter_name for r in result}
        assert names == {"linear"}
        assert slack.calls == []

    def test_per_tenant_disabled_skipped(self) -> None:
        slack = _StubNotifier("slack")
        linear = _StubNotifier("linear")
        disp = _build_dispatcher(
            adapters=[slack, linear],
            per_tenant_disabled={"tenant-alpha": frozenset({"slack"})},
        )
        ev = make_event(tenant_id="tenant-alpha", severity=NotificationSeverity.HIGH)
        result = asyncio.run(disp.dispatch(ev))
        assert {r.adapter_name for r in result} == {"linear"}

    def test_adapter_enabled_default_is_false(self) -> None:
        slack = _StubNotifier("slack")
        disp = NotificationDispatcher(
            adapters=[slack],
            enabled=True,
        )
        result = asyncio.run(
            disp.dispatch(make_event(severity=NotificationSeverity.HIGH))
        )
        assert result == []
        assert slack.calls == []

    def test_unknown_event_type_returns_empty(self) -> None:
        slack = _StubNotifier("slack")
        disp = _build_dispatcher(adapters=[slack])
        ev = make_event(event_type="not.a.known.type")
        result = asyncio.run(disp.dispatch(ev))
        assert result == []
        assert slack.calls == []


class TestDispatcherFanOut:
    def test_all_enabled_adapters_called_in_order(self) -> None:
        slack = _StubNotifier("slack")
        linear = _StubNotifier("linear")
        jira = _StubNotifier("jira")
        disp = _build_dispatcher(adapters=[slack, linear, jira])
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(disp.dispatch(ev))
        assert [r.adapter_name for r in result] == ["slack", "linear", "jira"]
        for stub in (slack, linear, jira):
            assert stub.calls == [(ev.tenant_id, ev)]

    def test_partial_failure_does_not_short_circuit(self) -> None:
        slack = _StubNotifier("slack", delivered=True)
        linear = _StubNotifier("linear", delivered=False)
        jira = _StubNotifier("jira", delivered=True)
        disp = _build_dispatcher(adapters=[slack, linear, jira])
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(disp.dispatch(ev))
        delivered = {r.adapter_name: r.delivered for r in result}
        assert delivered == {"slack": True, "linear": False, "jira": True}

    def test_unhandled_exception_is_absorbed(self) -> None:
        slack = _StubNotifier("slack", raise_with=RuntimeError("boom"))
        linear = _StubNotifier("linear")
        disp = _build_dispatcher(adapters=[slack, linear])
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(disp.dispatch(ev))
        slack_result = next(r for r in result if r.adapter_name == "slack")
        assert slack_result.delivered is False
        assert slack_result.error_code == "unhandled_exception"
        linear_result = next(r for r in result if r.adapter_name == "linear")
        assert linear_result.delivered is True

    def test_empty_adapter_set_returns_empty(self) -> None:
        disp = _build_dispatcher(adapters=[])
        ev = make_event(severity=NotificationSeverity.HIGH)
        assert asyncio.run(disp.dispatch(ev)) == []


class TestDispatcherSchedule:
    def test_schedule_returns_task_that_completes(self) -> None:
        slack = _StubNotifier("slack")
        disp = _build_dispatcher(adapters=[slack])
        ev = make_event(severity=NotificationSeverity.HIGH)

        async def _runner() -> list[AdapterResult]:
            task = disp.schedule(ev)
            return await task

        result = asyncio.run(_runner())
        assert [r.adapter_name for r in result] == ["slack"]


class TestDispatcherAudit:
    def test_audit_log_emitted_with_summary(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        slack = _StubNotifier("slack")
        disp = NotificationDispatcher(
            adapters=[slack],
            enabled=True,
            audit_logger=object(),  # type: ignore[arg-type]
        )
        disp.set_adapter_enabled("slack", True)
        ev = make_event(severity=NotificationSeverity.HIGH)
        with caplog.at_level(
            logging.INFO, logger="src.mcp.services.notifications.dispatcher"
        ):
            asyncio.run(disp.dispatch(ev))
        records = [
            r for r in caplog.records if r.message == "mcp.notifications.dispatched"
        ]
        assert records, "expected mcp.notifications.dispatched log row"
        adapters_summary = records[-1].adapters
        assert adapters_summary[0]["adapter_name"] == "slack"
        assert adapters_summary[0]["delivered"] is True

    def test_unknown_event_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        slack = _StubNotifier("slack")
        disp = _build_dispatcher(adapters=[slack])
        ev = make_event(event_type="bogus.event")
        with caplog.at_level(
            logging.WARNING, logger="src.mcp.services.notifications.dispatcher"
        ):
            asyncio.run(disp.dispatch(ev))
        assert any(
            r.message == "mcp.notifications.unknown_event_type" for r in caplog.records
        )

    def test_audit_logger_absent_does_not_raise(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        slack = _StubNotifier("slack")
        disp = _build_dispatcher(adapters=[slack], audit_logger=None)
        ev = make_event(severity=NotificationSeverity.HIGH)
        with caplog.at_level(
            logging.INFO, logger="src.mcp.services.notifications.dispatcher"
        ):
            asyncio.run(disp.dispatch(ev))
        assert not any(
            r.message == "mcp.notifications.dispatched" for r in caplog.records
        )


class TestDispatcherToggle:
    def test_set_enabled_runtime_toggle(self) -> None:
        slack = _StubNotifier("slack")
        disp = _build_dispatcher(adapters=[slack], enabled=False)
        assert (
            asyncio.run(disp.dispatch(make_event(severity=NotificationSeverity.HIGH)))
            == []
        )
        disp.set_enabled(True)
        result = asyncio.run(
            disp.dispatch(make_event(severity=NotificationSeverity.HIGH))
        )
        assert [r.adapter_name for r in result] == ["slack"]

    def test_set_adapter_enabled_unknown_raises(self) -> None:
        slack = _StubNotifier("slack")
        disp = _build_dispatcher(adapters=[slack])
        with pytest.raises(KeyError):
            disp.set_adapter_enabled("ghost", True)

    def test_aclose_propagates_to_all_adapters(self) -> None:
        slack = _StubNotifier("slack")
        linear = _StubNotifier("linear")
        disp = _build_dispatcher(adapters=[slack, linear])
        asyncio.run(disp.aclose())
        assert slack.closed is True
        assert linear.closed is True

    def test_set_tenant_disabled_at_runtime(self) -> None:
        slack = _StubNotifier("slack")
        linear = _StubNotifier("linear")
        disp = _build_dispatcher(adapters=[slack, linear])
        ev = make_event(tenant_id="tenant-x", severity=NotificationSeverity.HIGH)
        disp.set_tenant_disabled_adapters("tenant-x", {"linear"})
        result = asyncio.run(disp.dispatch(ev))
        assert {r.adapter_name for r in result} == {"slack"}


class TestEnvFlag:
    def test_default_env_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ENABLE_ENV, raising=False)
        assert is_globally_enabled_via_env() is False

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_truthy_values_enable(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv(ENABLE_ENV, value)
        assert is_globally_enabled_via_env() is True

    @pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "garbage"])
    def test_falsy_values_disable(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv(ENABLE_ENV, value)
        assert is_globally_enabled_via_env() is False
