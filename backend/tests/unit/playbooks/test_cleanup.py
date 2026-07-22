"""Tests for the P4 :class:`CleanupRunner` (always-run teardown)."""

from __future__ import annotations

from src.playbooks.actions import (
    ActionContext,
    HttpRequestSpec,
    HttpResponse,
    RegisterCleanupAction,
)
from src.playbooks.cleanup import CleanupRunner
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.schema import Playbook


class _StubHttp:
    def __init__(self, *, fail_on: str | None = None) -> None:
        self._fail_on = fail_on
        self.sent: list[str] = []

    def send(self, spec: HttpRequestSpec, *, principal: str | None = None) -> HttpResponse:
        self.sent.append(spec.url)
        if self._fail_on is not None and self._fail_on in spec.url:
            raise RuntimeError("simulated cleanup failure")
        return HttpResponse(status=204, body="")


def _cleanup_playbook() -> Playbook:
    return Playbook(
        schema_version=1,
        playbook_id="account.cleanup-test",
        version=1,
        title="Cleanup test",
        description="Declarative cleanup test playbook.",
        category="account_lifecycle",
        risk_level="low",
        requires_approval=False,
        steps=[
            {
                "id": "create_probe",
                "action": "http_request",
                "params": {
                    "method": "POST",
                    "url": "https://api.example.com/accounts",
                    "headers": {},
                },
            }
        ],
        assertions=[{"type": "authn", "params": {}}],
        cleanup=[
            {
                "id": "del_a",
                "action": "http_request",
                "params": {
                    "method": "DELETE",
                    "url": "https://api.example.com/accounts/a",
                    "headers": {},
                },
            },
            {
                "id": "del_b",
                "action": "http_request",
                "params": {
                    "method": "DELETE",
                    "url": "https://api.example.com/accounts/b",
                    "headers": {},
                },
            },
        ],
    )


def test_runs_only_registered_steps() -> None:
    http = _StubHttp()
    ctx = ActionContext(http=http)
    ctx.variables[RegisterCleanupAction._VAR_KEY] = ["del_a"]
    outcome = CleanupRunner().run(_cleanup_playbook(), ctx)
    assert outcome.status is ScenarioStatus.CLEANUP_COMPLETE
    assert outcome.executed_step_ids == ("del_a",)
    assert http.sent == ["https://api.example.com/accounts/a"]


def test_falls_back_to_all_cleanup_steps_when_none_registered() -> None:
    http = _StubHttp()
    ctx = ActionContext(http=http)
    outcome = CleanupRunner().run(_cleanup_playbook(), ctx)
    assert outcome.status is ScenarioStatus.CLEANUP_COMPLETE
    assert set(outcome.executed_step_ids) == {"del_a", "del_b"}


def test_cleanup_failure_is_reported_not_raised() -> None:
    http = _StubHttp(fail_on="accounts/b")
    ctx = ActionContext(http=http)
    outcome = CleanupRunner().run(_cleanup_playbook(), ctx)
    assert outcome.status is ScenarioStatus.CLEANUP_FAILED
    assert outcome.reason is not None
    assert "del_b" in outcome.failed_step_ids
    # del_a still ran even though del_b failed (teardown is total).
    assert "del_a" in outcome.executed_step_ids


def test_no_cleanup_steps_is_complete() -> None:
    playbook = Playbook(
        schema_version=1,
        playbook_id="account.no-cleanup",
        version=1,
        title="No cleanup",
        description="Playbook with no cleanup steps.",
        category="account_lifecycle",
        risk_level="low",
        requires_approval=False,
        steps=[
            {
                "id": "probe",
                "action": "http_request",
                "params": {
                    "method": "GET",
                    "url": "https://api.example.com/x",
                    "headers": {},
                },
            }
        ],
        assertions=[{"type": "authn", "params": {}}],
    )
    outcome = CleanupRunner().run(playbook, ActionContext(http=_StubHttp()))
    assert outcome.status is ScenarioStatus.CLEANUP_COMPLETE
