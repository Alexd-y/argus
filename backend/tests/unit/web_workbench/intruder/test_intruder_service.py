"""Unit tests for the Intruder execution service (WB-P4b, offline).

Uses an in-memory fake repository + spy sender so the gate/budget/flag/resume/
control behaviour is exercised without a DB or network. Security-critical
assertions: an out-of-scope request is never sent, and an over-budget attack
sends nothing at all.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.policy.scope import ScopeKind, ScopeRule
from src.web_workbench.intruder.repository import (
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PAUSED,
    IntruderAttackDTO,
    IntruderRequestDTO,
)
from src.web_workbench.intruder.service import AttackControl, IntruderService
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.repeater.engine import RawResponse

_TENANT = "t-1"


def _attack(
    *,
    template: bytes,
    attack_type: str = "sniper",
    config: dict | None = None,
    checkpoint: dict | None = None,
) -> IntruderAttackDTO:
    now = datetime.now(tz=timezone.utc)
    return IntruderAttackDTO(
        id="atk-1",
        tenant_id=_TENANT,
        project_id="proj-1",
        name="attack",
        attack_type=attack_type,
        status="queued",
        raw_request_template=template,
        positions=None,
        payload_config=None,
        config=config,
        checkpoint=checkpoint,
        requests_total=0,
        requests_completed=0,
        findings_total=0,
        error_reason=None,
        version=1,
        created_at=now,
        updated_at=now,
    )


class _FakeRepo:
    """Minimal async stand-in for IntruderRepository used by the service."""

    def __init__(self, attack: IntruderAttackDTO) -> None:
        self._attack = attack
        self.records: list[dict] = []

    async def get_attack(self, _session, _tenant, _attack_id):
        return self._attack

    async def save_progress(self, _session, _tenant, _attack_id, **fields):
        data = self._attack.__dict__.copy()
        for key, value in fields.items():
            if value is not None:
                data[key] = value
        self._attack = IntruderAttackDTO(**data)
        return self._attack

    async def record_request(self, _session, _tenant, **kwargs):
        self.records.append(kwargs)
        now = datetime.now(tz=timezone.utc)
        return IntruderRequestDTO(
            id=f"req-{len(self.records)}",
            tenant_id=_TENANT,
            project_id=kwargs["project_id"],
            attack_id=kwargs["attack_id"],
            request_index=kwargs["request_index"],
            payload_label=kwargs.get("payload_label"),
            payload_index=kwargs.get("payload_index"),
            forward_outcome=kwargs["forward_outcome"],
            block_reason=kwargs.get("block_reason"),
            status_code=kwargs.get("status_code"),
            response_length=kwargs.get("response_length"),
            response_time_ms=kwargs.get("response_time_ms"),
            response_sha256=kwargs.get("response_sha256"),
            flagged=kwargs.get("flagged", False),
            error_reason=kwargs.get("error_reason"),
            created_at=now,
        )


class _SpySender:
    """Returns a response whose body depends on the request target."""

    def __init__(self, *, boom_on: str | None = None) -> None:
        self.calls = 0
        self._boom_on = boom_on

    def send(self, request, body: bytes) -> RawResponse:  # noqa: ARG002
        self.calls += 1
        marker = b"boom" if self._boom_on and self._boom_on in request.target else b"ok"
        raw = b"HTTP/1.1 200 OK\r\n\r\n" + marker
        return RawResponse(status_code=200, raw=raw, duration_ms=2)


def _scope() -> ProjectScopeService:
    return ProjectScopeService([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")])


_TEMPLATE = b"GET /?q={{x}} HTTP/1.1\r\nHost: app.example.com\r\n\r\n"


async def test_in_scope_attack_forwards_and_records_each_request() -> None:
    repo = _FakeRepo(_attack(template=_TEMPLATE))
    sender = _SpySender()
    service = IntruderService(repo, sender=sender)
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"a", b"b"]]
    )
    assert summary.status == STATUS_COMPLETED
    assert summary.requests_planned == 2
    assert summary.forwarded == 2
    assert sender.calls == 2
    assert all(r["forward_outcome"] == "forward" for r in repo.records)


async def test_out_of_scope_attack_blocks_without_sending() -> None:
    template = b"GET /?q={{x}} HTTP/1.1\r\nHost: evil.test\r\n\r\n"
    repo = _FakeRepo(_attack(template=template))
    sender = _SpySender()
    service = IntruderService(repo, sender=sender)
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"a", b"b"]]
    )
    assert summary.blocked == 2
    assert summary.forwarded == 0
    assert sender.calls == 0  # SI-WB-1: nothing left the process
    assert all(r["forward_outcome"] == "blocked" for r in repo.records)
    assert repo.records[0]["block_reason"] == "out_of_scope"


async def test_over_budget_attack_sends_nothing_and_fails_closed() -> None:
    repo = _FakeRepo(_attack(template=_TEMPLATE, config={"max_requests": 1}))
    sender = _SpySender()
    service = IntruderService(repo, sender=sender)
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"a", b"b"]]
    )
    assert summary.status == STATUS_FAILED
    assert summary.completed == 0
    assert sender.calls == 0
    assert repo.records == []
    assert repo._attack.error_reason == "budget_exceeded"


async def test_grep_flags_matching_response() -> None:
    repo = _FakeRepo(
        _attack(template=_TEMPLATE, config={"grep": {"patterns": ["boom"], "regex": False}})
    )
    sender = _SpySender(boom_on="q=b")
    service = IntruderService(repo, sender=sender)
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"a", b"b"]]
    )
    assert summary.flagged == 1
    flagged = [r for r in repo.records if r.get("flagged")]
    assert len(flagged) == 1
    assert flagged[0]["request_index"] == 1


async def test_flag_on_status_code() -> None:
    repo = _FakeRepo(_attack(template=_TEMPLATE, config={"flag_statuses": [200]}))
    sender = _SpySender()
    service = IntruderService(repo, sender=sender)
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"a"]]
    )
    assert summary.flagged == 1


async def test_resume_skips_already_recorded_indices() -> None:
    repo = _FakeRepo(_attack(template=_TEMPLATE, checkpoint={"next_index": 1}))
    sender = _SpySender()
    service = IntruderService(repo, sender=sender)
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"a", b"b"]]
    )
    assert summary.completed == 1
    assert sender.calls == 1
    assert repo.records[0]["request_index"] == 1


async def test_cancel_control_hook_halts_run() -> None:
    repo = _FakeRepo(_attack(template=_TEMPLATE))
    sender = _SpySender()
    service = IntruderService(
        repo,
        sender=sender,
        control_hook=lambda: AttackControl.CANCEL,
        control_poll_interval=1,
    )
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"a", b"b", b"c"]]
    )
    assert summary.status == STATUS_CANCELLED
    assert summary.completed == 1  # first request ran, then cancel was observed


async def test_pause_control_hook_holds_run() -> None:
    repo = _FakeRepo(_attack(template=_TEMPLATE))
    sender = _SpySender()
    service = IntruderService(
        repo,
        sender=sender,
        control_hook=lambda: AttackControl.PAUSE,
        control_poll_interval=1,
    )
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"a", b"b", b"c"]]
    )
    assert summary.status == STATUS_PAUSED
    assert repo._attack.checkpoint == {"next_index": 1}


async def test_malformed_rendered_request_is_recorded_errored() -> None:
    repo = _FakeRepo(_attack(template=b"{{x}}"))
    sender = _SpySender()
    service = IntruderService(repo, sender=sender)
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"zz"]]
    )
    assert summary.errored == 1
    assert sender.calls == 0
    assert repo.records[0]["error_reason"] == "malformed_request"


async def test_payload_labels_recorded_as_reference() -> None:
    repo = _FakeRepo(_attack(template=_TEMPLATE))
    sender = _SpySender()
    service = IntruderService(repo, sender=sender)
    await service.run_attack(
        None,
        _TENANT,
        "atk-1",
        scope_service=_scope(),
        payload_sets=[[b"a", b"b"]],
        payload_labels=["xss[0]", "xss[1]"],
    )
    assert repo.records[0]["payload_label"] == "xss[0]"
    assert repo.records[1]["payload_label"] == "xss[1]"


async def test_send_failure_recorded_without_aborting_run() -> None:
    class _FlakySender:
        def __init__(self) -> None:
            self.calls = 0

        def send(self, request, body):  # noqa: ARG002
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("connection reset")
            return RawResponse(status_code=200, raw=b"HTTP/1.1 200 OK\r\n\r\nok", duration_ms=1)

    repo = _FakeRepo(_attack(template=_TEMPLATE))
    service = IntruderService(repo, sender=_FlakySender())
    summary = await service.run_attack(
        None, _TENANT, "atk-1", scope_service=_scope(), payload_sets=[[b"a", b"b"]]
    )
    assert summary.errored == 1
    assert summary.forwarded == 1
    assert summary.status == STATUS_COMPLETED
    assert repo.records[0]["error_reason"] == "send_failed"


def test_control_poll_interval_must_be_positive() -> None:
    with pytest.raises(ValueError, match="control_poll_interval"):
        IntruderService(
            _FakeRepo(_attack(template=_TEMPLATE)), sender=_SpySender(), control_poll_interval=0
        )
