"""Offline unit tests for the pure helpers in ``intruder.tasks`` (WB-P4b).

The live send loop is infra-gated; here we cover the two pure helpers used by
the task: the DB-status→control-signal mapping (kill-switch) and payload-set
materialisation from signed-registry *references* (no raw payload in config).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from src.web_workbench.intruder.repository import STATUS_CANCELLED, STATUS_PAUSED, STATUS_RUNNING
from src.web_workbench.intruder.service import AttackControl
from src.web_workbench.intruder.tasks import control_from_status, materialize_payload_sets


def test_control_from_status_cancel_is_kill_switch() -> None:
    assert control_from_status(STATUS_CANCELLED) is AttackControl.CANCEL


def test_control_from_status_pause_holds() -> None:
    assert control_from_status(STATUS_PAUSED) is AttackControl.PAUSE


@pytest.mark.parametrize("status", [STATUS_RUNNING, "queued", None, "completed"])
def test_control_from_status_otherwise_continues(status: str | None) -> None:
    assert control_from_status(status) is AttackControl.CONTINUE


# -- materialize_payload_sets -----------------------------------------------


@dataclass
class _Rendered:
    id: str
    payload: str


@dataclass
class _Bundle:
    family_id: str
    payloads: list[_Rendered]


class _FakeBuilder:
    """Records build requests and returns deterministic bundles."""

    def __init__(self) -> None:
        self.requests: list[str] = []

    def build(self, request):  # noqa: ANN001 — duck-typed PayloadBuildRequest
        self.requests.append(request.family_id)
        return _Bundle(
            family_id=request.family_id,
            payloads=[
                _Rendered(id="p0", payload="<script>"),
                _Rendered(id="p1", payload="' OR 1=1"),
            ],
        )


def test_materialize_single_set_returns_bytes_and_labels() -> None:
    builder = _FakeBuilder()
    sets, labels = materialize_payload_sets({"sets": [{"family_id": "xss_basic"}]}, builder=builder)
    assert sets == [[b"<script>", b"' OR 1=1"]]
    assert labels == ["xss_basic#p0", "xss_basic#p1"]
    assert builder.requests == ["xss_basic"]


def test_materialize_multiple_sets_labels_from_first_only() -> None:
    builder = _FakeBuilder()
    sets, labels = materialize_payload_sets(
        {"sets": [{"family_id": "fam_a"}, {"family_id": "fam_b"}]}, builder=builder
    )
    assert len(sets) == 2
    # Labels are ordinal references to the first set (sniper/battering-ram).
    assert labels == ["fam_a#p0", "fam_a#p1"]
    assert builder.requests == ["fam_a", "fam_b"]


@pytest.mark.parametrize("bad", [None, {}, {"sets": []}, {"sets": "x"}])
def test_materialize_rejects_malformed_config(bad: object) -> None:
    with pytest.raises(ValueError, match="sets"):
        materialize_payload_sets(bad, builder=_FakeBuilder())  # type: ignore[arg-type]
