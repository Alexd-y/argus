"""P5 catalog integrity: the signed playbook catalog loads all 12 executable
scenarios, is Ed25519-verified on load, and every step/oracle is executable.
"""

from __future__ import annotations

from src.playbooks.planner import (
    _EXECUTABLE_ACTIONS_DEFAULT,
    _IMPLEMENTED_ORACLES,
)
from src.playbooks.registry import PlaybookRegistry

_EXPECTED_IDS = frozenset(
    {
        "auth.direct-protected-route",
        "authorization.method-variant",
        "idor.cross-user-read",
        "idor.cross-user-write",
        "massassignment.role-injection",
        "mfa.direct-step-skip",
        "race.single-use-token",
        "ratelimit.login-account-keyed",
        "ratelimit.otp-resend",
        "registration.duplicate-casefold",
        "reset.token-reuse-after-password-change",
        "session.logout-invalidation",
    }
)

_EXPECTED_APPROVAL_GATED = frozenset(
    {
        "idor.cross-user-write",
        "massassignment.role-injection",
        "race.single-use-token",
        "reset.token-reuse-after-password-change",
    }
)


def test_catalog_loads_twelve_signed_playbooks(playbook_registry: PlaybookRegistry) -> None:
    summary = playbook_registry.load()
    assert summary.total == 12
    assert frozenset(summary.playbook_ids) == _EXPECTED_IDS


def test_catalog_approval_gated_set(playbook_registry: PlaybookRegistry) -> None:
    gated = {pb.playbook_id for pb in playbook_registry.all() if pb.requires_approval}
    assert gated == _EXPECTED_APPROVAL_GATED


def test_every_playbook_is_executable_on_stub(playbook_registry: PlaybookRegistry) -> None:
    """Every step action has an interpreter and every oracle is implemented,
    so none of the 12 scenarios needs external infrastructure to execute."""
    for pb in playbook_registry.all():
        for step in (*pb.steps, *pb.cleanup):
            assert (
                step.action in _EXECUTABLE_ACTIONS_DEFAULT
            ), f"{pb.playbook_id}: step {step.id} uses non-executable action {step.action}"
        for assertion in pb.assertions:
            assert (
                assertion.type in _IMPLEMENTED_ORACLES
            ), f"{pb.playbook_id}: oracle {assertion.type} not implemented"


def test_every_playbook_declares_az0x7_provenance(playbook_registry: PlaybookRegistry) -> None:
    for pb in playbook_registry.all():
        assert pb.provenance.source_url == "https://github.com/Az0x7/vulnerability-Checklist"
        assert str(pb.provenance.adapted_at) == "2026-07-22"
