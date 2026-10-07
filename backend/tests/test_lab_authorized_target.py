"""Lab-unrestriction tranche 1 — scope-bound guardrail bypass for lab_unrestricted.

The internal-network guardrail (RFC1918 / loopback / metadata) is lifted ONLY when
execution mode is lab_unrestricted AND the target is inside the operator-declared
lab scope (argus_lab_allowed_targets). Fail-closed everywhere else.
"""

from __future__ import annotations

from types import SimpleNamespace

from src.orchestration.execution_mode_context import lab_authorized_target
from src.tools.guardrails import validate_target_for_tool

_LAB = {"execution_mode": "lab_unrestricted"}
_PROD = {"execution_mode": "production"}


def test_guardrail_bypass_only_when_lab_authorized() -> None:
    # default (production path): private IP blocked
    assert validate_target_for_tool("10.10.0.5", "nmap")["allowed"] is False
    # lab_authorized: internal-network guard lifted
    r = validate_target_for_tool("10.10.0.5", "nmap", lab_authorized=True)
    assert r["allowed"] is True
    assert r["reason"] == "lab_unrestricted_authorized_scope"
    # empty target still rejected even when lab_authorized
    assert validate_target_for_tool("", "nmap", lab_authorized=True)["allowed"] is False


def test_requires_lab_unrestricted_mode() -> None:
    s = SimpleNamespace(argus_lab_allowed_targets="10.10.0.0/24")
    assert lab_authorized_target("10.10.0.5", _PROD, settings=s) is False
    assert lab_authorized_target("10.10.0.5", _LAB, settings=s) is True


def test_scope_membership_cidr_and_domain() -> None:
    s = SimpleNamespace(argus_lab_allowed_targets="lab.example.com,10.10.0.0/24")
    assert lab_authorized_target("lab.example.com", _LAB, settings=s) is True
    assert lab_authorized_target("https://api.lab.example.com/path", _LAB, settings=s) is True
    assert lab_authorized_target("10.10.0.200", _LAB, settings=s) is True
    # out of scope
    assert lab_authorized_target("10.20.0.1", _LAB, settings=s) is False
    assert lab_authorized_target("evil.example.org", _LAB, settings=s) is False
    # a sibling domain that merely contains the allowed string must NOT match
    assert lab_authorized_target("notlab.example.com.attacker.net", _LAB, settings=s) is False


def test_fail_closed_on_empty_scope() -> None:
    s = SimpleNamespace(argus_lab_allowed_targets="")
    assert lab_authorized_target("10.10.0.5", _LAB, settings=s) is False
