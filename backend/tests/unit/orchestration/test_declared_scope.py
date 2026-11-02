"""Engagement-scope confine: active tools stay within a declared target allow-list.

§6 gate enforcement: when a scan declares lab_allowed_targets / argus_lab_allowed_targets,
active sandbox tools must be confined to it in EVERY mode (not only the lab private-IP
bypass). A scope-less scan is unrestricted (unchanged), so this never breaks scans that
set no scope.
"""

from __future__ import annotations

from src.orchestration.execution_mode_context import target_in_declared_scope


def test_no_declared_scope_is_unrestricted() -> None:
    assert target_in_declared_scope("https://anything.example", {}) is True
    assert target_in_declared_scope("https://anything.example", None) is True
    assert target_in_declared_scope("https://x.example", {"lab_allowed_targets": []}) is True


def test_in_scope_domain_and_subdomain_allowed() -> None:
    opts = {"lab_allowed_targets": ["svalbard.ca"]}
    assert target_in_declared_scope("https://svalbard.ca/x", opts) is True
    assert target_in_declared_scope("https://www.svalbard.ca", opts) is True


def test_out_of_scope_denied() -> None:
    opts = {"lab_allowed_targets": ["svalbard.ca"]}
    assert target_in_declared_scope("https://evil.example", opts) is False
    assert (
        target_in_declared_scope("https://svalbard.ca.evil.com", opts) is False
    )  # not a subdomain


def test_csv_allowlist_and_cidr() -> None:
    opts = {"argus_lab_allowed_targets": "svalbard.ca, 10.0.0.0/24"}
    assert target_in_declared_scope("https://svalbard.ca", opts) is True
    assert target_in_declared_scope("10.0.0.5", opts) is True
    assert target_in_declared_scope("10.0.1.5", opts) is False


def test_mixed_in_and_out_of_scope_string_rejected() -> None:
    # Fail-closed: a target string mixing in- and out-of-scope hosts does not pass.
    opts = {"lab_allowed_targets": ["svalbard.ca"]}
    assert target_in_declared_scope("svalbard.ca evil.example", opts) is False


def test_empty_scope_values_are_unrestricted_not_deny() -> None:
    # The API emits "" / [] for a scope-less scan — these must NOT deny everything.
    assert target_in_declared_scope("https://x", {"argus_lab_allowed_targets": ""}) is True
    assert target_in_declared_scope("https://x", {"lab_allowed_targets": []}) is True
    assert (
        target_in_declared_scope(
            "https://x", {"lab_allowed_targets": [], "argus_lab_allowed_targets": ""}
        )
        is True
    )


def test_declared_but_unparseable_scope_fails_closed() -> None:
    # A declared scope of an unexpected shape must deny, not silently allow.
    assert target_in_declared_scope("https://x", {"lab_allowed_targets": {"a": 1}}) is False


def test_set_shape_allowlist_supported() -> None:
    assert (
        target_in_declared_scope("https://svalbard.ca", {"lab_allowed_targets": {"svalbard.ca"}})
        is True
    )
    assert (
        target_in_declared_scope("https://evil.example", {"lab_allowed_targets": {"svalbard.ca"}})
        is False
    )
