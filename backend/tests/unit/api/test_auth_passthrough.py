"""Auth-passthrough — engagement auth_config survives scan-create into the pipeline.

The public API previously dropped auth_config (ScanOptions has extra="ignore").
create_scan now validates req.auth_config as a TargetConfig and embeds it into
options["auth_config"], which the pipeline reads via
TargetConfig.from_scan_options. These tests lock that contract.
"""

from __future__ import annotations

import pytest
from src.api.schemas import ScanCreateRequest
from src.orchestration.auth_config import TargetConfig

_MIN_CFG = {
    "principals": [
        {
            "principal_id": "owner",
            "role": "owner",
            "credentials": {"username": "admin@juice-sh.op", "password": "admin123"},
        },
        {"principal_id": "anon", "role": "anonymous"},
    ]
}


def test_scan_create_request_accepts_auth_config():
    req = ScanCreateRequest(target="https://example.com", auth_config=_MIN_CFG)
    assert req.auth_config == _MIN_CFG


def test_scan_create_request_auth_config_defaults_none():
    req = ScanCreateRequest(target="https://example.com")
    assert req.auth_config is None


def test_embedded_auth_config_is_read_by_pipeline():
    # Mirror the create_scan embedding step, then assert the pipeline reader
    # (TargetConfig.from_scan_options) resolves the principals.
    options: dict = {}
    options["auth_config"] = _MIN_CFG
    tc = TargetConfig.from_scan_options(options)
    assert tc is not None
    roles = {p.role.value for p in tc.resolved_principals()}
    assert "owner" in roles
    assert "anonymous" in roles


def test_target_config_key_also_supported():
    tc = TargetConfig.from_scan_options({"target_config": _MIN_CFG})
    assert tc is not None
    assert any(p.principal_id == "owner" for p in tc.resolved_principals())


def test_invalid_auth_config_is_rejected():
    # create_scan validates via TargetConfig.from_json → invalid shape raises.
    with pytest.raises(Exception):  # noqa: B017 — pydantic ValidationError
        TargetConfig.from_json({"principals": [{"principal_id": "Bad ID!", "role": "owner"}]})
