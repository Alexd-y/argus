"""Multi-principal auth config: back-compat + new principals (P3-AUTH-003, G-2)."""

from __future__ import annotations

from src.orchestration.auth_config import (
    AuthConfig,
    AuthCredentials,
    LoginFlowStep,
    LoginType,
    PrincipalConfig,
    PrincipalRole,
    SuccessCondition,
    SuccessConditionType,
    TargetConfig,
)

_LEGACY_YAML = """\
description: Legacy single-auth target
authentication:
  login_type: form
  login_url: https://app.example.com/login
  credentials:
    username: owner@example.com
    password: s3cret
  login_flow:
    - instruction: Type $username into the email field
    - instruction: Type $password into the password field
    - instruction: Click Sign In
  success_condition:
    type: url_contains
    value: /dashboard
exploit: true
"""


class TestLegacyBackCompat:
    """SI-7: the pre-existing single-``authentication`` model still works."""

    def test_legacy_auth_maps_to_single_owner_principal(self) -> None:
        cfg = TargetConfig.from_yaml(_LEGACY_YAML)
        principals = cfg.resolved_principals()

        assert len(principals) == 1
        owner = principals[0]
        assert owner.principal_id == "owner"
        assert owner.role is PrincipalRole.OWNER
        assert owner.login is not None
        assert owner.login.login_url == "https://app.example.com/login"
        assert owner.credentials is not None
        assert owner.credentials.username == "owner@example.com"

    def test_resolve_placeholders_unchanged(self) -> None:
        cfg = TargetConfig.from_yaml(_LEGACY_YAML)
        resolved = cfg.resolve_placeholders()

        assert resolved.authentication is not None
        assert "owner@example.com" in resolved.authentication.login_flow[0].instruction
        assert "s3cret" in resolved.authentication.login_flow[1].instruction

    def test_no_auth_yields_empty_principals(self) -> None:
        cfg = TargetConfig(description="anon target")
        assert cfg.resolved_principals() == []


class TestMultiPrincipal:
    """G-2: several declared principals coexist."""

    def _cfg(self) -> TargetConfig:
        owner = PrincipalConfig(
            principal_id="owner",
            role=PrincipalRole.OWNER,
            tenant_id="tenant_a",
            login=AuthConfig(
                login_type=LoginType.FORM,
                login_url="https://app.example.com/login",
                credentials=AuthCredentials(username="owner@example.com", password="ownerpw"),
                login_flow=[
                    LoginFlowStep(instruction="Type $username", selector="#u", value="$username"),
                    LoginFlowStep(instruction="Type $password", selector="#p", value="$password"),
                ],
                success_condition=SuccessCondition(
                    type=SuccessConditionType.URL_CONTAINS, value="/dashboard"
                ),
            ),
        )
        attacker = PrincipalConfig(
            principal_id="attacker",
            role=PrincipalRole.ATTACKER,
            tenant_id="tenant_b",
            bearer_token_ref="ATTACKER_BEARER",
        )
        return TargetConfig(description="multi", principals=[owner, attacker])

    def test_principals_take_precedence_over_legacy(self) -> None:
        cfg = self._cfg()
        principals = cfg.resolved_principals()

        assert [p.principal_id for p in principals] == ["owner", "attacker"]
        assert principals[0].role is PrincipalRole.OWNER
        assert principals[1].role is PrincipalRole.ATTACKER
        # Split-plane: attacker carries only a handle, never a value.
        assert principals[1].bearer_token_ref == "ATTACKER_BEARER"
        assert principals[1].credentials is None

    def test_principal_placeholder_resolution(self) -> None:
        owner = self._cfg().resolved_principals()[0]
        resolved = owner.resolve_placeholders()

        assert resolved.login is not None
        assert resolved.login.login_flow[0].value == "owner@example.com"
        assert resolved.login.login_flow[1].value == "ownerpw"

    def test_yaml_round_trip_with_principals(self) -> None:
        yaml_cfg = """\
description: multi-principal
principals:
  - principal_id: owner
    role: owner
    tenant_id: tenant_a
    login:
      login_type: form
      login_url: https://app/login
      credentials:
        username: u
        password: p
  - principal_id: anon
    role: anonymous
"""
        cfg = TargetConfig.from_yaml(yaml_cfg)
        principals = cfg.resolved_principals()
        assert len(principals) == 2
        assert principals[0].tenant_id == "tenant_a"
        assert principals[1].role is PrincipalRole.ANONYMOUS
        assert principals[1].login is None
