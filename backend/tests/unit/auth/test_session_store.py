"""SessionStore lifecycle, isolation, and secret resolution (P3-AUTH-003)."""

from __future__ import annotations

import json

import pytest

from src.auth.session_store import (
    PrincipalSession,
    SecretResolutionError,
    SessionNotFoundError,
    SessionStore,
)
from src.orchestration.auth_config import PrincipalConfig, PrincipalRole


class TestLifecycle:
    def test_create_get_invalidate(self) -> None:
        store = SessionStore()
        session = store.create_session("owner", PrincipalRole.OWNER, tenant_id="t1")

        assert isinstance(session, PrincipalSession)
        assert store.get_session("owner") is session
        assert "owner" in store
        assert len(store) == 1

        assert store.invalidate("owner") is True
        assert store.get_session("owner") is None
        assert store.invalidate("owner") is False

    def test_refresh_extends_ttl(self) -> None:
        store = SessionStore(default_ttl_seconds=100)
        store.create_session("owner", PrincipalRole.OWNER)
        first_exp = store.get_session("owner").expires_at

        refreshed = store.refresh("owner", ttl_seconds=10_000)
        assert refreshed.expires_at is not None
        assert first_exp is not None
        assert refreshed.expires_at > first_exp

    def test_refresh_unknown_raises(self) -> None:
        store = SessionStore()
        with pytest.raises(SessionNotFoundError):
            store.refresh("ghost")

    def test_logout_clears_and_removes(self) -> None:
        store = SessionStore()
        session = store.create_session("owner", PrincipalRole.OWNER)
        session.set_cookie("sid", "value")
        session.set_bearer("token")

        assert store.logout("owner") is True
        assert store.get_session("owner") is None
        # session object itself is scrubbed
        assert session.cookies_as_map() == {}
        assert session.headers() == {}
        assert store.logout("owner") is False


class TestIsolation:
    """G-2: cookie jars of different principals never mix."""

    def test_owner_cookie_not_visible_to_attacker(self) -> None:
        store = SessionStore()
        owner = store.create_session("owner", PrincipalRole.OWNER)
        attacker = store.create_session("attacker", PrincipalRole.ATTACKER)

        owner.set_cookie("session", "OWNER-JAR-VALUE")
        attacker.set_cookie("session", "ATTACKER-JAR-VALUE")

        assert owner.get_cookie("session") == "OWNER-JAR-VALUE"
        assert attacker.get_cookie("session") == "ATTACKER-JAR-VALUE"
        # Owner's secret must not leak into the attacker's session.
        assert "OWNER-JAR-VALUE" not in attacker.cookie_header()
        assert attacker.get_cookie("owner_only") is None

    def test_setting_owner_cookie_after_creation_does_not_touch_attacker(self) -> None:
        store = SessionStore()
        owner = store.create_session("owner", PrincipalRole.OWNER)
        attacker = store.create_session("attacker", PrincipalRole.ATTACKER)

        owner.set_cookie("only_owner", "SECRET")
        assert attacker.has_cookie("only_owner") is False
        assert "SECRET" not in json.dumps(attacker.to_redacted_dict())


class TestSecretResolution:
    """SI-3: secret_ref resolves only on the execution layer; never logged."""

    def test_resolve_from_injected_map(self) -> None:
        store = SessionStore(secrets={"OWNER_PW": "supersecret"})
        assert store.resolve_secret("OWNER_PW") == "supersecret"

    def test_resolve_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARGUS_TEST_SECRET_REF", "env-value")
        store = SessionStore()
        assert store.resolve_secret("ARGUS_TEST_SECRET_REF") == "env-value"

    def test_unresolvable_raises(self) -> None:
        store = SessionStore(allow_env=False)
        with pytest.raises(SecretResolutionError):
            store.resolve_secret("MISSING_HANDLE")

    def test_secret_not_in_store_repr(self) -> None:
        store = SessionStore(secrets={"OWNER_PW": "supersecret"})
        assert "supersecret" not in repr(store)
        assert "OWNER_PW" not in repr(store)  # ref map is not enumerated either

    def test_create_session_for_principal_resolves_bearer(self) -> None:
        store = SessionStore(secrets={"BR": "bearer-tok", "AK": "api-key-val"})
        principal = PrincipalConfig(
            principal_id="attacker",
            role=PrincipalRole.ATTACKER,
            bearer_token_ref="BR",
            api_key_ref="AK",
        )
        session = store.create_session_for_principal(principal)

        assert session.headers()["Authorization"] == "Bearer bearer-tok"
        assert session.headers()["X-API-Key"] == "api-key-val"
        # …but the resolved values never appear in the repr.
        assert "bearer-tok" not in repr(session)
        assert "api-key-val" not in repr(session)

    def test_create_session_for_principal_missing_secret_fails_loud(self) -> None:
        store = SessionStore(allow_env=False)
        principal = PrincipalConfig(
            principal_id="attacker",
            role=PrincipalRole.ATTACKER,
            bearer_token_ref="NOPE",
        )
        with pytest.raises(SecretResolutionError):
            store.create_session_for_principal(principal)


class TestExploitationExport:
    def test_as_exploitation_auth_shape(self) -> None:
        store = SessionStore()
        session = store.create_session("owner", PrincipalRole.OWNER)
        session.set_cookie("sid", "abc")
        session.set_cookie("csrf", "xyz")
        session.set_bearer("tok")

        ctx = session.as_exploitation_auth()
        assert ctx["principal_id"] == "owner"
        assert ctx["cookies"] == {"sid": "abc", "csrf": "xyz"}
        assert ctx["cookie_header"] == "sid=abc; csrf=xyz"
        assert ctx["headers"]["Authorization"] == "Bearer tok"
