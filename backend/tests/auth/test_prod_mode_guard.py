"""Boot-time guard for production admin auth (B6-T09 / ISS-T20-003).

Covers the ``Settings._enforce_production_admin_auth`` model-validator
added to :mod:`src.core.config`. The guard fires only when the
``ENVIRONMENT`` env var is exactly ``production`` (case-insensitive) and
either:

* ``ADMIN_AUTH_MODE`` is anything other than ``session`` (the cookie shim
  is dev-only and would let any visitor mint themselves an admin role); or
* sessions are enabled (``session`` / ``both``) but ``ADMIN_SESSION_PEPPER``
  is empty (the resolver hard-fails with HTTP 503 without the pepper).

Both failure paths must abort the process via ``SystemExit(1)`` so
operators see the misconfiguration at boot — not on the first admin
request. Non-production environments must NEVER trigger the guard,
regardless of mode / pepper combo, so dev / staging / CI keeps working
with the legacy defaults.

Test isolation
--------------
We instantiate a fresh ``Settings()`` per test so the global ``settings``
singleton (initialised at module import with the dev defaults) is not
disturbed by env mutations. ``monkeypatch.setenv`` / ``delenv`` are
sufficient because the validator reads ``ENVIRONMENT`` via ``os.getenv``
and pydantic-settings re-reads the env on every ``__init__`` call.
"""

from __future__ import annotations

import pytest

from src.core.config import Settings


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


def _set_admin_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    environment: str | None,
    admin_auth_mode: str | None,
    admin_session_pepper: str | None,
) -> None:
    """Pin the three knobs the guard inspects; ``None`` means delete."""
    for key, value in (
        ("ENVIRONMENT", environment),
        ("ADMIN_AUTH_MODE", admin_auth_mode),
        ("ADMIN_SESSION_PEPPER", admin_session_pepper),
    ):
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)


_VALID_PEPPER = "test-pepper-iss-t20-003-not-for-prod-32chars-min"


# ---------------------------------------------------------------------------
# Production: unsafe ADMIN_AUTH_MODE values must abort boot
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["cookie", "both"])
def test_production_rejects_non_session_mode(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ENVIRONMENT=production`` + cookie/both mode → SystemExit(1)."""
    _set_admin_env(
        monkeypatch,
        environment="production",
        admin_auth_mode=mode,
        admin_session_pepper=_VALID_PEPPER,
    )
    with pytest.raises(SystemExit) as excinfo:
        Settings()
    assert excinfo.value.code == 1


def test_production_rejects_unknown_mode_normalised_to_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown values (e.g. front-end-only ``auto``) normalise to ``both`` and fail.

    Settings.normalize_admin_auth_mode treats anything outside the closed
    {cookie, session, both} taxonomy as ``both`` — the guard then trips on
    the result so a typo or stale frontend env can never silently survive.
    """
    _set_admin_env(
        monkeypatch,
        environment="production",
        admin_auth_mode="auto",
        admin_session_pepper=_VALID_PEPPER,
    )
    with pytest.raises(SystemExit):
        Settings()


def test_production_environment_value_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``Production`` / ``PRODUCTION`` / ``  production  `` all trigger the guard."""
    for variant in ("Production", "PRODUCTION", "  production  "):
        _set_admin_env(
            monkeypatch,
            environment=variant,
            admin_auth_mode="cookie",
            admin_session_pepper=_VALID_PEPPER,
        )
        with pytest.raises(SystemExit):
            Settings()


# ---------------------------------------------------------------------------
# Production: missing ADMIN_SESSION_PEPPER must abort boot when sessions are on
# ---------------------------------------------------------------------------


def test_production_session_mode_requires_pepper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``session`` mode with empty pepper → SystemExit(1)."""
    _set_admin_env(
        monkeypatch,
        environment="production",
        admin_auth_mode="session",
        admin_session_pepper="",
    )
    with pytest.raises(SystemExit) as excinfo:
        Settings()
    assert excinfo.value.code == 1


def test_production_session_mode_rejects_whitespace_only_pepper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whitespace-only pepper is treated as empty (no real entropy)."""
    _set_admin_env(
        monkeypatch,
        environment="production",
        admin_auth_mode="session",
        admin_session_pepper="   \t\n",
    )
    with pytest.raises(SystemExit):
        Settings()


def test_production_session_mode_with_pepper_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: session mode + non-empty pepper → no error."""
    _set_admin_env(
        monkeypatch,
        environment="production",
        admin_auth_mode="session",
        admin_session_pepper=_VALID_PEPPER,
    )
    s = Settings()
    assert s.admin_auth_mode == "session"
    assert s.admin_session_pepper == _VALID_PEPPER


# ---------------------------------------------------------------------------
# Non-production environments: guard MUST stay silent for every combo
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env", ["development", "staging", "test", "", "dev"])
@pytest.mark.parametrize("mode", ["cookie", "session", "both"])
def test_non_production_environment_never_trips_guard(
    env: str,
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dev / staging / empty ENVIRONMENT must boot regardless of mode + pepper."""
    _set_admin_env(
        monkeypatch,
        environment=env,
        admin_auth_mode=mode,
        admin_session_pepper="",
    )
    s = Settings()
    assert s.admin_auth_mode == mode


def test_environment_unset_never_trips_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing ENVIRONMENT env var is treated as non-production (dev default)."""
    _set_admin_env(
        monkeypatch,
        environment=None,
        admin_auth_mode="cookie",
        admin_session_pepper="",
    )
    s = Settings()
    assert s.admin_auth_mode == "cookie"


# ---------------------------------------------------------------------------
# Structured logging: CRITICAL emitted with the canonical event name
# ---------------------------------------------------------------------------


def test_critical_log_emitted_for_unsafe_mode(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Operators get a structured CRITICAL record naming the offending knob."""
    _set_admin_env(
        monkeypatch,
        environment="production",
        admin_auth_mode="cookie",
        admin_session_pepper=_VALID_PEPPER,
    )
    with caplog.at_level("CRITICAL", logger="src.core.config"):
        with pytest.raises(SystemExit):
            Settings()
    matching = [
        r
        for r in caplog.records
        if r.name == "src.core.config"
        and r.message == "admin_auth_mode_unsafe_for_production"
    ]
    assert matching, "expected one CRITICAL record for the unsafe-mode path"
    record = matching[0]
    assert record.levelname == "CRITICAL"
    assert getattr(record, "admin_auth_mode", None) == "cookie"
    assert getattr(record, "environment", None) == "production"


def test_critical_log_emitted_for_missing_pepper(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Missing pepper logs a distinct event so dashboards can split the alerts."""
    _set_admin_env(
        monkeypatch,
        environment="production",
        admin_auth_mode="session",
        admin_session_pepper="",
    )
    with caplog.at_level("CRITICAL", logger="src.core.config"):
        with pytest.raises(SystemExit):
            Settings()
    matching = [
        r
        for r in caplog.records
        if r.name == "src.core.config"
        and r.message == "admin_session_pepper_missing_in_production"
    ]
    assert matching, "expected one CRITICAL record for the missing-pepper path"
    record = matching[0]
    assert record.levelname == "CRITICAL"
    assert getattr(record, "admin_auth_mode", None) == "session"
