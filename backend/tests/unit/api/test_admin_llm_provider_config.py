"""Admin LLM provider rows — masked responses, write-only api_key."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.testclient import TestClient

from main import app
from src.core.config import settings
from src.db.session import get_db

_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY}

_FULL_KEY_PLACEHOLDER = "sk-proj-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz9999"


@pytest.fixture
def _clear_db_override():
    yield
    app.dependency_overrides.pop(get_db, None)


def test_llm_runtime_summary_no_secret_material(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    distinctive_secret = "argus-runtime-summary-leak-check-7f3c9a1b2d4e"
    monkeypatch.setenv("OPENAI_API_KEY", distinctive_secret)
    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    r = client.get("/api/v1/admin/llm/runtime-summary", headers=_ADMIN_HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body.get("execution_uses_global_env") is True
    providers = body.get("global_env_providers")
    assert isinstance(providers, dict)
    assert all(isinstance(v, bool) for v in providers.values())
    raw = r.text.lower()
    assert "sk-" not in raw
    assert "api_key" not in raw
    assert distinctive_secret not in r.text
    assert distinctive_secret.lower() not in raw


def test_list_providers_masks_config_and_shows_last4(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    row = MagicMock()
    row.id = str(uuid.uuid4())
    row.tenant_id = tid
    row.provider_key = "openai"
    row.enabled = True
    row.config = {
        "api_key": _FULL_KEY_PLACEHOLDER,
        "model_fallback_chain": ["gpt-4o-mini", "gpt-4o"],
        "note": "ok",
    }
    row.created_at = datetime.now(timezone.utc)

    r_exec = MagicMock()
    r_exec.scalars.return_value.all.return_value = [row]
    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_exec)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.get(
            f"/api/v1/admin/providers?tenant_id={tid}",
            headers=_ADMIN_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 200
    payload = r.json()
    assert len(payload) == 1
    item = payload[0]
    assert item["api_key_set"] is True
    assert item["api_key_last4"] == "9999"
    assert item["config"]["api_key"] == "***"
    assert item["config"]["note"] == "ok"
    assert item["model_fallback_chain"] == ["gpt-4o-mini", "gpt-4o"]
    assert _FULL_KEY_PLACEHOLDER not in r.text
    assert "sk-proj-zzzz" not in r.text
    assert "sk-" not in r.text


def test_list_providers_masks_secret_like_strings_under_benign_keys(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    embedded = "sk-proj-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz9999"
    row = MagicMock()
    row.id = str(uuid.uuid4())
    row.tenant_id = tid
    row.provider_key = "openai"
    row.enabled = True
    row.config = {
        "api_key": "x",
        "note": f"prefix {embedded} suffix",
        "model": "gpt-4o-mini",
    }
    row.created_at = datetime.now(timezone.utc)

    r_exec = MagicMock()
    r_exec.scalars.return_value.all.return_value = [row]
    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_exec)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.get(
            f"/api/v1/admin/providers?tenant_id={tid}",
            headers=_ADMIN_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 200
    item = r.json()[0]
    assert embedded not in r.text
    assert "sk-" not in r.text
    note_out = item["config"]["note"]
    assert "***" in note_out
    assert embedded not in note_out


def test_patch_provider_unknown_config_key_422(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = str(uuid.uuid4())

    class FakeProv:
        __tablename__ = "provider_configs"

        def __init__(self) -> None:
            self.id = pid
            self.tenant_id = str(uuid.uuid4())
            self.provider_key = "openai"
            self.enabled = True
            self.config: dict[str, object] = {"model": "gpt-4o-mini"}
            self.created_at = datetime.now(timezone.utc)

    prov = FakeProv()
    session = AsyncMock()

    async def _exec(_stmt: object) -> MagicMock:
        r = MagicMock()
        r.scalar_one_or_none.return_value = prov
        return r

    session.execute = AsyncMock(side_effect=_exec)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.patch(
            f"/api/v1/admin/providers/{pid}",
            headers=_ADMIN_HEADERS,
            json={"config": {"arbitrary_injection": True, "model": "x"}},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 422
    detail = r.json().get("detail", "")
    assert "Unknown provider config keys" in str(detail)
    assert "arbitrary_injection" in str(detail)


def test_patch_provider_nested_model_fallback_chain_respects_length_limit(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = str(uuid.uuid4())
    too_many = [f"m{i}" for i in range(25)]

    class FakeProv:
        __tablename__ = "provider_configs"

        def __init__(self) -> None:
            self.id = pid
            self.tenant_id = str(uuid.uuid4())
            self.provider_key = "openai"
            self.enabled = True
            self.config: dict[str, object] = {}
            self.created_at = datetime.now(timezone.utc)

    prov = FakeProv()
    session = AsyncMock()

    async def _exec(_stmt: object) -> MagicMock:
        r = MagicMock()
        r.scalar_one_or_none.return_value = prov
        return r

    session.execute = AsyncMock(side_effect=_exec)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.patch(
            f"/api/v1/admin/providers/{pid}",
            headers=_ADMIN_HEADERS,
            json={"config": {"model_fallback_chain": too_many}},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 422
    assert "too long" in str(r.json().get("detail", "")).lower()


def test_patch_provider_never_echoes_plain_api_key(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = str(uuid.uuid4())

    class FakeProv:
        __tablename__ = "provider_configs"

        def __init__(self) -> None:
            self.id = pid
            self.tenant_id = str(uuid.uuid4())
            self.provider_key = "openai"
            self.enabled = True
            self.config: dict[str, object] = {
                "api_key": "oldoldoldold",
                "model_fallback_chain": ["x"],
            }
            self.created_at = datetime.now(timezone.utc)

    prov = FakeProv()

    session = AsyncMock()

    async def _exec(_stmt: object) -> MagicMock:
        r = MagicMock()
        r.scalar_one_or_none.return_value = prov
        return r

    session.execute = AsyncMock(side_effect=_exec)
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.patch(
            f"/api/v1/admin/providers/{pid}",
            headers=_ADMIN_HEADERS,
            json={"api_key": "sk-newsecretvaluehere"},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 200
    body = r.json()
    assert body["api_key_last4"] == "here"
    assert body["config"]["api_key"] == "***"
    assert "sk-new" not in r.text
    assert prov.config.get("api_key") == "sk-newsecretvaluehere"


def test_patch_updates_last4_get_list_still_masks(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PATCH persists new key; subsequent GET must never echo plaintext."""
    pid = str(uuid.uuid4())
    tid = str(uuid.uuid4())

    class FakeProv:
        __tablename__ = "provider_configs"

        def __init__(self) -> None:
            self.id = pid
            self.tenant_id = tid
            self.provider_key = "openai"
            self.enabled = True
            self.config: dict[str, object] = {
                "api_key": "sk-initialkeyvalueoldoldoldold",
                "model_fallback_chain": ["gpt-4o-mini"],
            }
            self.created_at = datetime.now(timezone.utc)

    prov = FakeProv()
    exec_calls = 0

    async def _exec(_stmt: object) -> MagicMock:
        nonlocal exec_calls
        exec_calls += 1
        r = MagicMock()
        if exec_calls == 1:
            r.scalar_one_or_none.return_value = prov
        else:
            r.scalars.return_value.all.return_value = [prov]
        return r

    session = AsyncMock()
    session.execute = AsyncMock(side_effect=_exec)
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r_patch = client.patch(
            f"/api/v1/admin/providers/{pid}",
            headers=_ADMIN_HEADERS,
            json={"api_key": "sk-replacementkeyvaluebrandnew"},
        )
        r_get = client.get(
            f"/api/v1/admin/providers?tenant_id={tid}",
            headers=_ADMIN_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r_patch.status_code == 200
    assert r_patch.json()["api_key_last4"] == "new"
    assert r_patch.json()["config"]["api_key"] == "***"

    assert r_get.status_code == 200
    item = r_get.json()[0]
    assert item["api_key_last4"] == "new"
    assert item["config"]["api_key"] == "***"
    assert "sk-replacement" not in r_get.text
    assert prov.config.get("api_key") == "sk-replacementkeyvaluebrandnew"


def test_create_provider_duplicate_returns_409(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    exec_calls = 0

    async def _exec(_stmt: object) -> MagicMock:
        nonlocal exec_calls
        exec_calls += 1
        r = MagicMock()
        if exec_calls == 1:
            r.scalar_one_or_none.return_value = MagicMock()
        else:
            r.scalar_one_or_none.return_value = MagicMock()
        return r

    session = AsyncMock()
    session.execute = AsyncMock(side_effect=_exec)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.post(
            "/api/v1/admin/providers",
            headers=_ADMIN_HEADERS,
            json={"tenant_id": tid, "provider_key": "openai", "enabled": True},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 409
    assert "already exists" in r.json().get("detail", "").lower()


def test_admin_llm_endpoints_401_without_admin_key(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    pid = str(uuid.uuid4())
    tid = str(uuid.uuid4())
    calls = [
        lambda: client.get("/api/v1/admin/llm/runtime-summary"),
        lambda: client.get("/api/v1/admin/providers", params={"tenant_id": tid}),
        lambda: client.patch(f"/api/v1/admin/providers/{pid}", json={"enabled": True}),
        lambda: client.post(
            "/api/v1/admin/providers",
            json={"tenant_id": tid, "provider_key": "openai"},
        ),
    ]
    for call in calls:
        r = call()
        assert r.status_code == 401
        assert r.json().get("detail") == "Invalid X-Admin-Key"
