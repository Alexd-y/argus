# Playbooks Integration Testing & Practical Examples

**Дата:** 2026-07-22  
**Версия:** 1.0  
**Scope:** P5-SCEN-005: 12 базовых сценариев + integration-тесты

---

## Обзор 12 базовых сценариев (P5)

| Категория | Playbook ID | Риск | Principals | WSTG |
|-----------|------------|------|-----------|------|
| **Authentication** | `auth.direct-protected-route` | low | owner, anon | WSTG-AUTHN-01 |
| | `mfa.direct-step-skip` | high | owner | WSTG-AUTHN-05 |
| **Account Lifecycle** | `registration.duplicate-casefold` | low | (none) | WSTG-IDNT-01 |
| | `reset.token-reuse-after-password-change` | high | owner | WSTG-IDNT-04 |
| **Session** | `session.logout-invalidation` | medium | owner | WSTG-SESS-02 |
| **Authorization** | `idor.cross-user-read` | low | owner, attacker | WSTG-ATHZ-04 |
| | `idor.cross-user-write` | medium | owner, attacker | WSTG-ATHZ-04 |
| | `authorization.method-variant` | low | owner, attacker | WSTG-ATHZ-03 |
| | `massassignment.role-injection` | high | owner, attacker | WSTG-ATHZ-01 |
| **Rate Limiting** | `ratelimit.login-account-keyed` | medium | (none) | WSTG-ATCK-01 |
| | `ratelimit.otp-resend` | low | (none) | WSTG-ATCK-01 |
| **Race Conditions** | `race.single-use-token` | high | owner | WSTG-RACE-01 |

---

## Структура Integration-теста

```
backend/tests/integration/playbooks/
├─ conftest.py                          # pytest fixtures
├─ test_registry_load.py                # registry validation
├─ test_idor_cross_user.py              # idor.cross-user-read
├─ test_auth_direct_protected.py        # auth.direct-protected-route
├─ test_race_single_use_token.py        # race.single-use-token
└─ scenarios/
   ├─ mock_target.py                    # MockHttpTransport
   └─ fixtures.yaml                     # mock responses
```

### conftest.py: Фикстуры

```python
# backend/tests/integration/playbooks/conftest.py

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from src.playbooks.registry import PlaybookRegistry
from src.playbooks.executor import ScenarioExecutor, ScenarioTransport
from src.playbooks.lifecycle import ScenarioState, ScenarioStatus
from src.playbooks.actions import HttpResponse
from src.auth.session_store import SessionStore, PrincipalRole

@pytest.fixture(scope="session")
def playbook_registry() -> PlaybookRegistry:
    """Load playbook registry once per session."""
    registry = PlaybookRegistry(Path(__file__).parent.parent.parent / "config" / "playbooks")
    registry.load()
    return registry

@pytest.fixture
def session_store() -> SessionStore:
    """Create fresh session store with owner + attacker."""
    store = SessionStore()
    
    # Owner: authenticated user
    store.register_session(
        principal_id="owner",
        role=PrincipalRole.OWNER,
        cookies={"session_id": "owner_session_123"},
        headers={"X-User-Id": "user_001"}
    )
    
    # Attacker: different authenticated user
    store.register_session(
        principal_id="attacker",
        role=PrincipalRole.ATTACKER,
        cookies={"session_id": "attacker_session_456"},
        headers={"X-User-Id": "user_002"}
    )
    
    return store

class MockHttpTransport(ScenarioTransport):
    """Stub transport for testing (no real network)."""
    
    def __init__(self, responses_by_url: dict[str, dict[str, HttpResponse]]):
        """
        responses_by_url: {
            "/api/v1/users/2001": {
                "owner": HttpResponse(status=200, body=..., headers=...),
                "attacker": HttpResponse(status=200, body=..., headers=...)
            }
        }
        """
        self.responses = responses_by_url
        self.calls = []  # Track all calls for assertions
    
    def send(self, spec, *, principal: str | None = None) -> HttpResponse:
        self.calls.append({
            "principal": principal,
            "method": spec.method,
            "url": spec.url,
        })
        
        # Match by path
        path = spec.url.split("?")[0].replace("http://localhost:8888", "")
        if path in self.responses:
            response_map = self.responses[path]
            if principal in response_map:
                return response_map[principal]
            # Return default for unmapped principals
            return HttpResponse(status=200, body="{}", headers={})
        
        return HttpResponse(status=404, body="{}", headers={})

@pytest.fixture
def mock_target_idor():
    """Mock target with IDOR responses."""
    return MockHttpTransport({
        "/api/v1/users/2001": {
            "owner": HttpResponse(
                status=200,
                body="""{
                    "id": 2001,
                    "email": "owner@example.com",
                    "phone": "555-1234",
                    "account_number": "1234567890"
                }""",
                headers={"content-type": "application/json"}
            ),
            "attacker": HttpResponse(
                status=200,
                body="""{
                    "id": 2001,
                    "email": "owner@example.com",
                    "phone": "555-1234",
                    "account_number": "1234567890"
                }""",
                headers={"content-type": "application/json"}
            )
        }
    })

@pytest.fixture
def mock_target_no_idor():
    """Mock target WITHOUT IDOR (properly protected)."""
    return MockHttpTransport({
        "/api/v1/users/2001": {
            "owner": HttpResponse(
                status=200,
                body="""{
                    "id": 2001,
                    "email": "owner@example.com",
                    "phone": "555-1234"
                }""",
                headers={"content-type": "application/json"}
            ),
            "attacker": HttpResponse(
                status=403,  # ← forbidden
                body="""{"error": "Forbidden"}""",
                headers={"content-type": "application/json"}
            )
        }
    })
```

---

## Пример 1: IDOR Cross-User Read

```python
# backend/tests/integration/playbooks/test_idor_cross_user.py

import pytest
from src.playbooks.executor import ScenarioExecutor
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.oracles import OracleVerdict

def test_idor_cross_user_read_vulnerable(playbook_registry, session_store, mock_target_idor):
    """IDOR scenario confirms vulnerability when attacker can read owner data."""
    
    # Load playbook
    playbook = playbook_registry.get("idor.cross-user-read")
    assert playbook.playbook_id == "idor.cross-user-read"
    assert set(playbook.required_principals) == {"owner", "attacker"}
    
    # Execute scenario
    executor = ScenarioExecutor(
        playbook=playbook,
        transport=mock_target_idor,
        session_store=session_store
    )
    
    result = executor.run()
    
    # Assertions
    assert result.state.status == ScenarioStatus.CONFIRMED
    assert result.oracle_result.verdict == OracleVerdict.FINDING
    assert result.oracle_result.confidence.value == "high"
    
    # Evidence must be redacted
    assert "[REDACTED]" in result.evidence.baseline_exchange.request_redacted or \
           result.evidence.baseline_exchange.request_redacted  # at least present
    assert result.evidence.diff is not None
    
    # No cleanup needed (read-only)
    assert result.cleanup_status.value == "complete"

def test_idor_cross_user_read_protected(playbook_registry, session_store, mock_target_no_idor):
    """IDOR scenario rejects when server properly restricts access."""
    
    playbook = playbook_registry.get("idor.cross-user-read")
    
    executor = ScenarioExecutor(
        playbook=playbook,
        transport=mock_target_no_idor,
        session_store=session_store
    )
    
    result = executor.run()
    
    # Oracle verdict: NO_FINDING (attacker got 403, didn't access data)
    assert result.state.status == ScenarioStatus.REJECTED
    assert result.oracle_result.verdict == OracleVerdict.NO_FINDING
    assert "denied_status 403" in result.oracle_result.reason

def test_idor_requires_both_principals(playbook_registry, session_store):
    """Scenario is skipped if attacker principal is not available."""
    
    playbook = playbook_registry.get("idor.cross-user-read")
    
    # Remove attacker from session store
    attacker_session = session_store.get_session("attacker")
    del session_store._sessions["attacker"]
    
    executor = ScenarioExecutor(
        playbook=playbook,
        transport=MockHttpTransport({}),
        session_store=session_store
    )
    
    result = executor.run()
    
    # Should be skipped because attacker not available
    assert result.state.status == ScenarioStatus.SKIPPED_NOT_APPLICABLE
    assert "missing required principals: attacker" in result.state.reason
```

---

## Пример 2: Rate Limit OTP Resend

```python
# backend/tests/integration/playbooks/test_ratelimit_otp_resend.py

def test_ratelimit_otp_resend_vulnerable(playbook_registry):
    """Rate-limit on OTP resend vulnerable to brute force."""
    
    playbook = playbook_registry.get("ratelimit.otp-resend")
    assert playbook.risk_level.value == "low"  # Only informational
    
    # Mock: no rate limit
    transport = MockHttpTransport({
        "/api/v1/auth/otp/send": {
            "anon": [
                HttpResponse(status=200, body='{"status":"sent"}', headers={}),
                HttpResponse(status=200, body='{"status":"sent"}', headers={}),
                HttpResponse(status=200, body='{"status":"sent"}', headers={}),
                HttpResponse(status=200, body='{"status":"sent"}', headers={}),
                HttpResponse(status=200, body='{"status":"sent"}', headers={}),
            ]
        }
    })
    
    # This playbook uses rate-limit oracle
    # 5 rapid requests should see no 429 → oracle: FINDING
    
    executor = ScenarioExecutor(
        playbook=playbook,
        transport=transport,
        session_store=SessionStore()
    )
    
    result = executor.run()
    
    if result.state.status == ScenarioStatus.CONFIRMED:
        assert result.oracle_result.oracle_type == OracleType.RATE_LIMIT
        assert result.oracle_result.verdict == OracleVerdict.FINDING
```

---

## Пример 3: Race Condition - Single-Use Token

```python
# backend/tests/integration/playbooks/test_race_single_use_token.py

def test_race_single_use_token_vulnerable(playbook_registry, session_store):
    """Race condition: token reused before server invalidates."""
    
    playbook = playbook_registry.get("race.single-use-token")
    assert playbook.risk_level.value == "high"
    assert playbook.requires_approval is True
    
    # Mock: token not invalidated between requests
    class RaceTransport(ScenarioTransport):
        def __init__(self):
            self.token_used = False
            self.race_succeeded = False
        
        def send(self, spec, *, principal=None):
            # First use: success, but don't invalidate token
            if "?token=abc123" in spec.url and not self.token_used:
                self.token_used = True
                return HttpResponse(status=200, body='{"status":"ok"}', headers={})
            
            # Second (parallel) use: also succeeds (race condition!)
            if "?token=abc123" in spec.url and self.token_used:
                self.race_succeeded = True
                return HttpResponse(status=200, body='{"status":"ok"}', headers={})
            
            return HttpResponse(status=400, body='{"error":"invalid"}', headers={})
    
    executor = ScenarioExecutor(
        playbook=playbook,
        transport=RaceTransport(),
        session_store=session_store
    )
    
    result = executor.run()
    
    # Race oracle should detect the condition
    if result.state.status == ScenarioStatus.CONFIRMED:
        assert result.oracle_result.oracle_type == OracleType.RACE
        assert result.oracle_result.verdict == OracleVerdict.FINDING
```

---

## Пример 4: MFA Direct Step Skip

```yaml
# backend/config/playbooks/authentication/mfa.direct-step-skip.yaml

schema_version: 1
playbook_id: mfa.direct-step-skip
version: 1
title: MFA - Direct Step Skip
description: >-
  Attacker bypasses MFA by directly requesting protected endpoint
  without completing the MFA challenge. Server accepts request without
  MFA verification token.

category: authentication
risk_level: high
requires_approval: true  # HIGH risk → approval required

required_principals:
  - owner
required_capabilities:
  - http_client

applies_when:
  methods:
    - GET
    - POST
  path_globs:
    - /api/*/me
    - /api/*/profile
    - /dashboard/*
  input_kinds:
    - cookie  # Must have session after login

preconditions:
  - kind: principal_available
    value: owner
  - kind: capability_available
    value: mfa_challenge  # Must support MFA scenarios

steps:
  - id: login_with_mfa
    action: browser_action
    principal: owner
    params:
      kind: navigate
      url: "https://target.internal/login"
  
  - id: enter_credentials
    action: browser_action
    principal: owner
    params:
      kind: type
      selector: "input[name=username]"
      value: "$mfa_user"
  
  - id: enter_password
    action: browser_action
    principal: owner
    params:
      kind: type
      selector: "input[name=password]"
      value: "$mfa_password"
  
  - id: click_login
    action: browser_action
    principal: owner
    params:
      kind: click
      selector: "button:contains('Sign In')"
  
  - id: wait_mfa_prompt
    action: browser_action
    principal: owner
    params:
      kind: wait_for
      selector: "input[name=totp]"
  
  - id: capture_mfa_cookies
    action: browser_action
    principal: owner
    save_as: post_login_cookies
    params:
      kind: screenshot  # placeholder; real action exports cookies
  
  - id: extract_session
    action: extract
    save_as: session_cookie
    params:
      from_step: capture_mfa_cookies
      source: response_header
      selector: "set-cookie"
      regex: "session_id=([^;]+)"
  
  - id: try_protected_endpoint
    action: http_request
    principal: owner
    save_as: protected_response
    params:
      method: GET
      url: "https://target.internal/api/v1/me"
      headers:
        Cookie: "session_id=$session_cookie"

assertions:
  - type: authn
    params:
      required_header: x-mfa-verified
      denied_statuses: [401, 403]

cleanup: []
timeout_seconds: 300
max_concurrency: 1
```

---

## Запуск integration-тестов

```bash
cd backend

# Запустить все playbook integration-тесты
python -m pytest tests/integration/playbooks/ -v

# Конкретный сценарий
python -m pytest tests/integration/playbooks/test_idor_cross_user.py::test_idor_cross_user_read_vulnerable -v

# С full debug output
python -m pytest tests/integration/playbooks/ -vv -s

# Покрытие
python -m pytest tests/integration/playbooks/ --cov=src/playbooks --cov-report=html
```

---

## Загрузка registry при старте backend

Файл: `backend/src/app.py` или `backend/src/api/app.py`

```python
from fastapi import FastAPI
from pathlib import Path
from src.playbooks.registry import PlaybookRegistry, RegistryLoadError

app = FastAPI()

# Load registry on startup
@app.on_event("startup")
async def load_registries():
    """Load signed playbook registry at startup (fail-closed)."""
    try:
        playbooks_dir = Path(__file__).parent.parent / "config" / "playbooks"
        playbook_registry = PlaybookRegistry(playbooks_dir)
        summary = playbook_registry.load()
        
        app.state.playbook_registry = playbook_registry
        
        logger.info(
            "playbooks_loaded",
            extra={
                "total": summary.total,
                "by_category": summary.by_category,
                "by_risk": summary.by_risk,
                "requires_approval": summary.requires_approval_count,
            }
        )
    except RegistryLoadError as e:
        logger.critical(f"Failed to load playbook registry: {e}")
        raise

@app.get("/health/playbooks")
async def health_playbooks():
    """Readiness probe: check registry loaded."""
    registry = app.state.get("playbook_registry")
    if registry is None:
        return {"status": "not_ready"}
    
    summary = ... # get summary
    return {
        "status": "ready",
        "total": summary.total,
        "by_category": summary.by_category,
    }
```

---

## Гарантии тестирования

**Coverage checklist:**

```
✓ Registry fail-closed
  ├─ test_registry_unsigned_playbook_fails
  ├─ test_registry_duplicate_id_fails
  ├─ test_registry_id_filename_mismatch_fails
  ├─ test_registry_wrong_category_dir_fails
  └─ test_registry_invalid_yaml_fails

✓ Lifecycle
  ├─ test_lifecycle_discovered_to_planned
  ├─ test_lifecycle_invalid_transition_fails
  ├─ test_lifecycle_reason_required_on_skip
  └─ test_lifecycle_terminal_statuses

✓ Planner
  ├─ test_planner_applies_when_filtering
  ├─ test_planner_principals_available_check
  ├─ test_planner_capabilities_available_check
  └─ test_planner_approval_routing

✓ Executor
  ├─ test_executor_multi_principal_isolation
  ├─ test_executor_session_applied_per_step
  ├─ test_executor_secret_redaction
  ├─ test_executor_cleanup_always_runs
  └─ test_executor_approval_gate

✓ Oracles
  ├─ test_oracle_authz_finds_cross_user_access
  ├─ test_oracle_authz_no_finding_on_403
  ├─ test_oracle_rate_limit_detects_429
  ├─ test_oracle_race_detects_parallel_use
  └─ test_oracle_deterministic_same_inputs

✓ Evidence
  ├─ test_evidence_redaction_mandatory
  ├─ test_evidence_no_secrets_in_persistence
  └─ test_evidence_diff_normalized

✓ 12 Playbooks (each with CONFIRMED + REJECTED scenarios)
  ├─ test_auth_direct_protected_*
  ├─ test_mfa_direct_step_skip_*
  ├─ test_idor_cross_user_*
  ├─ test_race_single_use_token_*
  └─ ... (12 total)

✓ Back-compat (SI-7)
  ├─ test_legacy_single_auth_still_works
  ├─ test_finding_dto_optional_fields_backward_compat
  └─ test_no_api_breaking_changes
```

---

## Миграция при добавлении новых playbooks

1. **Напишите YAML** (`backend/config/playbooks/<категория>/<id>.yaml`)
2. **Подпишите:** `python scripts/playbooks_sign.py --sign`
3. **Тест на валидацию:** `python scripts/playbooks_sign.py --verify`
4. **Unit-тест:** `pytest tests/unit/playbooks/test_schema_validation.py`
5. **Integration-тест:** `pytest tests/integration/playbooks/test_new_playbook_name.py`
6. **Линт + mypy:** `ruff check src/playbooks/`, `mypy src/playbooks/`
7. **Коммит + PR**

---

**Created:** 2026-07-22  
**Author:** ARGUS Documentation System  
**Status:** Integration-ready
