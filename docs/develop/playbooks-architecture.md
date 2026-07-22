# Архитектура подсистемы Playbooks и Scenarios

**Дата:** 2026-07-22  
**Версия:** 1.0  
**Статус:** Production (P2–P4 выполнены)  
**Сквозная гарантия:** Security Invariants SI-1 до SI-7

---

## 📋 Оглавление

1. [Обзор архитектуры](#обзор-архитектуры)
2. [Слои исполнения](#слои-исполнения)
3. [Lifecycle сценариев](#lifecycle-сценариев)
4. [Как создать новый playbook](#как-создать-новый-playbook)
5. [Payload и SI-5](#payload-и-si-5)
6. [Nuclei argus-* шаблоны](#nuclei-argus--шаблоны)
7. [Multi-principal auth](#multi-principal-auth)
8. [Approval и EAP](#approval-и-eap)
9. [Scenario coverage](#scenario-coverage)
10. [Troubleshooting](#troubleshooting)

---

## Обзор архитектуры

### Высокоуровневая диаграмма

```
┌────────────────────────────────────────────────────────────────────────┐
│ PIPELINE: discovery → planning → execution → confirmation → evidence  │
│                                             → finding → report        │
└────────────────────────────────────────────────────────────────────────┘

discovery (LLM/статический анализ)
    ↓
    ├─> endpoints, input-surface, capabilities, principals available
    ↓
┌─────────────────────────────────────────────────────────────────────┐
│ PLANNING LAYER (stateless selection)                              │
│                                                                     │
│ PlaybookRegistry.load()  ──> all playbooks indexed by ID          │
│ ScenarioPlanner.plan()   ──> filter by applies_when / capability  │
│                             & executor availability                │
│                             & approval requirements                 │
│                          ──> emit PlannedScenario(PLANNED/SKIPPED)  │
└─────────────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────────────┐
│ APPROVAL GATE (SI-1 — Engagement Authorization Profile)            │
│                                                                      │
│ High/Destructive playbooks → PreflightChecker → PolicyEngine        │
│                              → EAP pre-authorization (if available) │
│                              → ApprovalService signature verify      │
│                              OR manual approval on file              │
│                          ──> WAITING_APPROVAL or RUNNING           │
└──────────────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────────────┐
│ EXECUTION LAYER (multi-principal, session-aware)                   │
│                                                                      │
│ ScenarioExecutor.run()                                              │
│   ├─> resolve multi-principal sessions (SessionStore, SI-3)        │
│   ├─> for each step in playbook.steps:                             │
│   │     ├─ apply step.principal's isolated session                 │
│   │     ├─ execute action (HTTP, browser, extract, compare, etc.)  │
│   │     └─ capture baseline/mutated exchanges                      │
│   │                                                                 │
│   ├─> run oracle assertions (authz, authn, rate-limit, race, etc.) │
│   │     ├─ compare baseline vs mutated                             │
│   │     ├─ emit OracleResult (FINDING / NO_FINDING / INCONCLUSIVE) │
│   │     ├─ redact secrets (SI-3)                                   │
│   │                                                                 │
│   └─> register & execute cleanup steps                             │
│       ├─ CLEANUP_COMPLETE or CLEANUP_FAILED                        │
└──────────────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────────────┐
│ EVIDENCE & FINDING (SI-3 — redacted, audit-trail)                  │
│                                                                      │
│ EvidenceBundle.build()  ──> normalized baseline/mutated diff        │
│                            with mandatory redaction                  │
│                                                                      │
│ ScenarioContextDTO + oracle result → FindingDTO                    │
│   ├─ scenario_id, playbook_id, playbook_run_id                     │
│   ├─ source_principal, target_principal                            │
│   ├─ baseline_request/response, mutated_request/response           │
│   ├─ diff, oracle_result, approval_id                              │
│   ├─ provenance (source_url, commit, adapted_at)                   │
└──────────────────────────────────────────────────────────────────────┘
    ↓
├─> Confirmation policy (HYPOTHESIS → PARTIALLY_CONFIRMED → CONFIRMED)
├─> Report tier classification (Asgard/Midgard/Valhalla)
└─> WSTG coverage tracking
```

### Четыре исполняемых слоя

| Слой | Назначение | Например | Результат |
|------|-----------|----------|-----------|
| **Schema** | Pydantic-модели playbook, immutable + fail-closed | `backend/src/playbooks/schema.py` | Валидация YAML, `extra="forbid"`, версионирование |
| **Registry** | Загрузка + Ed25519-подпись + индексация | `backend/src/playbooks/registry.py` | PlaybookRegistry в памяти, fail-closed на сигнатуре |
| **Planner** | Выбор применимых playbooks + маршрут на approval | `backend/src/playbooks/planner.py` | PlannedScenario(PLANNED/SKIPPED/WAITING_APPROVAL) |
| **Executor** | Исполнение + actions + oracles + cleanup | `backend/src/playbooks/executor.py` | ScenarioResult(CONFIRMED/REJECTED/CLEANUP_FAILED) + evidence |

### Отличие ScenarioPlanner (stateful multi-step) от InjectionPlanner (stateless)

```python
# InjectionPlanner — старый слой, используется для обнаружения уязвимостей
# Все инъекции атомарны, без state between steps, argv-only
class InjectionPlanner:
    def plan_injections(endpoint):
        # Генерирует flat list паралльных инъекций
        return [(tool, payload_family), ...]  # статeless

# ScenarioPlanner — новый слой для многошаговых сценариев
# Multi-step, session-aware, declarative oracle assertions
class ScenarioPlanner:
    def plan(context: ScenarioPlanningContext) -> list[PlannedScenario]:
        # Выбирает playbooks по applies_when + capabilities + approval requirements
        # Каждый playbook =序列 шагов, сохраняющих state между собой
        # Сессия principal'а переживает весь playbook
        return [PlannedScenario(playbook_id, state=PLANNED), ...]

class ScenarioExecutor:
    def run(scenario: PlannedScenario):
        # Исполняет все steps playbook'а в одной сессии principal'а
        # Шаг 1 (baseline) → сохраняет результат
        # Шаг 2 (mutated attack) → сравнивает с шагом 1 в oracle
        # Гарантирует, что обе инъекции используют один principal + cookies
```

---

## Слои исполнения

### 1. Schema Layer (`backend/src/playbooks/schema.py`)

Все поля **декларативные**, никогда не выполняются как Python:

```python
class Playbook(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)  # SI-4: no shell, no eval
    
    schema_version: int      # 1 (для версионирования схемы в будущем)
    playbook_id: str         # regex: ^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$
    version: int             # v1, v2, ... (обновления playbook'а)
    title: str               # "IDOR - cross-user record read"
    description: str         # human + audit trail, НИКОГДА не в prompt
    category: PlaybookCategory  # authorization, authentication, rate_limit, etc.
    
    # Applicability: когда этот playbook может запуститься
    applies_when: AppliesWhen
        methods: [GET, POST, ...]
        path_globs: ["/api/*/users/*", ...]  # fnmatch patterns
        requires_openapi: bool
        input_kinds: [PATH_PARAM, QUERY_PARAM, BODY_JSON, ...]
    
    # Требуемые ресурсы
    required_principals: ["owner", "attacker"]  # names of PrincipalConfig
    required_capabilities: ["http_client"]      # чем должен быть оснащён environment
    required_evidence: ["baseline_response", "mutated_response"]
    
    # Риск и одобрение (SI-1)
    risk_level: PlaybookRiskLevel  # low, medium, high, destructive
    requires_approval: bool  # High/Destructive → всегда True
    
    # Провенанс (SI-6: отслеживание источника)
    provenance: Provenance
        source_url: str          # https://github.com/Az0x7/vulnerability-Checklist
        commit: str              # commit hash откуда адаптирована идея
        adapted_at: date         # когда адаптирована
        note: str                # контекст адаптации
    
    # Классификация найденных уязвимостей
    cwe: [639, 284]                      # CWE id (BOLA/IDOR)
    wstg: ["WSTG-ATHZ-04"]               # WSTG 4.2 test case'ы
    owasp_api: ["API1:2023"]             # OWASP API Top 10
    tags: ["idor", "bola"]
    
    # Исполнение
    steps: list[PlaybookStep]       # min 1 шаг
    assertions: list[OracleSpec]    # min 1 oracle assertion
    cleanup: list[PlaybookStep]     # 0..N cleanup-действий
    
    preconditions: list[Precondition]  # gates перед исполнением
    timeout_seconds: int            # default 300, max 86400
    max_concurrency: int            # default 1

class PlaybookStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    
    id: str                     # step_id: "owner_baseline"
    action: ActionType          # http_request, browser_action, extract, etc.
    params: dict                # re-validated against _ACTION_PARAM_MODELS
    principal: str | None       # owner, attacker, ... (isolation, SI-3)
    save_as: str | None         # $owner_resp (для extract/compare later)
```

Все **enum'ы** — замкнутые:

```python
class PlaybookCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ACCOUNT_LIFECYCLE = "account_lifecycle"
    SESSION_MANAGEMENT = "session_management"
    BUSINESS_LOGIC = "business_logic"
    RATE_LIMIT = "rate_limit"
    RACE_CONDITIONS = "race_conditions"
    FILE_UPLOAD = "file_upload"
    TECHNOLOGY_EXPOSURE = "technology_exposure"

class ActionType(StrEnum):
    HTTP_REQUEST = "http_request"        # объявляет метод/URL/headers/body
    BROWSER_ACTION = "browser_action"    # navigate/click/type/wait_for/screenshot
    EXTRACT = "extract"                  # read value from prior response
    COMPARE = "compare"                  # left vs right (equal/not_equal/contains/etc)
    WAIT = "wait"                        # sleep N seconds
    REGISTER_CLEANUP = "register_cleanup"  # запланировать cleanup-шаг

class OracleType(StrEnum):
    AUTHZ = "authz"              # cross-user data access
    AUTHN = "authn"              # bypass of auth
    RATE_LIMIT = "rate_limit"    # RateLimit header / 429 detection
    RACE = "race"                # race condition (timing)
    FILE_UPLOAD = "file_upload"  # malicious uploads
    BUSINESS_LOGIC = "business_logic"  # custom assertions
```

### 2. Registry Layer (`backend/src/playbooks/registry.py`)

**Fail-closed загрузка:**

```python
class PlaybookRegistry:
    def load(self) -> PlaybookRegistrySummary:
        """Discover, verify, and index playbooks under backend/config/playbooks/."""
        
        # Поиск YAML под /playbooks/<категория>/*.yaml
        yaml_paths = self._discover_yaml()  # rglob("*.yaml"), skip _keys/
        
        # Загрузка сигнатур
        signatures = self._load_signatures()  # backend/config/playbooks/SIGNATURES
        
        for yaml_path in yaml_paths:
            # 1. Проверка сигнатуры Ed25519
            signatures.verify_one(
                relative_path=yaml_path.relative_to(...),
                yaml_bytes=yaml_bytes,
                public_key_resolver=self._key_manager.get
            )  # На ошибку → PlaybookSignatureError
            
            # 2. Парс YAML
            payload = yaml.safe_load(yaml_bytes)  # На ошибку → RegistryLoadError
            
            # 3. Валидация по Pydantic schema
            playbook = Playbook(**payload)  # На ошибку → ValidationError → RegistryLoadError
            
            # 4. Валидация oracle params
            for spec in playbook.assertions:
                validate_oracle_params(spec.type, spec.params)
            
            # 5. Проверка: playbook_id == filename.stem
            if playbook.playbook_id != yaml_path.stem:
                raise RegistryLoadError(
                    f"playbook_id {playbook.playbook_id!r} != filename {yaml_path.stem!r}"
                )
            
            # 6. Проверка: file в правильной категории
            if yaml_path.parent.name != playbook.category.value:
                raise RegistryLoadError(
                    f"playbook category {playbook.category.value!r} != "
                    f"directory {yaml_path.parent.name!r}"
                )
            
            # 7. Проверка: нет дубликатов playbook_id
            if playbook.playbook_id in self._registered:
                raise RegistryLoadError(
                    f"duplicate playbook_id {playbook.playbook_id!r}"
                )
            
            self._registered[playbook.playbook_id] = playbook
        
        return PlaybookRegistrySummary(...)
    
    def get(self, playbook_id: str) -> Playbook:
        """Fetch by id or raise PlaybookNotFoundError."""
        record = self._registered.get(playbook_id)
        if record is None:
            raise PlaybookNotFoundError(playbook_id)
        return record.playbook
```

---

## Lifecycle сценариев

### Статус-машина

```
DISCOVERED (начальный)
    ├─> PLANNED (применим)
    ├─> SKIPPED_NOT_APPLICABLE (не применим, требует reason)
    │
    (если requires_approval=True)
    ├─> WAITING_APPROVAL (ожидание одобрения или EAP pre-auth)
    │       ├─> RUNNING (approved, начинаем)
    │       ├─> REJECTED (denied, с reason)
    │       └─> SKIPPED_NOT_APPLICABLE (невыполним)
    │
    (если требется исполнение)
    ├─> RUNNING (выполняется)
    │       ├─> PARTIAL (часть шагов упала, но oracle судит)
    │       ├─> CONFIRMED (oracle: FINDING обнаружена)
    │       ├─> REJECTED (oracle: NO_FINDING или INCONCLUSIVE)
    │       └─> CLEANUP_COMPLETE/CLEANUP_FAILED (с reason при FAILED)
```

**REASON_REQUIRED_STATUSES** — обязательно поле `reason`:

- `SKIPPED_NOT_APPLICABLE` — почему не применим?
- `REJECTED` — почему не подтверждена уязвимость?
- `CLEANUP_FAILED` — почему cleanup не удался?

Пример:

```python
reason="missing required principals: attacker"  # SKIPPED
reason="method POST not in applies_when.methods"  # SKIPPED
reason="playbook requires approval; not pre-authorized by EAP"  # WAITING_APPROVAL
reason="oracle authz verdict: INCONCLUSIVE (only volatile fields differed)"  # REJECTED
reason="cleanup step failed: HTTP 500 on account deletion"  # CLEANUP_FAILED
```

---

## Как создать новый playbook

### Шаг 1: Планирование

Определите:

1. **Категория** (authorization, authentication, rate_limit, …)
2. **playbook_id** формат: `<категория>.<тип>` → `idor.cross-user-read` или `auth.direct-protected-route`
3. **Требуемые principals** (owner, attacker, admin, …)
4. **Требуемые capabilities** (http_client, browser, …)
5. **Риск уровень** (low, medium, high, destructive)
6. **Является ли HIGH/DESTRUCTIVE?** → `requires_approval: true`

### Шаг 2: Напишите YAML playbook'а

Создайте: `backend/config/playbooks/<category>/<playbook_id>.yaml`

Пример: `backend/config/playbooks/authorization/idor.cross-user-read.yaml`

```yaml
schema_version: 1
playbook_id: idor.cross-user-read
version: 1
title: IDOR - cross-user record read
description: >-
  Broken object-level authorization (BOLA/IDOR): an authenticated attacker
  requests another user's resource by id and receives the victim's private
  record. The oracle compares the victim's own (owner) response with the
  attacker's response and only confirms when the attacker actually obtained
  the victim's sensitive fields — a bare HTTP 200 is not proof.

category: authorization

provenance:
  source_url: https://github.com/Az0x7/vulnerability-Checklist
  commit: HEAD
  adapted_at: 2026-07-22
  note: >-
    Idea adapted from Az0x7 vulnerability checklist (IDOR / BOLA class)
    to ARGUS declarative playbook schema; read-only, non-destructive.

cwe:
  - 639  # Insecure Direct Object Reference (IDOR)
  - 284  # Improper Access Control Check

wstg:
  - WSTG-ATHZ-04  # WSTG Testing for Broken Object Level Authorization

owasp_api:
  - API1:2023  # Broken Object Level Authorization (BOLA)

tags:
  - idor
  - bola
  - authorization
  - data_exposure

# Когда этот playbook применим?
applies_when:
  methods:
    - GET
  path_globs:
    - /api/*/users/*
    - /api/*/accounts/*
  requires_openapi: false
  input_kinds:
    - path_param

# Требуемые ресурсы
required_principals:
  - owner      # контролирует data
  - attacker   # пробует читать чужие data
required_capabilities:
  - http_client

# Риск
risk_level: low
requires_approval: false  # не HIGH/DESTRUCTIVE

# Гейты перед исполнением
preconditions:
  - kind: principal_available
    value: owner
  - kind: principal_available
    value: attacker

# Шаги исполнения
steps:
  - id: owner_baseline
    action: http_request
    principal: owner
    save_as: owner_resp
    params:
      method: GET
      url: "https://target.internal/api/v1/users/2001"
      headers:
        Accept: application/json
      query: {}
      body: null

  - id: attacker_probe
    action: http_request
    principal: attacker
    save_as: attacker_resp
    params:
      method: GET
      url: "https://target.internal/api/v1/users/2001"
      headers:
        Accept: application/json

  - id: extract_attacker_status
    action: extract
    save_as: attacker_status
    params:
      from_step: attacker_resp
      source: status_code

# Oracle assertions: судит baseline vs mutated
assertions:
  - type: authz
    params:
      sensitive_fields:
        - email
        - account_number
        - phone
        - social_security_number
      denied_statuses:
        - 401
        - 403
        - 404

# Требуемые evidence артефакты
required_evidence:
  - baseline_response
  - mutated_response
  - normalized_diff

# Cleanup actions (если созданы пользователи, удалить их)
cleanup: []

# Таймауты
timeout_seconds: 120
max_concurrency: 1  # не паралльно с другими scenarios
```

### Шаг 3: Правила написания YAML

| Правило | Пример | Почему |
|---------|--------|--------|
| **playbook_id == filename.stem** | Файл: `idor.cross-user-read.yaml` ✓ | Registry fail-closed проверяет совпадение |
| **Только декларативные поля** | `url: https://...`, `method: GET` ✓ `command: "sh -c 'curl ...'"` ✗ | SI-4: no shell strings, no eval |
| **Payload только через registry** | Шаг `params.payload_family: "sql_injection"` ✓ | SI-5: no inline payloads |
| **Никаких инструкций LLM** | `title/description` для humans, никогда не в prompt | SI-6: text in playbook ≠ instructions |
| **Сигнатуры обязательны** | Playbook должен быть подписан Ed25519 | Fail-closed при загрузке |
| **Unique step IDs** | step IDs не повторяются (check в validator) | Ссылки extract/compare/register_cleanup работают |
| **Valid regex patterns** | `path_globs: ["/api/*/users/*"]` — fnmatch glob | Используется для matching endpoints |

### Шаг 4: Подпись playbook'а

Используйте `backend/scripts/playbooks_sign.py`:

```bash
cd backend

# 1. Генерируем dev-key (если его еще нет)
python scripts/playbooks_sign.py --init

# 2. Подписываем все playbook'ы (или конкретный)
python scripts/playbooks_sign.py --sign

# 3. Проверяем сигнатуры (CI/local)
python scripts/playbooks_sign.py --verify

# 4. Удаляем приватный ключ (dev-only, перед коммитом)
rm -f config/playbooks/_keys/*.private
```

Внутри скрипта:

```python
def sign_playbooks(playbooks_dir):
    """Sign all YAML playbooks with Ed25519."""
    key_manager = KeyManager(playbooks_dir / "_keys")
    key_manager.load()  # load or generate dev key
    
    signatures = {}
    for yaml_path in playbooks_dir.rglob("*.yaml"):
        yaml_bytes = yaml_path.read_bytes()
        relative_path = yaml_path.relative_to(playbooks_dir).as_posix()
        
        # Sign with Ed25519
        sig_bytes = sign_blob(
            yaml_bytes,
            private_key=key_manager.get_private_key()
        )
        
        signatures[relative_path] = {
            "signature": sig_bytes.hex(),
            "public_key_id": public_key_id(...)
        }
    
    # Write SIGNATURES file
    SignaturesFile(signatures).to_file(playbooks_dir / "SIGNATURES")
```

### Шаг 5: Тестирование

```python
# backend/tests/integration/playbooks/test_idor_cross_user.py

def test_idor_cross_user_playbook_loads():
    """Registry loads and validates playbook."""
    registry = PlaybookRegistry(Path("backend/config/playbooks"))
    summary = registry.load()
    
    playbook = registry.get("idor.cross-user-read")
    assert playbook.playbook_id == "idor.cross-user-read"
    assert playbook.category == PlaybookCategory.AUTHORIZATION
    assert playbook.required_principals == ["owner", "attacker"]

def test_idor_execution_end_to_end():
    """ScenarioExecutor runs playbook with 2 principals."""
    registry = PlaybookRegistry(...)
    registry.load()
    playbook = registry.get("idor.cross-user-read")
    
    # Setup mock target
    target = TargetSpec(url="http://localhost:8888", ...)
    
    # Create sessions for owner & attacker
    session_store = SessionStore()
    session_store.register_session(
        principal_id="owner",
        role=PrincipalRole.OWNER,
        cookies={"session_id": "owner_sid"}
    )
    session_store.register_session(
        principal_id="attacker",
        role=PrincipalRole.ATTACKER,
        cookies={"session_id": "attacker_sid"}
    )
    
    # Execute
    executor = ScenarioExecutor(
        playbook=playbook,
        transport=MockHttpTransport(),
        session_store=session_store
    )
    
    result = executor.run()
    
    assert result.state.status in (
        ScenarioStatus.CONFIRMED,
        ScenarioStatus.REJECTED
    )
    assert result.evidence is not None
    assert result.cleanup_status == CleanupStatus.COMPLETE
```

---

## Payload и SI-5

### Правило SI-5: Нет обхода PayloadRegistry

**Нарушение SI-5 (old code):**

```python
# ❌ ПЛОХО: LLM генерирует payload в обход registry
def _wrb_generate_additional_payloads(target, endpoint):
    llm_response = call_llm(f"Generate SQL injection payloads for {endpoint}")
    payloads = llm_response.split("\n")  # parsed from LLM output
    return payloads  # Used directly in tools, never validated/approved

# Проблема:
# 1. Payload'ы не подписаны
# 2. Не проходят PayloadRegistry
# 3. Не подлежат approval-гейту (HIGH/DESTRUCTIVE)
# 4. Нарушает SI-5
```

**Правильное использование (SI-5 соблюдено):**

```python
# ✅ ХОРОШО: LLM только предлагает, registry валидирует
from src.payloads.registry import PayloadRegistry
from src.payloads.builder import PayloadBuilder
from src.policy.preflight import PreflightChecker

def execute_with_payloads(target: TargetSpec, endpoint: str):
    registry = PayloadRegistry.load()  # fail-closed
    builder = PayloadBuilder(registry)
    
    # LLM может рекомендовать family_id, но сами payloads — только из registry
    recommended_families = llm_recommend_families(endpoint)
    # returned: ["sql_injection", "xss_reflected", ...]
    
    payloads = []
    for family_id in recommended_families:
        if family_id not in registry:
            continue  # Family not registered → skip
        
        # Все payload'ы проходят builder (LLM-generated dynamic entries
        # регистрируются с provenance=llm, проходят подпись/approval)
        payload_bundle = builder.build(
            family_id=family_id,
            target=target,
            provenance={"source": "llm_recommendation"}
        )
        
        # Preflight проверяет HIGH/DESTRUCTIVE → approval
        preflight_result = PreflightChecker.check(
            action=payload_bundle,
            target=target,
            approval_sigs=[]  # или из EAP
        )
        
        if not preflight_result.allowed:
            log_preflight_deny(payload_bundle, preflight_result.reason)
            continue
        
        payloads.append(payload_bundle)
    
    return payloads
```

### Как добавить новое семейство payload'ов

1. **Добавьте в `backend/config/payloads/sql_injection.yaml`:**

```yaml
schema_version: 1
family_id: sql_injection_union
version: 1
description: Union-based SQL injection
risk_level: high
requires_approval: true
seeds:
  - payload: "1' UNION SELECT 1,2,3 -- "
    category: detection
    provenance:
      source_url: https://owasp.org/www-community/attacks/SQL_Injection
      note: "Standard UNION-based detection"
  - payload: "1' UNION SELECT NULL,NULL,table_name FROM information_schema.tables -- "
    category: exploitation
```

2. **Подпишите:**

```bash
cd backend
python scripts/payloads_sign.py --sign
```

3. **В playbook'е используйте:**

```yaml
steps:
  - id: inject_sql
    action: http_request
    params:
      url: "..."
      payload_family: "sql_injection_union"  # registry разрешит
```

---

## Nuclei argus-* шаблоны

### Почему argus-* шаблоны?

**Проблема (G-6):**

```python
# ❌ nuclei_va_adapter.py: нет способа передать кастомные шаблоны
def build_nuclei_va_argv(target_url: str):
    return [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-duc",
        "-ni",
        "-rate-limit", "100",
        # ✗ No -t/templates option → no custom templates allowed
    ]
```

**Решение: встроенные argus-* шаблоны с strict matchers**

### Создайте шаблон

Файл: `backend/config/nuclei-templates/argus/argus-idor-get-list.yaml`

```yaml
id: argus-idor-get-list
info:
  name: "[ARGUS] IDOR - GET returns another user's list"
  description: >-
    Broken object-level authorization on list endpoints.
    Request a list resource (e.g., /api/v1/users/123/orders) as one user;
    if the response contains data from another user (detected by data
    fingerprints in corpus), flag as IDOR.
  author: ARGUS
  severity: high
  tags:
    - argus
    - idor
    - authorization
    - bola

# Strict matchers: only flag if ALL conditions met
matchers:
  - type: dsl
    dsl:
      # 1. Status must be 2xx
      - "status_code >= 200 && status_code < 300"
      
      # 2. Content-Type is JSON
      - "header('content-type') == 'application/json'"
      
      # 3. Response contains array (list)
      - "response.contains('[') || response.contains('[{') "
      
      # 4. AND matcher: must have ≥2 objects with "id" or "email" fields
      - "len(jsonpath(body, '$[*].id')) >= 2 || len(jsonpath(body, '$[*].email')) >= 2"
    
    condition: and

# Negative fixture: don't flag on empty/single-element response
matchers-condition: and

matcher-status:
  - success

# Provenance: why we created this
info:
  metadata:
    source_url: https://github.com/Az0x7/vulnerability-Checklist
    adapted_at: "2026-07-22"
    adapted_for: ARGUS playbooks as Nuclei template
```

### Safe argv в adapter

Файл: `backend/src/recon/vulnerability_analysis/active_scan/nuclei_va_adapter.py`

```python
def build_nuclei_va_argv(target_url: str, *, include_argus_templates: bool = True):
    """Build argv for nuclei, with optional ARGUS custom templates."""
    
    argv = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-duc",
        "-ni",
        "-rate-limit", "100",
        "-silent",
    ]
    
    if include_argus_templates:
        # Only hardcoded path inside repo, NEVER user-supplied
        templates_dir = Path(__file__).parent.parent.parent.parent / \
                        "config" / "nuclei-templates" / "argus"
        
        if templates_dir.exists():
            # Allowlist: only -t with absolute repo path
            argv.extend(["-t", str(templates_dir)])
        # If path doesn't exist, silently skip (nuclei will use defaults)
    
    return argv
```

### Тестирование в CI

```bash
# backend/tests/integration/tools/test_nuclei_validate.py

def test_nuclei_templates_validate():
    """Ensure all argus-* templates pass nuclei -validate."""
    templates_dir = Path("backend/config/nuclei-templates/argus")
    
    result = subprocess.run(
        ["nuclei", "-validate", "-t", str(templates_dir)],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, f"nuclei -validate failed:\n{result.stderr}"
```

---

## Multi-principal auth

### Основные концепции

**SI-3: Split-plane secrets**

```
┌────────────────────────────────────────────────────────────────┐
│ Planning / LLM Layer                                           │
│                                                                │
│ LLM видит: principal_id="owner", secret_ref="SECRET_OWNER"   │
│ LLM НЕ видит: password="supersecret"                          │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ Execution Layer (ScenarioExecutor)                            │
│                                                                │
│ SessionStore.resolve_secret("SECRET_OWNER")                  │
│   → returns actual password from env/vault                   │
│                                                                │
│ SessionAwareHttpClient.send(step, principal="owner")         │
│   → injects owner's session (cookies, headers) into request  │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ Evidence Layer (build_evidence_bundle)                        │
│                                                                │
│ Redact all secrets from baseline/mutated exchanges           │
│   → [REDACTED]                                               │
│                                                                │
│ Only redacted bundle persisted                               │
└────────────────────────────────────────────────────────────────┘
```

### PrincipalConfig

Файл: `backend/src/orchestration/auth_config.py`

```python
class PrincipalRole(StrEnum):
    OWNER = "owner"           # контролирует ресурсы
    ATTACKER = "attacker"     # пытается получить доступ к чужим
    TENANT_ADMIN = "tenant_admin"
    ANONYMOUS = "anonymous"

class PrincipalConfig(BaseModel):
    """One principal in multi-principal scenario."""
    
    principal_id: str          # "owner", "attacker"
    role: PrincipalRole
    tenant_id: str | None = None
    
    # Auth credentials (either inline или secret_ref for split-plane)
    login: AuthConfig | None = None  # full login_flow
    bearer_token_ref: str | None = None  # reference, not value (SI-3)
    api_key_ref: str | None = None

class TargetConfig(BaseModel):
    # Legacy: backward-compat single auth
    authentication: AuthConfig | None = None
    
    # New: multi-principal
    principals: list[PrincipalConfig] = []
    
    def resolved_principals(self) -> list[PrincipalConfig]:
        """Return actual principals, handling legacy single-auth."""
        if self.principals:
            return self.principals
        
        if self.authentication:
            # Treat as owner principal
            return [
                PrincipalConfig(
                    principal_id="owner",
                    role=PrincipalRole.OWNER,
                    login=self.authentication
                )
            ]
        
        return []
```

### SessionStore

Файл: `backend/src/auth/session_store.py`

```python
@dataclass(repr=False)
class PrincipalSession:
    """Isolated session for one principal."""
    
    principal_id: str
    role: PrincipalRole
    created_at: float
    
    # Isolated per-instance (two principals never share)
    _cookies: dict[str, dict] = field(default_factory=dict)
    _headers: dict[str, str] = field(default_factory=dict)
    storage_state: dict[str, Any] | None = None  # Playwright storageState
    
    def set_cookie(self, name: str, value: str, **kwargs) -> None:
        """Add to this session's jar only."""
        self._cookies[name] = {"name": name, "value": value, **kwargs}
    
    def cookies(self) -> dict[str, str]:
        """Export as name → value dict for HTTP."""
        return {c["name"]: c["value"] for c in self._cookies.values()}
    
    def set_header(self, name: str, value: str) -> None:
        """Add Authorization / X-API-Key / etc."""
        self._headers[name] = value

class SessionStore:
    """Container of isolated PrincipalSession instances."""
    
    def __init__(self) -> None:
        self._sessions: dict[str, PrincipalSession] = {}
    
    def register_session(
        self,
        principal_id: str,
        role: PrincipalRole,
        *,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        storage_state: dict[str, Any] | None = None
    ) -> PrincipalSession:
        """Create isolated session for principal."""
        session = PrincipalSession(
            principal_id=principal_id,
            role=role,
            storage_state=storage_state
        )
        
        if cookies:
            for name, value in cookies.items():
                session.set_cookie(name, value)
        
        if headers:
            for name, value in headers.items():
                session.set_header(name, value)
        
        self._sessions[principal_id] = session
        return session
    
    def get_session(self, principal_id: str) -> PrincipalSession:
        """Fetch session or raise SessionNotFoundError."""
        if principal_id not in self._sessions:
            raise SessionNotFoundError(principal_id)
        return self._sessions[principal_id]
    
    def resolve_secret(self, secret_ref: str) -> str:
        """Resolve secret_ref (handle) to actual value.
        
        Sources: env vars (PRINCIPAL_PASSWORD), vault, etc.
        Never returns unredacted value outside execution layer.
        """
        # Example: SECRET_OWNER → PRINCIPAL_OWNER env var
        env_key = f"PRINCIPAL_{secret_ref}"
        value = os.getenv(env_key)
        if value is None:
            raise SecretResolutionError(f"secret_ref {secret_ref!r} not found")
        return value
```

---

## Approval и EAP

### Что такое Engagement Authorization Profile (EAP)?

**Подписанный per-engagement профиль**, в котором customer предавторизует:

1. **Scope-allowlist целей** (IP/domain, которые можно тестировать)
2. **Классы действий** (SQL injection, XSS, rate-limit, race condition, …)

Ключевое правило (SI-1): **EAP удовлетворяет approval автоматически, но никогда не ослабляет policy.**

```python
class ActionClass(StrEnum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RATE_LIMIT = "rate_limit"
    RACE_CONDITION = "race_condition"
    BUSINESS_LOGIC = "business_logic"

class EngagementAuthorizationProfile(BaseModel):
    """Signed pre-authorization for a scope + action classes."""
    
    engagement_id: str          # UUID of the engagement
    authorized_by: str          # who signed (email)
    issued_at: datetime
    expires_at: datetime
    
    # Scope: what targets are allowed
    targets: list[str | IPv4Network]  # IPs/domains/CIDRs
    
    # Pre-authorized action classes within scope
    action_classes: list[ActionClass]
    
    # Cryptographic signature
    signature: str              # Ed25519, hex-encoded
    public_key_id: str
```

### Интеграция в PreflightChecker

Файл: `backend/src/policy/preflight.py`

```python
class PreflightChecker:
    def __init__(
        self,
        scope_engine: ScopeEngine,
        ownership_store: OwnershipProofStore,
        policy_engine: PolicyEngine,
        approval_service: ApprovalService,
        eap_service: EngagementAuthorizationService,  # NEW
    ):
        self._scope = scope_engine
        self._ownership = ownership_store
        self._policy = policy_engine
        self._approval = approval_service
        self._eap = eap_service
    
    def check(self, action: Action, target: TargetSpec) -> PreflightDecision:
        """Compose 4 guards: scope → ownership → policy → approval/EAP."""
        
        # 1. Scope check (cheapest)
        scope_decision = self._scope.check(target.url)
        if not scope_decision.allowed:
            self._audit.log_deny(
                event_type=AuditEventType.PREFLIGHT_DENY,
                reason=f"scope_denied: {scope_decision.reason}"
            )
            return PreflightDecision(allowed=False, reason=scope_decision.reason)
        
        # 2. Ownership check
        ownership_decision = self._ownership.check(target.url)
        if not ownership_decision.allowed:
            self._audit.log_deny(
                event_type=AuditEventType.PREFLIGHT_DENY,
                reason=f"ownership_not_proven: {ownership_decision.reason}"
            )
            return PreflightDecision(...)
        
        # 3. Policy check (HIGH/DESTRUCTIVE action require approval)
        policy_decision = self._policy.check(action, target)
        if not policy_decision.allowed:
            return PreflightDecision(...)
        
        # If approval required (from policy decision)
        if policy_decision.requires_approval:
            # 4a. Try EAP pre-authorization first (SI-1)
            eap_decision = self._eap.authorize(
                engagement_id=target.engagement_id,
                action=action,
                target=target,
                scope=scope_decision
            )
            
            if eap_decision.authorized:
                # EAP satisfied approval → mint approval_id
                approval_id = uuid4()
                self._audit.log_approval(
                    approval_id=approval_id,
                    reason="eap_preauthorized",
                    engagement_id=target.engagement_id
                )
                return PreflightDecision(
                    allowed=True,
                    approval_id=approval_id,
                    approval_source="eap"
                )
            
            # 4b. Fall back to manual approval check
            approval_sigs = self._approval.fetch_approvals(action, target)
            if not approval_sigs:
                self._audit.log_deny(
                    event_type=AuditEventType.PREFLIGHT_DENY,
                    reason="approval_required_no_signature"
                )
                return PreflightDecision(
                    allowed=False,
                    reason="approval required but not provided"
                )
            
            # Verify signatures
            try:
                approval_id = self._approval.verify(approval_sigs, action)
            except SignatureError as e:
                self._audit.log_deny(
                    event_type=AuditEventType.PREFLIGHT_DENY,
                    reason=f"approval_signature_invalid: {e}"
                )
                return PreflightDecision(allowed=False, reason=str(e))
        
        # All checks passed
        self._audit.log_pass(event_type=AuditEventType.PREFLIGHT_PASS)
        return PreflightDecision(allowed=True)
```

### EAP не расширяет scope

Это критично:

```python
# ❌ НЕПРАВИЛЬНО: EAP пытается добавить цель вне scope
class EngagementAuthorizationService:
    def authorize(self, engagement_id, action, target, scope):
        eap = self._load_eap(engagement_id)
        
        # ✗ ПЛОХО: EAP может добавить цель?
        if target.url not in eap.targets and target.url.startswith("internal"):
            return AuthorizationDecision(authorized=True)  # ✗ НАРУШАЕТ SI-2

# ✅ ПРАВИЛЬНО: EAP только дублирует, не расширяет
class EngagementAuthorizationService:
    def authorize(self, engagement_id, action, target, scope):
        eap = self._load_eap(engagement_id)
        
        # ✓ ХОРОШО: EAP targets must be subset of scope.allowed_targets
        # 1. Check scope first (already passed in preflight)
        if not scope.allowed:
            return AuthorizationDecision(authorized=False)
        
        # 2. Check EAP targets (redundant safety check)
        if not self._target_in_eap(target, eap):
            return AuthorizationDecision(
                authorized=False,
                reason=f"target {target.url} not in EAP allowlist"
            )
        
        # 3. Check action class
        if not self._action_class_preauthorized(action, eap):
            return AuthorizationDecision(
                authorized=False,
                reason=f"action class {action.class_} not pre-authorized"
            )
        
        return AuthorizationDecision(authorized=True)
```

---

## Scenario coverage

### 7 статусов покрытия

| Статус | Значение | Пример |
|--------|----------|--------|
| `NOT_APPLICABLE` | Playbook неприменим к цели | endpoint не в applies_when |
| `NOT_RUN` | Playbook не запущен (e.g., out of budget) | приоритет low, budget исчерпан |
| `BLOCKED` | Запуск заблокирован (e.g., no approval, no principal) | WAITING_APPROVAL, no attacker-principal available |
| `PARTIAL` | Часть шагов упала, но oracle дал вердикт | HTTP 200 baseline, но attacker-request упал → INCONCLUSIVE |
| `EXECUTED_NO_FINDING` | Playbook запущен полностью → oracle: NO_FINDING | успешно, но уязвимость не обнаружена |
| `CONFIRMED_FINDING` | Playbook запущен → oracle: FINDING | IDOR подтверждена: attacker получил owner data |
| `ERROR` | Крах (e.g., timeout, network error) | ScenarioExecutor упал с exception |

### Правило: "запуск инструмента ≠ COVERED"

```python
# ❌ ПЛОХО: просто запустили nuclei = COVERED
class WSTGCoverage:
    def track_coverage(self, wstg_test_case_id, tool_name, result):
        if tool_name == "nuclei":
            self.coverage[wstg_test_case_id] = "EXECUTED"  # ✗ Wrong!

# ✅ ПРАВИЛЬНО: oracle verdict + evidence = COVERED
class WSTGCoverage:
    def track_coverage(self, scenario_result: ScenarioResult, wstg_ids: list[str]):
        for wstg_id in wstg_ids:
            if scenario_result.state.status == ScenarioStatus.CONFIRMED:
                self.coverage[wstg_id] = "CONFIRMED_FINDING"
            elif scenario_result.state.status == ScenarioStatus.REJECTED:
                self.coverage[wstg_id] = "EXECUTED_NO_FINDING"
            elif scenario_result.state.status == ScenarioStatus.PARTIAL:
                self.coverage[wstg_id] = "PARTIAL"
            else:
                # SKIPPED_NOT_APPLICABLE, WAITING_APPROVAL, ERROR, etc.
                self.coverage[wstg_id] = map_status(scenario_result.state.status)
```

---

## Troubleshooting

### Частые ошибки и решения

| Ошибка | Причина | Решение |
|--------|--------|---------|
| `PlaybookSignatureError: signature verification failed` | Playbook не подписан или сигнатура неверна | `python scripts/playbooks_sign.py --sign` |
| `RegistryLoadError: duplicate playbook_id` | Два файла с одинаковым playbook_id | Переименуйте файл, проверьте id в YAML |
| `RegistryLoadError: playbook_id ... does not match filename stem` | playbook_id в YAML ≠ имя файла | `idor.cross-user-read` id → `idor.cross-user-read.yaml` file |
| `RegistryLoadError: playbook ... category ... does not match directory ...` | Файл не в правильной папке | `authorization/idor.cross-user-read.yaml`, не `root/` |
| `ValidationError: params for action http_request are invalid` | Неверные параметры шага | Проверьте `params` по типу action (`HttpRequestParams`, etc.) |
| `InvalidTransitionError: illegal scenario transition PLANNED -> CONFIRMED` | Неверный переход статуса | Проверьте lifecycle в `lifecycle.py` |
| `SessionNotFoundError: principal attacker` | Principal не зарегистрирован в SessionStore | Проверьте, что playbook указывает required_principals |
| `PlaybookNotFoundError: unknown.id` | Playbook не загружен в registry | Проверьте, что YAML под `config/playbooks/` + подписан |
| `OracleResult: INCONCLUSIVE` | Oracle не может судить (e.g., только volatile fields отличаются) | Уточните sensitive_fields в oracle params |

### Проверка конфигурации

```bash
cd backend

# 1. Проверьте registry загружается
python -c "
from src.playbooks.registry import PlaybookRegistry
from pathlib import Path

registry = PlaybookRegistry(Path('config/playbooks'))
summary = registry.load()
print(f'Loaded {summary.total} playbooks')
for pid in registry:
    playbook = registry.get(pid)
    print(f'  - {playbook.playbook_id} ({playbook.category})')
"

# 2. Валидируйте все YAML вручную
python -c "
import yaml
from pathlib import Path
from src.playbooks.schema import Playbook

for yaml_path in Path('config/playbooks').rglob('*.yaml'):
    with open(yaml_path) as f:
        payload = yaml.safe_load(f)
    try:
        Playbook(**payload)
        print(f'✓ {yaml_path}')
    except Exception as e:
        print(f'✗ {yaml_path}: {e}')
"

# 3. Проверьте сигнатуры
python scripts/playbooks_sign.py --verify

# 4. Запустите unit-тесты
python -m pytest tests/unit/playbooks/ -v
```

---

## Ссылки на смежную документацию

- **Auth Migration Guide:** `ai_docs/develop/architecture/2026-07-22-auth-migration-guide.md`
- **Planning Report:** `ai_docs/develop/plans/2026-07-22-argus-pipeline-playbooks.md`
- **API Contract:** `docs/api-contracts.md`
- **Security Model:** `docs/security.md`

---

**Created:** 2026-07-22  
**Author:** ARGUS Documentation System  
**Status:** Production Ready (P2–P4 delivered, P5–P7 in flight)
