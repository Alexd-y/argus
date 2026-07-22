# WSTG и Scenario Coverage

**Дата:** 2026-07-22  
**Версия:** 1.0  
**WSTG Version:** v4.2  
**Status:** Production Ready

---

## Обзор

Система WSTG v4.2 трекует покрытие всех test case'ов через **выполненные сценарии** (playbooks). На уровне Finding'а каждый результат oracle'а маппится на WSTG test case и 7 статусов покрытия.

---

## WSTG v4.2 Registry

Файл: `backend/src/reports/wstg_coverage.py`

Единый источник истины всех WSTG test case'ов:

```python
WSTG_REGISTRY = {
    "WSTG-ATHZ-04": {
        "name": "Testing for Broken Object Level Authorization (BOLA/IDOR)",
        "category": "Authorization",
        "test_objective": "Verify that the application enforces object-level authorization",
        "mapped_playbooks": [
            "idor.cross-user-read",
            "idor.cross-user-write",
        ]
    },
    "WSTG-AUTHN-02": {
        "name": "Testing for Session Management",
        "category": "Authentication",
        "test_objective": "Ensure proper session handling and timeout",
        "mapped_playbooks": [
            "session.logout-invalidation",
            "session.fixation",
        ]
    },
    # ... 120+ test cases
}
```

**Удалены дубли v2.0** — использование `wstg_coverage_v2.py` (G-4) запрещено (grep=0).

---

## 7 Статусов покрытия

```
┌─────────────────────────────────────────────────────────────┐
│ WSTG Coverage Status                                        │
│                                                             │
│  1. NOT_APPLICABLE                                         │
│     └─> Playbook не применим к целевому endpoint           │
│     └─> Reason: applies_when не match или нет principals   │
│                                                             │
│  2. NOT_RUN                                                │
│     └─> Playbook не запущен (отсутствие ресурсов)         │
│     └─> Reason: budget исчерпан, приоритет low             │
│                                                             │
│  3. BLOCKED                                                │
│     └─> Запуск заблокирован (policy/approval/error)       │
│     └─> Reason: WAITING_APPROVAL, no attacker, timeout     │
│                                                             │
│  4. PARTIAL                                                │
│     └─> Часть шагов упала, oracle судит partial data      │
│     └─> Reason: baseline OK, attacker HTTP 500, oracle OK │
│                                                             │
│  5. EXECUTED_NO_FINDING                                    │
│     └─> Playbook выполнен полностью → oracle NO_FINDING   │
│     └─> Reason: attacker не получил приватные данные      │
│                                                             │
│  6. CONFIRMED_FINDING                                      │
│     └─> Playbook выполнен → oracle FINDING ✓              │
│     └─> Reason: attacker реально получил owner data       │
│                                                             │
│  7. ERROR                                                  │
│     └─> Крах при исполнении (exception/timeout/crash)    │
│     └─> Reason: ScenarioExecutor exception                 │
└─────────────────────────────────────────────────────────────┘
```

### Правило: "Запуск инструмента ≠ COVERED"

```python
# ❌ СТАРЫЙ ПОДХОД (неправильно)
# Просто запустили nuclei → "EXECUTED" (неправда!)
def track_tool_run(self, tool_name, output):
    self.coverage = "EXECUTED"  # ✗ Неправильно!

# ✅ НОВЫЙ ПОДХОД (правильно)
# Oracle verdict + evidence → один из 7 статусов
def track_scenario_result(self, scenario_result: ScenarioResult, wstg_ids: list[str]):
    verdict = scenario_result.oracle_result.verdict
    
    if scenario_result.state.status == ScenarioStatus.SKIPPED_NOT_APPLICABLE:
        status = "NOT_APPLICABLE"
    elif scenario_result.state.status == ScenarioStatus.WAITING_APPROVAL:
        status = "BLOCKED"
    elif scenario_result.state.status == ScenarioStatus.PARTIAL:
        status = "PARTIAL"
    elif scenario_result.state.status == ScenarioStatus.CONFIRMED:
        # Oracle вердикт: FINDING = уязвимость найдена
        if verdict == OracleVerdict.FINDING:
            status = "CONFIRMED_FINDING"
        else:
            status = "EXECUTED_NO_FINDING"
    elif scenario_result.state.status == ScenarioStatus.CLEANUP_FAILED:
        status = "ERROR"
    else:
        status = "EXECUTED_NO_FINDING"
    
    for wstg_id in wstg_ids:
        self.coverage[wstg_id] = status
```

### Обратная совместимость

FindingDTO расширяется **только Optional-полями**:

```python
class FindingDTO(BaseModel):
    # Existing fields (pre-P7)
    finding_id: str
    severity: Severity
    status: FindingStatus  # NEW/VALIDATED/...
    description: str
    
    # NEW FIELDS (P7, all Optional for back-compat)
    scenario_id: str | None = None              # UUID of executed scenario
    playbook_id: str | None = None              # idor.cross-user-read
    playbook_run_id: str | None = None          # UUID, for audit trail
    
    # Multi-principal context
    source_principal: str | None = None         # owner, attacker, ...
    target_principal: str | None = None         # who is being attacked
    
    # Evidence: baseline vs mutated
    baseline_request: str | None = None         # redacted
    baseline_response: str | None = None        # redacted
    mutated_request: str | None = None          # redacted
    mutated_response: str | None = None         # redacted
    diff: str | None = None                     # normalized diff
    
    # Oracle result
    oracle_result: OracleResult | None = None   # {verdict, reason, confidence}
    
    # Cleanup tracking
    cleanup_status: str | None = None           # COMPLETE, FAILED
    
    # Attribution
    provenance: Provenance | None = None        # source_url, commit, adapted_at
    approval_id: str | None = None              # UUID from EAP/manual approval
    
    # WSTG coverage
    wstg_ids: list[str] = []                    # ["WSTG-ATHZ-04", ...]
    owasp_api_ids: list[str] = []               # ["API1:2023", ...]
```

**Существующие продюсеры (sandbox/parsers)** НЕ требуют изменений: новые поля Optional.

**Мост из confirmation → evidence → FindingDTO:**

```python
def build_finding_dto_from_scenario(scenario_result: ScenarioResult):
    """Project scenario result into FindingDTO."""
    
    finding = FindingDTO(
        finding_id=uuid4(),
        severity=Severity.HIGH,
        status=FindingStatus.VALIDATED,  # предполагаем подтверждено
        
        # NEW FIELDS (P7)
        scenario_id=scenario_result.scenario_id,
        playbook_id=scenario_result.playbook.playbook_id,
        playbook_run_id=scenario_result.run_id,
        
        source_principal=scenario_result.source_principal_id,
        target_principal=scenario_result.target_principal_id,
        
        baseline_request=scenario_result.evidence.baseline_exchange.request_redacted,
        baseline_response=scenario_result.evidence.baseline_exchange.response_redacted,
        mutated_request=scenario_result.evidence.mutated_exchange.request_redacted,
        mutated_response=scenario_result.evidence.mutated_exchange.response_redacted,
        diff=scenario_result.evidence.diff,
        
        oracle_result=scenario_result.oracle_result,
        cleanup_status=scenario_result.cleanup_status,
        
        provenance=scenario_result.playbook.provenance,
        approval_id=scenario_result.approval_id,
        
        wstg_ids=scenario_result.playbook.wstg,
        owasp_api_ids=scenario_result.playbook.owasp_api,
    )
    
    return finding
```

---

## Scenario-to-WSTG Mapping

Каждый playbook декларирует WSTG test case'ы:

```yaml
# backend/config/playbooks/authorization/idor.cross-user-read.yaml
wstg:
  - WSTG-ATHZ-04  # Broken Object Level Authorization
owasp_api:
  - API1:2023     # Broken Object Level Authorization

# backend/src/reports/wstg_coverage.py регистрирует обратное отношение:
WSTG_REGISTRY["WSTG-ATHZ-04"]["mapped_playbooks"].append("idor.cross-user-read")
```

Во время выполнения:

```python
def collect_wstg_coverage(scan_id: str):
    """Aggregate coverage from all executed scenarios."""
    
    scenarios = fetch_scenario_results(scan_id)  # all PlaybookRun records
    
    coverage = {}  # wstg_id -> status
    
    for scenario in scenarios:
        playbook = scenario.playbook
        
        # Get WSTG test cases this playbook covers
        for wstg_id in playbook.wstg:
            # Determine coverage status from scenario result
            if scenario.state.status == ScenarioStatus.CONFIRMED:
                coverage[wstg_id] = "CONFIRMED_FINDING"
            elif scenario.state.status == ScenarioStatus.REJECTED:
                coverage[wstg_id] = "EXECUTED_NO_FINDING"
            elif scenario.state.status == ScenarioStatus.PARTIAL:
                coverage[wstg_id] = "PARTIAL"
            elif scenario.state.status == ScenarioStatus.WAITING_APPROVAL:
                coverage[wstg_id] = "BLOCKED"
            elif scenario.state.status == ScenarioStatus.SKIPPED_NOT_APPLICABLE:
                coverage[wstg_id] = "NOT_APPLICABLE"
            # ... etc
    
    return coverage
```

---

## Модель данных: Scenario Persistence

Каждый сценарий сохраняется в DB:

```sql
CREATE TABLE playbook_runs (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    playbook_id VARCHAR(128) NOT NULL,
    playbook_version INT NOT NULL,
    
    -- Execution context
    principal_id VARCHAR(32) NOT NULL,  -- owner, attacker, ...
    target_spec_json JSONB,              -- target being tested
    
    -- Lifecycle
    state_status VARCHAR(32) NOT NULL,   -- DISCOVERED, RUNNING, CONFIRMED, ...
    state_reason TEXT,                   -- why SKIPPED/REJECTED/FAILED
    state_updated_at TIMESTAMP,
    
    -- Evidence
    evidence_bundle_id UUID,             -- refs evidence_bundles.id
    oracle_verdict VARCHAR(16),          -- FINDING, NO_FINDING, INCONCLUSIVE
    oracle_confidence VARCHAR(16),       -- HIGH, MEDIUM, LOW
    
    -- Approval
    approval_id UUID,                    -- from EAP or manual approval
    approval_source VARCHAR(16),         -- "eap" or "manual"
    
    -- Cleanup
    cleanup_status VARCHAR(16),          -- COMPLETE, FAILED
    cleanup_reason TEXT,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Evidence redacted bundles
CREATE TABLE evidence_bundles (
    id UUID PRIMARY KEY,
    playbook_run_id UUID NOT NULL REFERENCES playbook_runs(id),
    
    baseline_request_redacted TEXT,
    baseline_response_redacted TEXT,
    mutated_request_redacted TEXT,
    mutated_response_redacted TEXT,
    
    normalized_diff TEXT,
    redaction_count INT,                 -- how many secrets redacted
    sha256_hash VARCHAR(64),              -- for dedup
    
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

## Пример: IDOR Scenario от планирования до report'а

```
1. DISCOVERY (LLM находит endpoint)
   /api/v1/users/2001 (GET) → может быть IDOR
   
2. PLANNING (ScenarioPlanner)
   ├─ applicability: method=GET ✓, path matches /api/*/users/* ✓
   ├─ principals: owner, attacker available ✓
   ├─ capabilities: http_client available ✓
   ├─ approval: LOW risk → no approval needed
   └─ Result: PlannedScenario(status=PLANNED, playbook_id=idor.cross-user-read)

3. EXECUTION (ScenarioExecutor)
   ├─ Step 1: owner reads /api/v1/users/2001
   │  └─ Response: {"id":2001, "email":"owner@example.com", "phone":"555-1234"}
   │
   ├─ Step 2: attacker reads /api/v1/users/2001 (attacker's session)
   │  └─ Response: {"id":2001, "email":"owner@example.com", "phone":"555-1234"}
   │
   ├─ Oracle authz judgment:
   │  ├─ baseline: owner response (control)
   │  ├─ mutated: attacker response (attack)
   │  ├─ sensitive_fields: [email, phone]
   │  ├─ compare: attacker HAS email + phone from owner ✗
   │  └─ verdict: FINDING (confidence=HIGH)
   │
   └─ Cleanup: none needed (read-only)

4. EVIDENCE & FINDING
   ├─ build_evidence_bundle()
   │  ├─ redact baseline request/response
   │  ├─ redact mutated request/response
   │  ├─ compute normalized diff
   │  └─ hash for dedup
   │
   └─ FindingDTO
      ├─ finding_id: <UUID>
      ├─ scenario_id: <UUID>
      ├─ playbook_id: idor.cross-user-read
      ├─ source_principal: attacker
      ├─ oracle_result: FINDING (HIGH confidence)
      ├─ wstg_ids: [WSTG-ATHZ-04]
      ├─ owasp_api_ids: [API1:2023]
      └─ approval_id: <from EAP>

5. CONFIRMATION
   ├─ oracle verdict FINDING → confirmation_policy.confirm()
   ├─ Finding status: HYPOTHESIS → CONFIRMED ✓
   │
   └─ WSTG Coverage Update
      ├─ WSTG-ATHZ-04: "CONFIRMED_FINDING" ✓
      └─ API1:2023: "CONFIRMED_FINDING" ✓

6. REPORT GENERATION (Midgard tier)
   ├─ WSTG Coverage Section:
   │  ├─ Authorization
   │  │  └─ WSTG-ATHZ-04: ✓ CONFIRMED
   │  │     └─ BOLA/IDOR on /api/v1/users/<id>
   │  │     └─ Attacker can read victim's email + phone
   │  │     └─ Evidence: baseline vs mutated diff [REDACTED]
   │  │
   │  └─ ... other test cases
   │
   └─ Finding Detail: (with baseline/mutated diff, audit trail)
```

---

## Versioning WSTG

**Перевод старых scan'ов не требуется:**

- WSTG v4.2 — единая версия (no v2.0 backward-compat)
- Старые findings с v2.0 WSTG ID'ами → аннотация `wstg_version: 2.0` (опционально, для аудита)
- Новые playbook'ы всегда используют v4.2 ID'ы

**Dead code cleanup:**

```python
# backend/src/reports/wstg_coverage_v2.py
# ✗ Удалить или оставить stub с DeprecationWarning

import warnings

def build_wstg_coverage_v2(*args, **kwargs):
    warnings.warn(
        "wstg_coverage_v2 is deprecated; use wstg_coverage.build_wstg_coverage",
        DeprecationWarning,
        stacklevel=2
    )
    from src.reports.wstg_coverage import build_wstg_coverage
    return build_wstg_coverage(*args, **kwargs)
```

---

## Интеграция в Reporting Layer

Файл: `backend/src/reports/report_service.py`

```python
def generate_midgard_report(scan_id: str, tier: str = "midgard"):
    """Generate Midgard tier technical report with WSTG coverage."""
    
    scan = fetch_scan(scan_id)
    findings = fetch_findings(scan_id)
    scenarios = fetch_scenarios(scan_id)
    
    # Build WSTG coverage matrix
    coverage = collect_wstg_coverage(scenarios)
    
    # Section: Coverage Summary
    coverage_by_status = {}
    for test_case_id, status in coverage.items():
        coverage_by_status.setdefault(status, []).append(test_case_id)
    
    report_sections = [
        MidgardSection(
            title="WSTG Test Coverage",
            subsections=[
                {
                    "title": "Confirmed Findings",
                    "test_cases": coverage_by_status.get("CONFIRMED_FINDING", []),
                    "count": len(coverage_by_status.get("CONFIRMED_FINDING", []))
                },
                {
                    "title": "Executed - No Finding",
                    "test_cases": coverage_by_status.get("EXECUTED_NO_FINDING", []),
                    "count": len(coverage_by_status.get("EXECUTED_NO_FINDING", []))
                },
                {
                    "title": "Blocked / Not Applicable",
                    "test_cases": coverage_by_status.get("NOT_APPLICABLE", []) +
                                 coverage_by_status.get("BLOCKED", []),
                    "count": len(...)
                },
            ]
        ),
        
        # Detail: each finding with scenario context
        *[
            MidgardSection(
                title=f"Finding: {finding.title}",
                details={
                    "scenario_id": finding.scenario_id,
                    "playbook": finding.playbook_id,
                    "wstg_coverage": finding.wstg_ids,
                    "evidence": {
                        "baseline": finding.baseline_response[:200],  # truncated
                        "mutated": finding.mutated_response[:200],
                        "diff": finding.diff,
                    },
                    "oracle_result": finding.oracle_result,
                }
            )
            for finding in findings
            if finding.oracle_result and finding.oracle_result.verdict == OracleVerdict.FINDING
        ]
    ]
    
    return MidgardReport(sections=report_sections)
```

---

## Резюме: Back-compat гарантии (SI-7)

✓ Все новые fields в FindingDTO — `Optional`  
✓ Существующие продюсеры (sandbox/parsers) не падают  
✓ Старые API вызовы продолжают работать  
✓ WSTG v2.0 полностью заменена v4.2 (нет дубля)  
✓ Playbook versioning позволяет обновлять без breaking changes

**Тест:**

```bash
# backend/tests/integration/test_wstg_coverage_backcompat.py

def test_finding_dto_backward_compat():
    """Old FindingDTO creation still works with new optional fields."""
    
    # Old-style creation (pre-P7)
    finding = FindingDTO(
        finding_id="test",
        severity=Severity.HIGH,
        status=FindingStatus.VALIDATED,
        description="IDOR"
    )
    
    # New-style creation (with optional scenario fields)
    finding_new = FindingDTO(
        finding_id="test2",
        severity=Severity.HIGH,
        status=FindingStatus.VALIDATED,
        description="IDOR",
        scenario_id="uuid",
        playbook_id="idor.cross-user-read",
        # ...
    )
    
    assert finding is not None
    assert finding_new is not None
    assert finding.scenario_id is None  # Old-style has None
    assert finding_new.scenario_id == "uuid"
```

---

**Created:** 2026-07-22  
**Author:** ARGUS Documentation System  
**Status:** Production Ready
