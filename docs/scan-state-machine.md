# ARGUS Scan State Machine

**Version:** 0.1  
**Phases:** 6 sequential phases  
**Source:** TZ.md, src/orchestration/state_machine.py, phases.py

---

## 1. Overview

Scan lifecycle реализован как state machine из 6 последовательных фаз:
1. **recon** — разведка
2. **threat_modeling** — моделирование угроз
3. **vuln_analysis** — анализ уязвимостей
4. **exploitation** — эксплуатация (с approval gates)
5. **post_exploitation** — пост-эксплуатация
6. **reporting** — формирование отчёта

---

## 2. Phase Diagram (Mermaid)

```mermaid
stateDiagram-v2
    [*] --> recon
    recon --> threat_modeling
    threat_modeling --> vuln_analysis
    vuln_analysis --> exploitation
    exploitation --> post_exploitation
    post_exploitation --> reporting
    reporting --> [*]

    recon --> failed : error
    threat_modeling --> failed : error
    vuln_analysis --> failed : error
    exploitation --> failed : error
    post_exploitation --> failed : error
    reporting --> failed : error

    exploitation --> exploitation : approval_gate
    exploitation --> post_exploitation : approved
```

---

## 3. Phase Order

| Order | Phase | Progress % |
|-------|-------|------------|
| 0 | recon | ~17 |
| 1 | threat_modeling | ~33 |
| 2 | vuln_analysis | ~50 |
| 3 | exploitation | ~67 |
| 4 | post_exploitation | ~83 |
| 5 | reporting | 100 |

---

## 4. Phase Definitions

### 4.1 recon

**Input:** `target`, `options`  
**Output:** `assets`, `subdomains`, `ports`  
**DB:** `phase_inputs`, `phase_outputs`, `scan_timeline`, `assets`  
**Events:** `phase_start`, `progress`, `phase_complete`, `tool_run`  
**Failure:** Scan → `failed`, `scan_events` → `error`, re-raise

**Tools:** nmap, subfinder, nikto, nuclei (read-only); guardrails: IP/domain validation.

**Raw Artifacts:** Phase persists raw artifacts to MinIO via `upload_raw_artifact` (handler in `state_machine/handlers`):
- Path: `{tenant_id}/{scan_id}/recon/raw/`
- Artifacts: tool logs, stdout/stderr, raw output files (e.g. nmap XML, nuclei JSON)

---

### 4.2 threat_modeling

**Input:** `assets` (from recon)  
**Output:** `threat_model` (dict)  
**DB:** `phase_inputs`, `phase_outputs`, `scan_timeline`  
**AI:** LLM prompt для threat model; strict JSON schema.  
**Failure:** Scan → `failed`, re-raise

**Raw Artifacts:** Phase persists raw artifacts to MinIO via pipeline execution:
- Path: `{tenant_id}/{scan_id}/threat_modeling/raw/`
- Artifacts: threat model JSON, LLM responses, intermediate analysis files

---

### 4.3 vuln_analysis

**Input:** `threat_model`, `assets`  
**Output:** `findings` (list of dict)  
**DB:** `phase_inputs`, `phase_outputs`, `scan_timeline`  
**AI:** LLM prompt для анализа; strict JSON schema; retry/fixer prompt.  
**Failure:** Scan → `failed`, re-raise

**Raw Artifacts:** Phase persists raw artifacts to MinIO via pipeline execution:
- Path: `{tenant_id}/{scan_id}/vuln_analysis/raw/`
- Artifacts: vulnerability scan outputs, evidence bundles, contradiction analysis, finding confirmation matrices

#### 4.3a — Active Web Scanning (OWASP)

> **State Machine Bridge** (WEB-001, 2026-03-24): `run_vuln_analysis()` в `handlers.py` теперь вызывает
> полный active-scan pipeline (`run_va_active_scan_phase`) напрямую из state machine, когда
> `SANDBOX_ENABLED=true`. Ранее active-scan вызывался только из recon engagement flow.
>
> **Порядок выполнения в state machine vuln_analysis:**
> 1. Извлечение URL-параметров и HTML-форм из target URL (`_extract_url_params_and_forms`)
> 2. Построение `VulnerabilityAnalysisInputBundle` с `params_inventory` и `forms_inventory`
> 3. Запуск `run_va_active_scan_phase` (dalfox, xsstrike, ffuf, nuclei, gobuster, wfuzz, commix)
> 4. Запуск OWASP-эвристик (SSRF, CSRF, IDOR, open redirect) — `run_web_vuln_heuristics`
> 5. Нормализация находок, назначение CVSS, генерация PoC
> 6. Передача контекста в LLM для финального анализа
> 7. Мердж и дедупликация всех findings
> 8. Пост-обработка CVSS (floor для XSS >= 7.0, SQLi >= 8.0)
>
> **Fallback:** Если `SANDBOX_ENABLED=false`, выполняется только LLM-анализ (прежнее поведение).
>
> **VA_AI_PLAN_ENABLED** (`va_ai_plan_enabled`, env `VA_AI_PLAN_ENABLED`): при `true` и наличии LLM-ключей после детерминированного плана вызывается `plan_active_scan_with_ai` — дополнительные шаги `{tool, args}` мержатся в active-scan plan (см. `active_scan_planner.py`, промпты `ACTIVE_SCAN_PLANNING_*` в [prompt-registry.md](./prompt-registry.md)).

**Запуск активного сканирования вебприложений с инструментами, ориентированными на OWASP Top 10:**

| Инструмент | Целевые уязвимости | Статус | Примечания |
|-----------|-------------------|--------|-----------|
| **dalfox** | XSS (reflected, stored, DOM-based), filter evasion | Доступен | WAF bypass detection, payload template library |
| **ffuf** | Directory traversal, hidden paths, parameter fuzzing | Доступен | Concurrent requests (customizable rate limiting) |
| **sqlmap** | SQL Injection (SQLi), database fingerprinting | Policy-gated | Requires approval gate (см. § 7 Policy); destructive operations disabled by default |
| **xsstrike** | XSS (advanced), context-aware payload generation | Доступен | Leverages DOM context analysis, bypass techniques |
| **nuclei** | Template-based VA (OWASP coverage, CWE mapping) | Read-only | Passive detection phase completion; integration in recon + vuln_analysis |
| **gobuster** | DNS enumeration, virtual host discovery | Доступен | Recon companion (phase 1); filtered for active scan scope |

**Policy Integration** (`§ 7 Policy / Approval Gates`):
- **sqlmap** запуски требуют одобрения при `policy.exploit_approval = true` (destructive database queries)
- **dalfox**, **ffuf**, **xsstrike**, **nuclei** — автоматические (без approval) в пределах scope
- **Scope validation:** Target должен быть в разрешённом scope; out-of-scope запросы блокируются перед запуском

**Sandbox & Compliance**:
- **MCP allowlist** (см. `src/recon/mcp/policy.py`): `web_vulnerability_scanning`, `xss_testing`, `sql_injection_testing`, `directory_discovery`
- **Rate limiting:** Настраивается на уровне tenant через `policies.config` (default: 10 req/sec)
- **Log redaction:** Credentials, cookies, sensitive headers исключаются из raw artifacts
- **Evidence collection:** Payloads, responses, PoC сохраняются в `finding_confirmation_matrix.csv` для последующей валидации
- **Sandbox reference:** [deployment.md](./deployment.md#sandbox-environment) — контейнеризованное окружение с network isolation

**Raw Artifacts** (подфаза active_web_scan):
- `web_scan_requests.json` — dalfox/ffuf/nuclei запросы (без credentials)
- `web_scan_responses.json` — responses (без sensitive data)
- `xss_payloads.json` — xsstrike payload templates и результаты
- `sqlmap_output.json` — (policy-gated) SQLi findings; пустой если approval denied
- `web_findings.csv` — vulnerability summary (type, endpoint, severity, PoC link)

**Related Documentation**:
- [Policy gates](./deployment.md#policies-and-approval) — exploit approval workflow
- [Sandbox](./deployment.md#sandbox-environment) — isolated environment controls
- OWASP Top 10 mapping: XSS (A03), Injection (A03), Path Traversal (A01)

---

### 4.4 exploitation

**Input:** `findings` (from vuln_analysis)  
**Output:** `exploits`, `evidence`  
**Sub-phases:** `exploit_attempt` → `exploit_verify`  
**Policy:** Approval gate для destructive/exploit actions.  
**DB:** `phase_inputs`, `phase_outputs`, `scan_timeline`, `tool_runs`, `evidence`  
**Failure:** Scan → `failed`, re-raise

**Approval gate:** Если policy требует approval — scan переходит в `awaiting_approval`; после approve — продолжение.

#### VA-007 — агрессивные VA-инструменты (Celery) в фазе exploitation

После прохождения approval gate и **до** `exploit_attempt` вызывается `maybe_run_aggressive_exploit_tools(findings, tenant_id, scan_id, target, scan_approval_flags=…)` (`src/orchestration/aggressive_exploit_tools.py`):

| Условие | Поведение |
|---------|-----------|
| `VA_EXPLOIT_AGGRESSIVE_ENABLED=false` (default) | No-op, обратная совместимость |
| `VA_EXPLOIT_AGGRESSIVE_ENABLED=true` | При эвристике SQLi в findings проверяется `evaluate_tool_approval_policy("sqlmap", scan_approval_flags=…)` |
| `scan.options["scan_approval_flags"]` | Словарь `{"sqlmap": true, ...}` — как в WEB-006; если ключа нет при переданном dict, sqlmap для destructive-ветки блокируется |
| `SQLMAP_VA_ENABLED=true` | Иначе задача не ставится в очередь (Celery task вернёт `sqlmap_va_disabled`) |
| Успех | `run_sqlmap.delay(tenant_id, scan_id, target, None)` — очередь `argus.va.run_sqlmap`, артефакты в `vuln_analysis/raw/` |

**Логи:** структурированные события `va_aggressive_exploit_*` без утечки тел запросов.

**Raw Artifacts:** Phase persists raw artifacts to MinIO via pipeline execution:
- Path: `{tenant_id}/{scan_id}/exploitation/raw/`
- Artifacts: exploit attempts, proof-of-concept evidence, tool outputs, post-exploit logs

---

### 4.5 post_exploitation

**Input:** `exploits` (from exploitation)  
**Output:** `lateral`, `persistence`  
**DB:** `phase_inputs`, `phase_outputs`, `scan_timeline`  
**AI:** LLM prompt для post-exploit analysis.  
**Failure:** Scan → `failed`, re-raise

**Raw Artifacts:** Phase persists raw artifacts to MinIO via handler (in `state_machine/handlers`):
- Path: `{tenant_id}/{scan_id}/post_exploitation/raw/`
- Artifacts: lateral movement evidence, persistence mechanisms, session data, reconnaissance within compromised systems

---

### 4.6 reporting

**Input:** `target`, `recon`, `threat_model`, `vuln_analysis`, `exploitation`, `post_exploitation`  
**Output:** `report` (dict: summary, findings, technologies, ai_insights)  
**DB:** `reports`, `findings`, `report_objects`, `phase_outputs`  
**Events:** `finding`, `complete`  
**Failure:** Scan → `failed`, re-raise

---

## 5. Transitions

| From | To | Condition |
|------|------|-----------|
| init | recon | Scan created |

| recon | threat_modeling | recon completed |
| threat_modeling | vuln_analysis | threat_modeling completed |
| vuln_analysis | exploitation | vuln_analysis completed |
| exploitation | post_exploitation | exploitation completed (or approval granted) |
| post_exploitation | reporting | post_exploitation completed |
| reporting | complete | reporting completed |

**Any phase** → **failed** | Exception raised

---

## 6. Failure Handling

| Event | Action |
|-------|--------|
| Phase exception | `scan_step.status = "failed"`; `scan_events` → `error`; `scan.status = "failed"`; `scan.phase = current_phase` |
| Re-raise | Celery task fails; retry policy (configurable) |
| User-facing | No stack trace; generic error; structured log only |

---

## 7. Policy / Approval Gates

| Gate | Phase | When | Behavior |
|------|-------|------|----------|
| **Exploit approval** | exploitation | Policy requires approval for destructive actions | Scan → `awaiting_approval`; admin must approve |
| **Scope check** | All phases | Target out of scope | Block phase; record event |
| **Rate limit** | All phases | Tenant usage exceeded | Block phase; return error |

**Policy config:** `policies` table; `policy_type = 'exploit_approval'`, `config = { "require_approval": true }`.

---

## 8. Events (SSE)

| Event | Payload | When |
|-------|---------|------|
| `phase_start` | phase, progress, message | Start of each phase |
| `progress` | phase, progress, message | Progress update |
| `tool_run` | phase, tool, data | Tool execution |
| `phase_complete` | phase, progress, data (output) | Phase finished |
| `finding` | severity, title, cwe, cvss | Finding added (reporting) |
| `complete` | phase=complete, progress=100 | Scan finished |
| `error` | phase, error, error message | Phase failed |

---

## 9. Text Diagram (Simplified)

```
[init] → recon → threat_modeling → vuln_analysis → exploitation → post_exploitation → reporting → [complete]
         │              │              │              │                    │              │
         └──────────────┴──────────────┴──────────────┴────────────────────┴──────────────┘
                                                    │
                                                    ▼
                                              [failed]
```

---

## 10. Raw Artifact Storage (MinIO)

All phases persist raw outputs to MinIO for audit trail, evidence preservation, and API access:

| Phase | MinIO Path | Handler/Pipeline | Artifacts |
|-------|-----------|-----------------|-----------|
| **recon** | `{tenant_id}/{scan_id}/recon/raw/` | `state_machine/handlers` | Tool logs, nmap XML, nuclei JSON, subdomain lists |
| **threat_modeling** | `{tenant_id}/{scan_id}/threat_modeling/raw/` | `pipelines/threat_modeling` | Threat model JSON, LLM responses, analysis files |
| **vuln_analysis** | `{tenant_id}/{scan_id}/vuln_analysis/raw/` | `pipelines/vulnerability_analysis` | Evidence bundles, contradiction analysis, confirmation matrices |
| **exploitation** | `{tenant_id}/{scan_id}/exploitation/raw/` | `pipelines/exploitation` | Exploit attempts, PoC evidence, tool outputs, logs |
| **post_exploitation** | `{tenant_id}/{scan_id}/post_exploitation/raw/` | `state_machine/handlers` | Lateral movement, persistence mechanisms, session data |

**API Access:** `GET /api/v1/scans/{id}/artifacts?phase={phase}&raw=true&presigned={bool}` — Returns presigned URLs or raw artifact metadata (see [reporting.md](./reporting.md#artifacts-in-html-reports)).

---

## 11. Related Documents

- [backend-architecture.md](./backend-architecture.md)
- [erd.md](./erd.md)
- [frontend-api-contract.md](./frontend-api-contract.md)
