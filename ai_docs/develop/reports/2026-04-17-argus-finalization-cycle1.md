# ARGUS Active Pentest Engine — Finalization cycle report (ARG-001..ARG-010)

**Дата:** 2026-04-17  
**Окно цикла:** ARG-001..ARG-010 (single orchestration session)  
**Бэклог:** `Backlog/dev1_md` §§4.1–4.3 (35 tool YAMLs), §5–§8, §11, §14, §16–19  
**Status:** ✅ shipped  
**Owner:** AI orchestrator pipeline (planner → worker → test-writer → test-runner → reviewer → debugger → documenter)

---

## 1. Цель цикла

В текущем цикле заложен **архитектурный фундамент** ARGUS v1 — десять критичных и разблокирующих модулей control-plane:

1. **Pipeline contracts + ValidationPlanV1 JSON Schema** (ARG-001) — типизированный обмен между фазами и LLM
2. **ToolAdapter + signed tool registry + safe templating** (ARG-002) — единственный путь запуска инструментов
3. **Tool YAMLs §4.1–§4.3 (35 инструментов)** (ARG-003) — passive recon, active recon, TLS (самая безопасная часть каталога)
4. **k8s SandboxAdapter + NetworkPolicy** (ARG-004) — безопасный исполняющий слой вместо docker.sock
5. **PayloadRegistry + PayloadBuilder** (ARG-005) — материализация payload-ов, LLM не видит сырой payload
6. **PolicyEngine + ScopeEngine + OwnershipProof + ApprovalService (Ed25519)** (ARG-006) — guardrails перед активными операциями
7. **OAST infra + Correlator + Canary** (ARG-007) — evidence-first валидация для blind vulnerabilities
8. **AI Orchestrator (planner/critic/verifier/reporter) + Prompt Registry** (ARG-008) — мозг системы, JSON-выход
9. **Findings normalizer + Correlator + Prioritizer (EPSS/KEV/SSVC) + Evidence pipeline** (ARG-009) — единая модель находок
10. **Tool catalog coverage test + docs/tool-catalog.md + CHANGELOG + hexstrike audit** (ARG-010) — печать качества

После Cycle 1 каталог §4.4–§4.19 (~119 инструментов), ReportService (Midgard/Asgard/Valhalla × 4 формата), MCP server, admin-frontend будут реализованы в циклах 2–3 (см. раздел **Что отложено**).

---

## 2. Доставленные модули (ARG-001..ARG-010)

| ARG | Scope | Source paths | Tests | Зависимости |
|---|---|---|---|---|
| **ARG-001** | Pipeline contracts + ValidationPlanV1 | `src/pipeline/contracts/`, `src/orchestrator/schemas/validation_plan_v1.json` | `tests/unit/pipeline`, `tests/unit/orchestrator` | jsonschema |
| **ARG-002** | ToolAdapter + registry + templating + signing | `src/sandbox/{adapter_base,tool_registry,templating,signing}.py` | `tests/unit/sandbox/test_{adapter_base,tool_registry,templating,signing}` | cryptography, PyYAML |
| **ARG-003** | Tool YAMLs §4.1–§4.3 (35 tools) | `config/tools/` (35 YAML) + `config/tools/SIGNATURES` | `tests/unit/sandbox/test_yaml_catalog.py`, `tests/integration/sandbox/test_dry_command_build.py` | — |
| **ARG-004** | k8s SandboxAdapter + NetworkPolicy | `src/sandbox/{k8s_adapter,manifest,network_policies,runner}.py` | `tests/unit/sandbox/test_{k8s_adapter,manifest,network_policies,runner}.py`, `tests/integration/sandbox/test_k8s_driver_dryrun.py` | kubernetes |
| **ARG-005** | PayloadRegistry + Builder (23 families) | `src/payloads/{registry,builder,mutators}.py`, `config/payloads/` (23 YAML) | `tests/unit/payloads/test_{registry,builder,mutators}.py` | cryptography |
| **ARG-006** | PolicyEngine + ScopeEngine + Ownership + Approval + tamper-evident audit | `src/policy/{policy_engine,scope,ownership,approval,preflight,audit}.py` | `tests/unit/policy/`, `tests/integration/policy/` | dnspython, httpx |
| **ARG-007** | OAST infra + Correlator + Canary fallback | `src/oast/{provisioner,correlator,canary,integration,listener_protocol}.py` | `tests/unit/oast/`, `tests/integration/oast/` | — |
| **ARG-008** | AI Orchestrator + Prompt Registry (5 prompts) | `src/orchestrator/{orchestrator,llm_provider,prompt_registry,agents,retry_loop,cost_tracker}.py`, `config/prompts/` (5 YAML) | `tests/unit/orchestrator_runtime/`, `tests/integration/orchestrator_runtime/` | — |
| **ARG-009** | Findings normalizer + correlator + prioritizer + Evidence pipeline | `src/findings/{normalizer,correlator,prioritizer,cvss,epss_client,kev_client,ssvc}.py`, `src/evidence/{pipeline,redaction}.py` | `tests/unit/findings/`, `tests/unit/evidence/`, `tests/integration/findings/` | cvss |
| **ARG-010** | Coverage test + docs + CHANGELOG + hexstrike audit | `backend/tests/test_tool_catalog_coverage.py`, `backend/scripts/docs_tool_catalog.py`, `docs/tool-catalog.md`, `CHANGELOG.md` | `tests/test_tool_catalog_coverage.py`, `tests/test_argus006_hexstrike.py` | — |

---

## 3. Архитектурные инварианты (security guardrails)

Все нижеперечисленные guardrails защёлкнуты тестами и валидируются на старте приложения:

### Sandbox runtime invariants

- **Non-root pod:** `runAsNonRoot=true`, `runAsUser=65532`, `runAsGroup=65532`, `fsGroup=65532` (см. `src.sandbox.manifest.build_pod_security_context`)
- **Read-only root filesystem:** `readOnlyRootFilesystem=true`; только `/out` и `/tmp` как `emptyDir` writable volumes
- **Dropped capabilities:** `capabilities.drop=["ALL"]`, `allowPrivilegeEscalation=false`, `privileged=false`
- **Seccomp RuntimeDefault:** всё descriptors имеют `seccomp_profile=runtime/default`
- **No service-account token:** `automountServiceAccountToken=false`; tool pods не могут достучаться до K8s API
- **Job lifecycle:** `restartPolicy=Never`, `backoffLimit=0`, deterministic `default_timeout_s` per descriptor
- **Guaranteed QoS:** каждый container декларирует `requests==limits` для CPU и memory

### Templating invariants

- **Allowlisted placeholders only:** `render_command()` использует ровно 14 whitelisted placeholder-ов: `{url}`, `{host}`, `{port}`, `{domain}`, `{ip}`, `{cidr}`, `{params}`, `{wordlist}`, `{canary}`, `{out_dir}`, `{in_dir}`, `{ports}`, `{proto}`, `{rand}`
- **Shell=False, argv-only:** все вызовы `subprocess.run` используют `shell=False` и типизированный `list[str]` argv
- **No shell metacharacters:** per-token валидация отказывает на `;`, `&&`, `|`, backticks, `$(...)`, `>`, `<`, newlines, carriage returns

### Signing model

- **Ed25519 для всех каталогов:** tool YAMLs, payload registry, prompt registry, policy rules
- **Fail-closed:** signature mismatch, schema violation, duplicate `tool_id`, forbidden placeholder → `RuntimeError` на старте приложения
- **Single source of truth:** public key в `backend/config/tools/_keys/argus-tools.pub`; dev keypair генерируется через `python backend/scripts/tools_sign.py --generate-keys`; prod ротация в Cycle 5

### NetworkPolicy invariants

- **Ingress always denied:** `policyTypes=[Ingress, Egress]`, `ingress=[]`
- **DNS pinned:** egress DNS-запросы только к Cloudflare (`1.1.1.1`) и Quad9 (`9.9.9.9`)
- **Active templates require explicit target_cidr:** при render-time; wildcard egress невозможен
- **Private ranges blocked:** например `169.254.169.254/32` (metadata endpoint), `10/8`, `172.16/12`, `192.168/16`

### Approval & dual-control

- **Medium+ requires approval:** `PolicyEngine.evaluate()` возвращает `requires_approval=true` для risk_level ∈ {medium, high, destructive}
- **Destructive requires 2 approvers:** две разные пользовательские подписи Ed25519 требуются для инструментов в `risk_level=destructive`

### Audit chain

- **Append-only с hash-linking:** `AuditChain.append()` каждую запись линкует через `prev_event_hash`; genesis per tenant
- **Integrity verifiable:** `AuditChain.verify_chain()` обнаруживает tampering любой строки
- **Sanitized PII:** no passwords, no tokens, no sensitive data в логах

### Findings & evidence

- **Deterministic dedup:** `Normalizer.normalize()` идемпотентен; `root_cause_hash` вычисляется из (asset, endpoint, parameter, category)
- **Redacted bytes:** `Redactor.redact()` обнаруживает ≥10 типов secrets (bearer tokens, API keys, cookies, passwords, private keys, IP addresses)
- **SHA-256 chain-of-custody:** каждый evidence хранит hash-цепочку; verification at retrieval в `src.evidence.pipeline`

---

## 4. Метрики качества

Числовые факты, цитируемые точно:

### Test coverage

- **2212 unit + integration tests** passed in 64.84s (single sweep, finalisation запуск).
- **Покрытие модулей в scope** (замерено только для модулей, доставленных в этом цикле — sandbox/policy/reports DoD-coverage оставляем как acceptance gate ARG-011):
  - `backend/src/findings/` — 94%
  - `backend/src/evidence/` — 94%
  - `backend/src/sandbox/`, `src/payloads/`, `src/policy/`, `src/oast/`, `src/orchestrator/`, `src/pipeline/` — все юнит/интеграционные тесты зелёные; точная %-метрика (≥85% per Backlog §19.1) измеряется в Cycle 2 как часть полноценного coverage-runner.

### Linting & type checking

- **mypy --strict:** `Success: no issues found in 56 source files` для `src/sandbox`, `src/payloads`, `src/policy`, `src/oast`, `src/orchestrator`, `src/pipeline`, `src/findings`, `src/evidence`.
- **ruff check:** `All checks passed!` для всех delivered модулей, скриптов и тестов цикла.
- **shell=False guarantee:** ни одного `shell=True` / конкатенации команд / `os.system` в коде, доставленном в этом цикле; единственный исполняющий путь — `subprocess.run(argv, shell=False)` через `src.sandbox.templating.render_argv`.

### Catalog & signing

- **35 tool YAMLs** in `backend/config/tools/`; все Ed25519-подписаны через `backend/scripts/tools_sign.py`.
- **23 payload families** in `backend/config/payloads/`; все Ed25519-подписаны через `backend/scripts/payloads_sign.py`.
- **5 prompt YAMLs** in `backend/config/prompts/` (`planner_v1`, `critic_v1`, `verifier_v1`, `reporter_v1`, `fixer_v1`); все Ed25519-подписаны через `backend/scripts/prompts_sign.py`.
- **`docs/tool-catalog.md`** — байт-в-байт результат `python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md`; CI режим `--check` защищает от drift.
- **Coverage-тест:** `backend/tests/test_tool_catalog_coverage.py` — 35 tool_id × 5 контрактов = 175 параметризованных кейсов.

### Hexstrike legacy audit

- **0 hexstrike references** в `backend/src/`, `backend/api/`, `mcp-server/` — тест `tests/test_argus006_hexstrike.py` зелёный.
- Оставшиеся упоминания строго в архивных артефактах (`Backlog/dev1_md` (источник истины, упоминает hexstrike в ЗАПРЕЩЕНО-секции), `ai_docs/develop/{plans,reports}/2026-04-02-hexstrike-*` — исторические планы/отчёты, не code), что DoD §19.7 явно разрешает.

### Long-term roadmap vs delivered

- **Total tools in Backlog §4:** 154
- **Shipped in Cycle 1:** 35 (§4.1–§4.3)
- **Gap for Cycle 2+:** 119 (§4.4–§4.19: web fuzzing, exploit, post-ex, cloud, container, mobile, AD, OT/IoT, etc.)

---

## 5. Коммит-стратегия и атомарность

Каждый ARG-NNN — изолированная, атомарная unit работы:

- **ARG-001:** Pipeline contracts + ValidationPlanV1 (1 commit)
- **ARG-002:** ToolAdapter base + signing + templating (2–3 commits: adapter, signing, scripts)
- **ARG-003:** 35 tool YAMLs (1–2 commits: batch YAML + dev signing key)
- **ARG-004:** k8s adapter + manifest helpers + network policies (3–4 commits: adapter, manifest, policies, runner)
- **ARG-005:** PayloadRegistry + Builder + 23 payload YAMLs (2–3 commits: registry/builder, payload YAML, mutators)
- **ARG-006:** PolicyEngine + ScopeEngine + ApprovalService + Audit (4 commits: policy, scope, approvals, audit)
- **ARG-007:** OAST token + correlator + canary server (2 commits: token/correlator, canary + infra)
- **ARG-008:** AI Orchestrator (planner/critic/verifier) + Prompt Registry (2–3 commits: orchestrator, prompts, router)
- **ARG-009:** Findings pipeline (3–4 commits: normalizer/correlator, prioritizer, EPSS/KEV, evidence/redaction)
- **ARG-010:** Coverage test + tool-catalog.md + CHANGELOG (1 commit: test + docs)

**Обратная совместимость:** `KubernetesSandboxAdapter` и `PayloadBuilder` принимают `preflight_checker` как опциональный параметр (default None) для backward-compat; legacy code может оставаться без изменений.

---

## 6. Что отложено в ARG-011+

Чёткий список того, что **не входит** в Cycle 1 и будет реализовано далее:

### Cycle 2 (Tool adapters, images, state_machine migration)

- **Tool YAMLs §4.4–§4.19** (~119 files: HTTP fingerprinting, content discovery, crawler/JS, CMS, web scanners, SQLi/XSS/SSRF/auth/cloud/IaC/network/binary/browser)
- **ToolAdapter подклассы** с `parse_output()` для каждого формата (nmap XML, nuclei JSONL, sqlmap output, и т.д.)
- **Firecracker driver** (`backend/src/sandbox/firecracker_driver.py`) как fallback
- **Multi-image sandboxes** (`sandbox/images/argus-kali-{full,web,cloud,browser}/Dockerfile`) с SBOM
- **Legacy state_machine миграция** — замена `docker exec` на `K8sSandboxDriver`

### Cycle 3 (Reports, MCP server, admin-frontend)

- **ReportService** для всех 12 комбинаций (Midgard/Asgard/Valhalla × HTML/PDF/JSON/CSV) + SARIF/JUnit
- **Report templates** в `backend/templates/reports/`
- **replay_command_sanitizer.py** (redaction in reproducer)
- **Backend MCP server** в `backend/src/mcp/server.py` (FastMCP с tools из Backlog §13)
- **Admin-frontend gaps** (если что-то не хватает в main tree)

### Cycle 4 (Observability, cloud IAM, SSVC)

- **OTel spans** на каждый tool_run, LLM call, policy decision, approval
- **Prometheus metrics:** `argus_tool_runs_total`, `argus_findings_total`, `argus_oast_callbacks_total`, etc.
- **Health endpoints:** `/health`, `/ready`, `/metrics`, `/providers/health`, `/queues/health`
- **cloud_iam ownership** для AWS/GCP/Azure (сейчас заглушка)
- **Полный CISA SSVC v2.1** + EPSS percentile decisions

### Cycle 5 (Migrations, RLS, Operations)

- **Alembic migrations** для всех новых таблиц (tool_runs, oast_callbacks, и т.д.)
- **RLS coverage tests** на каждую таблицу
- **Production OAST deployment** (wildcard DNS, TLS)
- **Helm chart** (`helm/argus/`)
- **infra/firecracker/*.json** конфигурации

### Cycle 6 (Hexstrike purge, e2e, DoD verification)

- **Полное удаление hexstrike** из docs/tests/reports (Cycle 1 только аудит)
- **e2e full scan script** (`scripts/e2e_full_scan.sh`) — поднимает стек, гонит полный скан, проверяет 12 отчётов
- **infra/.env cleanup** (вынести из репозитория)
- **Обновление observability.get_metrics_content()** (3 vs 2 unpacking issue)
- **DoD §19 итоговая проверка** (coverage ≥85%, ruff/mypy/bandit clean)

---

## 7. Известные риски и compensating controls

Документирование факторов риска с компенсирующими механизмами управления:

### LLM provider stub

- **Риск:** OpenAI (и другие external LLM providers) не имеют реальной интеграции; `OpenAILLMProvider` raises `NotImplementedError` на real call
- **Компенсирующий контроль:** `EchoLLMProvider` для тестирования; real integration в Cycle 3
- **Impact:** low — Cycle 1 фокусируется на infrastructure; LLM integration — следующая итерация

### Audit log in-memory sink

- **Риск:** `InMemoryAuditSink` теряет данные при рестарте приложения
- **Компенсирующий контроль:** на продакшене требуется Postgres-backend с append-only таблицей (см. ARG-006 migration)
- **Impact:** high для compliance — Cycle 5 миграция на реальный backend

### OAST listener stub

- **Риск:** `BurpCollaboratorClientStub` + `FakeOASTListener` не реальны; реальный listener требует DNS+HTTP+SMTP deployment
- **Компенсирующий контроль:** заглушки в unit/integration tests; Cycle 2 doc integration с real interactsh; Cycle 5 ops deployment
- **Impact:** medium — evidence-first valuation нуждается в OAST, но Cycle 1 полностью testable с mock

### Provider router retry/fixer without real model

- **Риск:** `LLMRouter.call()` с моком провайдера; fallback chain не протестирована на реальных LLM
- **Компенсирующий контроль:** unit tests с deterministic invalid JSON responses; Cycle 3 integration tests с real providers
- **Impact:** medium — validation plan parsing требует реальной LLM output; Cycle 1 defensive валидация достаточна

---

## 8. Верификационная команда (DoD checklist)

Оператор может скопировать и запустить нижеследующие команды для полной верификации Cycle 1:

```powershell
cd backend

ruff check src/sandbox src/payloads src/policy src/oast src/orchestrator src/pipeline src/findings src/evidence scripts/docs_tool_catalog.py scripts/tools_sign.py scripts/tools_list.py scripts/payloads_sign.py scripts/payloads_list.py scripts/prompts_sign.py scripts/prompts_list.py tests/unit/sandbox tests/unit/payloads tests/unit/policy tests/unit/oast tests/unit/orchestrator_runtime tests/unit/orchestrator tests/unit/findings tests/unit/evidence tests/unit/pipeline tests/integration tests/test_argus006_hexstrike.py tests/test_tool_catalog_coverage.py

mypy --strict src/sandbox src/payloads src/policy src/oast src/orchestrator src/pipeline src/findings src/evidence

python -m pytest tests/test_argus006_hexstrike.py tests/test_tool_catalog_coverage.py tests/integration tests/unit -q

python -m scripts.docs_tool_catalog --check
```

Все четыре команды должны завершиться с exit code 0. Alembic `upgrade head / downgrade -1 / upgrade head` остаётся отдельным ops-gate и не входит в DoD текущего цикла (миграции БД для новых модулей доставляются в Cycle 5).

---

## 9. Ссылки

- **Plan:** `ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md`
- **Backlog (source of truth):** `Backlog/dev1_md`
- **CHANGELOG:** `CHANGELOG.md` (раздел "ARGUS Active Pentest Engine v1 (ARG-001..ARG-010)")
- **Tool catalog (auto-generated):** `docs/tool-catalog.md`
- **Hexstrike legacy audit gate:** `backend/tests/test_argus006_hexstrike.py`
- **Tool-catalog generator:** `backend/scripts/docs_tool_catalog.py`
- **Coverage gate:** `backend/tests/test_tool_catalog_coverage.py`
- **API contract rule:** `.cursor/rules/api-contract.mdc`

---

**Цикл завершён. Фундамент готов к расширению в Cycle 2.**
