# План: ARGUS v1 — Финализация, Cycle 1 (Foundation)

**Создан:** 2026-04-17
**Orchestration:** `orch-2026-04-17-12-00-argus-final`
**Master plan (источник истины):** [`Backlog/dev1_md`](../../../Backlog/dev1_md)
**Сопроводительные документы:** [`codex.md`](../../../codex.md), [`Анализ_архитектуры_ARGUS.md`](../../../Анализ_архитектуры_ARGUS.md), [`docs/frontend-api-contract.md`](../../../docs/frontend-api-contract.md), [`.cursor/rules/api-contract.mdc`](../../../.cursor/rules/api-contract.mdc)
**Status:** ⏳ Ready

---

## 1. Цель цикла (Goal)

Заложить **архитектурный фундамент** ARGUS v1 (см. `Backlog/dev1_md` §16.1–§16.10) — самые критичные и блокирующие модули control-plane, без которых ни одна последующая задача каталога 150+ инструментов и системы отчётов не может быть начата:

1. **Контракты pipeline + ValidationPlanV1 JSON Schema** — типизированный обмен между фазами и LLM.
2. **ToolAdapter + signed tool registry + safe templating** — единственный путь запуска внешних инструментов.
3. **Тулзы §4.1–§4.3 (35 YAML)** — passive recon, active recon, TLS — самая безопасная и базовая часть каталога.
4. **k8s SandboxAdapter + NetworkPolicy** — безопасный исполняющий слой вместо `docker.sock`/`docker exec`.
5. **PayloadRegistry + PayloadBuilder** — материализация payload-ов внутри sandbox, LLM не видит сырой payload.
6. **PolicyEngine + ScopeEngine + OwnershipProof + ApprovalService (Ed25519)** — обязательные guardrails перед любой активной операцией.
7. **OAST infra + correlator + canary fallback** — основа evidence-first валидации (blind SSRF/RCE/XSS).
8. **AI Orchestrator (planner/critic/verifier/reporter) + Prompt Registry + retry/fixer** — мозг системы, строго JSON-выход.
9. **Findings normalizer + correlator + prioritizer (EPSS/KEV/SSVC) + Evidence pipeline + redaction** — единая модель находок с приоритизацией.
10. **Tool catalog coverage test + docs/tool-catalog.md + CHANGELOG + audit hexstrike** — печать качества и старт документации.

После закрытия Cycle 1 каталог §4.4–§4.19 (≈115 инструментов), Firecracker fallback, sandbox-images, ReportService 12-комбинаций, MCP server, admin-frontend и e2e DoD §19 будут реализованы в последующих циклах (см. секцию **Deferred** ниже).

---

## 2. Gap Analysis (что есть / чего нет)

### 2.1 ✅ Существует в `backend/` (main tree)

| Компонент | Файлы | Статус |
|---|---|---|
| 6-фазный state machine (legacy) | `backend/src/orchestration/{state_machine,handlers,phases,prompt_registry,ai_prompts}.py` | Работает, но связан с `docker exec` sandbox-ом |
| LLM-фасад + provider router | `backend/src/llm/{router,facade,task_router,adapters,cost_tracker,errors,base}.py` | OK, нужен retry/fixer |
| Reports v0 | `backend/src/reports/*` (17 файлов: generators, data_collector, valhalla_report_context, ai_text_generation, …) | Есть база, но не разделены midgard/asgard/valhalla × 4 формата явно |
| API роутеры | 14 роутеров: scans, reports, findings, sandbox, tools, admin, intelligence, internal_va, … | OK, контракт с Frontend стабилен |
| DB models + RLS | `backend/src/db/{models,models_recon,session}.py` + 17 миграций (001–017) | Есть базовые таблицы, но нет `tool_runs`, `approvals` (ed25519), `audit_logs` hash-chain, `ownership_proofs`, `oast_callbacks` |
| Storage (MinIO) | `backend/src/storage/s3.py` + бакеты `argus`, `argus-reports`, `stage1-4-artifacts` | OK |
| Exploitation legacy | `backend/src/recon/exploitation/{planner,executor,policy_engine,adapters/*}.py` (5 адаптеров) | Нужно мигрировать на ToolAdapter |
| OWASP-2025 mapping | `backend/src/owasp_top10_2025.py` | OK |
| Intel | `backend/src/intel/{shodan_enricher,perplexity_enricher,enrichment_pipeline}.py` | OK |
| Prompts (legacy) | `backend/src/prompts/{threat_modeling_prompts,vulnerability_analysis_prompts}.py` | Нет YAML registry per-vuln-type |
| Sandbox base image | `sandbox/Dockerfile` (Kali rolling, monolith) | Есть, но нет `images/argus-kali-{full,web,cloud,browser}/` мульти-image |
| Infra base | `infra/docker-compose.yml`, nginx, cloudflared, backend/worker Dockerfiles | OK |
| MCP server (legacy) | `mcp-server/argus_mcp.py` (отдельный сервис, FastMCP) | Есть, но в `backend/src/mcp/` пустой `__init__.py` — нужна миграция |
| Docs | `docs/*.md` (40+ файлов: architecture, ERD, security-model, deployment, …) | Есть, нужно обновить + добавить tool-catalog.md |

### 2.2 ❌ Отсутствует (foundational, блокирует всё остальное)

| Компонент | Где должен быть | Влияние |
|---|---|---|
| Pipeline contracts | `backend/src/pipeline/contracts/*.py` | **0 файлов** — нет типизированного обмена между фазами |
| ValidationPlanV1 JSON Schema | `backend/src/orchestrator/schemas/validation_plan_v1.json` | **0 файлов** — LLM не имеет строгого выходного контракта |
| ToolAdapter base | `backend/src/sandbox/adapter_base.py` | **0 файлов** — нет единого контракта для запуска инструментов |
| Tool registry + Ed25519 signed YAML | `backend/src/sandbox/tool_registry.py`, `backend/config/tools/*.yaml`, `backend/config/tools/SIGNATURES` | **0 YAML** — каталог не существует |
| Safe templating | `backend/src/sandbox/templating.py` | **0 файлов** — риск shell injection / unsafe placeholders |
| k8s SandboxAdapter | `backend/src/sandbox/k8s_driver.py`, `infra/k8s/sandbox-job.yaml` | **0 файлов** — нет безопасного исполнителя |
| Firecracker fallback | `backend/src/sandbox/firecracker_driver.py`, `infra/firecracker/*.json` | **0 файлов** — нет fallback (deferred в Cycle 2) |
| PayloadRegistry / PayloadBuilder | `backend/src/payloads/{builder,registry,mutators}.py`, `backend/config/payloads/*.yaml` | **0 файлов** — LLM не имеет sandboxed materialization |
| PolicyEngine | `backend/src/policy/engine.py` | **0 файлов** — нет formal scope/risk/approval check (есть только embedded в exploitation) |
| ScopeEngine + OwnershipProof | `backend/src/scope/{engine,ownership}.py` | **0 файлов** — нет DNS TXT / HTTP token / cloud IAM verification |
| ApprovalService (Ed25519) | `backend/src/approvals/service.py` | **0 файлов** — есть только `policy.exploit_approval` boolean, без подписей |
| Audit hash-chain | `backend/src/approvals/audit_chain.py` | **0 файлов** — append-only without `prev_hash` linking |
| OAST correlator + canary | `backend/src/oast/{correlator,canary_server,token}.py`, `infra/oast/` | **0 файлов** — нет blind-vuln evidence |
| AI Orchestrator (planner/critic/verifier/reporter) | `backend/src/orchestrator/*.py` | **0 файлов** (только пустой `mcp/__init__.py`) |
| Prompt registry (YAML per-vuln-type) | `backend/src/prompts/registry/*.yaml` | **0 YAML** — есть Python-только legacy |
| Findings normalizer/correlator/prioritizer | `backend/src/findings/{normalizer,correlator,prioritizer}.py` | **0 файлов** — есть только `reports/finding_dedup.py` |
| EPSS / KEV / SSVC clients | `backend/src/findings/{epss_client,kev_client,ssvc}.py` | **0 файлов** — приоритизации по EPSS/KEV нет |
| Evidence pipeline + redaction | `backend/src/evidence/{pipeline,redaction}.py` | **0 файлов** |
| FastMCP backend MCP | `backend/src/mcp/server.py` | Только пустой `__init__.py` (real MCP — в отдельном `mcp-server/`) |
| docs/tool-catalog.md | `docs/tool-catalog.md` | **Отсутствует** |
| Tool catalog coverage test | `backend/tests/test_tool_catalog_coverage.py` | **Отсутствует** |
| `scripts/e2e_full_scan.sh` | `scripts/e2e_full_scan.sh` | **Отсутствует** (есть только `infra/scripts/check_env.sh`) |

### 2.3 ⚠️ Известные leftovers (предупреждение, не блокирующее)

- **`hexstrike` mentions** в: `docs/2026-03-09-argus-implementation-plan.md`, `ai_docs/develop/reports/2026-04-02-hexstrike-v4-orchestration-report.md`, `backend/tests/test_argus006_hexstrike.py`, `README-REPORT.md`, `COMPLETION-SUMMARY.md`, `ai_docs/develop/plans/2026-04-02-hexstrike-v4-mcp-orchestration.md` → §19.7 запрещает любые упоминания. Cycle 1 закрывает только аудит (документирование), полная зачистка — Cycle 6.
- **`infra/.env`** в `git status` как modified (не должен быть в репозитории, см. рекомендацию Анализа архитектуры §6 — Critical). Не входит в текущий цикл, эскалирована в issue.
- Сигнатура несоответствия `observability.get_metrics_content()` (3 значения) vs `metrics.py:42` (распаковка 2) — High, см. Анализ архитектуры §6. Не входит в текущий цикл.

---

## 3. Tasks (≤10, упорядочены по зависимостям)

### ARG-001 — Pipeline contracts + ValidationPlanV1 JSON Schema

- **Status:** `[x] ARG-001 — Pipeline contracts + ValidationPlanV1 JSON Schema (✅ Completed)`
- **Priority:** Critical
- **Estimated complexity:** Moderate (2–3 ч)
- **Dependencies:** —
- **Files to create:**
  - `backend/src/pipeline/__init__.py`
  - `backend/src/pipeline/contracts/__init__.py`
  - `backend/src/pipeline/contracts/phase_io.py` — `PhaseInput`, `PhaseOutput`, `ScanPhase` enum (recon/threat_modeling/vuln_analysis/exploitation/post_exploitation/reporting)
  - `backend/src/pipeline/contracts/tool_job.py` — `ToolJob` (tool_id, target, params, scan_id, tenant_id, correlation_id), `ToolRunResult`
  - `backend/src/pipeline/contracts/validation_job.py` — `ValidationJob` (finding_id, validator, payload_strategy, canary_token, …), `ValidationResult`
  - `backend/src/pipeline/contracts/exploit_job.py` — `ExploitJob`, `ExploitResult`
  - `backend/src/pipeline/contracts/finding_dto.py` — DTO для передачи между phases (отдельно от ORM `Finding`)
  - `backend/src/orchestrator/__init__.py`
  - `backend/src/orchestrator/schemas/__init__.py`
  - `backend/src/orchestrator/schemas/validation_plan_v1.json` — JSON Schema из `codex.md` §3 + `Backlog/dev1_md` §6 (точная копия, mutation_classes ∈ {canonicalization, context_encoding, length_variation, case_normalization, charset_shift, waf_detour_lite}, `raw_payloads_allowed: const false`)
  - `backend/src/orchestrator/schemas/loader.py` — `load_validation_plan_v1_schema() -> dict`, кэш в памяти, `validate_validation_plan(payload: dict) -> None | raises ValidationError`
- **Tests:**
  - `backend/tests/unit/pipeline/test_contracts.py` — round-trip pydantic .model_dump_json()/.model_validate_json() для всех DTO, проверка enum-литералов
  - `backend/tests/unit/orchestrator/test_validation_plan_v1_schema.py` — позитивные/негативные кейсы (raw_payloads_allowed=true → reject; пустой mutation_classes → ok; неизвестный validator.tool → reject; `registry_family` regex)
- **Acceptance criteria:**
  1. Все pydantic-модели имеют strict types (`StrictStr`, `Literal[...]`), `ConfigDict(extra="forbid")`.
  2. `validation_plan_v1.json` валидируется через `jsonschema` (Draft 2020-12).
  3. `pytest -q backend/tests/unit/pipeline backend/tests/unit/orchestrator` — зелёный.
  4. `mypy --strict backend/src/pipeline backend/src/orchestrator/schemas` — без ошибок.
- **Risks / out-of-scope:** В этой задаче **только контракты** — никакой логики (planner/critic — в ARG-008). Не трогаем legacy `backend/src/orchestration/phases.py`.

### ARG-002 — ToolAdapter base + signed tool registry + safe templating

- **Status:** `[x] ARG-002 — ToolAdapter base + signed tool registry + safe templating (✅ Completed)`
- **Priority:** Critical
- **Estimated complexity:** Complex (4–6 ч)
- **Dependencies:** ARG-001
- **Files to create:**
  - `backend/src/sandbox/__init__.py`
  - `backend/src/sandbox/adapter_base.py` — `ToolAdapter` Protocol (см. `Backlog/dev1_md` §3): `tool_id`, `category`, `phase`, `risk_level`, `requires_approval`, `network_policy`, `seccomp_profile`, `default_timeout_s`, `cpu_limit`, `memory_limit`, `build_command()`, `parse_output()`, `collect_evidence()`. + Enums `ToolCategory`, `RiskLevel`, `NetworkPolicyRef`, `ScanPhase`.
  - `backend/src/sandbox/tool_registry.py` — `ToolRegistry` (singleton): `register()`, `get(tool_id)`, `list_by_category()`, `list_by_phase()`, валидация всех YAML на старте через signed loader; **fail-closed** при invalid signature.
  - `backend/src/sandbox/templating.py` — `render_command(template: str, params: dict) -> list[str]` с allowlist placeholders ровно из `Backlog/dev1_md` §18: `{url}, {host}, {port}, {domain}, {ip}, {cidr}, {params}, {wordlist}, {canary}, {out_dir}, {in_dir}` + `{ports}`, `{proto}`, `{community}`, `{rand}` (документировать в docstring). Любой другой placeholder → `TemplateRejectedError`. Защита от shell metacharacters: split на argparse-safe `list[str]` через `shlex.split` + повторная валидация каждого токена.
  - `backend/src/sandbox/signing.py` — `Ed25519Signer.sign(path)`, `Ed25519Verifier.verify(path, signature)` (PyNaCl или cryptography). Public key path: `backend/config/tools/_keys/argus-tools.pub`. Private key — НЕ в репозитории, инструкция в README.
  - `backend/config/tools/SIGNATURES` — JSON map `{filename: base64-ed25519-signature, ...}`. На этапе ARG-002 — только пустой stub + dev key.
  - `backend/config/tools/_keys/README.md` — инструкция: как сгенерировать dev key (`python backend/scripts/tools_sign.py --generate-keys`), куда положить prod-public-key, порядок ротации.
  - `backend/scripts/tools_sign.py` — CLI: `--generate-keys`, `--sign <yaml-or-dir>`, `--verify <yaml-or-dir>`. Перезаписывает `SIGNATURES` атомарно.
  - `backend/scripts/tools_list.py` — CLI: `tools list [--category recon] [--phase recon] [--json]` — печатает таблицу/JSON всех зарегистрированных tool_id.
- **Tests:**
  - `backend/tests/unit/sandbox/test_adapter_base.py` — Protocol conformance (mock adapter), enum coverage.
  - `backend/tests/unit/sandbox/test_tool_registry.py` — fail-closed на bad signature; happy path; отказ зарегистрировать tool_id-дубликат.
  - `backend/tests/unit/sandbox/test_templating.py` — allowlist enforcement (≥10 negative cases: `;rm -rf /`, `$(curl evil)`, `{secret}`, `\\n`, etc.); positive cases для каждого placeholder; argparse-safe экранирование.
  - `backend/tests/unit/sandbox/test_signing.py` — sign+verify round-trip; reject tampered file; reject wrong key.
- **Acceptance criteria:**
  1. `ToolRegistry.load()` валидирует подписи всех YAML; при mismatch — `RuntimeError("tool registry signature invalid")` и приложение не стартует.
  2. `render_command()` ни при каких входных параметрах не возвращает строку с `;`, `&&`, `|`, backticks, `$(...)`, `>`, `<`, `\n`, `\r`.
  3. `python backend/scripts/tools_list.py --json | jq length` (на этапе ARG-002 без YAML) → `0`.
  4. `pytest -q backend/tests/unit/sandbox` — зелёный, coverage ≥ 90%.
- **Risks / out-of-scope:** Не реализуем ни одного конкретного `ToolAdapter` (это ARG-003, ARG-011+). Не трогаем legacy `backend/src/recon/exploitation/adapters/*` — миграция в Cycle 2.

### ARG-003 — Tool YAMLs §4.1–§4.3 (35 инструментов: passive recon 17, active recon 12, TLS 6)

- **Status:** `[x] ARG-003 — Tool YAMLs §4.1-§4.3 (35 tools) + dev signing key (✅ Completed)`
- **Priority:** High
- **Estimated complexity:** Complex (5–7 ч, рутинная)
- **Dependencies:** ARG-002
- **Files to create (35 YAML + signature + dev key + tests):**

  **§4.1 Passive recon / OSINT (17):** `amass_passive.yaml`, `subfinder.yaml`, `assetfinder.yaml`, `findomain.yaml`, `chaos.yaml`, `theharvester.yaml`, `crt_sh.yaml`, `shodan_cli.yaml`, `censys.yaml`, `securitytrails.yaml`, `whois_rdap.yaml`, `dnsx.yaml`, `dnsrecon.yaml`, `fierce.yaml`, `github_search.yaml`, `urlscan.yaml`, `otx_alienvault.yaml`.

  **§4.2 Active recon / port & service (12):** `nmap_tcp_top.yaml`, `nmap_tcp_full.yaml`, `nmap_udp.yaml`, `nmap_version.yaml`, `nmap_vuln.yaml`, `masscan.yaml`, `rustscan.yaml`, `naabu.yaml`, `unicornscan.yaml`, `smbmap.yaml`, `enum4linux_ng.yaml`, `rpcclient_enum.yaml`.

  **§4.3 TLS/SSL (6):** `testssl.yaml`, `sslyze.yaml`, `sslscan.yaml`, `ssl_enum_ciphers.yaml`, `tlsx.yaml`, `mkcert_verify.yaml`.

  Каждый YAML обязан содержать (Pydantic-валидируемая схема в `tool_registry.py`):
  ```yaml
  tool_id: amass_passive
  category: RECON                     # ToolCategory enum
  phase: recon                        # ScanPhase enum
  risk_level: passive                 # passive|low|medium|high|destructive
  requires_approval: false
  command_template: ["amass", "enum", "-passive", "-d", "{domain}", "-json", "{out_dir}/amass.jsonl", "-timeout", "20"]
  parse_strategy: jsonl                # jsonl|json|xml|csv|text|nmap_xml|nuclei_jsonl|...
  evidence_artifacts: ["{out_dir}/amass.jsonl"]
  cwe_hints: []
  owasp_wstg: ["WSTG-INFO-04"]
  network_policy: egress_dns_https     # NetworkPolicyRef
  seccomp_profile: "runtime/default"
  default_timeout_s: 1200
  cpu_limit: "500m"
  memory_limit: "256Mi"
  image: "argus-kali-recon:latest"
  ```
  - `backend/config/tools/SIGNATURES` — обновлён через `python backend/scripts/tools_sign.py --sign backend/config/tools/`.
  - `backend/config/tools/_keys/argus-tools.pub` — dev public key (генерируется через `--generate-keys`, private key НЕ в репозитории).
- **Tests:**
  - `backend/tests/unit/sandbox/test_yaml_catalog.py` — для каждого YAML: валидация Pydantic-схемой; `command_template` использует только allowlist-placeholders; `image` совпадает с одним из `argus-kali-{recon,web,cloud,browser}` (проверка строкой; реальные образы — Cycle 2); `phase`/`risk_level`/`category` — валидные enum; `requires_approval=true` ⇔ `risk_level in {high, destructive}`.
  - `backend/tests/integration/sandbox/test_dry_command_build.py` — для каждого из 35 tool_id: вызов `render_command(yaml.command_template, sample_params)` возвращает `list[str]` без shell-метасимволов.
- **Acceptance criteria:**
  1. `python backend/scripts/tools_list.py --json | jq length` → `35`.
  2. `python backend/scripts/tools_sign.py --verify backend/config/tools/` → `OK`.
  3. На старте приложения `ToolRegistry.load()` подгружает все 35 без ошибок.
  4. `pytest -q backend/tests/unit/sandbox/test_yaml_catalog.py backend/tests/integration/sandbox/test_dry_command_build.py` — зелёный.
- **Risks / out-of-scope:** В Cycle 1 — только YAML + dry command build. Реальные `ToolAdapter` подклассы (с `parse_output()` для каждого парсер-формата) — в Cycle 2 (ARG-011+).

### ARG-004 — k8s SandboxAdapter + ephemeral Job + NetworkPolicy templates

- **Status:** `[x] ARG-004 — k8s SandboxAdapter + ephemeral Job + NetworkPolicy templates (✅ Completed)`
- **Priority:** Critical
- **Estimated complexity:** Complex (4–6 ч)
- **Dependencies:** ARG-002

**Реализовано:**

- `backend/src/sandbox/k8s_adapter.py` — `KubernetesSandboxAdapter` с двумя режимами: `DRY_RUN` (рендер manifest без кластера) и `CLUSTER` (lazy-import `kubernetes` SDK, submit + poll + log capture + artifact stub).
- `backend/src/sandbox/manifest.py` — pure helpers (`build_pod_security_context`, `build_container_security_context`, `build_resource_limits`, `build_volumes`, `build_volume_mounts`, `build_argv`, `build_job_name`, `resolve_image`, `build_job_metadata`, `build_pod_labels`).
- `backend/src/sandbox/network_policies.py` — 5 шаблонов (`recon-passive`, `recon-active-tcp`, `recon-active-udp`, `recon-smb`, `tls-handshake`) + рендерер с DNS egress, ingress deny, dynamic target CIDR.
- `backend/src/sandbox/runner.py` — `SandboxRunner.dispatch_jobs` + конвенция `dispatch_jobs(...)` с bounded concurrency (semaphore), per-job timeout, маппинг `ApprovalRequiredError|SandboxConfigError|SandboxClusterError|TemplateRenderError|TimeoutError → SandboxRunResult(failure_reason)` без аборта batch.
- `backend/src/sandbox/__init__.py` — публичный реэкспорт.
- `backend/requirements.txt` + `backend/pyproject.toml` — добавлены `kubernetes>=29,<30`, `PyYAML>=6.0,<7`.
- `backend/tests/unit/sandbox/test_k8s_adapter.py` (22 теста), `test_k8s_adapter_cluster.py` (28 тестов с фейковым kubernetes SDK), `test_runner.py` (16 тестов), `test_manifest.py` (24 теста), `test_network_policies.py` (40 тестов), `tests/integration/sandbox/test_dry_run_e2e.py` (6 тестов на полном signed catalog).

**Гарантии (защёлкнуты тестами):**

- `pod.securityContext.runAsNonRoot=true`, `runAsUser=65532`, `seccompProfile.type=RuntimeDefault`.
- `container.securityContext.allowPrivilegeEscalation=false`, `readOnlyRootFilesystem=true`, `capabilities.drop=["ALL"]`, `privileged=false`.
- `automountServiceAccountToken=false`, `restartPolicy=Never`, `backoffLimit=0`, `activeDeadlineSeconds=min(descriptor, adapter)`.
- 0 `hostPath`, 0 `docker.sock`, 0 `subprocess`/`os.system`/`shell=True` (статическая проверка по AST исходника).
- NetworkPolicy: `policyTypes=[Ingress, Egress]`, `ingress=[]` (deny-all), DNS pinned к `dns_resolvers`.
- `argv` рендерится через `templating.render_argv` → невозможно подсунуть shell-meta через user-controlled параметры (тест проходит весь catalog).
- Lazy import `kubernetes` SDK: `sys.modules` чист до первого `_run_in_cluster`; clean error если SDK не установлен.

**Метрики качества:**

- `pytest tests/unit/sandbox tests/integration/sandbox` — 726 passed, 0 failed.
- `mypy --strict src/sandbox` — 9 source files, 0 issues.
- `ruff check` + `ruff format --check` — clean.
- Coverage `src.sandbox` — 95% (k8s_adapter.py: 99%, manifest.py: 100%, network_policies.py: 96%, runner.py: 100%).
- **Files to create:**
  - `backend/src/sandbox/k8s_driver.py` — `K8sSandboxDriver`: `submit(tool_run: ToolJob) -> str` (job name), `wait(job_name, timeout) -> ToolRunResult`, `stream_logs(job_name) -> AsyncIterator[bytes]`, `collect_artifacts(job_name) -> dict[str, bytes]` (через MinIO/PVC), `cleanup(job_name)`. Использует `kubernetes` async client, читает kubeconfig из env (`KUBECONFIG` или in-cluster). При отсутствии k8s — explicit `K8sClusterUnavailableError` (Cycle 2: Firecracker fallback в этой ситуации).
  - `backend/src/sandbox/policies/network_policy_templates.py` — `NetworkPolicyRef` enum + рендереры манифестов (передаются в Job spec как `metadata.labels`).
  - `infra/k8s/sandbox-job.yaml` — Job template:
    - `runtimeClassName: kata-clh` (Kata Containers + Cloud Hypervisor) + comment с альтернативой `gvisor`
    - `securityContext.runAsNonRoot: true`, `runAsUser: 65532`
    - `spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem: true`
    - `securityContext.capabilities.drop: ["ALL"]` (NET_RAW добавляется явно для tools, где нужно)
    - `securityContext.seccompProfile.type: RuntimeDefault`
    - `automountServiceAccountToken: false`
    - `restartPolicy: Never`, `activeDeadlineSeconds: ${TIMEOUT}`, `ttlSecondsAfterFinished: 600`
    - `resources.limits` / `resources.requests` из YAML
    - `volumes`: `emptyDir{medium:Memory}` для `/tmp` и `/out`; `csi` ReadOnly для `/wordlists`; `csi` для secrets (если требуются по `tool.requires_secrets`)
    - **Запрещено**: `hostPath`, `hostNetwork`, `hostPID`, `hostIPC`, `privileged`, `docker.sock`
  - `infra/k8s/networkpolicy-recon.yaml` — egress: DNS + HTTPS (53/UDP, 443/TCP), запрет приватных диапазонов (10/8, 172.16/12, 192.168/16, 169.254.169.254/32).
  - `infra/k8s/networkpolicy-web-va.yaml` — egress: 80/443/8080/8443, target IP по `egress.allowlist` ConfigMap.
  - `infra/k8s/networkpolicy-cloud.yaml` — egress: AWS/GCP/Azure API endpoints + 443.
  - `infra/k8s/networkpolicy-egress-allowlist.yaml` — `default deny all egress` baseline для namespace.
  - `infra/k8s/serviceaccount-sandbox.yaml` — minimal SA, без RBAC, для подов sandbox.
- **Tests:**
  - `backend/tests/unit/sandbox/test_k8s_driver.py` — мокирует `kubernetes` client; проверяет: формирование Job manifest из `ToolJob` (security policy, resources, volumes); rejection on missing required fields; правильный `metadata.labels` для NetworkPolicy selector.
  - `backend/tests/integration/sandbox/test_k8s_driver_dryrun.py` — `kubectl --dry-run=server -f infra/k8s/sandbox-job.yaml` (если `kubectl` есть в PATH) → exit 0; иначе skip with reason.
- **Acceptance criteria:**
  1. Все Job manifests проходят `kubectl --dry-run=server` (best-effort, skip-if-no-kubectl).
  2. Generated Job ни при каких условиях не содержит `hostPath|privileged|docker.sock`.
  3. NetworkPolicy templates отказывают egress на 169.254.169.254 (тест-кейс).
  4. `K8sSandboxDriver.submit()` не использует `subprocess`/`os.system`/`shell=True` (статическая проверка).
  5. `pytest -q backend/tests/unit/sandbox/test_k8s_driver.py backend/tests/integration/sandbox/test_k8s_driver_dryrun.py` — зелёный.
- **Risks / out-of-scope:** Firecracker driver (`backend/src/sandbox/firecracker_driver.py`) — в Cycle 2. Смена базы legacy `docker exec` исполнителя на k8s — отдельная миграция (Cycle 2). В Cycle 1 — только адаптер + манифесты, без интеграции с `state_machine.py`.

### ARG-005 — PayloadRegistry + PayloadBuilder + 23 payload-семейства (signed)

- **Status:** `[ ] ARG-005 — PayloadRegistry + PayloadBuilder (23 families) (⏳ Pending)`
- **Priority:** High
- **Estimated complexity:** Complex (4–5 ч)
- **Dependencies:** ARG-002 (использует тот же signing infra)
- **Files to create:**
  - `backend/src/payloads/__init__.py`
  - `backend/src/payloads/registry.py` — `PayloadRegistry`: `get(family: str) -> PayloadFamilyDef`, валидация Ed25519 на старте (тот же `signing.py` из ARG-002, отдельный keypair `argus-payloads.pub`).
  - `backend/src/payloads/builder.py` — `PayloadBuilder.materialize(family, mutation_classes, canary_token, context) -> str | bytes`. **Только в sandbox-side**: вызывается из k8s Job через CLI `python -m argus.payloads.builder ...` с явными аргументами (LLM никогда не видит финальный payload). Возвращает `MaterializedPayload(value, hash, family, mutations_applied, canary_token)`.
  - `backend/src/payloads/mutators.py` — реализации mutation_classes: `canonicalization`, `context_encoding` (HTML/JS/URL), `length_variation`, `case_normalization`, `charset_shift`, `waf_detour_lite` (только консервативные паттерны из OWASP-evasion cheat sheet, no actual bypass tooling).
  - `backend/config/payloads/*.yaml` — 23 семейства (точные имена из `Backlog/dev1_md` §5):
    - SQLi (4): `sqli.boolean.diff.v3`, `sqli.time.blind.v2`, `sqli.error.mysql.v2`, `sqli.error.mssql.v2`
    - XSS (3): `xss.reflected.canary.v3`, `xss.dom.canary.v2`, `xss.stored.canary.v1`
    - SSRF (2): `ssrf.oast.redirect.v1`, `ssrf.oast.gopher.v1`
    - RCE (2): `rce.oast.dns.v1`, `rce.oast.http.v1`
    - LFI (2): `lfi.sentinel.etc.v1`, `lfi.sentinel.wrapper.v1`
    - XXE (2): `xxe.oast.v1`, `xxe.dtd.v1`
    - SSTI (1): `ssti.marker.v1`
    - NoSQLi (1): `nosqli.bool.v1`
    - LDAPi (1): `ldapi.bool.v1`
    - CMDi (1): `cmdi.oast.v1`
    - CORS (1): `cors.origin.v1`
    - Open Redirect (1): `openredirect.canary.v1`
    - CSRF (1): `csrf.marker.v1`
    - Prototype Pollution (1): `prototype_pollution.v1`

    Каждый YAML содержит:
    ```yaml
    family: sqli.boolean.diff.v3
    description: "Boolean-based blind SQLi differential validation."
    risk_level: low
    requires_approval: false
    canary_required: false
    template_a: "{param}=1' AND '1'='1"
    template_b: "{param}=1' AND '1'='2"
    success_signals: ["response_diff > threshold"]
    stop_conditions: ["http_500", "rate_limited"]
    references: ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"]
    allowed_mutations: ["canonicalization", "context_encoding", "case_normalization"]
    ```
  - `backend/config/payloads/SIGNATURES` — Ed25519-подписи всех YAML.
- **Tests:**
  - `backend/tests/unit/payloads/test_builder.py` — happy path для каждого семейства; mutation order детерминирован; canary_token подставляется только когда `canary_required=true`; `raw_payloads_allowed=false` enforcement.
  - `backend/tests/unit/payloads/test_mutators.py` — каждый mutator меняет input предсказуемо; idempotency не нарушена при повторе.
  - `backend/tests/unit/payloads/test_registry_signed.py` — fail-closed на bad signature; reject unknown family.
- **Acceptance criteria:**
  1. Все 23 семейства зарегистрированы и имеют валидную подпись.
  2. `PayloadBuilder.materialize()` возвращает `MaterializedPayload` с непустым `hash` (sha256), не пишет ничего в логи кроме `family`/`mutations_applied`/`hash` (не `value`).
  3. Coverage `backend/src/payloads` ≥ 85%.
- **Risks / out-of-scope:** Реальная интеграция с `validator` adapters (browser_validator, oast_canary, safe_validator) — в Cycle 2. В Cycle 1 — только реестр и builder.

### ARG-006 — PolicyEngine + ScopeEngine + OwnershipProof + ApprovalService (Ed25519, audit hash-chain)

- **Status:** `[ ] ARG-006 — PolicyEngine + ScopeEngine + OwnershipProof + ApprovalService (⏳ Pending)`
- **Priority:** Critical
- **Estimated complexity:** Complex (5–7 ч)
- **Dependencies:** ARG-001
- **Files to create:**
  - `backend/src/policy/__init__.py`
  - `backend/src/policy/engine.py` — `PolicyEngine.evaluate(action, context) -> PolicyDecision`. Загружает правила из `backend/config/policy/*.yaml`. Реализует: scope check (delegate to `ScopeEngine`), risk_level → approval mapping, RPS rate limit, maintenance_window cron parsing (croniter), kill_switch global flag из Redis.
  - `backend/src/policy/decisions.py` — `PolicyDecision` Pydantic (allow, reason, requires_approval, approvers_required, max_rps, maintenance_window_ok), `PolicyAction` enum (TOOL_RUN, EXPLOIT, POST_EXPLOIT, REPORT_EXPORT).
  - `backend/config/policy/default.yaml` — пример правил из `Backlog/dev1_md` §8 (risk_level mapping, default RPS, kill_switch enabled).
  - `backend/src/scope/__init__.py`
  - `backend/src/scope/engine.py` — `ScopeEngine.assert_in_scope(target, tenant_id) -> None | raises OutOfScopeError`. Поддержка domain glob (`*.example.com`), CIDR, exact URL match. Логирует в audit_log при denial.
  - `backend/src/scope/ownership.py` — `OwnershipProof.verify(target, tenant_id) -> ProofResult` с 4 стратегиями: `dns_txt` (`_argus-verify=<token>`), `http_well_known` (`/.well-known/argus-verify.txt`), `cloud_iam` (заглушка с интерфейсом для AWS/GCP/Azure — реализация Cycle 4), `signed_letter` (PDF hash в БД). Token TTL 30 дней per `Backlog/dev1_md` §1.
  - `backend/src/approvals/__init__.py`
  - `backend/src/approvals/service.py` — `ApprovalService.request(tenant_id, action, payload_diff) -> ApprovalRequestId`. Создаёт `ApprovalRequest` row, шлёт SSE event `approval.requested`. `ApprovalService.sign(request_id, signature, public_key_id) -> ApprovalRecord`. Проверяет Ed25519 подпись против `tenant.public_keys[public_key_id]`. На успех — SSE `approval.granted`, на отказ — `approval.denied`.
  - `backend/src/approvals/audit_chain.py` — `AuditChain.append(tenant_id, event_type, payload) -> AuditEntry`. Каждая запись хранит `prev_hash` (sha256 предыдущей `(prev_hash || row_canonical_json)`); генезис-блок per tenant. Метод `verify_chain(tenant_id) -> bool` для проверки целостности.
  - `backend/alembic/versions/018_argus_v1_policy_scope_approvals.py` — новые таблицы:
    - `policies` (extend если уже есть): rules JSONB, version, signature
    - `ownership_proofs` (id, tenant_id, target, method, token, verified_at, expires_at)
    - `approval_requests` (id, tenant_id, action, payload_diff JSONB, status, created_at, expires_at)
    - `approval_records` (id, request_id, signer_user_id, signature, public_key_id, signed_at)
    - `tenant_public_keys` (id, tenant_id, key_id, public_key, created_at, revoked_at)
    - `audit_entries` (id, tenant_id, event_type, payload JSONB, prev_hash, hash, created_at) — append-only через `audit_entries_no_update_no_delete` constraint trigger
    - RLS на всех таблицах: `app.current_tenant_id`
- **Tests:**
  - `backend/tests/unit/policy/test_engine.py` — каждое правило (high → approval, destructive → 2 approvers, in maintenance window → deny, kill_switch on → deny everything).
  - `backend/tests/unit/scope/test_engine.py` — domain glob (`*.example.com` matches `api.example.com`, не matches `evil.com`), CIDR, edge cases.
  - `backend/tests/unit/scope/test_ownership.py` — 4 стратегии (с моками для DNS/HTTP/PDF); reject expired (>30d).
  - `backend/tests/unit/approvals/test_service_signed.py` — sign+verify happy path; reject mismatched signature; reject revoked key; reject expired request.
  - `backend/tests/unit/approvals/test_audit_chain.py` — chain integrity, detect tampering on any row.
- **Acceptance criteria:**
  1. `alembic upgrade head` + `alembic downgrade -1` + `alembic upgrade head` — всё проходит без ошибок.
  2. `PolicyEngine.evaluate()` для destructive action без approval → `allow=false, reason="approval required (1 approver)"`.
  3. `OwnershipProof.verify()` отказывает при отсутствии TXT-записи и истёкшем сроке.
  4. `ApprovalService.sign()` отказывает при подделанной подписи (test использует фиксированную пару ключей).
  5. `AuditChain.verify_chain()` обнаруживает подделку любой строки.
  6. Coverage `backend/src/policy + scope + approvals` ≥ 85%.
- **Risks / out-of-scope:** Не интегрируем `PolicyEngine` в `state_machine.py` — это Cycle 2. `cloud_iam` ownership стратегия — заглушка до Cycle 4.

### ARG-007 — OAST infra + Correlator + ArgusCanaryServer fallback

- **Status:** `[ ] ARG-007 — OAST infra + Correlator + ArgusCanaryServer fallback (⏳ Pending)`
- **Priority:** High
- **Estimated complexity:** Moderate (3–4 ч)
- **Dependencies:** ARG-001
- **Files to create:**
  - `backend/src/oast/__init__.py`
  - `backend/src/oast/token.py` — `generate_canary_token(tenant_id, scan_id) -> str` (формат: `hex(16) + tenant_hash8`, как в `Backlog/dev1_md` §7), `parse_canary_token(token) -> CanaryTokenInfo`.
  - `backend/src/oast/correlator.py` — `OastCorrelator`:
    - `register_callback_listener(token, callback)` (in-memory + Redis pub-sub backup)
    - `on_callback(callback_data)` — парсит token, lookup `tool_run_id`, пишет `Evidence(kind=oast_callback)`, триггерит `finding.confidence = confirmed`, шлёт SSE `oast.callback.received`.
    - Интеграция с `interactsh-server` через polling API (HTTP) **или** SSE (если включено).
  - `backend/src/oast/canary_server.py` — `ArgusCanaryServer` (FastAPI sub-app): endpoint `GET/POST /c/{token}` — логирует callback (HTTP method, path, headers, body, source IP), пушит в `OastCorrelator.on_callback()`. Mountable в основной FastAPI `main.py`.
  - `infra/oast/docker-compose.oast.yml` — отдельный compose-файл для разработки:
    - `interactsh-server` (image `projectdiscovery/interactsh-server:latest`) с DNS, HTTP, SMTP listeners
    - `--domain oast.argus.local` (dev) / configurable
    - shared network с основным `infra/docker-compose.yml`
  - `infra/oast/interactsh.env.example` — переменные: `INTERACTSH_DOMAIN`, `INTERACTSH_TOKEN`, `INTERACTSH_LISTEN_IP`.
  - `infra/oast/README.md` — как поднять локально, как настроить prod (`oast.<tenant>.argus.cloud` через wildcard DNS).
- **Tests:**
  - `backend/tests/unit/oast/test_token.py` — round-trip generate→parse, проверка `tenant_hash8` корректности, отказ на tampered token.
  - `backend/tests/unit/oast/test_correlator.py` — callback с валидным token → создаётся Evidence + SSE event; callback с unknown token → ignored + log warning.
  - `backend/tests/integration/oast/test_canary_server.py` — поднимает FastAPI testclient, шлёт `GET /c/{token}` → корректный ответ + callback зафиксирован.
- **Acceptance criteria:**
  1. `generate_canary_token` всегда возвращает 24 hex-символа.
  2. `ArgusCanaryServer` отвечает 204 No Content (не раскрывая ничего об токене), но фиксирует callback.
  3. `OastCorrelator.on_callback()` идемпотентна (повторный вызов с тем же `(token, source_ip, ts)` не дублирует Evidence).
  4. `pytest -q backend/tests/unit/oast backend/tests/integration/oast` — зелёный.
- **Risks / out-of-scope:** Реальный deployment `interactsh-server` в prod (wildcard DNS, TLS) — Ops-задача (Cycle 5). Интеграция с конкретными tool_id (interactsh_client, ssrfmap, …) — Cycle 2.

### ARG-008 — AI Orchestrator (planner/critic/verifier/reporter) + Prompt Registry + provider router with retry/fixer

- **Status:** `[ ] ARG-008 — AI Orchestrator + Prompt Registry + retry/fixer (⏳ Pending)`
- **Priority:** High
- **Estimated complexity:** Complex (5–6 ч)
- **Dependencies:** ARG-001, ARG-006
- **Files to create:**
  - `backend/src/orchestrator/planner.py` — `Planner.select_next_actions(scan_state, normalized_findings) -> list[ValidationPlan]`. Для каждой category из top-N findings → LLM call с per-vuln prompt → парсинг ValidationPlanV1 → возврат списка планов.
  - `backend/src/orchestrator/critic.py` — `Critic.evaluate(evidence_bundle) -> ConfidenceAssessment` (FP detection, score 0–1, reason).
  - `backend/src/orchestrator/verifier.py` — `Verifier.reproduce(finding, validation_plan) -> ReproducerResult` (replay из canary + PoC).
  - `backend/src/orchestrator/reporter.py` — `Reporter.enrich(finding) -> EnrichedFinding` (remediation focus, prioritization hints).
  - `backend/src/orchestrator/dispatcher.py` — `Dispatcher.enqueue(jobs: list[ToolJob | ValidationJob])` через Celery (`argus.tools`, `argus.exploitation`, …). Использует `PolicyEngine.evaluate()` перед enqueue.
  - `backend/src/prompts/registry/__init__.py`
  - `backend/src/prompts/registry/loader.py` — `PromptRegistry.get(name, schema_ref="validation_plan_v1") -> RenderedPrompt`. Поддержка `system.yaml` + `developer.yaml` + per-vuln `<name>.yaml`. Каждый — структура: `{system, developer, context_template, retry_fixer, schema_ref}`.
  - `backend/src/prompts/registry/system.yaml` — базовый system prompt из `codex.md` §3 ("You are ARGUS Pentest Orchestrator…").
  - `backend/src/prompts/registry/developer.yaml` — developer constraints (allowed_tools, output_schema=ValidationPlanV1, …).
  - **16 per-vuln-type YAML** (имена ровно как в `Backlog/dev1_md` §6): `sqli.yaml`, `xss.yaml`, `rce.yaml`, `lfi.yaml`, `ssrf.yaml`, `ssti.yaml`, `xxe.yaml`, `nosqli.yaml`, `ldapi.yaml`, `cmdi.yaml`, `openredirect.yaml`, `csrf.yaml`, `cors.yaml`, `auth.yaml`, `idor.yaml`, `jwt.yaml`. Тексты для SQLi/XSS/RCE/LFI/SSRF — **дословно из `codex.md` §3**, остальные — по той же структуре (`Finding type: ...; Given ...; Return ... ValidationPlanV1 JSON only.`).
  - `backend/src/llm/router.py` — обновить (если уже есть) или создать `LLMRouter.call(task, prompt_bundle, schema_ref) -> ParsedResponse`. Логика:
    1. Primary provider call (по `task_router.ROUTING_TABLE`).
    2. Если ответ невалиден по `schema_ref` → call `retry_fixer_prompt` с тем же провайдером (max 1 retry).
    3. Если всё ещё невалиден → fallback chain: openai → deepseek → openrouter → gemini → kimi → perplexity (порядок из `Backlog/dev1_md` §6).
    4. Cost tracking через существующий `ScanCostTracker`.
  - `backend/src/llm/retry_fixer.py` — `build_retry_fixer_prompt(invalid_response, schema_errors) -> str`.
- **Tests:**
  - `backend/tests/unit/orchestrator/test_planner.py` — мокирует LLM, проверяет: SQLi finding → вызов `sqli.yaml` prompt → парсинг ValidationPlanV1 → передача в Dispatcher.
  - `backend/tests/unit/orchestrator/test_critic.py` — confidence scoring на синтетических evidence.
  - `backend/tests/unit/orchestrator/test_verifier.py` — replay-сценарий с canary callback.
  - `backend/tests/unit/prompts/test_registry_loader.py` — все 16 vuln-types грузятся, schema_ref резолвится.
  - `backend/tests/unit/llm/test_router_retry_fixer.py` — invalid → fixer → fallback → success path.
- **Acceptance criteria:**
  1. Все 16 vuln-type YAML загружаются без ошибок, валидируются Pydantic.
  2. `LLMRouter.call()` с моком провайдером, возвращающим invalid JSON, успешно проходит fallback chain.
  3. Не более 1 retry на провайдера (защита от стоимости).
  4. Coverage `backend/src/orchestrator + prompts + llm/router + retry_fixer` ≥ 80%.
- **Risks / out-of-scope:** Реальная интеграция с `state_machine.py` (замена legacy `ai_prompts.call_llm_unified`) — Cycle 2. Тут — отдельный модуль, который legacy не ломает.

### ARG-009 — Findings normalizer + correlator + prioritizer (EPSS/KEV/SSVC) + Evidence pipeline + redaction

- **Status:** `[x] ARG-009 — Findings normalizer/correlator/prioritizer + Evidence pipeline (✅ Done 2026-04-17)`
- **Priority:** High
- **Estimated complexity:** Complex (5–6 ч)
- **Dependencies:** ARG-001
- **Files to create:**
  - `backend/src/findings/__init__.py`
  - `backend/src/findings/normalizer.py` — `Normalizer.normalize(tool_run_result) -> list[FindingDTO]`. Дедуп по `(asset, endpoint, parameter, category, root_cause_hash)`. Поддержка ключевых форматов из ARG-003 каталога (jsonl, nuclei jsonl, nmap xml, generic json, csv).
  - `backend/src/findings/correlator.py` — `Correlator.correlate(findings: list[FindingDTO]) -> list[FindingChain]`. Связывает findings в kill-chains через ATT&CK technique mapping + asset graph.
  - `backend/src/findings/prioritizer.py` — `Prioritizer.prioritize(finding) -> PriorityScore`. Формула: `0.4 * cvss_score + 0.25 * epss_score * 100 + 0.2 * kev_listed_bool * 100 + 0.15 * ssvc_score`. Возврат: priority_score (0–100) + breakdown.
  - `backend/src/findings/cvss.py` — парсер CVSS v3/v4 vectors (используем `cvss` PyPI package), валидация, `vector → score`.
  - `backend/src/findings/epss_client.py` — `EpssClient.get(cve_id) -> float | None`. Источник: `https://api.first.org/data/v1/epss?cve=...` (FIRST.org public API). Кэш в Redis 24h.
  - `backend/src/findings/kev_client.py` — `KevClient.is_listed(cve_id) -> bool`. Источник: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. Кэш в Redis 24h.
  - `backend/src/findings/ssvc.py` — SSVC decision tree (CISA stakeholder-specific): `ssvc_decide(exploitation: str, exposure: str, automatable: bool, technical_impact: str, mission_well_being: str) -> SSVCDecision` (Track / Track* / Attend / Act).
  - `backend/src/evidence/__init__.py`
  - `backend/src/evidence/pipeline.py` — `EvidencePipeline.persist(tool_run_id, kind, raw_data) -> EvidenceRecord`. Загрузка в S3 (через существующий `storage/s3.py`), вычисление sha256, redaction перед записью.
  - `backend/src/evidence/redaction.py` — `Redactor.redact(content: bytes | str, redaction_specs: list[RedactionSpec]) -> tuple[bytes, list[RedactionReport]]`. Поддержка regex-паттернов: bearer tokens, API keys (sk_*, AKIA*, ghp_*, …), cookies (Set-Cookie / Cookie), passwords (`password=...`), private keys (`-----BEGIN`), IPs (опционально, контролируется `RedactionSpec.scrub_ips`).
- **Tests:**
  - `backend/tests/unit/findings/test_normalizer.py` — синтетические outputs nmap/nuclei/sqlmap → корректные FindingDTO; дедуп работает.
  - `backend/tests/unit/findings/test_correlator.py` — kill-chain mapping (sample input).
  - `backend/tests/unit/findings/test_prioritizer.py` — приоритизация: critical CVSS + KEV listed + EPSS 0.95 → priority_score > 90.
  - `backend/tests/unit/findings/test_epss_client.py` — мок httpx, кеширование в Redis.
  - `backend/tests/unit/findings/test_kev_client.py` — то же.
  - `backend/tests/unit/findings/test_ssvc.py` — таблица решений (decision tree coverage).
  - `backend/tests/unit/evidence/test_pipeline.py` — E2E: tool_run → evidence в S3 → row в БД.
  - `backend/tests/unit/evidence/test_redaction.py` — каждый regex-паттерн (≥10 кейсов, включая negative — нормальные строки не должны обрезаться).
- **Acceptance criteria:**
  1. `Normalizer.normalize()` идемпотентен (повторный вызов с тем же input → тот же `root_cause_hash`).
  2. `Prioritizer.prioritize()` на edge cases (CVSS=0, EPSS=None, KEV=False) возвращает 0–100 без divide-by-zero.
  3. `Redactor.redact()` обнаруживает все 10+ типовых secrets; не падает на binary data.
  4. EPSS/KEV clients работают через mock httpx, real-API тест помечен `@pytest.mark.integration` и пропускается без `INTEGRATION=1`.
  5. Coverage `backend/src/findings + evidence` ≥ 85%.
- **Risks / out-of-scope:** Не подключаем к `state_machine.py` — Cycle 2. `cvss` Python package добавляем в `backend/requirements.txt` (с version pin, проверить latest stable).

### ARG-010 — Tool catalog coverage test + docs/tool-catalog.md skeleton + CHANGELOG + hexstrike audit

- **Status:** `[ ] ARG-010 — Coverage test + docs/tool-catalog.md + CHANGELOG + hexstrike audit (⏳ Pending)`
- **Priority:** High
- **Estimated complexity:** Simple (2–3 ч)
- **Dependencies:** ARG-002, ARG-003
- **Files to create / modify:**
  - `backend/tests/test_tool_catalog_coverage.py` — для каждого `tool_id`, найденного в `backend/config/tools/*.yaml`, проверяет:
    1. YAML валиден (Pydantic schema)
    2. Подпись валидна (`backend/config/tools/SIGNATURES`)
    3. Упомянут в `docs/tool-catalog.md` (grep по строке `\| {tool_id} \|`)
    4. (soft) есть unit/integration тест с именем `test_*{tool_id}*` (warning, не fail в Cycle 1, fail в Cycle 2 после ARG-011+)
  - `docs/tool-catalog.md` — скелет с заголовком и таблицей §4.1–§4.3 (35 строк). Шапка:
    ```
    # ARGUS Tool Catalog
    
    Total tools registered: <auto-count>
    Cycle 1 coverage: §4.1 (17) + §4.2 (12) + §4.3 (6) = 35
    Pending: §4.4-§4.19 (~115 tools, см. Backlog/dev1_md)
    ```
    Таблица: `| tool_id | category | phase | risk | requires_approval | command_template (truncated) | reference |`.
  - `CHANGELOG.md` — добавить раздел `## [Unreleased] — Cycle 1 Foundation`:
    - feat(pipeline): pipeline contracts + ValidationPlanV1 schema
    - feat(sandbox): ToolAdapter base + signed tool registry + safe templating
    - feat(tools): catalog §4.1-§4.3 (35 tools)
    - feat(sandbox): k8s SandboxAdapter + ephemeral Job + NetworkPolicy
    - feat(payloads): PayloadRegistry + Builder + 23 families
    - feat(policy): PolicyEngine + ScopeEngine + OwnershipProof + ApprovalService (Ed25519, audit hash-chain)
    - feat(oast): OAST correlator + interactsh infra + canary server
    - feat(orchestrator): planner/critic/verifier/reporter + prompt registry + retry/fixer
    - feat(findings): normalizer + correlator + prioritizer (EPSS/KEV/SSVC) + Evidence pipeline + redaction
    - test(tools): test_tool_catalog_coverage
    - docs: tool-catalog.md skeleton
  - `ai_docs/develop/issues/ISS-ARG-001-hexstrike-leftovers.md` — issue с перечислением всех файлов с `hexstrike` упоминаниями (в Cycle 1 — только аудит, fix — Cycle 6):
    - `docs/2026-03-09-argus-implementation-plan.md`
    - `ai_docs/develop/reports/2026-04-02-hexstrike-v4-orchestration-report.md`
    - `backend/tests/test_argus006_hexstrike.py`
    - `README-REPORT.md`
    - `COMPLETION-SUMMARY.md`
    - `ai_docs/develop/plans/2026-04-02-hexstrike-v4-mcp-orchestration.md`
- **Tests:** Сам `test_tool_catalog_coverage.py` — это и есть тест.
- **Acceptance criteria:**
  1. `pytest -q backend/tests/test_tool_catalog_coverage.py` — зелёный с **35 проверенными tool_id**.
  2. `docs/tool-catalog.md` содержит **≥ 35 строк** (одна на tool_id).
  3. `CHANGELOG.md` имеет раздел `## [Unreleased]` со всеми 9 feat-записями выше.
  4. `ai_docs/develop/issues/ISS-ARG-001-hexstrike-leftovers.md` создан и содержит 6+ путей.
  5. `rg -i hexstrike backend/src/ infra/ sandbox/ Frontend/ admin-frontend/ docs/architecture-decisions.md` (но не legacy plans/reports) → **0 matches** (если есть в backend/src — fail).
- **Risks / out-of-scope:** Полная зачистка hexstrike из docs/tests — Cycle 6 (после миграции legacy state_machine).

---

## 4. Граф зависимостей

```
ARG-001 (contracts + ValidationPlanV1 schema)
   |
   ├──> ARG-002 (ToolAdapter + tool registry + templating + signing)
   |       |
   |       ├──> ARG-003 (Tool YAMLs §4.1-§4.3, 35 tools)
   |       |       \
   |       |        \
   |       ├──> ARG-004 (k8s SandboxAdapter + NetworkPolicy)
   |       |        \
   |       └──> ARG-005 (PayloadRegistry + Builder + 23 families)
   |                \
   |                 \
   ├──> ARG-006 (PolicyEngine + ScopeEngine + Ownership + ApprovalService)
   |                 |
   ├──> ARG-007 (OAST infra + Correlator + Canary)
   |                 |
   ├──> ARG-008 (AI Orchestrator + Prompt Registry + retry/fixer) <─ ARG-006
   |                 |
   └──> ARG-009 (Findings normalizer + Evidence pipeline)
                     |
                     v
                  ARG-010 (Coverage test + tool-catalog.md + CHANGELOG + hexstrike audit) <─ ARG-002, ARG-003
```

**Параллелизация:** После ARG-001 все из {ARG-002, ARG-006, ARG-007, ARG-009} могут идти параллельно. ARG-003/004/005 ждут ARG-002. ARG-008 ждёт ARG-006. ARG-010 — финальный seal-task, требует ARG-002 и ARG-003.

---

## 5. Архитектурные решения для Cycle 1

| Решение | Обоснование |
|---|---|
| **Kata Containers (kata-clh) как `runtimeClassName`** для sandbox Job | VM-уровень изоляции, поддерживается на современных k8s clusters (EKS, GKE, AKS, kind, microk8s); fallback `gvisor` отмечен в комментариях |
| **Ed25519 для всех подписей** (tool YAMLs, payload registry, approvals) | Современный, быстрый, маленький размер ключа; библиотека `cryptography` (стандарт de-facto Python) |
| **PyNaCl как альтернатива** не используем | минимизируем зависимости, `cryptography` уже в `requirements.txt` |
| **FastMCP для backend MCP server** (Cycle 2, не Cycle 1) | Совместимость с уже работающим `mcp-server/` (отдельный сервис), миграция в `backend/src/mcp/server.py` потребует pubсub-моста, оставляем для следующего цикла |
| **WeasyPrint для PDF** | Уже в `backend/requirements.txt`, проверена в проекте |
| **`cvss` Python package** для парсинга CVSS векторов | maintained by FIRST.org, поддержка v3/v4 |
| **`croniter`** для maintenance window cron parsing | Стандарт |
| **`kubernetes` async client** | Официальный, поддерживается в asyncio-контексте FastAPI/Celery |
| **EPSS из FIRST.org public API**, **KEV из CISA JSON feed** | Бесплатные, no API key |
| **SSVC: CISA stakeholder-specific decision tree** (упрощённая версия Coordinator) | Полную FIRST.org SSVC v2.1 — Cycle 4 |
| **Не интегрируем новые модули в `state_machine.py` в Cycle 1** | KISS + safety: legacy продолжает работать, новый control plane строится параллельно. Миграция — Cycle 2 (ARG-026+). |
| **Scope Cycle 1 to foundation only** | 10 задач упираются в 5–7 человеко-дней; полный план §16 = 6+ циклов. Foundation разблокирует параллельную работу команды на Cycle 2. |

---

## 6. Out of Scope — Cycle 1

Эти категории **не входят** в текущий цикл и будут реализованы в последующих оркестрациях:

### Cycle 2 (~10 задач): "Tool YAMLs остатки + ToolAdapter implementations + sandbox-images + state_machine миграция"
- Tool YAMLs §4.4–§4.19 (~115 файлов: HTTP fingerprinting, content discovery, crawler/JS, CMS-specific, web scanners, SQLi/XSS/SSRF/auth/cloud/IaC/network/binary/browser).
- Конкретные `ToolAdapter` подклассы с `parse_output()` для каждого формата (nmap XML, nuclei jsonl, sqlmap output, …).
- `backend/src/sandbox/firecracker_driver.py` (fallback driver).
- `sandbox/images/argus-kali-{full,web,cloud,browser}/Dockerfile` — мульти-image c SBOM (`syft`).
- Замена legacy `docker exec` в `backend/src/orchestration/state_machine.py` на `K8sSandboxDriver`.

### Cycle 3 (~8 задач): "Reports v1 + MCP server + admin-frontend"
- `ReportService` для всех **12 комбинаций** (Midgard/Asgard/Valhalla × HTML/PDF/JSON/CSV) + SARIF + JUnit.
- Шаблоны `backend/templates/reports/{midgard,asgard,valhalla}/`.
- `replay_command_sanitizer.py` (redaction в reproducer).
- `backend/src/mcp/server.py` (FastMCP с tools из `Backlog/dev1_md` §13).
- Закрытие gaps в `admin-frontend/` (если в main tree чего-то не хватает).

### Cycle 4 (~6 задач): "Observability + cloud_iam ownership + полный SSVC"
- OTel spans на каждый tool_run / LLM call / policy decision / approval.
- Prometheus metrics: `argus_tool_runs_total`, `argus_findings_total`, `argus_oast_callbacks_total`, ...
- Endpoints `/health`, `/ready`, `/metrics`, `/providers/health`, `/queues/health`.
- Полная реализация `OwnershipProof.cloud_iam` для AWS/GCP/Azure.
- Полный CISA SSVC v2.1 + EPSS percentile decisions.

### Cycle 5 (~5 задач): "Migrations + RLS coverage + Operations"
- Alembic migrations для всех новых таблиц (см. ARG-006 + tool_runs, oast_callbacks).
- RLS coverage tests на каждую таблицу.
- Production OAST deployment (wildcard DNS, TLS).
- Helm chart `helm/argus/`.
- `infra/firecracker/*.json`.

### Cycle 6 (~5 задач): "Hexstrike purge + e2e + DoD §19 verification + repository hygiene"
- Полное удаление `hexstrike` из docs/tests/reports (Cycle 1 только аудит).
- `scripts/e2e_full_scan.sh http://juice-shop:3000` — поднимает стек, гоняет полный скан, проверяет 12 отчётов с ≥1 confirmed-finding с OAST evidence.
- `infra/.env` cleanup (вынести из репозитория).
- Fix `observability.get_metrics_content()` 3 vs 2 unpacking.
- DoD §19 итоговая проверка (coverage ≥ 85%, ruff/mypy/bandit clean, alembic round-trip).

### Не входит **никогда** в эту оркестрацию
- Изменения в `Frontend/` (запрещено `Backlog/dev1_md` §0).
- Изменения в `.claude/worktrees/busy-mclaren/` (reference-only).

---

## 7. Open questions / Blockers (не блокирующие, но требуют внимания)

1. **k8s cluster availability**: Есть ли у dev-environment локальный `kind`/`minikube`/`microk8s`? В Cycle 1 это не блокирует (k8s_driver будет с graceful fallback `K8sClusterUnavailableError`), но для CI integration tests (ARG-004) понадобится `kubectl --dry-run=server` (best-effort, скип если нет).
2. **Ed25519 key management**: Cycle 1 генерирует **dev-keypair** в `backend/config/tools/_keys/`. Prod ротация — Cycle 5 (документирована в `_keys/README.md`).
3. **EPSS/KEV public API rate limits**: FIRST.org EPSS — 1 req/sec без API key, OK для кэшированного 24h-доступа. CISA KEV JSON feed — без лимитов. Не блокирует.
4. **`mcp-server/` vs `backend/src/mcp/`**: legacy MCP server работает как отдельный сервис; полная миграция в backend — Cycle 3, в Cycle 1 не трогаем.
5. **`infra/.env`** в `git status` modified (риск утечки секретов — Critical из Анализа архитектуры §6) — эскалирована в issue, fix Cycle 6, **рекомендуется** срочно проверить вручную и при необходимости `git rm --cached`.

---

## 8. Progress (updates by orchestrator)

- ✅ ARG-001: Pipeline contracts + ValidationPlanV1 JSON Schema (Completed — 109 tests, 98.79% cov)
- ✅ ARG-002: ToolAdapter + signed tool registry + safe templating (Completed — 304 tests, sandbox 92%)
- ✅ ARG-003: Tool YAMLs §4.1-§4.3 (35 tools) (Completed)
- ✅ ARG-004: k8s SandboxAdapter + NetworkPolicy (Completed)
- ⏳ ARG-005: PayloadRegistry + Builder + 23 families (Pending)
- ✅ ARG-006: PolicyEngine + ScopeEngine + OwnershipProof + ApprovalService (Completed)
- ⏳ ARG-007: OAST infra + Correlator + Canary (Pending)
- ⏳ ARG-008: AI Orchestrator + Prompt Registry + retry/fixer (Pending)
- ✅ ARG-009: Findings normalizer + Evidence pipeline (Done 2026-04-17)
- ⏳ ARG-010: Coverage test + tool-catalog.md + CHANGELOG + hexstrike audit (Pending)

---

## 9. Implementation notes

- **Атомарные коммиты** (по `Backlog/dev1_md` §0): `feat(pipeline): add validation_plan_v1 schema`, `feat(sandbox): add ToolAdapter base`, `feat(tools): add nmap_tcp_top yaml`, `feat(oast): add canary server`, `test(...): ...`, `docs(...): ...`. **Один коммит ≈ один тест-файл + соответствующий код**.
- **После каждой задачи**: `pytest -q <task scope>`, `ruff check backend/src`, `mypy backend/src/<новый_модуль>`, при добавлении миграций — `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`.
- **Прогресс обновляется** автоматически orchestrator-ом в `.cursor/workspace/active/orch-2026-04-17-12-00-argus-final/{progress,tasks}.json` + чекбоксы в этом файле.
- **Если задача не помещается в timebox** (например ARG-008 разрастается) — выделить sub-tasks и переоткрыть план через `planner` (но **не ломать atomicity** — каждый sub-PR должен быть мерж-абельным).
- **При найденных не-критичных проблемах** — создавать issue в `ai_docs/develop/issues/ISS-NNN-*.md`, не блокируя текущую задачу.

---

**End of plan. Ready to execute via `/orchestrate execute orch-2026-04-17-12-00-argus-final`.**
