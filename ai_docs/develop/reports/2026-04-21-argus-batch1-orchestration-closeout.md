# Batch 1 — закрытие оркестрации `orch-argus-20260420-1430`

**Дата:** 2026-04-21  
**Область:** Foundation hygiene & carry-over closure (план `Backlog/dev1_.md`, batch1_only).  
**Статус workspace:** 10/10 задач выполнены; Phase 4 — финальный отчёт.

## Краткое резюме

В рамках одного батча закрыт набор задач Cycle 6: рефакторинг policy, миграция сетевых tool-YAML, документация mypy/Windows + WSL2, Helm/kubeconform, advisory SCA-гейты в `argus_validate.py`, OAST на Redis Streams (MVP), opt-in экспорт SARIF/JUnit по флагу тенанта, Renovate + проверка дрейфа SBOM, расширение E2E smoke на DVWA/WebGoat, батч heartbeat-парсеров top-20. Часть пунктов перенесена в `ISS-cycle6-carry-over.md` как **RESOLVED** с сохранением истории.

## Таблица задач

| ID | Название (кратко) | Ключевые артефакты | Коммит-скрипт |
|----|-------------------|--------------------|---------------|
| T02 | Cyclic policy import | `backend/src/policy/*`, unit-тесты | `scripts/orchestration/commit_T02.ps1` |
| T03 | 16 dual-listed → network image | YAML, `tool_to_package.json`, тесты ARG-058 | `commit_T03.ps1` |
| T06 | mypy Windows + WSL2 docs | `ai_docs/develop/troubleshooting/…`, `wsl2-setup.md` | `commit_T06.ps1` |
| T07 | Helm kubeconform CI | `helm-validation.yml`, `helm_kubeconform.*` | `commit_T07.ps1` |
| T08 | Advisory gates (pip-audit, npm, trivy, bandit) | `argus_validate.py`, `advisory-gates.yml` | `commit_T08.ps1` |
| T01 | OAST → Redis Streams | `redis_stream.py`, коррелятор, конфиг | `commit_T01.ps1` |
| T04 | SARIF/JUnit API opt-in | Alembic 024, `scans`/`admin` routers, тесты | `scripts/orchestration/commit_T04.ps1` |
| T09 | Renovate + SBOM drift | `renovate.json`, `sbom_drift_check.py`, CI шаг | `commit_T09.ps1` |
| T10 | E2E vuln matrix | `docker-compose.vuln-targets.yml`, Playwright, workflow | `commit_T10.ps1` |
| T05 | Heartbeat parsers top-20 | Новые парсеры, фикстуры, ratchet 118/39 | `commit_T05.ps1` |

## Рекомендуемый порядок коммитов

Из-за частых правок `ai_docs/develop/issues/ISS-cycle6-carry-over.md` и смежной документации **держите один поток коммитов** в фиксированном порядке (каждый скрипт делает `git reset` и allow-list):

1. T02 → T03 → T06 → T07 → T08 → T01 → **T04** → T09 → T10 → T05  

Перед первым коммитом: `.\scripts\orchestration\commit_T02.ps1 -DryRun` и далее по цепочке.

## Проверка перед коммитом T05

В `test_t05_heartbeat_top20_dispatch.py` golden-файлы должны попадать на диск под **каноническими именами** парсера (`gobuster.txt`, `wayback.txt`), а не только под именами фикстур — см. `_ARTIFACT_BASENAME_BY_TOOL` в тесте.

## CRITICAL — SEC-001

В `infra/.env.example` ранее выявлены строки, похожие на **боевые API-ключи** внешних провайдеров. Действия:

1. Считать ключи скомпрометированными — **ротация** в кабинетах провайдеров.  
2. Заменить значения в файле на явные плейсхолдеры.  
3. **Очистка истории git** (`git filter-repo` / BFG) + уведомление всех клонов.  
4. Pre-commit / CI: `gitleaks` или `detect-secrets`.

Полный чеклист (провайдеры, staging/prod, бэкап/legal, без команд с секретами в тексте): [`ai_docs/develop/issues/ISS-SEC-001-env-example-sanitization.md`](../issues/ISS-SEC-001-env-example-sanitization.md).

Не смешивать исправление SEC-001 с функциональными коммитами Batch 1.

## Follow-ups (темы из workspace)

- **T02–T10:** см. `.cursor/workspace/active/orch-argus-20260420-1430/notes/T0*-followups.md` — soft CI, supply-chain SHA для kubeconform, wiring `run_consumer` OAST, OpenAPI shorthand для SARIF-роутов и т.д.  
- Документер через subagent мог не отработать при лимите API — этот файл закрывает отчёт Phase 4 вручную.

## Ссылки

- План / задачи: `.cursor/workspace/active/orch-argus-20260420-1430/`  
- Carry-over: `ai_docs/develop/issues/ISS-cycle6-carry-over.md`  
- Спека: `Backlog/dev1_.md`
