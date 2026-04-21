# ISS — Cycle 4 Carry-over Backlog (ARG-031..ARG-040)

**Issue ID:** ISS-cycle4-carry-over
**Owner:** ARGUS Cycle 3 → Cycle 4 transition
**Source:** ARG-030 capstone (`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md` §3 ARG-030)
**Sign-off report:** [`ai_docs/develop/reports/2026-04-19-argus-finalization-cycle3.md`](../reports/2026-04-19-argus-finalization-cycle3.md)
**Status:** Open — seed для Cycle 4 plan
**Priority:** mixed (см. per-item)
**Date filed:** 2026-04-19

---

## Context

Cycle 3 (ARG-021..ARG-030) закрыл основные deliverables (см. sign-off): +35 mapped-парсеров (33 → 68), Backend MCP Server (15/4/3), ReportService Tier 1 + Tier 2 (12/18 ячеек), 4 production-ready Dockerfile'а, 11 NetworkPolicy templates, dev-default зелёный pytest, расширение coverage matrix до 12 контрактов × 157 = 1884 кейсов.

Этот документ собирает 10 carry-over пунктов (ARG-031..ARG-040), которые **выявлены и задокументированы внутри Cycle 3**, но сознательно отложены до Cycle 4 (либо для соблюдения scope-boundary'ев Cycle 3, либо потому что требуют отдельной инфраструктуры — например, Docker daemon на CI).

Каждый пункт содержит: **title**, **description**, **complexity estimate** (S / M / L / XL), **dependencies**, **source** (какой Cycle 3 task'ой surfaced).

---

## ARG-031 — Valhalla tier renderer (executive summary + business-impact lens)

- **Description:** Завершить ReportService matrix (12/18 → **18/18**), реализовав Valhalla tier — executive-level отчёт с business-impact lens'ом, risk-quantification per asset, сжатой OWASP rollup, top-N финдингов by `(severity × exploitability × business_value)`. Пере-использовать `tier_classifier._project_valhalla` (уже существует как pass-through), добавить `valhalla_tier_renderer.py` (по аналогии с `asgard_tier_renderer.py`), wire через `ReportService.render_bundle` для всех 6 форматов (HTML / PDF / JSON / CSV / SARIF / JUnit). Ввести Pydantic-модель `ValhallaSectionAssembly` (immutable, hashable). Snapshot-тесты для всех 6 форматов.
- **Complexity:** L (≈ 3-4 дня worker-time, mirror ARG-024 + ARG-025 структуры).
- **Dependencies:** ARG-024 (Midgard) ✅, ARG-025 (Asgard + sanitizer) ✅, существующий `tier_classifier._project_valhalla` ✅.
- **Source:** ARG-024 / ARG-025 worker reports (Valhalla явно отложен); sign-off report «Headline Metrics Table» (12/18 → 18/18).

## ARG-032 — Heartbeat parsers batch 4 (target: ещё +30 mapped tools)

- **Description:** Сократить heartbeat fallback с 89 → ~59 (mapped 68 → ~98). Приоритет по `Parser coverage by category` секции `docs/tool-catalog.md`:
  - **`browser`** (0/6, 0 %) — playwright, pyppeteer, puppeteer, retire-js + 2 вспомогательных.
  - **`binary`** (1/5, 20 %) — radare2, ghidra, ropgadget, capstone (heartbeat → mapped, BINARY_BLOB skip-rule сохранить).
  - **`recon`** (7/35, 20 %) — assetfinder, subfinder, amass, dnsrecon, fierce, sublist3r, shodan_cli, censys_cli, whois и др.
  - **`auth`** (3/11, 27 %) — hydra, medusa, patator, ncrack, crackmapexec, responder.
  Каждый парсер — pure-функция в стиле ARG-021/022/029 (через `_base.py` / `_text_base.py` / `_jsonl_base.py`); ноль новых helper'ов; per-module coverage ≥ 90 %; интеграционный suite `test_arg032_dispatch.py` со всеми security-gate'ами (redaction completeness, dedup determinism).
- **Complexity:** XL (≈ 5-7 дней worker-time, аналог ARG-021+ARG-022+ARG-029 в одном; разбить на 3 параллельных batch'а).
- **Dependencies:** Cycle 3 parsers infrastructure (ARG-021/022/029) ✅; ARG-030 C11+C12 contracts ✅ (новые парсеры будут проверяться автоматически).
- **Source:** ARG-029 worker report § 9 «Outstanding parser backlog»; ARG-030 sign-off «Parser coverage by category» (browser 0 %, binary 20 %).

## ARG-033 — Cosign full prod wiring + GH OIDC keyless signing

- **Description:** Превратить `infra/scripts/sign_images.sh` skeleton (dry-run по умолчанию) в production-ready подпись через GitHub Actions OIDC + Sigstore Fulcio (keyless), Rekor transparency log enabled. Вместо `--tlog-upload=false` — `--tlog-upload=true`; `cosign attest --predicate <SBOM> --type cyclonedx` для каждого образа. Добавить verify-job в CI (`cosign verify --certificate-identity-regexp "..." --certificate-oidc-issuer https://token.actions.githubusercontent.com`). Документировать в `docs/sandbox-images.md` § «Cosign keyless signing» полный recipe + roll-back plan.
- **Complexity:** M (≈ 2 дня — основная работа в `.github/workflows/sandbox-images.yml` + IAM permissions + Sigstore setup; код-изменения минимальные).
- **Dependencies:** ARG-026 (Cosign skeleton) ✅; ARG-034 (real `docker build` в CI) — ARG-033 имеет смысл только после того, как образы реально пушатся в registry.
- **Source:** ARG-026 worker report «5 — Deferred CI smoke».

## ARG-034 — Image-build CI gating (real `docker build`, push в `ghcr.io`, SBOM как OCI artefact)

- **Description:** Переключить `.github/workflows/sandbox-images.yml::build-images` job из «build + extract SBOM локально» в «build + push в `ghcr.io/<org>/argus-kali-<profile>` + push SBOM как OCI artefact через `cosign attach sbom`». Включить `paths-filter` по `sandbox/images/**` для экономии CI-минут. Добавить gate на merge в `main`: build-images матрица [web,cloud,browser,full] обязана пройти. Trivy scan job переключить с `informational` (continue-on-error) на `blocking` (fail-on-CRITICAL).
- **Complexity:** M (≈ 2 дня — основное это `.github/workflows/sandbox-images.yml` + GHCR permissions + branch protection rules).
- **Dependencies:** ARG-026 (Dockerfiles + build script) ✅; ARG-033 для cosign-attestation на push.
- **Source:** ARG-026 worker report «8 — Cycle 4 follow-up».

## ARG-035 — MCP webhook integrations (Slack / Linear / Jira) + per-LLM-client rate limiting

- **Description:** Добавить webhook-эмиттеры в `backend/src/mcp/services/`:
  - `SlackNotifier` — на approval-pending / scan-completed / critical-finding-detected.
  - `LinearAdapter` — auto-create Linear issue для critical/high-finding'ов.
  - `JiraAdapter` — same для Jira projects.
  Все три behind feature-flag (`MCP_NOTIFICATIONS_ENABLED=false` по умолчанию). Параллельно: per-LLM-client token-bucket rate-limiter (`MCPRuntime.rate_limiter` с per-client / per-tenant budget'ом) — защищает от runaway-loop'ов в Claude/GPT/Gemini. Лимиты конфигурируются в `backend/config/mcp/server.yaml` (signed manifest).
- **Complexity:** L (≈ 3-4 дня — webhook'и легко, но reliable retry + dedup + secret-handling требуют осторожности; rate-limiter — отдельная подзадача с тестами на race-condition'ы).
- **Dependencies:** ARG-023 (MCP server skeleton) ✅; secret-management через переменные окружения (Slack/Linear/Jira tokens).
- **Source:** ARG-023 worker report «Cycle 4 follow-ups»; sign-off report «Architectural Impact §3 — MCP как новая внешняя поверхность».

## ARG-036 — ReportService PDF templating polish (branded WeasyPrint template; LaTeX fallback?)

- **Description:** Заменить generic-WeasyPrint stub в `src/reports/generators.py::generate_pdf` на:
  1. Branded HTML/CSS template'ы под Midgard / Asgard / Valhalla tier'ы (logo, цветовая схема, header/footer с tenant_id + scan_id + SHA-256, page numbering, TOC).
  2. PDF-determinism (где возможно) — fixed font embedding, fixed timestamp, no `/CreationDate` randomness.
  3. **Optional LaTeX fallback** — если WeasyPrint native libs недоступны (типичный CI-bug), generate `.tex` через `jinja2-latex`, render через `latexmk`. Behind feature-flag `REPORT_PDF_BACKEND=weasyprint|latex|disabled`.
  4. Snapshot-тест с `pypdf` для structural-equality (page count, section headers, embedded images count) — без byte-equality.
- **Complexity:** L (≈ 3-4 дня — template-design + WeasyPrint-debugging + опциональная LaTeX-инфраструктура).
- **Dependencies:** ARG-024 / ARG-025 (ReportService Midgard + Asgard) ✅; ARG-031 (Valhalla — для бизнес-template'а).
- **Source:** ARG-024 / ARG-025 worker reports «PDF determinism — known limitation».

## ARG-037 — Stale-import follow-ups триаж (ISS-fix-004, ISS-fix-006, ISS-payload-signatures-drift, ISS-pytest-test-prefix-collisions)

- **Description:** Закрыть 4 follow-up issue'а, surfaced в ARG-028 / ARG-029:
  1. **`ISS-fix-004-imports`** — stale import'ы в `src/api/routers/*.py` (несколько `from src.X import Y` где `Y` уже не существует или переехал).
  2. **`ISS-fix-006-imports`** — same в `src/services/*.py`.
  3. **`ISS-payload-signatures-drift`** — `backend/config/payloads/SIGNATURES` content-hash для `apktool.yaml` (см. ARG-038) расходится с YAML после некоторых test-runs.
  4. **`ISS-pytest-test-prefix-collisions`** — `tests/test_*.py` модули с одинаковыми class-prefix'ами (например, `TestUser` в трёх разных модулях) ломают pytest-discovery в pyproject-mode.
  Все 4 — низкая complexity по отдельности, но требуют систематического прогона. Сделать одним worker-проходом с PR-чеклистом.
- **Complexity:** M (≈ 1-2 дня — много мелких правок, но без архитектурных изменений).
- **Dependencies:** ARG-028 (pytest marker discipline) ✅.
- **Source:** ARG-028 / ARG-029 worker reports «Out-of-scope follow-ups».

## ARG-038 — `apktool.yaml` drift root-cause investigation

- **Description:** В нескольких worker-проходах Cycle 3 (ARG-021, ARG-022, ARG-027, ARG-029) поверхность всплыла идентичная: `backend/config/tools/apktool.yaml` мутировался mid-run каким-то test'ом / fixture'ом, и `python -m scripts.docs_tool_catalog --check` начинал ругаться на signature drift между YAML hash'ом и записью в `SIGNATURES`. Никто из worker'ов не локализовал root-cause (каждый просто восстанавливал YAML из git и шёл дальше). Cycle 4 надо:
  1. Запустить `pytest -p pytest_changedfiles` или подобную bisection-стратегию для определения, какой именно test пишет в `apktool.yaml`.
  2. Запретить такой write через `tests/conftest.py::pytest_collection_modifyitems` hook (отметить fixture'у `read_only_catalog`).
  3. Если есть legitimate reason для mutation (например, тест валидирует ToolRegistry.reload()) — переместить в tmp_path, не трогать ground-truth YAML.
- **Complexity:** S (≈ 1 день — bisection + fix; root-cause скорее всего конкретная fixture).
- **Dependencies:** ни от чего не зависит (parallel с любой другой задачей).
- **Source:** ARG-021 / ARG-022 / ARG-027 / ARG-029 worker reports + sign-off report «Cycle 3 invariants — apktool.yaml drift».

## ARG-039 — OpenAPI export of MCP server schema (для client SDK generation)

- **Description:** Сейчас MCP server (`backend/src/mcp/`) описан signed manifest'ом `backend/config/mcp/server.yaml` + Pydantic-схемами в `backend/src/mcp/schemas/`. Client'ы вынуждены либо парсить manifest, либо вручную писать типы. Cycle 4: сгенерить OpenAPI 3.1 spec'у MCP-tools surface'а из Pydantic-моделей (через `pydantic.json_schema_of()` + custom OpenAPI emitter), опубликовать как `docs/mcp-server-openapi.yaml`. Bonus: автоматическая генерация TypeScript SDK через `openapi-typescript-codegen`. Все public-MCP-tools должны иметь docstring (формальный gate в CI).
- **Complexity:** M (≈ 2 дня — pydantic-to-OpenAPI emitter + CI gate + doc).
- **Dependencies:** ARG-023 (MCP server) ✅.
- **Source:** ARG-023 worker report «Cycle 4 follow-ups»; sign-off report «Architectural Impact §3».

## ARG-040 — Cycle 4 capstone scaffolding

- **Description:** Cycle 4 capstone аналог ARG-030 (этого документа): coverage matrix expansion (12 → 14 контрактов? кандидаты: **C13 — `signature-mtime-stability`** (touched-but-unchanged YAML не должен инвалидировать SIGNATURES), **C14 — `tool-yaml-version-field-presence`** (закрывает ISS-cycle3-tool-yaml-version-field из ARG-026 follow-up'ов)); регенерация `docs/tool-catalog.md` (с per-image coverage по ARG-026 pinned-versions matrix); Cycle 4 sign-off report; CHANGELOG rollup; Cycle 5 carry-over backlog.
- **Complexity:** L (≈ 3 дня — mirror ARG-030, но с большим количеством новых deliverables Cycle 4).
- **Dependencies:** все 9 предыдущих ARG-031..ARG-039 должны быть закрыты.
- **Source:** ARG-030 sign-off report «Known Gaps / Cycle 4 Candidates».

---

## Suggested Cycle 4 phasing

Если Cycle 4 идёт ~5 недель (как Cycle 3), грубое разбиение:

- **Week 1:** ARG-038 (apktool.yaml root-cause, S, parallel) + ARG-037 (stale-import триаж, M, parallel) + ARG-031 (Valhalla, L, primary).
- **Week 2:** ARG-031 finish + ARG-036 (PDF polish, L, primary) + ARG-039 (OpenAPI MCP, M, parallel).
- **Week 3:** ARG-032 batch 4a (browser + binary, L) + ARG-033 (Cosign keyless, M, parallel).
- **Week 4:** ARG-032 batch 4b (recon + auth, L) + ARG-034 (image CI gating, M, parallel).
- **Week 5:** ARG-035 (MCP webhooks + rate-limiter, L) + ARG-040 (capstone, L).

После Cycle 4 ожидаемые состояния: parsers `mapped ≥ 98 / heartbeat ≤ 59`, ReportService `18/18`, MCP `15/4/3 + webhooks + OpenAPI export + rate-limiter`, supply-chain `4/4 images signed via Cosign keyless + SBOM attached + Trivy gate blocking`.

---

## Tracking

- **Этот файл:** `ai_docs/develop/issues/ISS-cycle4-carry-over.md`
- **Cycle 3 sign-off:** `ai_docs/develop/reports/2026-04-19-argus-finalization-cycle3.md`
- **Cycle 4 plan:** будет создан в `ai_docs/develop/plans/2026-XX-XX-argus-finalization-cycle4.md` после kickoff'а Cycle 4.
- **Workspace state:** `.cursor/workspace/active/orch-2026-04-19-argus-cycle3/tasks.json` — для каждого ARG-031..ARG-040 будет создана новая запись в Cycle 4 workspace при kickoff'е (НЕ в этом цикле).

Cycle 3 ✅ closed — Cycle 4 unblocked.
