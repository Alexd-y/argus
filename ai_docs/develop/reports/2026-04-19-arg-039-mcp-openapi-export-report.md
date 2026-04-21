# ARG-039 — Worker Report

**Цикл:** Cycle 4 (финализация ARGUS v0.4)
**Worker:** Cursor agent (Claude Sonnet 4.5)
**Дата:** 2026-04-20
**Статус:** ✅ Completed
**План-источник:** `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle4.md` (§3 ARG-039, lines 474-523)

---

## 1. Executive summary

Реализован детерминированный экспорт капабилити-поверхности backend MCP-сервера в каноническую OpenAPI 3.1 спецификацию, развёрнут TypeScript-SDK для Frontend и подключены три CI-гейта, страхующие пайплайн от silent drift и от деградации описаний.

Ядро задачи — **pure-function** эмиттер `build_openapi_spec(app: FastMCP) -> dict[str, Any]`: он обходит зарегистрированные tools, resources, resource templates и prompts, поднимает Pydantic-схемы из локальных `$defs` в глобальный `components.schemas`, переписывает все `$ref` на `#/components/schemas/<Name>` и сериализуется в стабильный YAML с `sort_keys=True`. Тот же артефакт используется как источник правды для `openapi-typescript-codegen@0.29.0`, генерирующего полный typed-клиент в `Frontend/src/sdk/argus-mcp/`.

Никаких изменений в `backend/src/mcp/{server,runtime,services,tools,resources,prompts}/` не сделано — эмиттер живёт сбоку, использует только публичный API FastMCP. Подписанные манифесты (`backend/config/mcp/server.yaml::SIGNATURES`) не пересобирались.

---

## 2. Файлы

### Создано (5 + 75 auto-generated)

| Путь | Строк | Назначение |
|------|------:|-----------|
| `backend/src/mcp/openapi_emitter.py` | ~310 | Эмиттер OpenAPI 3.1 — pure function без I/O |
| `backend/scripts/export_mcp_openapi.py` | ~135 | CLI с `--out` / `--check` режимами |
| `docs/mcp-server-openapi.yaml` | ~2 700 | Закоммиченная спецификация (68 KB) |
| `backend/tests/test_mcp_tools_have_docstrings.py` | ~135 | Параметризованный CI-гейт (≥30 chars) |
| `backend/tests/integration/mcp/test_openapi_export_stable.py` | ~190 | 6 snapshot-инвариантов |
| `Frontend/src/sdk/argus-mcp/**/*.ts` | 75 файлов | Auto-generated TypeScript SDK (74 KB) |
| `ai_docs/develop/reports/2026-04-19-arg-039-mcp-openapi-export-report.md` | ~250 | Этот отчёт |
| `.cursor/workspace/active/orch-2026-04-19-argus-cycle4/tasks.json` | 39 | Workspace state (ARG-039=completed) |
| `.cursor/workspace/active/orch-2026-04-19-argus-cycle4/links.json` | 7 | Per-task report linkage |

### Изменено (6)

| Путь | Что изменено |
|------|-------------|
| `Frontend/package.json` | + `openapi-typescript-codegen@0.29.0` (pinned exact) + `sdk:generate` / `sdk:check` scripts |
| `Frontend/package-lock.json` | Регенерация после `npm install` |
| `backend/tests/conftest.py` | `_OFFLINE_FILE_NAMES` += `test_mcp_tools_have_docstrings.py`, `test_openapi_export_stable.py` (оба тесты — pure introspection, без БД/брокера) |
| `.github/workflows/ci.yml` | + новый job `mcp-openapi-drift` (drift спецификации, docstring gate, drift SDK); добавлен в `needs:` для `build` |
| `docs/mcp-server.md` | + новая секция A.11 «OpenAPI 3.1 export + TypeScript SDK» (~120 строк): mapping table, регенерация спецификации, использование SDK, описание CI-гейтов, pin-версий |
| `CHANGELOG.md` | + entry «Added (ARG-039 — Cycle 4: MCP OpenAPI 3.1 export + TypeScript SDK + docstring CI gate)» с детальной декомпозицией изменений и метрик |

---

## 3. Технические детали

### 3.1 Mapping FastMCP entity → OpenAPI

| MCP entity | OpenAPI path | Метод | `operationId` | Тег |
|------------|-------------|-------|---------------|-----|
| `@mcp.tool(name="x.y")` | `POST /rpc/x.y` | POST | `call_x_y` | `mcp-tool` |
| `@mcp.resource("argus://x/y")` | `GET /resources/x/y` | GET | `read_argus_x_y` | `mcp-resource` |
| `argus://x/{id}` (template) | `GET /resources/x/{id}` | GET (path param) | `read_argus_x` | `mcp-resource` |
| `@mcp.prompt(name="x.y")` | `POST /prompts/x.y` | POST | `render_x_y` | `mcp-prompt` |

Каждая `POST /rpc/*` operation отдаёт стандартизованный набор responses: 200 (с `$ref` на output schema), 400 / 422 (validation error), 401 (unauthorized), 403 (forbidden — tenant mismatch / scope violation), 404 (anti-enumeration), 429 (rate limit), 500 (internal). Это — контракт всего MCP transport, фиксированный в эмиттере.

`POST /prompts/*` использует синтетическую схему `{Name}PromptArguments`, генерируемую из `mcp.types.PromptArgument` списка (`type=string`, `description` если задан, `required` если flag поднят). Имя всегда CamelCase производное от prompt name (`vulnerability.explainer` → `VulnerabilityExplainerPromptArguments`).

### 3.2 Schema lifting + `$ref` rewriting

Pydantic-сгенерированные JSON-схемы часто содержат локальные `$defs`. Эмиттер рекурсивно:

1. Снимает `$defs` с каждого верхнеуровневого input/output schema.
2. Поднимает каждое определение в `components.schemas` (deduplicated by name; повторное появление одинаковой модели — no-op).
3. Переписывает любой `$ref: "#/$defs/X"` → `$ref: "#/components/schemas/X"` в произвольной глубине.
4. Финальный sort `components.schemas` по ключу — снэпшот стабильный.

Контракт self-containment проверяется тестом `test_every_ref_resolves_into_components_schemas`: каждый `$ref` обязан резолвиться внутри `components.schemas`, **leaked** `#/$defs/*` ссылок не должно остаться (любой такой случай — баг эмиттера).

### 3.3 Детерминированность

`yaml.safe_dump(spec, sort_keys=True, allow_unicode=False, default_flow_style=False, width=120)` + LF newlines (`write_text(..., newline="\n")`) — байт-в-байт идентичный output на Windows / Linux / macOS, что делает `git diff --exit-code` корректным CI-гейтом. Все списки sorted by name внутри `_collect_runtime_snapshot`.

### 3.4 TypeScript SDK

Параметры кодогена: `--client fetch --useUnionTypes --useOptions --indent 2`.

Структура:
- `core/` — runtime: `OpenAPI` (config), `request` (HTTP layer), `CancelablePromise`, `ApiError` / `ApiResult`.
- `models/` — TypeScript-интерфейсы для каждой Pydantic-схемы из spec'а.
- `services/` — три класса `McpToolService`, `McpResourceService`, `McpPromptService` со статическими методами для каждого `operationId`.

`npx tsc --noEmit` на Frontend проходит чисто — SDK интегрируется без правок tsconfig и без shim-типов.

---

## 4. Метрики спецификации

| Метрика | Значение |
|---------|---------:|
| OpenAPI version | 3.1.0 |
| Tool paths (`/rpc/*`) | 15 |
| Resource paths (`/resources/*`) | 4 |
| Resource template paths | 0 (на момент Cycle 4 templates встроены в `resources` через FastMCP API; см. ниже) |
| Prompt paths (`/prompts/*`) | 3 |
| **Всего paths** | **22** |
| Component schemas | 65 |
| Security schemes | 2 (`bearer`, `apiKey`) |
| YAML размер | 68 004 bytes |

> **Замечание по resource templates:** На момент Cycle 4 backend MCP-сервер регистрирует 4 «классических» resources и 0 resource templates через `await app.list_resource_templates()`. Resources с path-параметрами (`argus://findings/{scan_id}`, `argus://reports/{report_id}`) экспонируются через `list_resources`, поэтому попадают в спецификацию как обычные `GET /resources/*` paths. Если в Cycle 5+ команда переключит часть resources на template-API FastMCP, эмиттер автоматически их подхватит — `_build_resource_template_paths` уже реализован и протестирован на этой ветке кода.

---

## 5. Status TypeScript SDK

✅ **Сгенерирован локально** (Windows + Node 20 + npm 10).

`npm install` (13 новых packages) + `npm run sdk:generate` отработали за ~25 сек суммарно. `npm run sdk:check` (после `git add`) → exit 0, drift отсутствует. CI повторит ту же последовательность на Ubuntu — генератор выдаёт идентичный output между платформами (LF newlines fixed).

Все 75 файлов SDK закоммичены в репозиторий; `.gitignore` Frontend намеренно не маскирует `src/sdk/`, поэтому состояние reproducible.

---

## 6. Docstring gate — результаты

**Гейт:** `pytest tests/test_mcp_tools_have_docstrings.py` — **23/23 PASS**, ноль inline-фиксов.

| Категория | Зарегистрировано | Описаний ≥ 30 chars | Inline fixes |
|-----------|----------------:|---------------------:|-------------:|
| Tools | 15 | 15 | 0 |
| Resources | 4 | 4 | 0 |
| Resource templates | 0 | 0 | 0 |
| Prompts | 3 | 3 | 0 |
| **Итого** | **22** | **22** | **0** |

Дополнительный sanity-тест `test_mcp_surface_is_non_empty` страхует от регрессии «пустого» surface'а.

> **Важно:** Гейт проверяет поле `description` объекта MCP entity (то, что попадает в OpenAPI и SDK), а **не** Python `__doc__` callable'а. План использовал термин «docstring», но в FastMCP-контексте каноническим источником описания для downstream агентов и SDK является именно `description`. Существующий тест `tests/integration/mcp/test_e2e_smoke.py` уже опирался на ту же интерпретацию (assertion'ы `assert tool.description and len(tool.description) >= 30`), поэтому новый гейт сохраняет преемственность контракта.

---

## 7. Acceptance gates — verification

| # | Команда | Cwd | Результат |
|---|---------|-----|-----------|
| G1 | `python -m scripts.export_mcp_openapi --out ../docs/mcp-server-openapi.yaml` | `backend/` | ✅ wrote 68 004 bytes |
| G2 | `python -m scripts.export_mcp_openapi --check` | `backend/` | ✅ in sync |
| G3 | `pytest tests/test_mcp_tools_have_docstrings.py -q` | `backend/` | ✅ 23 passed |
| G4 | `pytest tests/integration/mcp/test_openapi_export_stable.py -q` | `backend/` | ✅ 6 passed |
| G5 | `pytest tests/unit/mcp tests/integration/mcp -q` (regression) | `backend/` | ✅ no regressions (см. §8) |
| G6 | `ruff check src/mcp/openapi_emitter.py scripts/export_mcp_openapi.py tests/test_mcp_tools_have_docstrings.py tests/integration/mcp/test_openapi_export_stable.py` | `backend/` | ✅ clean |
| G7 | `ruff format --check ...` (те же файлы) | `backend/` | ✅ clean |
| G8 | `mypy --strict src/mcp/openapi_emitter.py scripts/export_mcp_openapi.py` | `backend/` | ✅ clean (см. §8.1) |
| G9 | `npm install` | `Frontend/` | ✅ 412 packages, codegen pinned 0.29.0 |
| G10 | `npm run sdk:generate` | `Frontend/` | ✅ 75 files generated |
| G11 | `npm run sdk:check` (после `git add`) | `Frontend/` | ✅ no drift |
| G12 | `npx tsc --noEmit -p tsconfig.json` | `Frontend/` | ✅ clean |
| G13 | YAML-валидность `.github/workflows/ci.yml` (mcp-openapi-drift job parsed) | repo root | ✅ 8 steps parsed correctly |

---

## 8. Out-of-scope follow-ups

### 8.1 Pre-existing CI workflow YAML quirk

Pre-existing job `test-no-docker` в `.github/workflows/ci.yml` использует unquoted plain-scalar `DATABASE_URL: sqlite+aiosqlite:///:memory:` (line 68). Парсер GitHub Actions (YAML 1.2) принимает это, но строгий PyYAML/ruamel.yaml парсит с ошибкой `mapping values are not allowed here` из-за двоеточия в значении.

Это **не моя regression** — я только изменил блок `mcp-openapi-drift` + `build.needs`. Все мои `DATABASE_URL` — quoted `"sqlite+aiosqlite:///:memory:"`. Если команда захочет нормализовать pre-existing блоки — это отдельная косметическая правка (не блокирующая ни для одного гейта, потому что GitHub Actions парсит файл корректно).

### 8.2 Resource templates surface

Backend MCP-сервер на момент Cycle 4 не использует FastMCP resource templates (`@mcp.resource_template`); все path-параметризованные resources зарегистрированы через `@mcp.resource("argus://x/{id}")`. Это **рабочий контракт**, эмиттер корректно их обрабатывает. Если в будущем потребуется явное разделение, эмиттер уже умеет — `_build_resource_template_paths` готов к продакшен-нагрузке.

### 8.3 OpenAPI summary vs description

Сейчас summary = (`title or name`), description = (`description or "(no description)"`). Дефолтное значение `(no description)` может проникнуть в SDK комментарии для tools без `description`, но docstring-гейт страхует от этого: ни один tool не пропустит CI с пустым description. Если в Cycle 5 захочется явный «empty-description» reject — поменять fallback на `raise RuntimeError(...)` в `_build_tool_paths`.

### 8.4 Auth scheme refinement

Спецификация декларирует два альтернативных security schemes (`bearer` и `apiKey`). Реальный backend поддерживает три варианта bearer'а: static token (`MCP_AUTH_TOKEN`), JWT (Authorization: Bearer JWT), HMAC-issued bearer (см. `backend/src/mcp/auth.py`). Все три заявлены через единый `bearerFormat: JWT`-маркер, что технически корректно для OpenAPI, но не отражает HMAC-вариант. Это можно уточнить в Cycle 5 через `oauth2 + scopes` security scheme — out of ARG-039 scope.

### 8.5 SDK BASE URL bootstrap

Сгенерированный TypeScript SDK даёт `OpenAPI` config-singleton с `BASE = ""` по умолчанию. Frontend integration potential: добавить тонкий wrapper `Frontend/src/lib/mcp-client.ts`, инициализирующий `OpenAPI.BASE` из `process.env.NEXT_PUBLIC_MCP_BASE_URL` и `OpenAPI.TOKEN` из auth-context'а. Это не входит в scope ARG-039 (генератор + drift-гейт) — wiring SDK in реальные UI-компоненты — отдельная задача (ARG-04x).

---

## 9. Sign-off

ARG-039 **закрыт**. Все 13 acceptance gates зелёные. Backend код tools / resources / prompts / signed manifests **не тронут**. CI-пайплайн получил три новых барьера (drift спецификации, drift SDK, docstring quality), все три блокирующие. Документация и changelog обновлены.

**One-sentence summary:** MCP OpenAPI 3.1 spec exported (22 paths, 65 schemas, 68 KB), TypeScript SDK pipeline wired (75 files via openapi-typescript-codegen@0.29.0), docstring gate enforces ≥30 chars across all 22 MCP entities, three CI gates (`mcp-openapi-drift`) block silent drift.
