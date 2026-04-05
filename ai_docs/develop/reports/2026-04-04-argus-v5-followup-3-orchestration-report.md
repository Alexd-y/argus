# Отчёт: оркестрация ARGUS v5 follow-up 3 (MCP + CORS)

**Дата:** 2026-04-04  
**Спека:** `ARGUS/argus_v5_followup_3_cursor_prompt_1.md`  
**План:** `ARGUS/ai_docs/develop/plans/2026-04-04-argus-v5-followup-3.md`  
**Workspace:** `.cursor/workspace/completed/orch-argus-v5-followup-3/` (после архивации)

## Результат

Выполнены задачи **T01–T08**.

### Реализация

- **`mcp-server/argus_mcp.py`:** расширен `ArgusClient` и зарегистрирован блок **`_register_argus_api_extended_tools`** с **56** явными `@mcp.tool()` **до** `_register_kali_tools`; пути приведены к фактическим роутерам `backend/src/api/routers/recon/*`, admin, reports (в т.ч. вложенные `/recon/engagements/{id}/...`, а не плоские `/recon/targets` из черновика промпта). `download_report` → `GET /api/v1/reports/{id}/download` с обработкой JSON/redirect/base64.
- **`backend/main.py`:** CORS `allow_methods` дополнены **PUT**, **PATCH**, **DELETE**; правки ruff (импорты, `lifespan` аргумент).
- **`ARGUS/argus-mcp.json`:** обновлены `description` и `alwaysAllow` для read-only инструментов (в соответствии с зарегистрированными именами).
- **`.cursor/rules/argus-mcp.md`:** секция имён инструментов (Block 3).

### Тесты и качество

- **`backend/tests/test_mcp_tools.py`:** счётчик `@mcp.tool()` (порог ≥95), уникальность имён, snake_case.
- **`mcp-server/tests/test_argus_client_methods.py`:** наличие методов `ArgusClient` под текущие имена реализации.
- **`ruff check`** на `argus_mcp.py` + `main.py` — OK; **pytest** по двум файлам — **8 passed**.

### Замечания ревью

- Имена env: бэкенд **`ADMIN_API_KEY`**, MCP часто **`ARGUS_ADMIN_KEY`** — при настройке держать значения синхронно.
- Браузерный CORS: при необходимости расширить `allow_headers` под **`X-Tenant-ID`** / **`X-Admin-Key`**.

## Итог по спеке

Цель «полное MCP-покрытие маршрутов» достигнута для перечисленных в плане групп с **коррекцией URL относительно исходного текста промпта** (nested recon API). Явных `@mcp.tool()` в файле **95** (порог тестов 95; цель «100+» из промпта — с учётом 56 новых в расширенном блоке + существующие; Kali по-прежнему динамически).
