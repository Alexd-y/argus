# Plan: ARGUS v5 follow-up 3 — MCP расширение, CORS, тесты

**Создано:** 2026-04-04  
**Оркестрация:** `orch-argus-v5-followup-3`  
**Спецификация:** `ARGUS/argus_v5_followup_3_cursor_prompt_1.md`  
**Статус:** готов к выполнению

## Цель

Расширить MCP (`mcp-server/argus_mcp.py`): `ArgusClient`, явные `@mcp.tool()` до `_register_kali_tools`, конфиг Cursor, правило именования, CORS в backend, смоук-тесты. **Не полагаться слепо на примеры URL в промпте** — сверять с `backend/src/api/routers/`.

## Зависимости задач

```
T01 ──► T02 ──► T03
           └──► T04

T05 (независимо)

T01 ──► T07
T02 ──► T06

T03,T04,T05,T06,T07 ──► T08
```

## Задачи

| ID | Задача | Приоритет | Сложность |
|----|--------|-----------|-----------|
| **T01** | Проверить маршруты в `backend/src/api/routers/` и расширить `ArgusClient` в `ARGUS/mcp-server/argus_mcp.py` (recon, threat modeling, VA, exploitation, reports download, admin — включая недостающие admin POST/PATCH по спецификации 11 маршрутов) | Critical | Complex |
| **T02** | Зарегистрировать соответствующие `@mcp.tool()` **перед** вызовом `_register_kali_tools` в `setup_mcp_server()` | Critical | Complex |
| **T03** | Обновить `ARGUS/argus-mcp.json`: `alwaysAllow` для read-only из Block 2 + дополнить `description` | High | Simple |
| **T04** | Обновить `d:\Developer\Pentest_test\.cursor\rules\argus-mcp.md` — секция Tool naming из Block 3 | Medium | Simple |
| **T05** | `ARGUS/backend/main.py`: `allow_methods` добавить `PUT`, `PATCH`, `DELETE` | High | Simple |
| **T06** | Добавить/обновить `ARGUS/backend/tests/test_mcp_tools.py` по Block 5; путь к `argus_mcp.py` — относительно расположения тестов (при необходимости `Path(__file__).resolve().parents[...]`) | High | Moderate |
| **T07** | Добавить `ARGUS/mcp-server/tests/test_argus_client_methods.py` по Block 5; поправить импорт (`argus_mcp` / пакет) под фактический layout | High | Moderate |
| **T08** | Прогон: `ruff` и `pytest` для затронутых частей (из промпта: из каталога backend — учесть реальные пути проекта) | Critical | Simple |

## Критичные замечания по маршрутам (T01) — сверка с кодом

Примеры в промпте **частично устарели** относительно текущих роутеров:

1. **Targets:** создание и список — `POST/GET /recon/engagements/{engagement_id}/targets`, не `POST /recon/targets` с телом `engagement_id`. Деталь: `GET /recon/targets/{target_id}` (и есть `DELETE`).
2. **Jobs:** создание и список — под `/recon/engagements/{engagement_id}/jobs`; `GET /recon/jobs/{job_id}`, `POST /recon/jobs/{job_id}/cancel`.
3. **Artifacts:** список — `GET /recon/engagements/{engagement_id}/artifacts` (query `artifact_type`), не глобальный `GET /recon/artifacts` с `engagement_id` в query.
4. **Engagements list:** query-параметры в коде — `status`, `offset`, `limit` (не `target` как в сниппете промпта).
5. **Threat modeling / VA:** run-based API под `/recon/engagements/{engagement_id}/threat-modeling/...` и `.../vulnerability-analysis/...` (`runs`, `trigger`, `execute`, readiness, скачивание артефактов и т.д.) — **не** пути вида `/recon/threat-modeling/{id}/start|prepare|run` из таблицы в начале промпта. MCP-обёртки должны вызывать **фактические** endpoint-ы или тонкие адаптеры поверх них.
6. **Exploitation:** старт — `POST .../recon/engagements/{engagement_id}/exploitation/run`; статус/результаты/approvals — под тем же префиксом `.../exploitation/`; approve/reject — `.../exploitation/approvals/{approval_id}/approve|reject` (идентификатор — approval, не «candidate» в path). Сниппет с `/recon/exploitation/{id}/approve/{candidate_id}` **не совпадает** с `exploitation.py`.
7. **Admin:** префикс роутера `/admin` + монтирование `/api/v1` → клиент: `/api/v1/admin/tenants`, `/api/v1/admin/health/dashboard`, и т.д. Для полного покрытия 11 маршрутов — добавить методы клиента/MCP для `POST /tenants`, `GET /users`, `subscriptions`, `providers`, `PATCH /providers/{id}`, `policies`, и т.д., если их ещё нет.

## Acceptance criteria (итог)

- Все новые вызовы клиента соответствуют реальным путям и HTTP-методам роутеров.
- Новые `@mcp.tool()` зарегистрированы до `_register_kali_tools`.
- `argus-mcp.json` и `argus-mcp.md` согласованы с именами инструментов.
- CORS включает PUT, PATCH, DELETE.
- Тесты из Block 5 проходят; порог `@mcp.tool()` ≥ 100 (или скорректировать порог, если после выравнивания с API число инструментов иное — зафиксировать в PR).

## Ссылки на файлы

- `ARGUS/mcp-server/argus_mcp.py`
- `ARGUS/argus-mcp.json`
- `d:\Developer\Pentest_test\.cursor\rules\argus-mcp.md`
- `ARGUS/backend/main.py`
- `ARGUS/backend/src/api/routers/recon/*.py`, `admin.py`
- `ARGUS/backend/tests/test_mcp_tools.py`
- `ARGUS/mcp-server/tests/test_argus_client_methods.py`

## Прогресс (обновляет оркестратор)

- ⏳ T01 — Verify routes + ArgusClient
- ⏳ T02 — MCP tools registration
- ⏳ T03 — argus-mcp.json
- ⏳ T04 — cursor rule
- ⏳ T05 — CORS
- ⏳ T06 — backend MCP tool smoke tests
- ⏳ T07 — ArgusClient method tests
- ⏳ T08 — ruff/pytest gate
