# Backend vs frontend contract — расхождения

**Источник контракта:** `docs/frontend-api-contract-generated.md`  
**Дата:** 2026-03-20

## Итог

**none** — актуальных расхождений с контрактом нет (ниже — что было выровнено).

## Статус после синхронизации

| Область | Было | Стало |
|---------|------|--------|
| Ошибки 4xx/5xx на `/api/v1/scans*`, `/api/v1/reports*` | Часто `{"detail": ...}` (FastAPI по умолчанию) | Единый JSON `{"error": string, "code"?: string, "details"?: unknown}` |
| 500 на тех же путях | `{"detail": "..."}` | `{"error": "..."}` |
| `GET /scans/{id}` → `created_at` | `isoformat()` с `+00:00` | UTC с суффиксом `Z`, как в примере контракта |
| CORS | `allow_methods=["*"]`, `allow_headers=["*"]` | `GET,POST,OPTIONS`; заголовки `Content-Type`, `Authorization`; origins из `VERCEL_FRONTEND_URL` / `CORS_ORIGINS` + localhost |
| Инфра | Нет туннеля | Опциональный сервис `cloudflared` (profile `tunnel`) |

## Оставшиеся заметки (не блокеры)

1. **OpenAPI/Swagger** может всё ещё описывать стандартные схемы ошибок FastAPI (`detail`) для части ответов — нормативным для фронта остаётся контракт в `frontend-api-contract-generated.md` и фактическое поведение эндпоинтов.
2. **`reportFormat: "xml"`** на фронте в типах vs `download` только `pdf|html|json|csv` — вне объёма бэкенд-правки; при необходимости согласовать отдельно.
