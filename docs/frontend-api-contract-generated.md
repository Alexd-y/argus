# ARGUS Frontend — сгенерированный контракт API (FEAPI-001…005)

**Область:** только код в `ARGUS/Frontend` (анализ без изменений).  
**Дата анализа:** 2026-03-20.

---

## 1. Стек и конфигурация (FEAPI-001)

| Компонент | Значение |
|-----------|----------|
| **UI** | React 19.2.3 |
| **Фреймворк** | Next.js 16.1.6 (App Router: `src/app/`) |
| **HTTP-клиент** | нативный `fetch` (axios / ky / ofetch **не используются**) |
| **Стили** | Tailwind CSS 4 |
| **Тесты** | Vitest 3 |
| **База API** | `NEXT_PUBLIC_API_URL`, по умолчанию `/api/v1` (`src/lib/api.ts`) |

### Файлы конфигурации

| Файл | Назначение |
|------|------------|
| `Frontend/package.json` | скрипты: `dev` на `127.0.0.1:5000`, зависимости |
| `Frontend/next.config.ts` | **rewrites:** `/api/v1/:path*` → `${NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:8000"}/api/v1/:path*` |
| `Frontend/.env.example` | `NEXT_PUBLIC_API_URL=/api/v1`, опционально `NEXT_PUBLIC_BACKEND_URL` |

### Риск: несогласованность портов бэкенда

- В `next.config.ts` дефолт бэкенда: **`http://localhost:8000`**.
- В `.env.example` в комментарии указан пример **`http://localhost:5000`** (совпадает с портом `next dev`, но не с дефолтом rewrite).

Итог для разработчика: без `NEXT_PUBLIC_BACKEND_URL` прокси целится в **8000**; комментарий в `.env.example` может ввести в заблуждение.

### Структура слоя API

Папки `src/api/` и отдельного `services/` **нет**. Вызовы сосредоточены в:

- `src/lib/api.ts` — база URL, `apiFetch`, обработка ошибок
- `src/lib/scans.ts` — сканы + SSE
- `src/lib/reports.ts` — отчёты и URL скачивания

Хуки: `src/hooks/useScanProgress.ts`, `src/hooks/useReport.ts`.

---

## 2. Таблица контрактов: Endpoint | Method | Body | Response | Headers | Auth | Real-time

Все пути ниже относительно **`{API_BASE}`** = значение `NEXT_PUBLIC_API_URL` (нормализовано без завершающего `/`), по умолчанию **`/api/v1`**.

| Endpoint | Method | Request body / query | Response (ожидание фронта) | Заголовки (исходящие) | Auth | SSE / Polling |
|----------|--------|----------------------|----------------------------|------------------------|------|----------------|
| `{API_BASE}/scans` | POST | JSON: `CreateScanRequest` — `{ target, email, options }` (`options` = `ScanOptions`, см. §3) | JSON: `CreateScanResponse` — `{ scan_id, status, message? }` | Всегда: `Content-Type: application/json` (в т.ч. для GET в `apiFetch`) | **Нет:** `Authorization`, cookies, localStorage для API не задаются | — |
| `{API_BASE}/scans/{id}` | GET | — | JSON: `ScanStatus` — `{ id, status, progress, phase, target, created_at }` | то же | Нет | **Polling:** каждые **3000 ms** (`POLL_INTERVAL_MS` в `useScanProgress`), только если SSE падает (`onerror` → `startPolling`) |
| `{API_BASE}/scans/{id}/events` | GET (SSE) | — | Поток `text/event-stream`; `message`: JSON `SSEEventPayload` — `{ event?, phase?, progress?, message?, data? }` | EventSource (браузер): без кастомных заголовков | Нет (стандартный EventSource не добавляет Bearer) | **SSE:** основной канал прогресса; при ошибке соединения — fallback на polling |
| `{API_BASE}/reports?target={url}` | GET | Query `target` (полный URL цели, кодируется через `URLSearchParams`) | JSON: **массив** `Report[]`; фронт берёт **первый** элемент | `Content-Type: application/json` | Нет | — |
| `{API_BASE}/reports/{id}` | GET | — | JSON: объект `Report` | то же | Нет | — |
| `{API_BASE}/reports/{id}/download?format={fmt}` | GET | `format`: `pdf` \| `html` \| `json` \| `csv` (дефолт в коде `pdf`) | Бинарный поток / файл (навигация браузера) | **Не через `apiFetch`:** обычный переход по ссылке `<a href>` | Нет явных заголовков; разделяет cookies с origin | — |

### Эндпоинты бэкенда, которые **не вызываются** этим фронтендом

Из `docs/api-contracts.md` и OpenAPI бэкенда могут существовать `health`, `metrics`, `auth/*`, `tools/*` и др. — в просканированном коде `Frontend/src` **нет** обращений к ним.

---

## 3. Примеры запросов / ответов

### POST `/api/v1/scans`

**Пример тела** (упрощённо, поле `options` совпадает с формой на главной странице):

```json
{
  "target": "https://example.com",
  "email": "user@example.com",
  "options": {
    "scanType": "quick",
    "reportFormat": "pdf",
    "rateLimit": "normal",
    "ports": "80,443,8080,8443",
    "followRedirects": true,
    "vulnerabilities": {
      "xss": true,
      "sqli": true,
      "csrf": true,
      "ssrf": false,
      "lfi": false,
      "rce": false
    },
    "authentication": {
      "enabled": false,
      "type": "basic",
      "username": "",
      "password": "",
      "token": ""
    },
    "scope": {
      "maxDepth": 3,
      "includeSubs": false,
      "excludePatterns": ""
    },
    "advanced": {
      "timeout": 30,
      "userAgent": "chrome",
      "proxy": "",
      "customHeaders": ""
    }
  }
}
```

**Пример ответа:**

```json
{
  "scan_id": "scan-123",
  "status": "queued",
  "message": "Scan created"
}
```

### GET `/api/v1/scans/{scan_id}`

**Пример ответа:**

```json
{
  "id": "scan-123",
  "status": "running",
  "progress": 50,
  "phase": "scanning",
  "target": "https://example.com",
  "created_at": "2025-03-08T12:00:00Z"
}
```

**Семантика статуса на фронте:** при `status === "completed"` → UI `complete`; при `"failed"` → `error` с текстом «Scan failed». Polling останавливается в обоих случаях.

### SSE `/api/v1/scans/{scan_id}/events`

Абсолютный URL: `getApiBaseUrl() + "/scans/" + encodeURIComponent(scanId) + "/events"`.

**Пример полезной нагрузки в `event.data` (JSON):**

```json
{
  "event": "progress",
  "phase": "Port scanning",
  "progress": 40,
  "message": "Optional status text"
}
```

События, которые обрабатывает UI логикой:

- `event === "complete"` → прогресс 100%, статус завершения.
- `event === "error"` → ошибка; текст из `payload.error` если есть (через `getSafeErrorMessage`).

### GET `/api/v1/reports?target=...`

**Пример ответа:** массив из ≥1 отчёта; при пустом массиве фронт выбрасывает `Error("Report not found")` (не полагается на HTTP 404).

### GET `/api/v1/reports/{report_id}`

**Пример ответа** (сокращённо):

```json
{
  "report_id": "rpt-456",
  "target": "https://example.com",
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 5,
    "technologies": ["nginx", "React"],
    "sslIssues": 0,
    "headerIssues": 1,
    "leaksFound": false
  },
  "findings": [],
  "technologies": ["nginx", "React"]
}
```

Тип `Report` допускает индексную сигнатуру `[key: string]: unknown` — бэкенд может добавлять поля.

---

## 4. Реальное время (FEAPI-004)

| Механизм | Где | Endpoint / интервал |
|----------|-----|---------------------|
| **Server-Sent Events** | `subscribeScanEvents` (`src/lib/scans.ts`) | `GET {API_BASE}/scans/{id}/events` |
| **Polling** | `useScanProgress` (`src/hooks/useScanProgress.ts`) | `GET {API_BASE}/scans/{id}` каждые **3000 ms** |
| **WebSocket** | — | **не используется** |
| **setInterval (не API)** | `CompleteRedirect` в `src/app/page.tsx` | **1000 ms** — только обратный отсчёт редиректа на `/report?target=...`, **без HTTP** |

Поведение: сначала открывается SSE; при `onerror` SSE закрывается и запускается polling. Ошибки polling **глотаются** (цикл продолжается), пока не придёт терминальный статус скана.

---

## 5. Ошибки и статусы (FEAPI-005)

### Обработка в `apiFetch` (`src/lib/api.ts`)

- При `!res.ok`: попытка распарсить тело как JSON; ожидаемая форма **`{ error: string, code?: string, details?: unknown }`** (`ApiError`).
- Сообщение исключения: `body.error` или строка **`Request failed ({status})`**, если JSON невалиден или не JSON.
- Успешный ответ: если `Content-Type` содержит `application/json` → `res.json()`, иначе **`res.text()`**, приведённый к `T` (для текущих вызовов используется только JSON).

### Ожидаемые статусы (из тестов и логики)

| Сценарий | HTTP | Тело (пример) | Поведение фронта |
|----------|------|---------------|------------------|
| Ошибка валидации скана | 400 | `{ "error": "Invalid target URL" }` | `throw`, сообщение пользователю через `getSafeErrorMessage` |
| Скан не найден | 404 | `{ "error": "Scan not found" }` | throw |
| Отчёт не найден (HTTP) | 404 | `{ "error": "Report not found" }` | throw |
| Пустой список отчётов | 200 | `[]` | throw `Report not found` (клиентская логика) |
| Не-JSON при ошибке | 4xx/5xx | text/plain | `Request failed (500)` и т.д. |

Документ `docs/api-contracts.md` дополнительно перечисляет 401/403/429 и т.д. — фронт **не различает** их отдельно, только текст/фолбэк.

### `getSafeErrorMessage`

Отфильтровывает сообщения с подстроками `stack` или `at ` (защита от утечки стека). Поддерживает объекты с полем `error: string`.

---

## 6. Аутентификация (FEAPI-005)

| Механизм | Использование в Frontend |
|----------|---------------------------|
| **localStorage / sessionStorage** | **Нет** обращений в `src/` |
| **Authorization: Bearer** | **Не отправляется** в `apiFetch` / EventSource |
| **Refresh token** | **Нет** |
| **Cookies** | Не задаются явно; ссылки `download` идут same-origin → браузер пришлёт cookies, если они есть у домена |
| **Учётные данные цели** | Поля `options.authentication` в **теле POST /scans** (basic/bearer/cookie для **сканируемого приложения**, не для ARGUS API) |

UI на главной странице содержит подсказки про Bearer для **настроек скана** — это не заголовок к бэкенду ARGUS.

---

## 7. Неоднозначности и риски

1. **`GET` с заголовком `Content-Type: application/json`** — нестандартно; часть прокси/серверов может вести себя иначе (маловероятно, но заметно при аудите).
2. **`reportFormat: "xml"`** в `ScanOptions` (`types.ts`) vs **`download`** только `pdf|html|json|csv` — нет `xml` в `getReportDownloadUrl`; согласование с бэкендом неочевидно.
3. **SSE без заголовка Authorization** — если API станет защищённым, EventSource без cookie-сессии на том же домене или query-token не подставит Bearer.
4. **Два источника прогресса (SSE + polling)** — при расхождении полей возможны краткие рассинхроны; polling не очищается при успешном SSE до завершения скана (интервал останавливается только при `completed`/`failed`).
5. **Ссылка на скачивание** не использует `apiFetch` — ошибки 4xx/5xx показываются браузером, не через `ApiError`.
6. **Контракт `GET /reports`:** фронт ожидает **массив**; если бэкенд вернёт один объект, сломается `getReportByTarget`.

---

## 8. Ссылка на OpenAPI бэкенда

В репозитории бэкенда (`ARGUS/backend/main.py`) задано:

- **OpenAPI JSON:** `/api/v1/openapi.json`
- **Swagger UI:** `/api/v1/docs`

Через прокси Next.js (при `NEXT_PUBLIC_API_URL=/api/v1` и работающем rewrite):

- `http://127.0.0.1:5000/api/v1/openapi.json` (если фронт на 5000 и rewrite на бэкенд настроен)

Напрямую к бэкенду (как в `next.config.ts` по умолчанию):

- `http://localhost:8000/api/v1/openapi.json`

Нормативный текст контрактов в репозитории: **`docs/api-contracts.md`**.

---

## 9. Просканированные файлы

Исходный код и конфиги (без `node_modules`, без `.next`):

| Путь |
|------|
| `ARGUS/Frontend/package.json` |
| `ARGUS/Frontend/next.config.ts` |
| `ARGUS/Frontend/.env.example` |
| `ARGUS/Frontend/src/app/layout.tsx` |
| `ARGUS/Frontend/src/app/page.tsx` |
| `ARGUS/Frontend/src/app/report/page.tsx` |
| `ARGUS/Frontend/src/lib/api.ts` |
| `ARGUS/Frontend/src/lib/scans.ts` |
| `ARGUS/Frontend/src/lib/reports.ts` |
| `ARGUS/Frontend/src/lib/types.ts` |
| `ARGUS/Frontend/src/hooks/useScanProgress.ts` |
| `ARGUS/Frontend/src/hooks/useReport.ts` |
| `ARGUS/Frontend/src/lib/api.test.ts` |
| `ARGUS/Frontend/src/lib/scans.test.ts` |
| `ARGUS/Frontend/src/lib/reports.test.ts` |

Дополнительно для перекрёстной проверки контрактов (не часть Frontend, но использованы при анализе):

- `ARGUS/docs/api-contracts.md`
- `ARGUS/backend/main.py`

---

## Краткая сводка

- **Стек:** Next.js 16 + React 19, **только `fetch`**, база **`/api/v1`**, прокси через **rewrites** на бэкенд (дефолт **:8000**).
- **API в коде:** `POST/GET` scans, **SSE** events, `GET` reports (список по `target` + по `id`), **GET** download по ссылке.
- **Реальное время:** **SSE** к `/scans/{id}/events`, резерв **polling 3 с** к `/scans/{id}`; WebSocket нет.
- **Ошибки:** JSON **`{ error, code?, details? }`** или фолбэк по статусу; UI санитизирует сообщения.
- **Auth к ARGUS:** не реализован (ни Bearer, ни storage); опции **authentication** в теле скана относятся к целевому сайту.
- **OpenAPI:** `/api/v1/openapi.json` на бэкенде; интерактивно `/api/v1/docs`.
