# ARGUS SSE vs Polling

Real-time обновления прогресса сканирования.

---

## 1. SSE (Server-Sent Events)

### Endpoint

```
GET /api/v1/scans/:id/events
```

- `Accept: text/event-stream`
- Долгая HTTP-соединение, сервер шлёт события.

### Формат событий

Каждое событие — строка в формате SSE:

```
event: <event_type>
data: <JSON payload>

```

### Event Types

| event | Описание | data |
|-------|----------|------|
| `init` | Нет событий — скан только начат | `{ event: "init", phase: "init", progress: 0 }` |
| `phase_start` | Начало фазы | `{ phase: string, message?: string }` |
| `phase_complete` | Завершение фазы | `{ phase: string, progress?: number }` — **фильтруется** (ARGUS-010): только counts, без payloads/findings/evidence |
| `tool_run` | Запуск инструмента | `{ tool: string, input?: object }` |
| `finding` | Обнаружена уязвимость | `{ severity: string, title: string, ... }` |
| `progress` | Общий прогресс | `{ progress: number, message?: string }` |
| `complete` | Скан завершён | `{ status: string }` |
| `error` | Ошибка | `{ error: string, code?: string }` — без внутренних деталей |

### Пример payload (data)

```json
{
  "event": "phase_start",
  "phase": "recon",
  "progress": 10,
  "message": "Port scanning",
  "data": { "ports": "80,443" }
}
```

### Клиент (Frontend)

```ts
const eventSource = new EventSource(`${apiUrl}/scans/${scanId}/events`);
eventSource.onmessage = (e) => {
  const payload = JSON.parse(e.data);
  // update UI: payload.phase, payload.progress, payload.message
};
eventSource.onerror = () => eventSource.close();
```

---

## 2. Polling Fallback

Если SSE недоступен (прокси, старые браузеры):

```
GET /api/v1/scans/:id
```

- Интервал: 2–5 секунд.
- Response: `{ id, status, progress, phase, target, created_at }`.

### Когда использовать

- SSE не поддерживается или обрывается.
- Нет необходимости в мгновенных обновлениях.

---

## 3. pentagi Reference (GraphQL Subscriptions)

pentagi использует **WebSocket** (GraphQL subscriptions), не SSE:

- URL: `ws(s)://host/api/v1/graphql`
- Подписки: `terminalLogAdded`, `messageLogUpdated`, `assistantLogUpdated`, и др.
- Стриминг: `assistantLogUpdated` с `appendPart: true` для накопления частей.

Для ARGUS выбран SSE как более простой вариант для одностороннего потока событий скана.

---

## 4. Реализация (Phase 10)

- **Источник событий:** ScanEvent в PostgreSQL. Backend читает события по `scan_id`, отдаёт через `EventSourceResponse`.
- **Фильтрация phase_complete (ARGUS-010):** В `data` не передаются findings, exploits, evidence, credentials. Только агрегаты: `assets_count`, `findings_count`, `report_ready` и т.п.
- **Ошибки:** При 404 или exception — `event: error` с generic message, без stack trace.

## 5. Рекомендации

- SSE — основной канал для real-time progress.
- Polling — запасной вариант при ошибках SSE.
- Таймаут SSE: 300 сек (keepalive/comments при необходимости).
- При 401/403 — закрыть EventSource, показать сообщение об авторизации.
