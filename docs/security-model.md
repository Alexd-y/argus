# ARGUS Security Model

**Version:** 0.1  
**Source:** Backend implementation (auth, RLS, guardrails, exception handlers, storage)

---

## 1. Overview

Модель безопасности ARGUS охватывает: мультитенантную изоляцию (RLS), аутентификацию, защиту от command injection, отсутствие утечки traceback, защиту от path traversal и валидацию целей инструментов.

---

## 2. Row Level Security (RLS)

### 2.1 Таблицы с RLS

Политика `tenant_isolation` включена для таблиц:

- `subscriptions`, `scan_timeline`, `assets`, `tool_runs`, `evidence`
- `policies`, `usage_metering`, `provider_configs`, `provider_health`
- `phase_inputs`, `phase_outputs`, `report_objects`, `screenshots`

### 2.2 Политика

```sql
CREATE POLICY tenant_isolation ON "<table>"
USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
```

### 2.3 Установка tenant в сессии

Перед операциями с БД вызывается:

```python
await set_session_tenant(session, tenant_id)
# SET LOCAL app.current_tenant_id = :tid
```

**Источник tenant_id:**

- `X-Tenant-ID` header (если передан)
- `DEFAULT_TENANT_ID` из env (MVP без auth)

При наличии JWT — tenant берётся из токена.

---

## 3. Аутентификация

### 3.1 JWT

- **Алгоритм:** `HS256` (из `JWT_ALGORITHM`)
- **Срок жизни:** 15 минут (из `JWT_EXPIRY`, например `15m`)
- **Поля:** `sub` (user_id), `tenant_id`, `iat`, `exp`, `type: "access"`

**Зависимости:** `get_optional_auth`, `get_required_auth` — Bearer token в заголовке `Authorization`.

### 3.2 API Key

- **Заголовок:** `X-API-Key`
- **Валидация (MVP):** если задан `JWT_SECRET` и длина ключа ≥ 16 — принимается
- **Контекст:** `AuthContext(user_id="api-key", tenant_id="default", is_api_key=True)`

В Phase 3+ — проверка по БД или внешнему хранилищу.

### 3.3 Эндпоинты

- **Optional auth:** сканы, отчёты — работают с и без аутентификации (MVP)
- **Required auth:** защищённые эндпоинты используют `get_required_auth` → 401 при отсутствии токена

---

## 4. Защита от Command Injection

### 4.1 Allowlist инструментов

`POST /tools/execute` — только разрешённые инструменты:

- `nmap`, `nuclei`, `nikto`, `gobuster`, `sqlmap`

Неразрешённая команда → 400 с сообщением о списке допустимых.

### 4.2 Выполнение без shell

```python
subprocess.run(parts, shell=False, ...)
```

Команда собирается из списка аргументов, без интерпретации shell.

### 4.3 Экранирование аргументов

При сборке команд используется `shlex.quote(p)` для каждого аргумента.

### 4.4 Парсинг команды

- `parse_execute_command(command)` → `(tool_name, target)`
- `extract_tool_name` — первый токен после `shlex.split`
- Проверка `tool_name in ALLOWED_TOOLS` до выполнения

---

## 5. Отсутствие утечки traceback

### 5.1 Глобальный обработчик исключений

```python
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled exception", extra={"path": ..., "method": ...})
    return JSONResponse(status_code=500, content={"detail": GENERIC_ERROR_MESSAGE})
```

**Сообщение пользователю:** `"An unexpected error occurred. Please try again later."`

Детали ошибки и stack trace только в логах, не в ответе.

### 5.2 Регистрация

```python
app.add_exception_handler(Exception, generic_exception_handler)
```

---

## 6. Защита от Path Traversal

### 6.1 S3/MinIO object keys

**Запрещённые паттерны в компонентах пути:**

- `/`, `\`, `..`, пустая строка

**Функция:** `_sanitize_path_component(value, name)` — при нарушении выбрасывает `ValueError`.

**Структура ключа:** `{tenant_id}/{scan_id}/{object_type}/{filename}`

Все четыре компонента проходят санитизацию перед формированием ключа.

### 6.2 Полный object key

`_validate_object_key(object_key)` — проверка на `..`, `\`, ведущий `/`, пустоту.

### 6.3 Типы объектов

- `raw`, `screenshots`, `evidence`, `reports`, `attachments`

---

## 7. Валидация целей инструментов

### 7.1 IPValidator

Блокируются:

- Приватные сети: `10.x`, `172.16–31.x`, `192.168.x`
- Loopback: `127.x`
- Поддержка URL — извлечение host через `urlparse`

### 7.2 DomainValidator

Блокируются:

- `localhost`, `localhost.localdomain`
- домены `.local`
- `127.x.x.x`, `::1`, `0.0.0.0`

### 7.3 Интеграция

`validate_target_for_tool(target, tool_name)` вызывается перед выполнением:

- Поддержка нескольких целей (запятая/пробел)
- При блокировке → `{"allowed": False, "reason": "..."}`

---

## 8. Security Headers

Middleware добавляет заголовки (OWASP-рекомендации):

| Header | Значение |
|-------|----------|
| X-Content-Type-Options | nosniff |
| X-Frame-Options | DENY |
| X-XSS-Protection | 1; mode=block |
| Referrer-Policy | strict-origin-when-cross-origin |
| Permissions-Policy | geolocation=(), microphone=(), camera=() |

---

## 9. Rate Limiting

`POST /tools/execute` — rate limiter:

- In-memory при отсутствии Redis
- 30 запросов / 60 секунд на IP
- При превышении → 429

---

## 10. Логирование

- Структурированные логи (JSON)
- Пароли, токены, персональные данные не логируются
- `logger.exception` для необработанных исключений — только внутренний контекст
