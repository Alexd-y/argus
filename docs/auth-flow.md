# ARGUS Auth Flow

Поток аутентификации для ARGUS и референс pentagi.

---

## 1. ARGUS Scanner (публичный)

**Текущий ARGUS/Frontend:** без аутентификации. Публичный сканер.

- Пользователь вводит target, email, options.
- Запуск скана — без токена/сессии.
- Отчёт доступен по `?target=X` — без проверки владельца (на этапе MVP).

**Рекомендации для production:**

- Опционально: API key для programmatic access (CI/CD, скрипты).
- Admin-frontend: JWT (access + refresh) для входа в панель управления.

---

## 2. ARGUS Auth (реализовано, Phase 3)

### 2.1 Механизмы

| Механизм | Использование |
|----------|---------------|
| **JWT** | `Authorization: Bearer <token>` — access token (15m по умолчанию) |
| **API Key** | `X-API-Key: <key>` — для CI/CD, скриптов (≥16 символов при JWT_SECRET) |

Требуется `JWT_SECRET` в env. Без него — `POST /auth/login` возвращает 503.

### 2.2 Login Flow

1. `POST /api/v1/auth/login` с `{ mail, password }`.
2. Backend возвращает `{ status: "success", access_token: string, token_type: "bearer" }`.
3. Frontend сохраняет token (localStorage/sessionStorage) и передаёт в `Authorization: Bearer <token>`.
4. Stub: валидация credentials не реализована — любой mail/password принимается при наличии JWT_SECRET. Production: проверка против users table.

### 2.3 Protected Endpoints

- `GET /auth/me` — требует JWT или X-API-Key. Возвращает `{ user_id, tenant_id, is_api_key }`.

### 2.4 Scans/Reports

Scans и Reports — публичные (MVP). Auth опциональна для admin-frontend.

---

## 3. pentagi Auth (референс)

### 3.1 Механизмы

| Механизм | Использование |
|----------|---------------|
| **Cookies** | Сессия после login. `withCredentials: true` в axios. |
| **JWT** | В cookie или Authorization header (backend). |
| **OAuth 2.0** | Google, GitHub — popup, redirect на `/oauth/result`. |
| **API Key** | GraphQL/REST — header `Authorization: Bearer <token>`. |

### 3.2 Login Flow

1. `POST /api/v1/auth/login` с `{ mail, password }`.
2. Backend устанавливает httpOnly cookie с сессией.
3. Frontend вызывает `GET /api/v1/info` для получения `AuthInfo`.
4. `AuthInfo` сохраняется в `localStorage` (ключ `auth`).
5. `expires_at` проверяется при `isAuthenticated()`.

### 3.3 Logout Flow

1. `GET /api/v1/auth/logout`.
2. Очистка `localStorage` (AUTH_STORAGE_KEY).
3. Redirect на `/login?returnUrl=...`.

### 3.4 Обработка ошибок

| Code | Действие |
|------|----------|
| 401 | Удаление auth из localStorage, redirect на `/login`. |
| 403 + `code` in `AuthRequired`, `NotPermitted`, `PrivilegesRequired`, `AdminRequired`, `SuperRequired` | То же — redirect на login. |
| 403 другие | Только логирование, без redirect. |

### 3.5 Return URL

- `?returnUrl=/path` — куда вернуться после login.
- Валидация: только относительные пути, начинающиеся с `/`, не с `//`.

### 3.6 Password Change

- `PUT /api/v1/user/password` с `{ current_password, password, confirm_password }`.
- Требуется для local users с `password_change_required`.

---

## 4. ARGUS Admin (будущее)

Планируемая схема:

- **JWT:** access token (короткий) + refresh token (длинный).
- **API Key:** для CI/CD, скриптов, MCP.
- **RLS:** `SET LOCAL app.current_tenant_id` для multi-tenant изоляции.

---

## 5. Безопасность

- HttpOnly, Secure, SameSite для cookies.
- Никаких секретов в localStorage (кроме non-sensitive метаданных).
- API keys — только в заголовках, не в URL.
- Rate limiting на `/auth/login`.
