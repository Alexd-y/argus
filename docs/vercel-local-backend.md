# Frontend на Vercel + backend на ноутбуке (без своего домена)

Браузер пользователя ходит на **Vercel**; API-запросы проксируются Next.js на **публичный URL**, который туннелирует трафик на **nginx/backend на вашем ПК**. Ноутбук и туннель должны быть **включены**, пока вы тестируете.

**Источник контракта:** `docs/frontend-api-contract-generated.md` — `NEXT_PUBLIC_BACKEND_URL`, rewrites `/api/v1/*`.

---

## 0. Шпаргалка команд (PowerShell, Windows)

Выполняй по порядку. **Порт nginx** возьми из `docker compose ps` у `argus-nginx` (`0.0.0.0:80->80` → туннель на **80**; если `8080:80` → на **8080**).

```powershell
# 0) Каталог проекта
cd D:\Developer\Pentest_test\ARGUS

# 1) Стек (nginx + backend + worker и т.д.)
docker compose -f infra/docker-compose.yml --profile tools up -d

# 2) Узнать порт nginx на хосте
docker compose -f infra/docker-compose.yml ps nginx
# Пример: 0.0.0.0:80->80/tcp  → PORT=80
# Пример: 0.0.0.0:8080->80/tcp → PORT=8080

# 3) Локальная проверка API (подставь свой PORT)
curl http://127.0.0.1:80/api/v1/health

# 4) В infra\.env: VERCEL_FRONTEND_URL=https://<твой-app>.vercel.app  (без / в конце)
#    Перезапуск backend после правки .env:
docker compose -f infra/docker-compose.yml up -d backend

# 5) Cloudflare Quick Tunnel (отдельное окно PowerShell; пока окно открыто — URL живой)
cloudflared tunnel --url http://127.0.0.1:80
# Скопируй из лога: https://xxxx.trycloudflare.com  (без пути)

# 5a) Или скрипт (ASCII-only, PS 5.1; порт из infra\.env NGINX_HTTP_PORT или 80; либо -Port)
# Вставляй только строку команды, без префикса "PS C:\...>"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-tunnel.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-tunnel.ps1 -Port 8080

# 6) Vercel Dashboard → Project → Settings → Environment Variables → Production:
#    NEXT_PUBLIC_BACKEND_URL = https://xxxx.trycloudflare.com
#    Затем: Deployments → ⋮ → Redeploy (без кеша — по желанию)

# 7) Проверка с телефона / другой сети (должен быть JSON/200, не connection refused):
#    https://xxxx.trycloudflare.com/api/v1/health
```

**Важно:** после смены `NEXT_PUBLIC_BACKEND_URL` без **Redeploy** Vercel может продолжать проксировать на старый URL (rewrite фиксируется при сборке).

---

## 1. Подготовка бэкенда на ноутбуке

1. Запустите стек (из каталога `ARGUS`):

   ```powershell
   cd D:\Developer\Pentest_test\ARGUS
   docker compose -f infra/docker-compose.yml up -d
   ```

2. Убедитесь, что **nginx** слушает порт на хосте. По умолчанию в `infra/docker-compose.yml`: `NGINX_HTTP_PORT` → **80**. На Windows порт 80 часто занят — задайте в `infra/.env`:

   ```env
   NGINX_HTTP_PORT=8080
   ```

   Перезапуск: `docker compose -f infra/docker-compose.yml up -d`.

3. Проверка локально: откройте `http://127.0.0.1:8080/api/v1/health` (или `:80`), должен быть ответ API.

4. **CORS** — в `infra/.env`:

   ```env
   VERCEL_FRONTEND_URL=https://argus-frontend-jade.vercel.app
   ```

   (подставьте свой URL Vercel, без `/` в конце). Перезапустите контейнер `backend` / весь compose.

---

## 2. Способ A — Cloudflare Quick Tunnel (бесплатно, без домена в аккаунте)

Даёт URL вида `https://<случайно>.trycloudflare.com` на время работы процесса.

### Установка `cloudflared` (Windows)

- Скачайте с [Cloudflare — Downloads](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) или через пакетный менеджер.

### Скрипт из репозитория

Из корня `ARGUS` (нужен `cloudflared` в PATH):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-tunnel.ps1
```

Явный порт nginx на хосте:

```powershell
.\scripts\start-cloudflare-tunnel.ps1 -Port 8080
```

### Команда вручную

Подставьте порт, на котором у вас **nginx на хосте** (например `8080`):

```powershell
cloudflared tunnel --url http://127.0.0.1:8080
```

В логе появится строка вида:

`https://something-random.trycloudflare.com`

Скопируйте **полный HTTPS URL без пути** — это база для бэкенда.

### Vercel

**Settings → Environment Variables → Production (и при необходимости Preview):**

| Name | Value |
|------|--------|
| `NEXT_PUBLIC_BACKEND_URL` | `https://something-random.trycloudflare.com` |

Сохраните и сделайте **Redeploy** проекта.

### Важно

- URL **меняется** при каждом новом запуске `cloudflared` (если не используете именованный туннель с доменом).
- После смены URL снова обновите переменную в Vercel и redeploy.
- Окно с `cloudflared` должно оставаться запущенным.

---

## 3. Способ B — ngrok

1. Регистрация на [ngrok.com](https://ngrok.com), получите authtoken.
2. `ngrok config add-authtoken <TOKEN>`
3. Запуск:

   ```powershell
   ngrok http 8080
   ```

   (снова порт = nginx на хосте.)

4. В веб-интерфейсе ngrok или в консоли возьмите **HTTPS** URL (`https://xxxx.ngrok-free.app`).
5. В Vercel: `NEXT_PUBLIC_BACKEND_URL=https://xxxx.ngrok-free.app` → **Redeploy**.

На бесплатном плане URL может меняться между сессиями; для постоянного имени — платный план.

---

## 4. Проверка

1. Ноутбук: Docker + nginx + `cloudflared`/`ngrok` запущены.
2. Vercel: задан `NEXT_PUBLIC_BACKEND_URL`, выполнен redeploy.
3. Откройте сайт на Vercel → в DevTools **Network** запросы к `/api/v1/...` должны уходить на ваш туннель-домен и получать не CORS-ошибку, а ответ API (или осмысленную ошибку API).

Если CORS блокирует — проверьте `VERCEL_FRONTEND_URL` и точное совпадение origin (с `https`, без лишнего `/`).

---

## 5. Ограничения

| Тема | Комментарий |
|------|-------------|
| ПК выключен / сон | Сайт на Vercel откроется, API не ответит. |
| Смена URL туннеля | Обновить `NEXT_PUBLIC_BACKEND_URL` + redeploy. |
| Прод | Надёжнее свой домен + Zero Trust Tunnel с **Public hostname** (когда появится зона в Cloudflare). |

---

## 6. Связанные файлы

| Назначение | Путь |
|------------|------|
| Порт nginx на хосте | `ARGUS/infra/.env` → `NGINX_HTTP_PORT` |
| CORS + Vercel origin | `ARGUS/infra/.env` → `VERCEL_FRONTEND_URL`, `CORS_ORIGINS` |
| Rewrite фронта на бэкенд | `ARGUS/Frontend/next.config.ts` → `NEXT_PUBLIC_BACKEND_URL` |
| Общий деплой | `ARGUS/docs/deployment.md` |
