# Frontend на Vercel + backend на ноутбуке (без своего домена)

Браузер пользователя ходит на **Vercel**; API-запросы проксируются Next.js на **публичный URL**, который туннелирует трафик на **nginx/backend на вашем ПК**. Ноутбук и туннель должны быть **включены**, пока вы тестируете.

**Источник контракта:** `docs/frontend-api-contract-generated.md` — `NEXT_PUBLIC_BACKEND_URL`, rewrites `/api/v1/*`.

---

## 0. Шпаргалка команд (PowerShell, Windows)

Выполняй по порядку. **Порт nginx на хосте** — `ARGUS_HTTP_PORT` из `infra/.env` (по умолчанию `8080`); compose публикует `${ARGUS_HTTP_PORT:-8080}:80`. Скрипт `start-cloudflare-tunnel.ps1` подхватывает его автоматически.

```powershell
# 0) Каталог проекта
cd D:\Developer\Pentest_test\ARGUS

# 1) Стек (backend + worker + nginx + minio + postgres + redis)
docker compose -f infra/docker-compose.yml up -d

# 2) Проверка порта nginx на хосте (должен показать 0.0.0.0:8080->80/tcp по дефолту)
docker compose -f infra/docker-compose.yml ps nginx

# 3) Локальная проверка API (подставь ARGUS_HTTP_PORT, по умолчанию 8080)
curl http://127.0.0.1:8080/api/v1/health

# 4) В infra\.env обязательны:
#    VERCEL_FRONTEND_URL=https://<your-app>.vercel.app          (без / в конце; для backend CORS)
#    CORS_ORIGINS=https://<your-app>.vercel.app                 (для backend FastAPI)
#    ARGUS_CORS_ALLOWED_ORIGINS=https://<your-app>.vercel.app,http://localhost:3000,http://127.0.0.1:3000
#                                                               (для nginx CORS map; ОБЯЗАТЕЛЬНО включает Vercel URL)
#    После правки .env recreate (env_file подхватывается только при пересоздании):
docker compose -f infra/docker-compose.yml up -d --force-recreate backend nginx

# 5) Cloudflare Quick Tunnel (отдельное окно PowerShell; URL живой пока окно открыто)
#    Скрипт автоматически читает ARGUS_HTTP_PORT из infra\.env.
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-tunnel.ps1

#    Явный порт (если стек на нестандартном):
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-tunnel.ps1 -Port 8080

#    Если на Windows QUIC падает с "wsasendto ... buffer space" — переключись на HTTP/2 (TCP):
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-tunnel.ps1 -Protocol http2

# 6) Из лога cloudflared скопируй: https://<random-words>.trycloudflare.com
#    Vercel Dashboard → Project → Settings → Environment Variables → Production:
#      NEXT_PUBLIC_BACKEND_URL = https://<random-words>.trycloudflare.com
#    Затем: Deployments → ⋮ → Redeploy

# 7) Проверка с другой сети (телефон/4G), должен быть JSON 200:
#    https://<random-words>.trycloudflare.com/api/v1/health
```

**Важно:**

- **Quick Tunnel URL ротируется при каждом запуске cloudflared.** Каждый раз нужно обновлять `NEXT_PUBLIC_BACKEND_URL` в Vercel и делать Redeploy (rewrite в Next.js фиксируется на этапе сборки). Для стабильного URL — **named tunnel** через Cloudflare Zero Trust Dashboard (см. раздел 4).
- **CORS на двух уровнях:** FastAPI (`CORS_ORIGINS`) И nginx (`ARGUS_CORS_ALLOWED_ORIGINS`). Если Vercel URL пропущен в `ARGUS_CORS_ALLOWED_ORIGINS`, nginx возвращает пустой `Access-Control-Allow-Origin` — браузер блокнёт preflight.
- **Cloudflare 530** = "Origin Unreachable". Чаще всего: `ARGUS_HTTP_PORT` ≠ порт в скрипте/туннеле, либо стек упал. Проверь `Test-NetConnection -ComputerName 127.0.0.1 -Port 8080` — должно быть `True`.

---

## 1. Подготовка бэкенда на ноутбуке

1. Запустите стек (из каталога `ARGUS`):

   ```powershell
   cd D:\Developer\Pentest_test\ARGUS
   docker compose -f infra/docker-compose.yml up -d
   ```

2. Убедитесь, что **nginx** слушает порт на хосте. В `infra/docker-compose.yml` mapping: `${ARGUS_HTTP_PORT:-8080}:80`. По умолчанию из `infra/.env.example` — **8080** (Windows 80 часто занят IIS/Skype/Hyper-V).

   ```env
   ARGUS_HTTP_PORT=8080
   ```

   Recreate (важно: env_file подхватывается только при `--force-recreate`):

   ```powershell
   docker compose -f infra/docker-compose.yml up -d --force-recreate nginx
   ```

3. Локальная проверка: `curl http://127.0.0.1:8080/api/v1/health` — должно быть JSON 200.

4. **CORS — два уровня, обе переменные обязательны:**

   ```env
   # FastAPI (backend) — для CORS-заголовков из приложения
   VERCEL_FRONTEND_URL=https://argus-frontend-jade.vercel.app
   CORS_ORIGINS=https://argus-frontend-jade.vercel.app

   # Nginx gateway — для preflight (OPTIONS) на уровне reverse-proxy
   # Включи Vercel URL + localhost для npm dev сессий.
   ARGUS_CORS_ALLOWED_ORIGINS=https://argus-frontend-jade.vercel.app,http://localhost:3000,http://127.0.0.1:3000
   ```

   После правки `.env`: `docker compose up -d --force-recreate backend nginx`.

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
| Порт nginx на хосте | `ARGUS/infra/.env` → `ARGUS_HTTP_PORT` (default `8080`; legacy alias `NGINX_HTTP_PORT` поддерживается скриптом) |
| CORS — backend FastAPI | `ARGUS/infra/.env` → `VERCEL_FRONTEND_URL`, `CORS_ORIGINS` |
| CORS — nginx gateway | `ARGUS/infra/.env` → `ARGUS_CORS_ALLOWED_ORIGINS` (ОБЯЗАТЕЛЬНО включить Vercel URL) |
| Rewrite фронта на бэкенд | `ARGUS/Frontend/next.config.ts` → `NEXT_PUBLIC_BACKEND_URL` |
| Скрипт quick tunnel | `ARGUS/scripts/start-cloudflare-tunnel.ps1` (читает `ARGUS_HTTP_PORT`) |
| Общий деплой | `ARGUS/docs/deployment.md` |
