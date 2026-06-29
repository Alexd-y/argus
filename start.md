Ниже — **практичный порядок запуска** для локальной разработки на **Windows (PowerShell)**. Опора на корневой `README.md` и `infra/docker-compose.yml`.

---

## 0. Что нужно установить

- **Docker Desktop** (включён WSL2 backend — так надёжнее для `docker.sock` и образов).
- **Node.js** (для UI), если хотите открыть веб-клиент с хоста.

> ⚠️ **ARGUS требует rootful Docker Engine.** Worker'ы монтируют `/var/run/docker.sock`
> и запускают тулзы через `docker exec argus-sandbox …`. Rootless Docker и **Podman**
> (rootless / `podman system service`) **не поддерживаются**: из-за user-namespace
> remap сокет внутри контейнера принадлежит `nobody` (65534), `docker exec` падает с
> `permission denied`, и весь пентест заканчивается ошибками `tool_not_found` /
> `va_active_scan_docker_exec_failed`. На Linux/EC2 проверьте `docker info | grep -i rootless`
> (должно быть пусто) и при необходимости поставьте Docker Engine, а не Podman.

---

## 1. Окружение Compose

Файл окружения для стека — **`infra/.env`** (не путать с `backend/.env` для локальных pytest).

```powershell
cd D:\Developer\Pentest_test\ARGUS
Copy-Item infra\.env.example infra\.env
notepad infra\.env   # или редактор по вкусу
```

Минимум проверьте:

- `POSTGRES_PASSWORD`, `JWT_SECRET`, `MINIO_SECRET_KEY`, `ADMIN_API_KEY` — **не дефолты**, если это не чистый dev.
- **`POSTGRES_PORT`** — на Windows часто конфликт с зарезервированными диапазонами; в примере уже есть `15432` — оставьте или выберите свободный порт.
- **CORS для фронта на порту 5000:** в `docker-compose` бэкенд по умолчанию смотрит на `http://localhost:3000`. У Next.js в проекте dev-сервер на **5000** (`Frontend/package.json`). Добавьте в `infra/.env`, например:

```env
CORS_ORIGINS=http://localhost:5000,http://127.0.0.1:5000,http://localhost:3000,http://127.0.0.1:3000
```

(или задайте `ARGUS_CORS_ALLOWED_ORIGINS` тем же списком — см. комментарии в compose для nginx.)

---

## 2. Поднять инфраструктуру

Из каталога **`infra`** (так подхватывается `docker-compose.override.yml`: hot-reload бэкенда, порты БД/Redis/MinIO на хост):

```powershell
cd D:\Developer\Pentest_test\ARGUS\infra
docker compose up -d --build
```

**Важно:** первый билд тянет **backend, worker, sandbox (Kali)** — может занять **очень долго** и много места на диске. Это ожидаемо.

Сервис **whiterabbitneo** (локальная LLM) может долго качать модель; он **не блокирует** подъём `backend` и **nginx**, чтобы фронт на хосте мог ходить в API (`NEXT_PUBLIC_BACKEND_URL=http://127.0.0.1:8080` — прямой проброс FastAPI из `docker-compose.override.yml`).

Проверка статуса:

```powershell
docker compose ps
docker compose logs -f backend
```

Точки входа по умолчанию (из каталога `infra/` с подключённым `docker-compose.override.yml`):

- **API для Next.js rewrites:** `http://127.0.0.1:8080` — **прямо FastAPI** (проброс `backend:8000` на хост).
- **Через nginx (шлюз, CORS/ключи):** `http://127.0.0.1:18888` (переменная `ARGUS_HTTP_PORT`, дефолт в compose **18888**; не ставьте `ARGUS_HTTP_PORT=8080`, если нужен проброс бэкенда на 8080 — будет конфликт портов).
- **MinIO console** (если порты открыты override’ом): `http://127.0.0.1:9001`.

Health:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8080/api/v1/health" -UseBasicParsing
```

---

## 3. Миграции БД

После того как `backend` здоров:

```powershell
cd D:\Developer\Pentest_test\ARGUS\infra
docker compose exec backend alembic upgrade head
```

---

## 4. Веб-клиент (Next.js) на хосте

```powershell
cd D:\Developer\Pentest_test\ARGUS\Frontend
npm install
```

Создайте **`Frontend/.env.local`** (файла-примера в репо может не быть; ориентир — переменные из тестов, например `NEXT_PUBLIC_BACKEND_URL`):

```env
NEXT_PUBLIC_BACKEND_URL=http://127.0.0.1:8080
```

При необходимости режима админки/сессий смотрите, что у вас задано для `NEXT_PUBLIC_ADMIN_AUTH_MODE` и dev-ролей (как в ваших тестах `serverSession.test.ts`).

Запуск:

```powershell
npm run dev
```

Открыть: **http://127.0.0.1:5000** (порт зашит в `npm run dev`).

> **⚠️ Публичный хост (AWS EC2 и т.п.).** `npm run dev` биндится только на localhost,
> а Next 16 по умолчанию **блокирует cross-origin запросы к `/_next/*`** в dev-режиме.
> Если открыть UI по публичному IP/домену (например `http://<ec2-ip>:5000`), Origin
> не входит в `allowedDevOrigins` → CSS/JS/шрифты блокируются и страница рендерится
> **без стилей**. Для публичного развёртывания используйте **production-сборку**
> (нет dev-гейта, статика отдаётся для любого origin):
>
> ```bash
> npm run build
> npm start            # публичный UI на 0.0.0.0:5000
> npm run start:admin  # админка на 0.0.0.0:6100
> ```
>
> Либо контейнер: `infra/docker-compose.yml` → сервис `frontend` (standalone, порт 5000).
> Если всё же нужен `next dev` за публичным хостом — пропишите точный origin в
> `Frontend/.env.local`: `NEXT_ALLOWED_DEV_ORIGINS=http://<ec2-ip>:5000`
> (приватные/LAN IP интерфейсов подхватываются автоматически в `next.config.ts`).

---

## 5. Остановка

```powershell
cd D:\Developer\Pentest_test\ARGUS\infra
docker compose down
```

(Данные БД/MinIO в volumes сохранятся, если не добавлять `-v`.)

---

## Краткая шпаргалка порядка

1. `Copy-Item infra\.env.example infra\.env` → правки секретов + **CORS для :5000**.  
2. `cd infra` → `docker compose up -d --build`.  
3. `docker compose exec backend alembic upgrade head`.  
4. `Frontend`: `npm install` → `.env.local` с `NEXT_PUBLIC_BACKEND_URL=http://127.0.0.1:8080` → `npm run dev`.  
5. Браузер: UI **:5000**, API **:8080** (прямой FastAPI с хоста; nginx-шлюз по умолчанию **:18888**).

Если нужно, могу отдельно расписать **только API без UI** или вариант **без sandbox/worker** (если в вашей ветке compose это вынесено в profile — в текущем `docker-compose.yml` у `worker`/`sandbox` профиля нет, они поднимаются вместе со стеком).