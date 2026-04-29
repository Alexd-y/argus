Ниже — **практичный порядок запуска** для локальной разработки на **Windows (PowerShell)**. Опора на корневой `README.md` и `infra/docker-compose.yml`.

---

## 0. Что нужно установить

- **Docker Desktop** (включён WSL2 backend — так надёжнее для `docker.sock` и образов).
- **Node.js** (для UI), если хотите открыть веб-клиент с хоста.

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

Проверка статуса:

```powershell
docker compose ps
docker compose logs -f backend
```

Точки входа по умолчанию:

- **API через nginx:** `http://127.0.0.1:8080` (переменная `ARGUS_HTTP_PORT`, по умолчанию **8080**).
- **Прямой бэкенд с хоста** в dev-override **не проброшен** — ходите в API через **8080**.
- **MinIO console** (если порты открыты override’ом): `http://127.0.0.1:9001`.

Health (через прокси, если маршрут настроен как в типичном nginx-шаблоне):

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
5. Браузер: UI **:5000**, API **:8080**.

Если нужно, могу отдельно расписать **только API без UI** или вариант **без sandbox/worker** (если в вашей ветке compose это вынесено в profile — в текущем `docker-compose.yml` у `worker`/`sandbox` профиля нет, они поднимаются вместе со стеком).