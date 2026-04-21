# ARGUS Backend — production multi-stage build
# Builder: install deps | Runtime: minimal image, gunicorn+uvicorn workers
# Build context: ARGUS/backend (set in docker-compose)

# --- Builder stage ---
FROM python:3.12-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Single source of truth for runtime deps: PEP 621 [project.dependencies] in
# pyproject.toml. requirements.txt is kept in the repo as an auto-generated
# mirror for legacy CI / SCA tooling (regenerate with
# `python backend/scripts/sync_requirements.py`).
COPY pyproject.toml ./
RUN python -c "import tomllib, pathlib; \
deps = tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['dependencies']; \
pathlib.Path('/tmp/requirements.txt').write_text('\n'.join(deps))" \
    && pip install --no-cache-dir -r /tmp/requirements.txt

# --- Runtime stage ---
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Runtime deps: recon tools + WeasyPrint (RPT-009 PDF)
# Optional XSS-005 / POC-003: Playwright verification runs in-process here and in the Celery worker
# (same image). Base image does not install playwright by default; to enable browser verification,
# add `playwright` to backend requirements, then e.g. `RUN pip install playwright && playwright install chromium`
# plus OS deps (`playwright install-deps chromium` or Playwright Docker docs for Debian slim).
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dnsutils whois curl net-tools \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
    libgdk-pixbuf-2.0-0 libffi8 shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI only — VA active scan runs `docker exec` into argus-sandbox (host socket mounted).
COPY --from=docker:26-cli /usr/local/bin/docker /usr/local/bin/docker

# Copy application
COPY main.py .
COPY src/ ./src/
COPY app/ ./app/
COPY data/ ./data/
COPY alembic.ini .
COPY alembic/ ./alembic/

# Non-root user
RUN adduser --system --group --no-create-home appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Gunicorn + Uvicorn workers (worker overrides with celery in compose)
CMD ["gunicorn", "main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000"]
