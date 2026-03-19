# ARGUS Celery Worker — inherits from backend image
# Same codebase as backend; only CMD differs (celery worker vs gunicorn).
# Requires backend to be built first: docker compose build backend
#
# Build context: ARGUS/infra (set in docker-compose)
# Backend image: argus-backend (from backend service)

ARG BACKEND_IMAGE=argus-backend
FROM ${BACKEND_IMAGE}

CMD ["celery", "-A", "src.celery_app", "worker", "-l", "INFO", "-Q", "argus.scans,argus.reports,argus.tools,argus.recon,argus.exploitation,argus.default"]
