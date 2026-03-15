# ARGUS Backend — FastAPI application
# Python 3.12, non-root user, multi-stage optional

FROM python:3.12-slim

LABEL org.opencontainers.image.title="ARGUS Backend"
LABEL org.opencontainers.image.description="ARGUS pentest platform API"
LABEL org.opencontainers.image.source=""

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dnsutils whois curl net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN adduser --system --group --no-create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
