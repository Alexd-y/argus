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

# WeasyPrint (RPT-009): Pango/Cairo/HarfBuzz + fonts for PDF text rendering
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dnsutils whois curl net-tools \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
    libgdk-pixbuf-2.0-0 libffi8 shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN adduser --system --group --no-create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
