# ARGUS MCP Server — FastMCP HTTP transport (Docker); stdio for local Cursor
# Phase 4: argus_mcp.py, calls backend /api/v1/tools/*

FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 mcp
USER mcp

# ARGUS_SERVER_URL: backend URL (e.g. http://backend:8000 in docker-compose)
ENV ARGUS_SERVER_URL=http://backend:8000

# HTTP transport for Docker: keeps container running; stdio for local Cursor spawn
ENV MCP_TRANSPORT=http
ENV ARGUS_MCP_PORT=8765

CMD ["python", "argus_mcp.py"]
