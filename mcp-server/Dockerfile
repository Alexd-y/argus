# ARGUS MCP Server — FastMCP HTTP transport (Docker); stdio for local Cursor
# Phase 4: argus_mcp.py, calls backend /api/v1/tools/*

FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ARGUS_SERVER_URL: backend URL (e.g. http://backend:8000 in docker-compose)
ENV ARGUS_SERVER_URL=http://backend:8000

# HTTP transport for Docker: keeps container running; stdio for local Cursor spawn
ENV MCP_TRANSPORT=http
ENV MCP_PORT=8000

CMD ["python", "argus_mcp.py"]
