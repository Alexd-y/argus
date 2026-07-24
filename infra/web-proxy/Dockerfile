# Web Security Workbench intercepting-proxy image (WB-P2b-2).
#
# The live MITM daemon needs mitmproxy, a heavy dependency we deliberately keep
# OUT of the shared backend/worker/sandbox images. This image simply extends the
# already-built argus-backend with mitmproxy so the proxy profile is the only
# thing that carries it.
#
# Build (backend must be built first; use local image, not a registry pull):
#   export COMPOSE_BAKE=false
#   docker compose -f infra/docker-compose.yml build backend
#   docker compose -f infra/docker-compose.yml --profile web-proxy build web-proxy
ARG BACKEND_IMAGE=argus-backend:latest
FROM ${BACKEND_IMAGE}

# mitmproxy provides the interception loop + per-host leaf minting from our CA.
# Pinned to a compatible major range; cryptography is already present from backend.
USER root
RUN pip install --no-cache-dir "mitmproxy>=11.0,<14.0"
USER appuser
