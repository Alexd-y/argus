ARG NODE_VERSION=22
# Server-side rewrite target baked into the standalone bundle (next.config.ts).
# Internal docker DNS only — independent of the host's public IP/domain.
ARG BACKEND_URL=http://backend:8000
ARG NEXT_PUBLIC_BACKEND_URL=http://backend:8000
ARG NEXT_PUBLIC_MCP_ENABLED=false
ARG NEXT_PUBLIC_ADMIN_AUTH_MODE=session
# TEMP: skip the "Verify domain ownership" step for testing. Set to true to disable.
ARG NEXT_PUBLIC_DISABLE_DOMAIN_VERIFICATION=false
ARG APP_PORT=6100

FROM node:${NODE_VERSION}-bookworm AS builder
WORKDIR /app

# Re-declare the global (pre-FROM) ARGs inside this stage. Docker scopes
# pre-FROM ARGs out of build stages, so without these the ENV lines below
# would expand to empty strings — baking a hostless rewrite destination and
# an unset NEXT_PUBLIC_ADMIN_AUTH_MODE into the bundle (admin → 500 via the
# instrumentation guard, /api/v1/* → 404). Defaults mirror the global ARGs.
ARG BACKEND_URL=http://backend:8000
ARG NEXT_PUBLIC_BACKEND_URL=http://backend:8000
ARG NEXT_PUBLIC_MCP_ENABLED=false
ARG NEXT_PUBLIC_ADMIN_AUTH_MODE=session
ARG NEXT_PUBLIC_DISABLE_DOMAIN_VERIFICATION=false

ENV BACKEND_URL=${BACKEND_URL} \
    NEXT_PUBLIC_BACKEND_URL=${NEXT_PUBLIC_BACKEND_URL} \
    NEXT_PUBLIC_MCP_ENABLED=${NEXT_PUBLIC_MCP_ENABLED} \
    NEXT_PUBLIC_ADMIN_AUTH_MODE=${NEXT_PUBLIC_ADMIN_AUTH_MODE} \
    NEXT_PUBLIC_DISABLE_DOMAIN_VERIFICATION=${NEXT_PUBLIC_DISABLE_DOMAIN_VERIFICATION}

COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts

COPY . .
RUN npm run build

FROM node:${NODE_VERSION}-bookworm-slim AS runner
WORKDIR /app

ARG APP_PORT
ENV NODE_ENV=production
ENV PORT=${APP_PORT}
ENV HOSTNAME="0.0.0.0"

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE ${APP_PORT}

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:'+process.env.PORT+'/api/v1/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node", "server.js"]