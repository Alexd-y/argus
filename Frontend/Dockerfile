ARG NODE_VERSION=22
ARG NEXT_PUBLIC_BACKEND_URL=http://backend:8000
ARG NEXT_PUBLIC_MCP_ENABLED=false
ARG NEXT_PUBLIC_ADMIN_AUTH_MODE=session
ARG APP_PORT=6100

FROM node:${NODE_VERSION}-bookworm AS builder
WORKDIR /app

ENV NEXT_PUBLIC_BACKEND_URL=${NEXT_PUBLIC_BACKEND_URL} \
    NEXT_PUBLIC_MCP_ENABLED=${NEXT_PUBLIC_MCP_ENABLED} \
    NEXT_PUBLIC_ADMIN_AUTH_MODE=${NEXT_PUBLIC_ADMIN_AUTH_MODE}

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