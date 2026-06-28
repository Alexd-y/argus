# RAGNAROK - Penetration Testing Platform

A modern, cyberpunk-themed web application for security vulnerability scanning and penetration testing.

## Overview

**RAGNAROK** is a demo penetration testing platform by Svalbard Security that provides a sleek interface for security scanning with comprehensive reporting options.

## Features

### Scanning Capabilities
- **Multiple Scan Types**: Quick, Light, and Deep scans
- **Vulnerability Detection**: XSS, SQLi, CSRF, SSRF, LFI/RFI, RCE
- **Authentication Support**: Basic Auth, Bearer Token, Cookie-based
- **Advanced Options**:
  - Custom ports and port ranges
  - Rate limiting controls
  - Proxy support
  - Custom HTTP headers
  - User-Agent spoofing

### User Experience
- **Flexible Input**: Accept URLs with or without protocol (auto-adds https://)
- **Email Notifications**: Receive scan results via email
- **Real-time Progress**: Visual scan progress with 5 stages
- **Multiple Report Formats**: PDF, HTML, JSON, XML

### Reporting Tiers
1. **Basic (Free)**: Overview of discovered issues
2. **Professional ($204)**: Detailed analysis with recommendations
3. **Enterprise ($587)**: Complete audit with step-by-step remediation

## Tech Stack

- **Framework**: Next.js 16.1.6 (App Router)
- **UI**: React 19 with TypeScript
- **Styling**: Tailwind CSS v4
- **Design**: Dark cyberpunk theme with glitch effects

## Getting Started

```bash
# Install dependencies
npm install

# Run development server (localhost only)
npm run dev

# Build for production
npm run build

# Start production server (binds 0.0.0.0:5000 — public scan UI)
npm start
# Admin console on :6100
npm run start:admin
```

Open [http://localhost:5000](http://localhost:5000) to view the application.

### Deploying on a public host (AWS EC2, etc.)

Next 16 **blocks cross-origin requests to `/_next/*` in `next dev`** by default.
If you run `next dev` and open the app through a public IP/domain
(e.g. `http://<ec2-ip>:5000`), the browser's `Origin` is not in
`allowedDevOrigins`, so CSS/JS/font chunks are blocked and the page renders
**unstyled**.

For any public deployment use the **production build**, which has no
dev-origin gate and serves static assets for any origin:

```bash
npm run build
npm start            # public scan UI on 0.0.0.0:5000
npm run start:admin  # admin console on 0.0.0.0:6100
```

Or run the container (`infra/docker-compose.yml` → `frontend` service, already
standalone on port 5000).

If you must run `next dev` behind a public host, allow-list that exact origin:

```bash
# Frontend/.env.local — comma-separated, full origin(s)
NEXT_ALLOWED_DEV_ORIGINS=http://<ec2-ip>:5000
```

(Local/LAN/private interface IPs are auto-detected by `next.config.ts`; only the
NAT'd public IP/domain needs to be set explicitly.)

## Project Structure

```
src/
├── app/
│   ├── page.tsx           # Main scanning interface
│   ├── report/
│   │   └── page.tsx       # Report selection page
│   ├── mcp/               # MCP integration (ARG-042 — opt-in via feature flag)
│   │   ├── layout.tsx     # QueryClient + notifications drawer
│   │   ├── page.tsx       # Server entry — flag check + ToolRunnerClient
│   │   ├── feature-flag.ts
│   │   └── ToolRunnerClient.tsx
│   ├── layout.tsx         # Root layout
│   └── globals.css        # Global styles & animations
├── components/
│   └── mcp/               # ToolForm, ToolOutputView, NotificationsDrawer, NotEnabledNotice
├── services/
│   └── mcp/               # SDK wrapper, auth resolver, React Query hooks
├── sdk/
│   └── argus-mcp/         # Auto-generated OpenAPI client (do NOT edit)
└── tests/
    └── e2e/               # Playwright specs (mcp-tool-runner.spec.ts, …)
```

## MCP integration

The Frontend ships with an optional Model Context Protocol surface at
`/mcp`. It consumes the auto-generated `argus-mcp` TypeScript SDK
(`Frontend/src/sdk/argus-mcp/`) through a thin service layer
(`Frontend/src/services/mcp/`) and a set of React Query hooks.

### Enabling the integration

Set the following variables in your `.env.local` (see `.env.example` for
the full list):

```bash
NEXT_PUBLIC_MCP_ENABLED=true
NEXT_PUBLIC_MCP_BASE_URL=http://127.0.0.1:8000/mcp
```

When `NEXT_PUBLIC_MCP_ENABLED` is unset or `false` (the default), the
`/mcp` route renders a `NotEnabledNotice` and the rest of the
application is **unchanged** — no React Query, no SSE, no SDK fetch.

### Authentication

The SDK reads its bearer token and `X-Tenant-Id` header from a pluggable
session provider (`services/mcp/auth.ts`). In production, register a
real provider once at boot:

```ts
import { setMcpSessionProvider } from "@/services/mcp/auth";

setMcpSessionProvider({
  getAccessToken: async () => (await getSession())?.accessToken ?? null,
  getTenantId: async () => (await getSession())?.tenantId ?? null,
  refresh: async () => { await refreshSession(); },
});
```

For local development, the default fallback reads from `localStorage`:

```js
localStorage.setItem("argus.mcp.accessToken", "<bearer>");
localStorage.setItem("argus.mcp.tenantId", "<uuid>");
```

A `console.warn` is emitted exactly once per session to discourage
shipping the dev fallback to production.

### Hooks

| Hook                  | Purpose                                                                |
|-----------------------|------------------------------------------------------------------------|
| `useMcpTool`          | Type-safe `useMutation` over any tool / RPC (`McpToolService.*`).      |
| `useMcpResource`      | Type-safe `useQuery` with 30 s `staleTime` for read-only resources.    |
| `useMcpPrompt`        | `useMutation` for prompt-render endpoints (`McpPromptService.*`).      |
| `useMcpNotifications` | SSE subscription with exponential-backoff reconnect (1 s → 30 s cap). |

### Tests

* **Unit** — `npm run test:run` runs Vitest with jsdom. The MCP suite
  lives under `src/components/mcp/__tests__/`.
* **E2E** — `npm run test:e2e` runs Playwright (`tests/e2e/`); install
  the browsers with `npm run test:e2e:install` first.

### Regenerating the SDK

The SDK is checked in for offline development and is regenerated from
`docs/mcp-server-openapi.yaml`:

```bash
npm run sdk:generate   # regenerate
npm run sdk:check      # CI gate — fails if the generated SDK drifts
```

Never edit files under `src/sdk/argus-mcp/` by hand — they are
overwritten on the next regeneration.

## Visual Features

- **Glitch Effects**: Hover animations on text and buttons
- **Pulse Animations**: Status indicators
- **Progress Visualization**: Animated scan stages
- **Gradient Accents**: Purple (#A655F7) theme

## Notes

This is a **frontend-only demo**. No actual security scanning is performed - all results are mocked for demonstration purposes.

## Links

- [Svalbard Security](https://svalbard.ca)
- [Documentation](https://svalbard.ca/docs)
- [Support](https://svalbard.ca/support)

## Legal

Authorized testing only. Unauthorized access to computer systems is illegal.

---

© 2026 Svalbard Security Inc.
