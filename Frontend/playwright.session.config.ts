import { defineConfig, devices } from "@playwright/test";

import {
  ADMIN_BACKEND_MOCK_KEY,
  ADMIN_BACKEND_MOCK_PORT,
} from "./tests/e2e/fixtures/admin-backend-mock";

/**
 * Playwright config for the SESSION-MODE admin auth E2E suite (B6-T09 /
 * ISS-T20-003 Phase 1 frontend). Keeps `admin-auth.spec.ts` strictly
 * isolated from the cookie-mode functional suite (`playwright.mock.config.ts`)
 * because:
 *
 *   1. The dev server's `NEXT_PUBLIC_ADMIN_AUTH_MODE` is inlined at
 *      build time. Switching modes between specs would require a fresh
 *      `next dev` boot; running them in separate configs is simpler
 *      and faster.
 *   2. Session-mode tests must NOT seed `argus.admin.role` cookies via
 *      `loginAs()` — they exercise the real backend handshake. Sharing
 *      the cookie-mode helpers would make assertions ambiguous.
 *   3. Pinning a separate port (`PORT_SESSION`, default 5080) lets the
 *      cookie-mode + session-mode dev servers coexist on a developer
 *      machine.
 *
 * Run from `Frontend/`:
 *   npx playwright test --config playwright.session.config.ts
 */

const PORT = Number(process.env.PORT_SESSION ?? 5080);
const BASE_URL =
  process.env.PLAYWRIGHT_BASE_URL_SESSION ?? `http://127.0.0.1:${PORT}`;
const BACKEND_URL = `http://127.0.0.1:${ADMIN_BACKEND_MOCK_PORT}`;

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: /admin-auth\.spec\.ts$/,
  globalSetup: require.resolve("./tests/e2e/admin-axe.global-setup.ts"),
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : [["list"]],
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium-session",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: `npx next dev -H 127.0.0.1 -p ${PORT}`,
    url: BASE_URL,
    reuseExistingServer: false,
    timeout: 180_000,
    env: {
      // Pin the dev server to the in-memory mock backend.
      BACKEND_URL,
      ADMIN_API_KEY: ADMIN_BACKEND_MOCK_KEY,
      NEXT_PUBLIC_BACKEND_URL: BACKEND_URL,
      NEXT_PUBLIC_MCP_ENABLED: "false",
      NEXT_TELEMETRY_DISABLED: "1",
      // The whole point of this config — strictly session mode so the
      // login flow / middleware redirects / whoami calls are exercised.
      NEXT_PUBLIC_ADMIN_AUTH_MODE: "session",
    },
  },
});
