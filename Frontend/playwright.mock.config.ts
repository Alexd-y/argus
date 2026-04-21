import { defineConfig, devices } from "@playwright/test";

import {
  ADMIN_BACKEND_MOCK_KEY,
  ADMIN_BACKEND_MOCK_PORT,
} from "./tests/e2e/fixtures/admin-backend-mock";

/**
 * Dedicated Playwright config for the FUNCTIONAL admin E2E suite (T27).
 *
 * Why a separate config rather than another project in `playwright.config.ts`:
 *   - Same rationale as `playwright.a11y.config.ts`: the dev server has
 *     to be pointed at the mock backend, on a dedicated port, and
 *     `globalSetup` has to start/stop the mock listener exactly once.
 *     Reusing the a11y config and just changing `testMatch` would make
 *     either suite leak settings into the other.
 *   - Both configs share the SAME `admin-axe.global-setup.ts` because
 *     the mock backend is identical — adding richer routes was done
 *     in-place rather than forking the file.
 *   - We pin a different port (`PORT_MOCK`, default 5070) so the mock
 *     and a11y dev servers can be spawned side by side during local
 *     development without competing for the same socket. 5060 is
 *     reserved by Next.js (SIP), 5050 is taken by the a11y config —
 *     5070 is the next safe slot.
 *
 * Run from `Frontend/`:
 *   npx playwright test --config playwright.mock.config.ts
 *   # or via the npm script:
 *   npm run test:e2e:functional
 */

const PORT = Number(process.env.PORT_MOCK ?? 5070);
const BASE_URL =
  process.env.PLAYWRIGHT_BASE_URL_MOCK ?? `http://127.0.0.1:${PORT}`;
const BACKEND_URL = `http://127.0.0.1:${ADMIN_BACKEND_MOCK_PORT}`;

export default defineConfig({
  testDir: "./tests/e2e",
  // Match the four T27 spec files. Anchored regex so future spec files
  // don't get pulled into this config by accident.
  testMatch:
    /admin-(findings|audit|export-toggle|rbac)\.spec\.ts$/,
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
    // Required so `page.waitForEvent('download')` in the export-toggle
    // suite gets the synthetic file from the JS-driven `<a download>`
    // anchor click. Defaults to true in Playwright >=1.21 but pinned
    // here for clarity.
    acceptDownloads: true,
  },
  projects: [
    {
      name: "chromium-mock",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: `npx next dev -H 127.0.0.1 -p ${PORT}`,
    url: BASE_URL,
    reuseExistingServer: false,
    timeout: 180_000,
    env: {
      // Pin the dev server to the in-memory mock backend; no real
      // FastAPI / PostgreSQL / Redis is involved.
      BACKEND_URL,
      ADMIN_API_KEY: ADMIN_BACKEND_MOCK_KEY,
      // The page guard reads the role from cookies first; this dev-only
      // env is the fallback for tests that don't seed a cookie. The
      // T27 helpers always seed cookies, so this is a defensive default.
      NEXT_PUBLIC_ADMIN_DEV_ROLE: "admin",
      NEXT_PUBLIC_BACKEND_URL: BACKEND_URL,
      NEXT_PUBLIC_MCP_ENABLED: "false",
      NEXT_TELEMETRY_DISABLED: "1",
    },
  },
});
