import { defineConfig, devices } from "@playwright/test";

import {
  ADMIN_BACKEND_MOCK_KEY,
  ADMIN_BACKEND_MOCK_PORT,
} from "./tests/e2e/fixtures/admin-backend-mock";

/**
 * Dedicated Playwright config for the accessibility suite (T26).
 *
 * Why a separate config rather than another project in `playwright.config.ts`:
 *   - The a11y suite needs `BACKEND_URL` pointed at the mock backend
 *     started by `admin-axe.global-setup.ts`. The default config uses the
 *     real backend from `.env`, so changing it there would silently
 *     break the existing `admin-console.spec.ts` smoke tests.
 *   - The dev server is spawned on a different `PORT` (5050) so an
 *     already-running local `next dev` on 5000 doesn't get reused with
 *     the wrong env.
 *   - `globalSetup` only fires for this config, so the mock listener
 *     never lingers when the rest of the e2e suite runs.
 *
 * Run from `Frontend/`:
 *   npx playwright test --config playwright.a11y.config.ts
 *   # or via the npm script:
 *   npm run test:e2e:a11y
 */

const PORT = Number(process.env.PORT_A11Y ?? 5050);
const BASE_URL =
  process.env.PLAYWRIGHT_BASE_URL_A11Y ?? `http://127.0.0.1:${PORT}`;
const BACKEND_URL = `http://127.0.0.1:${ADMIN_BACKEND_MOCK_PORT}`;

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: /admin-axe\.spec\.ts$/,
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
      name: "chromium-a11y",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: `npx next dev -H 127.0.0.1 -p ${PORT}`,
    url: BASE_URL,
    reuseExistingServer: false,
    timeout: 180_000,
    env: {
      // Pin the dev server to the in-memory mock backend; the suite
      // never talks to a real FastAPI service.
      BACKEND_URL,
      ADMIN_API_KEY: ADMIN_BACKEND_MOCK_KEY,
      // The page guard reads the role from cookies first, then from
      // this env. We default to admin and override per-test via
      // `addInitScript` + cookie injection for super-admin scenarios.
      NEXT_PUBLIC_ADMIN_DEV_ROLE: "admin",
      NEXT_PUBLIC_BACKEND_URL: BACKEND_URL,
      NEXT_PUBLIC_MCP_ENABLED: "false",
      // Keep Next telemetry quiet in CI so the GitHub reporter is
      // easy to read.
      NEXT_TELEMETRY_DISABLED: "1",
    },
  },
});
