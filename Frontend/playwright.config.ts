import { existsSync, readFileSync } from "fs";
import { join } from "path";

import { defineConfig, devices } from "@playwright/test";

/**
 * Directory that contains this `playwright.config.ts` (works when cwd is `Frontend/`
 * or repo root with `Frontend/playwright.config.ts`).
 */
function resolveConfigRoot(): string {
  const cwd = process.cwd();
  if (existsSync(join(cwd, "playwright.config.ts"))) return cwd;
  const nested = join(cwd, "Frontend");
  if (existsSync(join(nested, "playwright.config.ts"))) return nested;
  return cwd;
}

function parseEnvFile(filePath: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!existsSync(filePath)) return out;
  for (const line of readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let val = trimmed.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

/**
 * So `npm run dev` spawned by Playwright inherits `ADMIN_API_KEY` / `BACKEND_URL`
 * the same way as a manual `next dev` (Next also reads `.env.local`, but the test
 * runner process often had no env until this merge — see server actions errors).
 */
function hydrateProcessEnvFromDotenvFiles() {
  const root = resolveConfigRoot();
  const merged = {
    ...parseEnvFile(join(root, ".env")),
    ...parseEnvFile(join(root, ".env.local")),
  };
  for (const [key, val] of Object.entries(merged)) {
    if (val === "") continue;
    const cur = process.env[key];
    if (cur === undefined || cur === "") {
      process.env[key] = val;
    }
  }
}

hydrateProcessEnvFromDotenvFiles();

const PORT = Number(process.env.PORT ?? 5000);
const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? `http://127.0.0.1:${PORT}`;
const VULN_BASE_URL = process.env.E2E_VULN_BASE_URL ?? "";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : [["list"]],
  timeout: 30_000,
  expect: { timeout: 5_000 },
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      // Vuln smoke specs expect E2E_VULN_BASE_URL (separate compose); never route them through the Next dev server.
      testIgnore: "**/vuln-targets/**",
      use: { ...devices["Desktop Chrome"] },
    },
    ...(VULN_BASE_URL
      ? [
          {
            name: "vuln-smoke",
            testDir: "./tests/e2e/vuln-targets",
            timeout: 120_000,
            use: {
              ...devices["Desktop Chrome"],
              baseURL: VULN_BASE_URL,
            },
          },
        ]
      : []),
  ],
  webServer:
    process.env.PLAYWRIGHT_NO_SERVER || VULN_BASE_URL
      ? undefined
      : {
        command: "npm run dev",
        url: BASE_URL,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
        env: {
          NEXT_PUBLIC_MCP_ENABLED: "true",
          NEXT_PUBLIC_MCP_BASE_URL:
            process.env.NEXT_PUBLIC_MCP_BASE_URL ?? "http://127.0.0.1:8000/mcp",
          // Admin E2E (`tests/e2e/admin-console.spec.ts`): default `admin` so guards allow tenants/LLM; override per CI. Operator scenarios set `sessionStorage` `argus.admin.role` in the spec (see AdminAuthContext).
          NEXT_PUBLIC_ADMIN_DEV_ROLE:
            process.env.NEXT_PUBLIC_ADMIN_DEV_ROLE ?? "admin",
          // After hydrateProcessEnvFromDotenvFiles(); explicit copy avoids edge cases where
          // the dev server would not see server-only vars needed by Server Actions.
          ...(process.env.ADMIN_API_KEY
            ? { ADMIN_API_KEY: process.env.ADMIN_API_KEY }
            : {}),
          ...(process.env.BACKEND_URL
            ? { BACKEND_URL: process.env.BACKEND_URL }
            : {}),
          ...(process.env.NEXT_PUBLIC_BACKEND_URL
            ? { NEXT_PUBLIC_BACKEND_URL: process.env.NEXT_PUBLIC_BACKEND_URL }
            : {}),
        },
      },
});
