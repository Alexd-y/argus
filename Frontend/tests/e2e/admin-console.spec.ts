/**
 * Admin console E2E — requires dev server with client role simulation.
 *
 * Env (see also `Frontend/.env.example`):
 * - `NEXT_PUBLIC_ADMIN_DEV_ROLE` — baked at dev start; Playwright `webServer` defaults to `admin`.
 *   Operator-only cases override via `sessionStorage` key `argus.admin.role` (see AdminAuthContext).
 * - `PLAYWRIGHT_BASE_URL` / `PORT` — optional; from `playwright.config.ts`.
 * - `E2E_TENANT_ID` — optional UUID for `/admin/tenants/{id}/scopes`; skipped if unset.
 * - `ADMIN_API_KEY` / backend URLs — affect tenant/scan data (empty/error UI is acceptable).
 *
 * Run from `Frontend`:
 *   npx playwright test tests/e2e/admin-console.spec.ts
 */

import { expect, test, type Page } from "@playwright/test";

const ADMIN_ROLE_STORAGE_KEY = "argus.admin.role";

async function assertNoLeakOverlay(page: Page) {
  await expect(page.getByText("Unhandled Runtime Error")).toHaveCount(0);
  await expect(page.getByText(/webpack-internal/i)).toHaveCount(0);
}

test.describe("admin console", () => {
  test("admin shell visible and menu navigation has no 5xx", async ({ page }) => {
    const failed: { url: string; status: number }[] = [];
    page.on("response", (res) => {
      const status = res.status();
      if (status >= 500) {
        failed.push({ url: res.url(), status });
      }
    });

    await page.goto("/admin");
    await expect(page.getByText("ARGUS Administration")).toBeVisible();
    const adminNav = page.getByRole("complementary", {
      name: "Admin navigation",
    });
    await expect(adminNav).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible();

    await adminNav.getByRole("link", { name: "Scans" }).click();

    await expect(page).toHaveURL(/\/admin\/scans/);
    await expect(
      page.getByRole("heading", { name: "Scan history" }),
    ).toBeVisible();
    await assertNoLeakOverlay(page);
    expect(failed, `5xx responses: ${JSON.stringify(failed)}`).toEqual([]);
  });

  test("operator cannot open admin-only tenants route (forbidden, no stack leak)", async ({
    context,
    page,
  }) => {
    await context.addInitScript((key: string) => {
      sessionStorage.setItem(key, "operator");
    }, ADMIN_ROLE_STORAGE_KEY);

    await page.goto("/admin/tenants");
    await expect(
      page.getByRole("heading", { name: "Access denied" }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("button", { name: "New tenant" })).toHaveCount(
      0,
    );
    await expect(page).toHaveURL(/\/admin\/forbidden/, { timeout: 15_000 });
    await assertNoLeakOverlay(page);
  });

  test("operator cannot open admin-only scans route (forbidden, no stack leak)", async ({
    context,
    page,
  }) => {
    await context.addInitScript((key: string) => {
      sessionStorage.setItem(key, "operator");
    }, ADMIN_ROLE_STORAGE_KEY);

    await page.goto("/admin/scans");
    await expect(
      page.getByRole("heading", { name: "Access denied" }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(page.getByLabel("Tenant")).toHaveCount(0);
    await expect(page).toHaveURL(/\/admin\/forbidden/, { timeout: 15_000 });
    await assertNoLeakOverlay(page);
  });

  test("tenants page loads meaningful state with admin role", async ({ page }) => {
    await page.goto("/admin/tenants");
    await expect(
      page.getByRole("heading", { name: "Tenants" }),
    ).toBeVisible();

    const main = page.locator("main");
    await expect(
      main
        .getByText("Loading…")
        .or(main.locator('[role="alert"]'))
        .or(main.getByText("No tenants yet."))
        .or(main.locator("table")),
    ).toBeVisible({ timeout: 25_000 });
    await assertNoLeakOverlay(page);
  });

  test("scans page shows key UI with admin role", async ({ page }) => {
    await page.goto("/admin/scans");
    await expect(
      page.getByRole("heading", { name: "Scan history" }),
    ).toBeVisible();
    await expect(page.getByLabel("Tenant")).toBeVisible();
    await assertNoLeakOverlay(page);
  });

  test("tenant scopes page when E2E_TENANT_ID is set", async ({ page }) => {
    const tenantId = process.env.E2E_TENANT_ID?.trim();
    test.skip(
      !tenantId,
      "Set E2E_TENANT_ID (optional UUID) to assert /admin/tenants/{id}/scopes in CI/local.",
    );

    await page.goto(`/admin/tenants/${encodeURIComponent(tenantId!)}/scopes`);
    await expect(page).not.toHaveURL(/\/admin\/forbidden/);
    await expect(page.getByRole("heading", { name: "Scopes" })).toBeVisible();
    await assertNoLeakOverlay(page);
  });

  test("LLM: operator forbidden; admin sees page shell", async ({
    context,
    page,
  }) => {
    await context.addInitScript((key: string) => {
      sessionStorage.setItem(key, "operator");
    }, ADMIN_ROLE_STORAGE_KEY);

    await page.goto("/admin/llm");
    await page.waitForURL(/\/admin\/forbidden/, { timeout: 20_000 });
    await expect(
      page.getByRole("heading", { name: "Access denied" }),
    ).toBeVisible({ timeout: 10_000 });
    await assertNoLeakOverlay(page);

    await context.addInitScript((key: string) => {
      sessionStorage.removeItem(key);
    }, ADMIN_ROLE_STORAGE_KEY);

    const adminPage = await context.newPage();
    await adminPage.goto("/admin/llm");
    await expect(adminPage).not.toHaveURL(/\/admin\/forbidden/);
    await expect(
      adminPage.getByRole("heading", { name: "LLM providers" }),
    ).toBeVisible();
    await assertNoLeakOverlay(adminPage);
    await adminPage.close();
  });
});
