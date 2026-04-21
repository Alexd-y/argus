/**
 * Accessibility audits for the admin pages introduced in Cycle 6
 * (T20 findings, T22 audit logs, T23 export toggle on /admin/scans).
 *
 * Each test:
 *   1. Plants the role + tenant cookies BEFORE navigation so the page's
 *      first server render already sees the right session — see
 *      `services/admin/serverSession.ts`. SessionStorage is also seeded
 *      via `addInitScript` so `AdminAuthContext`'s client-side hydration
 *      converges to the same role and the auth cookie isn't overwritten.
 *   2. Navigates and waits for the page heading to render.
 *   3. Optionally exercises an interactive state (dialog/drawer/banner).
 *   4. Runs `axe-core` with WCAG 2.0 AA + 2.1 AA tags and asserts the
 *      `violations` array is empty. Failures dump the full violation
 *      payload for actionability.
 *
 * Backend mock: see `playwright.a11y.config.ts` + `admin-axe.global-setup.ts`.
 * The dev server in this config is pointed at a synthetic mock; no real
 * tenant data, secrets, or PII can ever leak into a violation message.
 */

import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

import {
  MOCK_TENANT_PRIMARY,
} from "./fixtures/admin-backend-mock";

type AdminRole = "admin" | "super-admin";

const ADMIN_ROLE_COOKIE = "argus.admin.role";
const ADMIN_TENANT_COOKIE = "argus.admin.tenant";
const ADMIN_SUBJECT_COOKIE = "argus.admin.subject";
const ADMIN_ROLE_STORAGE_KEY = "argus.admin.role";

/**
 * Tags we audit against. WCAG 2.0 AA + 2.1 AA covers the legally
 * common bar; 2.0 A and 2.1 A are subsets but listed explicitly so a
 * future axe upgrade that splits a level keeps the gate strict.
 */
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] as const;

/**
 * Seed cookies + sessionStorage so both the server (cookie) and the
 * client (storage) agree on the role for this test. We use the loopback
 * domain `127.0.0.1` so the cookie is attached to dev-server requests.
 */
async function seedAdminSession(
  context: BrowserContext,
  role: AdminRole,
): Promise<void> {
  const tenantId = role === "admin" ? MOCK_TENANT_PRIMARY : "";
  const cookies = [
    {
      name: ADMIN_ROLE_COOKIE,
      value: role,
      domain: "127.0.0.1",
      path: "/",
      httpOnly: false,
      secure: false,
      sameSite: "Strict" as const,
    },
    {
      name: ADMIN_SUBJECT_COOKIE,
      value: `admin_console:${role}:a11y`,
      domain: "127.0.0.1",
      path: "/",
      httpOnly: false,
      secure: false,
      sameSite: "Strict" as const,
    },
  ];
  if (tenantId) {
    cookies.push({
      name: ADMIN_TENANT_COOKIE,
      value: tenantId,
      domain: "127.0.0.1",
      path: "/",
      httpOnly: false,
      secure: false,
      sameSite: "Strict" as const,
    });
  }
  await context.addCookies(cookies);
  await context.addInitScript(
    ({ key, value }: { key: string; value: string }) => {
      try {
        sessionStorage.setItem(key, value);
      } catch {
        // sessionStorage may be unavailable for cross-origin pages —
        // the cookie is the source of truth, the storage is best effort.
      }
    },
    { key: ADMIN_ROLE_STORAGE_KEY, value: role },
  );
}

/**
 * Run axe with a stable tag set against the entire `<main>` region (so
 * the surrounding admin chrome is excluded — that's covered by the
 * baseline admin-console.spec.ts) and assert zero violations.
 */
async function expectNoAxeViolations(
  page: Page,
  scenarioName: string,
): Promise<void> {
  const builder = new AxeBuilder({ page })
    .withTags([...AXE_TAGS])
    .include("main");
  const results = await builder.analyze();
  expect(
    results.violations,
    `[${scenarioName}] axe violations:\n${JSON.stringify(
      results.violations.map((v) => ({
        id: v.id,
        impact: v.impact,
        help: v.help,
        nodes: v.nodes.length,
      })),
      null,
      2,
    )}`,
  ).toEqual([]);
}

/** Wait for the admin route guard to release the spinner. */
async function waitForRouteReady(page: Page): Promise<void> {
  await expect(
    page.locator('[data-testid="admin-gate-loading"]'),
  ).toHaveCount(0, { timeout: 15_000 });
}

/**
 * Wait until the table at `testId` has finished its initial fetch — that
 * is, `aria-busy="false"`. Skipping this would mean we audit the loading
 * skeleton which is intentionally aria-hidden but still counted by axe
 * for some rules. Keeping the gate strict on the *steady state* mirrors
 * what real assistive-tech users perceive after opening the page.
 */
async function waitForTableSettled(
  page: Page,
  testId: string,
): Promise<void> {
  await expect(page.getByTestId(testId)).toHaveAttribute(
    "aria-busy",
    "false",
    { timeout: 15_000 },
  );
}

// ──────────────────────────────────────────────────────────────────────
// Route-level audits — render the page, wait for content, axe-scan.
// ──────────────────────────────────────────────────────────────────────

test.describe("admin a11y — route audits", () => {
  test("findings triage (super-admin)", async ({ context, page }) => {
    await seedAdminSession(context, "super-admin");
    await page.goto("/admin/findings");
    await waitForRouteReady(page);
    await expect(
      page.getByRole("heading", { name: "Global findings triage" }),
    ).toBeVisible();
    // Wait for either rows to render or the empty banner. Both are
    // a11y-relevant — we audit whichever is shown.
    await expect(
      page.getByTestId("findings-counter"),
    ).toBeVisible({ timeout: 15_000 });
    await waitForTableSettled(page, "findings-table");
    await expectNoAxeViolations(page, "findings-triage-super-admin");
  });

  test("findings triage (admin, no tenant binding)", async ({
    context,
    page,
  }) => {
    // Admin role with NO tenant cookie hits the explicit "no tenant
    // binding" empty state. We deliberately seed admin without the
    // tenant cookie to audit that empty-state copy + role/aria.
    await context.addCookies([
      {
        name: ADMIN_ROLE_COOKIE,
        value: "admin",
        domain: "127.0.0.1",
        path: "/",
        sameSite: "Strict",
      },
      {
        name: ADMIN_SUBJECT_COOKIE,
        value: "admin_console:admin:a11y",
        domain: "127.0.0.1",
        path: "/",
        sameSite: "Strict",
      },
    ]);
    await context.addInitScript(
      ({ key, value }: { key: string; value: string }) => {
        try {
          sessionStorage.setItem(key, value);
        } catch {
          // best effort
        }
      },
      { key: ADMIN_ROLE_STORAGE_KEY, value: "admin" },
    );
    await page.goto("/admin/findings");
    await waitForRouteReady(page);
    await expect(
      page.getByRole("heading", { name: "Global findings triage" }),
    ).toBeVisible();
    await expect(
      page.getByTestId("findings-admin-no-tenant"),
    ).toBeVisible();
    await expectNoAxeViolations(page, "findings-triage-admin-no-tenant");
  });

  test("audit log viewer (super-admin)", async ({ context, page }) => {
    await seedAdminSession(context, "super-admin");
    await page.goto("/admin/audit-logs");
    await waitForRouteReady(page);
    await expect(
      page.getByRole("heading", { name: "Audit log" }),
    ).toBeVisible();
    await expect(page.getByTestId("audit-counter")).toBeVisible({
      timeout: 15_000,
    });
    await waitForTableSettled(page, "audit-logs-table");
    await expectNoAxeViolations(page, "audit-logs-super-admin");
  });

  test("scans (admin, with export toggle)", async ({ context, page }) => {
    await seedAdminSession(context, "admin");
    await page.goto("/admin/scans");
    await waitForRouteReady(page);
    await expect(
      page.getByRole("heading", { name: "Scan history" }),
    ).toBeVisible();
    // Wait for the tenant select to mount (admins always see the
    // tenant dropdown, even if it falls back to the first tenant).
    await expect(page.getByLabel("Tenant")).toBeVisible({
      timeout: 15_000,
    });
    await expectNoAxeViolations(page, "scans-admin");
  });
});

// ──────────────────────────────────────────────────────────────────────
// Interactive-state audits — open dialog/drawer/banner, axe-scan.
// ──────────────────────────────────────────────────────────────────────

test.describe("admin a11y — interactive states", () => {
  test("findings: bulk-action dialog open", async ({ context, page }) => {
    await seedAdminSession(context, "super-admin");
    await page.goto("/admin/findings");
    await waitForRouteReady(page);
    await waitForTableSettled(page, "findings-table");

    // The page also renders sr-only severity-filter checkboxes; we
    // must scope to the row-selection checkboxes the table exposes
    // via `data-testid="findings-select-row-<id>"` to avoid clicking
    // an off-screen filter and timing out.
    const firstSelect = page
      .locator('[data-testid^="findings-select-row-"]')
      .first();
    await expect(firstSelect).toBeVisible({ timeout: 15_000 });
    await firstSelect.check();

    // Bulk toolbar appears once selectedCount > 0.
    const suppressBtn = page.getByTestId("bulk-action-suppress");
    await expect(suppressBtn).toBeVisible({ timeout: 5_000 });
    await suppressBtn.click();

    const dialog = page.getByTestId("bulk-action-dialog");
    await expect(dialog).toBeVisible();
    await expect(
      dialog.getByRole("heading", { name: /Подавить findings/i }),
    ).toBeVisible();

    await expectNoAxeViolations(page, "findings-bulk-dialog");
  });

  test("audit logs: chain-verify success banner", async ({
    context,
    page,
  }) => {
    // KNOWN FAILURE — see ai_docs/develop/issues/ISS-T26-001.md
    //
    // The "Verify chain integrity" button uses the brand `--accent`
    // background with `--bg-primary` text, yielding a contrast ratio
    // of 4.20:1 (WCAG AA threshold for normal text is 4.5:1). The
    // same token combo is reused by ≥6 other admin primary CTAs, so
    // the right fix is a design-system token change (Option A in
    // ISS-T26-001) rather than a per-component override. We surface
    // the failure in CI via `test.fail()` so:
    //   - the test still runs (gate cannot be silently bypassed),
    //   - axe still scans the rendered banner DOM,
    //   - the moment design lands the token fix, this test starts
    //     "failing" with "passed unexpectedly", forcing whoever ships
    //     the fix to remove this `test.fail()` annotation.
    //
    // Remove this `test.fail` block AFTER ISS-T26-001 acceptance
    // criterion (a) is met.
    test.fail(
      true,
      "ISS-T26-001: --accent button contrast = 4.20:1, need 4.5:1",
    );

    await seedAdminSession(context, "super-admin");
    await page.goto("/admin/audit-logs");
    await waitForRouteReady(page);
    await waitForTableSettled(page, "audit-logs-table");

    const verifyBtn = page.getByRole("button", {
      name: /Verify chain integrity/i,
    });
    await expect(verifyBtn).toBeVisible({ timeout: 15_000 });
    await verifyBtn.click();

    // The mock returns ok: true — wait for the success banner.
    const banner = page.getByTestId("audit-chain-ok");
    await expect(banner).toBeVisible({ timeout: 10_000 });

    await expectNoAxeViolations(page, "audit-chain-ok-banner");
  });

  test("scans: detail drawer open with export toggle", async ({
    context,
    page,
  }) => {
    await seedAdminSession(context, "admin");
    await page.goto("/admin/scans");
    await waitForRouteReady(page);

    // Wait for at least one Details button (the mock seeds two scans).
    const detailsBtn = page.getByRole("button", { name: "Details" }).first();
    await expect(detailsBtn).toBeVisible({ timeout: 15_000 });
    await detailsBtn.click();

    const drawer = page.getByRole("dialog", { name: "Scan details" });
    await expect(drawer).toBeVisible();

    await expectNoAxeViolations(page, "scans-detail-drawer");
  });
});
