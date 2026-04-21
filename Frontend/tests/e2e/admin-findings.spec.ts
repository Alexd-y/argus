/**
 * Functional E2E coverage for `/admin/findings` (T20 + T21) — Cycle 6.
 *
 * Each scenario:
 *   1. Plants role/tenant cookies via `loginAs` BEFORE navigation so the
 *      first server render already sees the right session — see
 *      `services/admin/serverSession.ts`.
 *   2. Navigates with optional URL filters (state-as-URL pattern that
 *      `AdminFindingsClient.writeFiltersToUrl` produces).
 *   3. Asserts on stable `data-testid` selectors only — never on visible
 *      copy that might be retranslated.
 *
 * These specs run against the deterministic mock backend defined in
 * `fixtures/admin-backend-mock.ts` so we don't depend on a real
 * PostgreSQL/Redis/FastAPI stack. The mock seeds 8 findings spread
 * across two tenants and all five severities.
 *
 * Reference docs / contract:
 *   - `src/app/admin/findings/AdminFindingsClient.tsx`  — page shell
 *   - `src/app/admin/findings/actions.ts`               — server actions
 *   - `src/lib/adminFindings.ts`                        — Zod schemas
 */

import { expect, test } from "@playwright/test";

import {
  loginAs,
  gotoAdminFindings,
  waitForAdminReady,
  waitForFindingsCounter,
  waitForTableSettled,
  assertNoLeakOverlay,
} from "./fixtures/admin-helpers";
import {
  MOCK_FINDINGS_IDS,
  MOCK_TENANT_PRIMARY,
  MOCK_TENANT_SECONDARY,
} from "./fixtures/admin-backend-mock";

test.describe("admin findings — functional E2E (T27)", () => {
  test("super-admin sees all 8 findings cross-tenant", async ({
    context,
    page,
  }) => {
    await loginAs(context, "super-admin");
    await gotoAdminFindings(page);
    await waitForFindingsCounter(page);
    await waitForTableSettled(page, "findings-table");
    await assertNoLeakOverlay(page);

    // Counter renders as `<displayed> / <total>`. Total = 8 across both tenants.
    await expect(page.getByTestId("findings-counter")).toHaveText("8 / 8");

    // Spot-check that rows for both tenants are in the DOM. We rely on the
    // stable per-row testid contract `findings-row-<uuid>` so there's no
    // brittle title or severity copy involved.
    await expect(
      page.getByTestId(`findings-row-${MOCK_FINDINGS_IDS.primaryCritical}`),
    ).toBeVisible();
    await expect(
      page.getByTestId(`findings-row-${MOCK_FINDINGS_IDS.secondaryCritical}`),
    ).toBeVisible();
    await expect(
      page.getByTestId(`findings-row-${MOCK_FINDINGS_IDS.secondaryInfo}`),
    ).toBeVisible();
  });

  test("admin role sees the 'no tenant binding' empty state instead of the table", async ({
    context,
    page,
  }) => {
    // Admin without an explicit tenant cookie (we override to `null`)
    // hits the S1-6 empty-state branch in `AdminFindingsClient`. The
    // table is intentionally NOT rendered — that's the security-relevant
    // assertion. (Source: ISS-T20-003 in ai_docs/develop/issues.)
    await loginAs(context, "admin", { tenantId: null });
    await gotoAdminFindings(page);
    await waitForAdminReady(page);
    await assertNoLeakOverlay(page);

    await expect(page.getByTestId("findings-admin-no-tenant")).toBeVisible();
    await expect(page.getByTestId("findings-table")).toHaveCount(0);
    // Bulk toolbar must NOT be rendered when no table is present —
    // selecting "all" against an empty surface would be a UX trap.
    await expect(page.getByTestId("bulk-actions-toolbar")).toHaveCount(0);
  });

  test("super-admin filters by severity=critical (URL hydration → 2 rows)", async ({
    context,
    page,
  }) => {
    await loginAs(context, "super-admin");
    // Hydrate filters from the URL so we don't have to click checkboxes
    // (which would also trigger a query refetch round-trip we don't need
    // to assert on twice).
    await gotoAdminFindings(page, { severity: ["critical"] });
    await waitForFindingsCounter(page);
    await waitForTableSettled(page, "findings-table");
    await assertNoLeakOverlay(page);

    // Two critical findings exist: 1 primary + 1 secondary. The counter is
    // the cheapest invariant to assert on; row presence below pins the
    // identity of the 2 rows so a future mock data change can't silently
    // rebalance the test.
    await expect(page.getByTestId("findings-counter")).toHaveText("2 / 2");
    await expect(
      page.getByTestId(`findings-row-${MOCK_FINDINGS_IDS.primaryCritical}`),
    ).toBeVisible();
    await expect(
      page.getByTestId(`findings-row-${MOCK_FINDINGS_IDS.secondaryCritical}`),
    ).toBeVisible();

    // Negative assertion: a high-severity row must NOT have leaked through
    // the filter. Catches a "filter ignored server-side" regression.
    await expect(
      page.getByTestId(`findings-row-${MOCK_FINDINGS_IDS.primaryHigh}`),
    ).toHaveCount(0);
  });

  test("super-admin selects two findings and bulk-suppresses → success banner", async ({
    context,
    page,
  }) => {
    // Pin the tenant filter so we deterministically pick two same-tenant
    // findings — that guarantees the per-tenant fan-out in
    // `bulkSuppressFindingsAction` makes exactly ONE backend POST.
    await loginAs(context, "super-admin");
    await gotoAdminFindings(page, { tenantId: MOCK_TENANT_PRIMARY });
    await waitForFindingsCounter(page);
    await waitForTableSettled(page, "findings-table");

    // 4 primary-tenant rows expected.
    await expect(page.getByTestId("findings-counter")).toHaveText("4 / 4");

    const row1 = page.getByTestId(
      `findings-select-row-${MOCK_FINDINGS_IDS.primaryCritical}`,
    );
    const row2 = page.getByTestId(
      `findings-select-row-${MOCK_FINDINGS_IDS.primaryHigh}`,
    );
    await expect(row1).toBeVisible();
    await expect(row2).toBeVisible();

    await row1.check();
    await row2.check();

    // Bulk toolbar + count is the contract surface a real operator sees.
    await expect(page.getByTestId("bulk-actions-toolbar")).toBeVisible();
    await expect(page.getByTestId("bulk-selection-count")).toContainText("2");

    // Open suppress dialog.
    await page.getByTestId("bulk-action-suppress").click();
    const dialog = page.getByTestId("bulk-action-dialog");
    await expect(dialog).toBeVisible();

            // Pick a closed-taxonomy reason. Value must match `BULK_SUPPRESS_REASONS`
            // in `lib/adminFindings.ts` ("duplicate" | "risk_accepted" |
            // "compensating_control" | "environmental_noise" | "other"). NOTE:
            // `false_positive` is NOT a suppress reason — it is the discriminator
            // for the separate `mark_false_positive` bulk action. The optional
            // comment is left blank.
            await dialog
              .getByTestId("bulk-suppress-reason")
              .selectOption("duplicate");

    const confirm = dialog.getByTestId("bulk-action-dialog-confirm");
    await expect(confirm).toBeEnabled();
    await confirm.click();

    // Success banner expected (ALL suppressed, no partial). The dialog
    // closes itself on success — that is also asserted to catch a
    // regression in `closeBulkDialog` after the action settles.
    const banner = page.getByTestId("bulk-action-banner");
    await expect(banner).toBeVisible({ timeout: 10_000 });
    await expect(banner).toHaveAttribute("data-tone", "success");
    await expect(page.getByTestId("bulk-action-dialog")).toHaveCount(0);
  });

  test("super-admin filters by tenant=secondary → 4 rows from beta tenant only", async ({
    context,
    page,
  }) => {
    // Extra coverage scenario (S5 in the T27 plan we extended to 5 — we
    // promised "≥4" but the second tenant filter pins MOCK_TENANT_SECONDARY
    // through the URL, demonstrating the super-admin scope-narrowing UX).
    await loginAs(context, "super-admin");
    await gotoAdminFindings(page, { tenantId: MOCK_TENANT_SECONDARY });
    await waitForFindingsCounter(page);
    await waitForTableSettled(page, "findings-table");

    await expect(page.getByTestId("findings-counter")).toHaveText("4 / 4");
    await expect(
      page.getByTestId(`findings-row-${MOCK_FINDINGS_IDS.secondaryInfo}`),
    ).toBeVisible();
    await expect(
      page.getByTestId(`findings-row-${MOCK_FINDINGS_IDS.primaryCritical}`),
    ).toHaveCount(0);
  });
});
