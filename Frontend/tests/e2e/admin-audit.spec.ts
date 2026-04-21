/**
 * Functional E2E coverage for `/admin/audit-logs` (T22 + T25) — Cycle 6.
 *
 * Three scenarios:
 *   1. admin sees their tenant's audit log rows (3 of 4 mock entries).
 *   2. super-admin verifies chain → green OK banner.
 *   3. super-admin uses the magic `event_type=_t27_drift` trigger to
 *      force a DRIFT response from the verify-chain endpoint, asserts
 *      the red banner with the drift event id.
 *
 * Why a magic event_type for the drift trigger:
 *   The verify-chain action only forwards `tenant_id`, `event_type`,
 *   `since`, `until` from the filter bar. To make DRIFT testable from
 *   the UI without leaking test plumbing into the production code path
 *   we bind it to an event_type value (`_t27_drift`) that no real
 *   audit row would ever have. See `admin-backend-mock.ts::handleVerifyChain`.
 */

import { expect, test } from "@playwright/test";

import {
  loginAs,
  gotoAdminAuditLogs,
  waitForAuditCounter,
  waitForTableSettled,
  assertNoLeakOverlay,
} from "./fixtures/admin-helpers";
import {
  MOCK_AUDIT_DRIFT_EVENT_ID,
  MOCK_TENANT_PRIMARY,
} from "./fixtures/admin-backend-mock";

const VERIFY_DRIFT_TRIGGER = "_t27_drift";

test.describe("admin audit-logs — functional E2E (T27)", () => {
  test("admin sees their tenant's audit log rows (3 of 4 entries)", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin", { tenantId: MOCK_TENANT_PRIMARY });
    await gotoAdminAuditLogs(page);
    await waitForAuditCounter(page);
    await waitForTableSettled(page, "audit-logs-table");
    await assertNoLeakOverlay(page);

    // 3 entries belong to MOCK_TENANT_PRIMARY; 1 to the secondary tenant.
    // The action server-side pins the tenant from the cookie, so even if
    // the operator tampers with the URL they only see their tenant's rows.
    await expect(page.getByTestId("audit-counter")).toHaveText("3 / 3");

    // The drift event row is in the loaded set — assert the row is
    // rendered and that the chain-aware badge shows up alongside it
    // (the badge presence is the UI-level cue that the row carries
    // chain markers, see `AuditLogsTable.hasChainMarkers`).
    await expect(
      page.getByTestId(`audit-row-${MOCK_AUDIT_DRIFT_EVENT_ID}`),
    ).toBeVisible();
    await expect(
      page.getByTestId(`audit-chain-badge-${MOCK_AUDIT_DRIFT_EVENT_ID}`),
    ).toBeVisible();
  });

  test("super-admin verifies chain → OK banner", async ({ context, page }) => {
    await loginAs(context, "super-admin");
    await gotoAdminAuditLogs(page);
    await waitForAuditCounter(page);
    await waitForTableSettled(page, "audit-logs-table");

    // 4 audit rows, all visible cross-tenant.
    await expect(page.getByTestId("audit-counter")).toHaveText("4 / 4");

    // The verify-chain CTA lives in the filter bar; matched by stable testid.
    const verifyBtn = page.getByTestId("audit-verify-chain");
    await expect(verifyBtn).toBeVisible();
    await verifyBtn.click();

    // Default mock response is `ok: true` so the green banner appears.
    const okBanner = page.getByTestId("audit-chain-ok");
    await expect(okBanner).toBeVisible({ timeout: 10_000 });

    // No drift banner is rendered alongside the success.
    await expect(page.getByTestId("audit-chain-drift")).toHaveCount(0);
  });

  test("super-admin triggers DRIFT verdict via magic event_type filter", async ({
    context,
    page,
  }) => {
    await loginAs(context, "super-admin");
    await gotoAdminAuditLogs(page, { eventType: VERIFY_DRIFT_TRIGGER });
    await waitForAuditCounter(page);
    // The list will be empty (no audit row uses that event_type) — that
    // is acceptable: the contract under test is the verify-chain banner.
    await waitForTableSettled(page, "audit-logs-table");
    await assertNoLeakOverlay(page);

    await expect(page.getByTestId("audit-counter")).toHaveText("0 / 0");

    await page.getByTestId("audit-verify-chain").click();

    const driftBanner = page.getByTestId("audit-chain-drift");
    await expect(driftBanner).toBeVisible({ timeout: 10_000 });
    // The drift banner carries a `<code>` element with the drift event id
    // returned by the mock. Substring match is sufficient — we don't want
    // to over-couple to copy.
    await expect(driftBanner).toContainText(MOCK_AUDIT_DRIFT_EVENT_ID);

    // No success banner alongside the drift one.
    await expect(page.getByTestId("audit-chain-ok")).toHaveCount(0);

    // Dismiss should clear the banner without throwing the page into
    // an error state — quick smoke that the dismiss handler is wired.
    await driftBanner.getByTestId("audit-chain-dismiss").click();
    await expect(page.getByTestId("audit-chain-drift")).toHaveCount(0);
  });
});
