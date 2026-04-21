/**
 * Functional E2E coverage for `/admin/operations` (T36, ARG-052+053).
 *
 * Verified surfaces:
 *   1. RBAC visibility — `super-admin` sees both panels; `admin` sees the
 *      throttle panel + a super-admin-only notice instead of the global
 *      kill-switch; `operator` is redirected to `/admin/forbidden`.
 *   2. Per-tenant throttle flow — open dialog, write reason, submit, badge
 *      flips to `data-state="active"` after refetch.
 *   3. Global STOP-ALL flow — typed-phrase + reason gate, banner flips to
 *      `data-state="active"`, audit-trail row materialises.
 *   4. Global RESUME-ALL flow — banner flips back to `data-state="normal"`.
 *   5. Audit-trail manual refresh button triggers a refetch.
 *
 * Why a separate spec rather than another describe-block in
 * `admin-rbac.spec.ts`:
 *   The state-mutation tests need a deterministic mock-backend reset
 *   between cases (see `resetMockBackend`). Mixing those into the
 *   read-only RBAC spec would couple the two suites' test ordering.
 *
 * Determinism:
 *   - `resetMockBackend()` runs in `beforeEach` so a STOP from one test
 *     never bleeds into the next test's tenant-throttle attempt.
 *   - We pin `serial` mode below so the mock state machine is mutated by
 *     exactly one worker at a time. The mock isn't transactional so a
 *     parallel STOP from another worker would corrupt this worker's
 *     `data-state="normal"` precondition.
 */

import { expect, test } from "@playwright/test";

import { MOCK_TENANT_PRIMARY } from "./fixtures/admin-backend-mock";
import {
  assertNoLeakOverlay,
  gotoAdminOperations,
  loginAs,
  resetMockBackend,
} from "./fixtures/admin-helpers";

const STOP_PHRASE = "STOP ALL SCANS";
const RESUME_PHRASE = "RESUME ALL SCANS";

test.describe.configure({ mode: "serial" });

test.beforeEach(async () => {
  await resetMockBackend();
});

test.describe("admin operations — RBAC visibility (T36)", () => {
  test("operator → redirected to /admin/forbidden", async ({
    context,
    page,
  }) => {
    await loginAs(context, "operator");
    await page.goto("/admin/operations");
    await page.waitForURL("**/admin/forbidden", { timeout: 10_000 });
    await expect(page.getByTestId("admin-forbidden-page")).toBeVisible();
    await expect(page.getByTestId("global-kill-switch-client")).toHaveCount(0);
    await expect(page.getByTestId("per-tenant-throttle-client")).toHaveCount(0);
  });

  test("admin → throttle panel + super-admin-only notice", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin");
    await gotoAdminOperations(page);

    await expect(
      page.getByTestId("per-tenant-throttle-client"),
    ).toBeVisible();
    await expect(
      page.getByTestId("global-kill-switch-admin-notice"),
    ).toBeVisible();
    await expect(page.getByTestId("global-kill-switch-client")).toHaveCount(0);

    // The selector is hidden for `admin` (pinned to session.tenantId) —
    // exercising the RBAC narrowing rather than just the visual chrome.
    await expect(
      page.getByTestId("throttle-tenant-selector-row"),
    ).toHaveCount(0);
  });

  test("super-admin → both panels rendered with default normal state", async ({
    context,
    page,
  }) => {
    await loginAs(context, "super-admin");
    await gotoAdminOperations(page);

    await expect(
      page.getByTestId("per-tenant-throttle-client"),
    ).toBeVisible();
    await expect(
      page.getByTestId("global-kill-switch-client"),
    ).toBeVisible();
    await expect(
      page.getByTestId("global-kill-switch-banner"),
    ).toHaveAttribute("data-state", "normal");

    // Super-admin sees the tenant selector, but the actual options arrive
    // asynchronously from `listTenants` — wait for at least one option.
    const select = page.getByTestId("throttle-tenant-select");
    await expect(select).toBeVisible();
    await expect(select.locator("option")).not.toHaveCount(0);
  });
});

test.describe("admin operations — per-tenant throttle (T36 / T29)", () => {
  test("admin throttles their own tenant → badge flips to active", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin");
    await gotoAdminOperations(page);

    // Precondition: badge starts in `inactive` state.
    await expect(
      page.getByTestId("throttle-status-badge"),
    ).toHaveAttribute("data-state", "inactive");

    await page.getByTestId("throttle-open-dialog").click();
    await expect(page.getByTestId("throttle-dialog")).toBeVisible();

    // Tenant is pinned for `admin`; only duration + reason are interactive.
    await expect(
      page.getByTestId("throttle-dialog-tenant"),
    ).toHaveCount(0);
    await expect(
      page.getByTestId("throttle-dialog-tenant-pinned"),
    ).toHaveAttribute("value", MOCK_TENANT_PRIMARY);

    await page
      .getByTestId("throttle-dialog-reason")
      .fill("Suspicious scan from CIDR 198.51.100.0/24, throttling 15 min.");

    await page.getByTestId("throttle-dialog-confirm").click();

    // Dialog closes on success.
    await expect(page.getByTestId("throttle-dialog")).toHaveCount(0);

    // Badge flips to `active` after `refetchStatus` resolves; we do not
    // wait for the polling tick — `handleThrottleSuccess` triggers an
    // immediate refetch.
    await expect(
      page.getByTestId("throttle-status-badge"),
    ).toHaveAttribute("data-state", "active", { timeout: 10_000 });

    // The "Resume now" button is rendered when a throttle is active.
    await expect(page.getByTestId("throttle-resume-now")).toBeVisible();

    await assertNoLeakOverlay(page);
  });

  test("submit blocked when reason is too short", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin");
    await gotoAdminOperations(page);

    await page.getByTestId("throttle-open-dialog").click();
    await page.getByTestId("throttle-dialog-reason").fill("short");

    const confirm = page.getByTestId("throttle-dialog-confirm");
    await expect(confirm).toBeDisabled();
    await expect(confirm).toHaveAttribute("aria-disabled", "true");
  });
});

test.describe("admin operations — global STOP-ALL (T36 / T30)", () => {
  test("super-admin STOP-ALL flips banner + audit row appears", async ({
    context,
    page,
  }) => {
    await loginAs(context, "super-admin");
    await gotoAdminOperations(page);

    await expect(
      page.getByTestId("global-kill-switch-banner"),
    ).toHaveAttribute("data-state", "normal");

    await page.getByTestId("global-kill-switch-open-stop").click();
    await expect(page.getByTestId("kill-switch-dialog")).toBeVisible();

    // Submit must stay disabled until BOTH conditions hold.
    const confirm = page.getByTestId("kill-switch-dialog-confirm");
    await expect(confirm).toBeDisabled();

    await page.getByTestId("kill-switch-dialog-phrase").fill(STOP_PHRASE);
    await page
      .getByTestId("kill-switch-dialog-reason")
      .fill("Confirmed supply-chain incident, killing dispatch.");

    await expect(confirm).toBeEnabled();
    await confirm.click();

    // Dialog closes; banner flips to `active`.
    await expect(page.getByTestId("kill-switch-dialog")).toHaveCount(0);
    await expect(
      page.getByTestId("global-kill-switch-banner"),
    ).toHaveAttribute("data-state", "active", { timeout: 10_000 });

    // Action info banner surfaces with cancel-count from the mock.
    await expect(
      page.getByTestId("global-kill-switch-action-info"),
    ).toBeVisible();

    // Audit-trail picks up the new row. We don't assert a specific id —
    // the mock issues sequential ids so a parallel test would shift them;
    // instead we wait for at least one row.
    const auditTable = page.getByTestId("emergency-audit-trail");
    await expect(auditTable).toBeVisible();
    await expect(auditTable.locator('[data-testid^="emergency-audit-row-"]'))
      .not.toHaveCount(0);

    await assertNoLeakOverlay(page);
  });

  test("super-admin RESUME-ALL flips banner back to normal", async ({
    context,
    page,
  }) => {
    await loginAs(context, "super-admin");
    await gotoAdminOperations(page);

    // 1. STOP first so RESUME has something to lift.
    await page.getByTestId("global-kill-switch-open-stop").click();
    await page.getByTestId("kill-switch-dialog-phrase").fill(STOP_PHRASE);
    await page
      .getByTestId("kill-switch-dialog-reason")
      .fill("Setting up RESUME flow precondition.");
    await page.getByTestId("kill-switch-dialog-confirm").click();
    await expect(
      page.getByTestId("global-kill-switch-banner"),
    ).toHaveAttribute("data-state", "active", { timeout: 10_000 });

    // 2. The STOP-ALL button is replaced by the RESUME-ALL button when
    //    the banner is `active`.
    await page.getByTestId("global-kill-switch-open-resume").click();
    await expect(page.getByTestId("resume-all-dialog")).toBeVisible();

    await page.getByTestId("resume-all-dialog-phrase").fill(RESUME_PHRASE);
    await page
      .getByTestId("resume-all-dialog-reason")
      .fill("Incident closed, lifting global stop.");
    await page.getByTestId("resume-all-dialog-confirm").click();

    await expect(page.getByTestId("resume-all-dialog")).toHaveCount(0);
    await expect(
      page.getByTestId("global-kill-switch-banner"),
    ).toHaveAttribute("data-state", "normal", { timeout: 10_000 });

    await assertNoLeakOverlay(page);
  });

  test("STOP-ALL refuses to submit without correct phrase", async ({
    context,
    page,
  }) => {
    await loginAs(context, "super-admin");
    await gotoAdminOperations(page);

    await page.getByTestId("global-kill-switch-open-stop").click();
    await page
      .getByTestId("kill-switch-dialog-phrase")
      .fill("stop all scans"); // wrong case → backend never called
    await page
      .getByTestId("kill-switch-dialog-reason")
      .fill("Verifying client-side phrase gate.");

    const confirm = page.getByTestId("kill-switch-dialog-confirm");
    await expect(confirm).toBeDisabled();
    await expect(confirm).toHaveAttribute("aria-disabled", "true");

    // Banner must NOT have flipped because the action never reached the
    // mock. This guards against a regression where the typed-phrase check
    // is moved to the server alone — a soft check.
    await expect(
      page.getByTestId("global-kill-switch-banner"),
    ).toHaveAttribute("data-state", "normal");
  });
});

test.describe("admin operations — audit refresh (T36)", () => {
  test("manual refresh button triggers refetch of audit-trail", async ({
    context,
    page,
  }) => {
    await loginAs(context, "super-admin");
    await gotoAdminOperations(page);

    // Capture initial last-fetched timestamp text.
    const initialFetchedAt = await page
      .getByTestId("emergency-audit-last-fetched")
      .textContent();

    // Triggering a STOP-ALL appends a row in the mock; clicking refresh
    // should pick it up. Use the refresh button explicitly so a future
    // change to the auto-refresh policy doesn't silently make the test
    // pass without exercising the manual refetch path.
    await page.getByTestId("global-kill-switch-open-stop").click();
    await page.getByTestId("kill-switch-dialog-phrase").fill(STOP_PHRASE);
    await page
      .getByTestId("kill-switch-dialog-reason")
      .fill("Audit refresh smoke test.");
    await page.getByTestId("kill-switch-dialog-confirm").click();
    await expect(
      page.getByTestId("global-kill-switch-banner"),
    ).toHaveAttribute("data-state", "active", { timeout: 10_000 });

    // Click refresh — the timestamp text must change at least once.
    await page.getByTestId("emergency-audit-refresh").click();
    await expect
      .poll(
        async () =>
          page.getByTestId("emergency-audit-last-fetched").textContent(),
        { timeout: 10_000 },
      )
      .not.toBe(initialFetchedAt);
  });
});
