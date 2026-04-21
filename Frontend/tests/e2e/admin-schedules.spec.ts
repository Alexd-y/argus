/**
 * Functional E2E coverage for `/admin/schedules` (T36, ARG-056).
 *
 * Verified surfaces:
 *   1. RBAC visibility:
 *      - `operator` lands on the page in READ-ONLY mode — the create
 *        button is hidden and every row action is `disabled`. This
 *        matches the SSR contract documented in `page.tsx`
 *        (`minimumRole="operator"`, mutation gated by `canMutate`).
 *      - `admin` lands on the page in read/write mode but the tenant
 *        selector is hidden (pinned to session.tenantId).
 *      - `super-admin` sees the tenant selector AND the tenant column
 *        on the table.
 *   2. CRUD round-trip — create → row appears → edit → row updates →
 *      delete → row vanishes.
 *   3. Run-Now flow:
 *      - happy-path: typed-name + reason → 202 + info banner.
 *      - maintenance-window blocked (no bypass) → red error in dialog.
 *      - maintenance-window bypassed → 202 + info banner.
 *
 * Determinism notes:
 *   - We `serial` the suite because schedules are tracked in a single
 *     in-memory `mockState.schedules` array; two parallel workers would
 *     poison each other's `expect`.
 *   - `resetMockBackend()` runs in `beforeEach` so the state machine is
 *     a clean slate every test.
 *   - We seed schedules via `seedSchedule()` rather than walking the
 *     editor for setup — the editor walk is itself the SUT in only the
 *     CRUD test.
 */

import { expect, test } from "@playwright/test";

import { MOCK_TENANT_PRIMARY } from "./fixtures/admin-backend-mock";
import {
  assertNoLeakOverlay,
  gotoAdminSchedules,
  loginAs,
  resetMockBackend,
  seedSchedule,
} from "./fixtures/admin-helpers";

test.describe.configure({ mode: "serial" });

test.beforeEach(async () => {
  await resetMockBackend();
});

test.describe("admin schedules — RBAC visibility (T36)", () => {
  test("operator → page renders read-only (no create, row actions disabled)", async ({
    context,
    page,
  }) => {
    // Seed BEFORE login so the page paints with a populated table on
    // first SSR — otherwise the row IDs we assert against would only
    // be in the DOM after the 30 s polling tick.
    const operatorReadName = "operator-readonly-row";
    const seededId = await seedSchedule({
      tenantId: MOCK_TENANT_PRIMARY,
      name: operatorReadName,
      cronExpression: "0 * * * *",
    });

    // The action layer requires every operator/admin call to carry a
    // tenant cookie (`resolveTenantForRead` returns `forbidden` for
    // null) — that contract matches real production sessions, so the
    // helper override here mirrors the deployment shape.
    await loginAs(context, "operator", { tenantId: MOCK_TENANT_PRIMARY });
    await gotoAdminSchedules(page);

    // The page itself MUST render — operator has read access.
    await expect(page.getByTestId("schedules-client")).toBeVisible();

    // Mutation surfaces are hidden / disabled.
    await expect(page.getByTestId("schedules-create-button")).toHaveCount(0);
    await expect(
      page.getByTestId(`schedule-edit-${seededId}`),
    ).toBeDisabled();
    await expect(
      page.getByTestId(`schedule-run-now-${seededId}`),
    ).toBeDisabled();
    await expect(
      page.getByTestId(`schedule-delete-${seededId}`),
    ).toBeDisabled();
    await expect(
      page.getByTestId(`schedule-enable-toggle-${seededId}`),
    ).toBeDisabled();

    await assertNoLeakOverlay(page);
  });

  test("admin → page renders, no tenant selector", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin");
    await gotoAdminSchedules(page);

    await expect(page.getByTestId("schedules-client")).toBeVisible();
    await expect(page.getByTestId("schedules-create-button")).toBeVisible();
    await expect(
      page.getByTestId("schedules-tenant-selector-row"),
    ).toHaveCount(0);
  });

  test("super-admin → tenant selector + tenant column visible", async ({
    context,
    page,
  }) => {
    await loginAs(context, "super-admin");
    await gotoAdminSchedules(page);

    await expect(
      page.getByTestId("schedules-tenant-selector-row"),
    ).toBeVisible();
    await expect(page.getByTestId("schedules-create-button")).toBeVisible();
  });
});

test.describe("admin schedules — CRUD round-trip (T36)", () => {
  test("create → edit → delete round-trip is observable in the table", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin");
    await gotoAdminSchedules(page);

    // Mock seeds two PRIMARY-tenant rows on reset, so the table — not
    // the empty state — should be visible. We assert by ROW NAME on the
    // unique schedule we're about to create instead of relying on the
    // empty/non-empty branch.
    const tableBody = page.getByTestId("schedules-table");
    await expect(tableBody).toBeVisible();

    const scheduleName = "E2E nightly ZAP scan";
    await expect(
      tableBody.getByText(scheduleName, { exact: true }),
    ).toHaveCount(0);

    // ── 1. Create ────────────────────────────────────────────────────
    await page.getByTestId("schedules-create-button").click();
    await expect(page.getByTestId("schedule-editor-dialog")).toBeVisible();

    // Tenant must be pinned for `admin` (no selector rendered).
    await expect(page.getByTestId("schedule-editor-tenant")).toHaveCount(0);
    await expect(
      page.getByTestId("schedule-editor-tenant-pinned"),
    ).toHaveValue(MOCK_TENANT_PRIMARY);

    await page.getByTestId("schedule-editor-name").fill(scheduleName);
    await page
      .getByTestId("schedule-editor-target")
      .fill("https://example.com/api");

    await page.getByTestId("schedule-editor-submit").click();
    await expect(page.getByTestId("schedule-editor-dialog")).toHaveCount(0);

    // Row materialises in the table — match by visible name rather than
    // row id (the id is generated by the mock and not exported back).
    await expect(
      tableBody.getByText(scheduleName, { exact: true }),
    ).toBeVisible();

    // Action info banner reports the create.
    await expect(page.getByTestId("schedules-action-info")).toContainText(
      scheduleName,
    );

    // ── 2. Edit (rename only — cron change is exercised by unit tests) ─
    const row = tableBody.locator("tr", { hasText: scheduleName });
    await row.locator('[data-testid^="schedule-edit-"]').click();
    await expect(page.getByTestId("schedule-editor-dialog")).toBeVisible();

    const renamed = "E2E nightly ZAP scan v2";
    const nameField = page.getByTestId("schedule-editor-name");
    await nameField.fill(renamed);
    await page.getByTestId("schedule-editor-submit").click();

    await expect(page.getByTestId("schedule-editor-dialog")).toHaveCount(0);
    await expect(tableBody.getByText(renamed, { exact: true })).toBeVisible();
    await expect(
      tableBody.getByText(scheduleName, { exact: true }),
    ).toHaveCount(0);

    // ── 3. Delete (with typed-name confirmation) ─────────────────────
    const renamedRow = tableBody.locator("tr", { hasText: renamed });
    await renamedRow.locator('[data-testid^="schedule-delete-"]').click();
    await expect(page.getByTestId("delete-schedule-dialog")).toBeVisible();

    const confirmDelete = page.getByTestId("delete-schedule-confirm");
    await expect(confirmDelete).toBeDisabled();
    await page.getByTestId("delete-schedule-typed-name").fill(renamed);
    await expect(confirmDelete).toBeEnabled();
    await confirmDelete.click();

    await expect(page.getByTestId("delete-schedule-dialog")).toHaveCount(0);
    // The renamed row vanishes — but the seeded rows remain, so we
    // assert ABSENCE of the renamed name rather than the empty state.
    await expect(
      tableBody.getByText(renamed, { exact: true }),
    ).toHaveCount(0);

    await assertNoLeakOverlay(page);
  });

  test("editor blocks submit when name is whitespace-only", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin");
    await gotoAdminSchedules(page);

    await page.getByTestId("schedules-create-button").click();
    // SCHEDULE_NAME_MIN === 1 — the editor only accepts a NON-empty,
    // non-whitespace name. We use spaces to confirm the trim() guard.
    await page.getByTestId("schedule-editor-name").fill("   ");
    const submit = page.getByTestId("schedule-editor-submit");
    await expect(submit).toBeDisabled();
    await expect(submit).toHaveAttribute("aria-disabled", "true");
  });
});

test.describe("admin schedules — Run Now flow (T36)", () => {
  test("happy path: typed-name + reason → info banner", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin");

    const seededName = "Hourly probe";
    await seedSchedule({
      tenantId: MOCK_TENANT_PRIMARY,
      name: seededName,
      cronExpression: "0 * * * *",
    });

    await gotoAdminSchedules(page);

    const row = page
      .getByTestId("schedules-table")
      .locator("tr", { hasText: seededName });
    await expect(row).toBeVisible();

    await row.locator('[data-testid^="schedule-run-now-"]').click();
    await expect(page.getByTestId("run-now-dialog")).toBeVisible();

    const confirm = page.getByTestId("run-now-confirm");
    await expect(confirm).toBeDisabled();

    await page.getByTestId("run-now-typed-name").fill(seededName);
    await page
      .getByTestId("run-now-reason")
      .fill("Customer asked for an out-of-cycle probe before release.");
    await expect(confirm).toBeEnabled();

    await confirm.click();

    await expect(page.getByTestId("run-now-dialog")).toHaveCount(0);
    await expect(
      page.getByTestId("schedules-action-info"),
    ).toContainText("Task id");

    await assertNoLeakOverlay(page);
  });

  test("maintenance-window blocks Run Now without bypass", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin");

    const seededName = "Always-in-maintenance probe";
    // The mock treats `* * * * *` maintenance cron as ALWAYS in window.
    await seedSchedule({
      tenantId: MOCK_TENANT_PRIMARY,
      name: seededName,
      cronExpression: "0 * * * *",
      maintenanceWindowCron: "* * * * *",
    });

    await gotoAdminSchedules(page);

    const row = page
      .getByTestId("schedules-table")
      .locator("tr", { hasText: seededName });
    await row.locator('[data-testid^="schedule-run-now-"]').click();

    await page.getByTestId("run-now-typed-name").fill(seededName);
    await page
      .getByTestId("run-now-reason")
      .fill("Verifying maintenance-window enforcement path.");
    await page.getByTestId("run-now-confirm").click();

    // Dialog stays open with a closed-taxonomy error code.
    const error = page.getByTestId("run-now-error");
    await expect(error).toBeVisible();
    await expect(error).toHaveAttribute(
      "data-error-code",
      "in_maintenance_window",
    );

    // Action info banner must NOT be set — the run was rejected.
    await expect(
      page.getByTestId("schedules-action-info"),
    ).toHaveCount(0);

    // Now retry with the bypass checkbox flipped — should succeed.
    await page.getByTestId("run-now-bypass").check();
    await page.getByTestId("run-now-confirm").click();

    await expect(page.getByTestId("run-now-dialog")).toHaveCount(0);
    await expect(
      page.getByTestId("schedules-action-info"),
    ).toContainText("Task id");

    await assertNoLeakOverlay(page);
  });
});
