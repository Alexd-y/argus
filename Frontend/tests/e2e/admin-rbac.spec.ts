/**
 * Functional E2E coverage for the admin RBAC redirect (T20–T23) — Cycle 6.
 *
 * Asserts that an `operator` (the lowest admin-console role) is redirected
 * to `/admin/forbidden` when they try to reach a privileged page. The
 * redirect is enforced client-side by `AdminRouteGuard` AND server-side
 * by every server action's `resolveBulkSession()` / `resolveEffectiveTenant()`
 * — but only the client redirect is observable here. The server-side
 * refusal is covered by the unit tests in `services/admin/serverSession.test.ts`.
 *
 * Why operator and not anonymous:
 *   "Anonymous" maps to "no role cookie" — the page guard redirects to
 *   `/admin/forbidden` for that case too. By using `operator` we cover
 *   the more interesting "valid login, insufficient privilege" branch
 *   that anonymous wouldn't exercise.
 */

import { expect, test } from "@playwright/test";

import { loginAs } from "./fixtures/admin-helpers";

test.describe("admin RBAC — functional E2E (T27)", () => {
  test("operator role is redirected from /admin/findings to /admin/forbidden", async ({
    context,
    page,
  }) => {
    await loginAs(context, "operator");
    await page.goto("/admin/findings");

    // The guard renders a loading skeleton while it resolves the role,
    // then triggers `router.replace("/admin/forbidden")`. Wait until the
    // URL settles.
    await page.waitForURL("**/admin/forbidden", { timeout: 10_000 });

    // The forbidden page renders a stable page-level testid. Asserting
    // both the URL and the testid catches a regression where the route
    // is correct but the page itself failed to render.
    await expect(page.getByTestId("admin-forbidden-page")).toBeVisible();

    // Belt-and-braces: the findings page's tell-tale UI markers must
    // NOT have leaked through (no rows, no counter, no bulk toolbar).
    // This guards against a future change that mistakenly renders the
    // page body alongside the redirect.
    await expect(page.getByTestId("findings-table")).toHaveCount(0);
    await expect(page.getByTestId("findings-counter")).toHaveCount(0);
    await expect(page.getByTestId("bulk-actions-toolbar")).toHaveCount(0);
  });
});
