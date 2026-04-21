/**
 * Functional E2E coverage for the SARIF / JUnit export toggle (T23) —
 * Cycle 6.
 *
 * The toggle lives inside the scan-detail drawer on `/admin/scans` and
 * persists the chosen format in `localStorage` so the operator's
 * pipeline preference survives a refresh. Both behaviours are pinned
 * here:
 *
 *   1. Download flow: switch to JUnit, click Скачать, assert the request
 *      hits `/api/v1/scans/<id>/findings/export?format=junit` and the
 *      mock backend's JUnit body comes back with the right content-type.
 *   2. Persistence: the chosen format survives a drawer close+reopen
 *      because `ExportFormatToggle` reads from `localStorage` on mount.
 *
 * The download itself uses a `<a download>` click against a blob URL
 * (see `lib/findingsExport.ts::downloadFindingsExport`), which Playwright
 * exposes through `page.waitForEvent('download')`. We use both signals
 * — the fetch response AND the download — so a regression in either
 * the network call or the anchor click trips a fail.
 */

import { expect, test } from "@playwright/test";

import {
  loginAs,
  gotoAdminScans,
  assertNoLeakOverlay,
} from "./fixtures/admin-helpers";
import { MOCK_SCAN_PRIMARY } from "./fixtures/admin-backend-mock";

/**
 * Wait for the scan-detail drawer to render with a hydrated export toggle.
 * `ExportFormatToggle` only enables the Download button after a
 * `useEffect` reads the persisted format from `localStorage`, so we wait
 * for the button to be enabled before asserting on selections.
 */
async function openScanDetailWithToggleReady(
  page: import("@playwright/test").Page,
  scanId: string,
) {
  await page.getByTestId(`scans-row-details-${scanId}`).click();
  const drawer = page.getByTestId("scans-detail-drawer");
  await expect(drawer).toBeVisible();
  await expect(page.getByTestId("export-format-toggle")).toBeVisible();
  await expect(page.getByTestId("export-format-download")).toBeEnabled({
    timeout: 5_000,
  });
}

test.describe("admin export toggle — functional E2E (T27)", () => {
  test("admin switches to JUnit and downloads", async ({ context, page }) => {
    await loginAs(context, "admin");
    // Make sure no stale persisted preference biases this test — the
    // worker context is fresh anyway, but explicit beats implicit.
    await page.addInitScript(() => {
      try {
        localStorage.removeItem("argus.export.format");
      } catch {
        // ignore
      }
    });

    await gotoAdminScans(page);
    await assertNoLeakOverlay(page);

    // Wait for the scan row to render before clicking its action.
    await expect(
      page.getByTestId(`scans-row-${MOCK_SCAN_PRIMARY}`),
    ).toBeVisible({ timeout: 15_000 });

    await openScanDetailWithToggleReady(page, MOCK_SCAN_PRIMARY);

    // Default is SARIF; switch to JUnit.
    await page.getByTestId("export-format-junit").check();
    await expect(page.getByTestId("export-format-toggle")).toHaveAttribute(
      "data-format",
      "junit",
    );

    // Both signals must fire: a fetch to the JUnit URL AND a download.
    const responsePromise = page.waitForResponse(
      (res) =>
        res.url().includes(`/findings/export?format=junit`) &&
        res.url().includes(MOCK_SCAN_PRIMARY) &&
        res.status() === 200,
    );
    const downloadPromise = page.waitForEvent("download");

    await page.getByTestId("export-format-download").click();

    const response = await responsePromise;
    expect(response.headers()["content-type"]).toContain("xml");

    const download = await downloadPromise;
    // The suggested filename in `lib/findingsExport.ts::suggestExportFilename`
    // ends with `.junit.xml` for JUnit; sanity-check the contract.
    expect(download.suggestedFilename()).toMatch(/\.junit\.xml$/);

    // No closed-taxonomy error banner should have surfaced.
    await expect(page.getByTestId("export-format-error")).toHaveCount(0);
  });

  test("export format persists in localStorage across drawer reopen", async ({
    context,
    page,
  }) => {
    await loginAs(context, "admin");
    await page.addInitScript(() => {
      try {
        localStorage.removeItem("argus.export.format");
      } catch {
        // ignore
      }
    });

    await gotoAdminScans(page);
    await expect(
      page.getByTestId(`scans-row-${MOCK_SCAN_PRIMARY}`),
    ).toBeVisible({ timeout: 15_000 });

    // First open: default = SARIF, switch to JUnit, assert persistence.
    await openScanDetailWithToggleReady(page, MOCK_SCAN_PRIMARY);
    await page.getByTestId("export-format-junit").check();
    await expect(page.getByTestId("export-format-toggle")).toHaveAttribute(
      "data-format",
      "junit",
    );

    // Verify localStorage actually carries the value the toggle persisted.
    const stored = await page.evaluate(() =>
      window.localStorage.getItem("argus.export.format"),
    );
    expect(stored).toBe("junit");

    // Close the drawer.
    await page.getByTestId("scans-detail-close").click();
    await expect(page.getByTestId("scans-detail-drawer")).toHaveCount(0);

    // Re-open the same scan's drawer — the new ExportFormatToggle mount
    // should read JUnit from `localStorage` and pre-select it.
    await openScanDetailWithToggleReady(page, MOCK_SCAN_PRIMARY);
    await expect(page.getByTestId("export-format-toggle")).toHaveAttribute(
      "data-format",
      "junit",
    );
    await expect(page.getByTestId("export-format-junit")).toBeChecked();
    await expect(page.getByTestId("export-format-sarif")).not.toBeChecked();
  });
});
