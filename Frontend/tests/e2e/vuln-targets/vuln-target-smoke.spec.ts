import { expect, test } from "@playwright/test";

/**
 * Smoke against lab targets brought up via `infra/docker-compose.vuln-targets.yml`.
 * Requires E2E_VULN_TARGET + E2E_VULN_BASE_URL (see playwright.config.ts vuln-smoke project).
 */
const target = process.env.E2E_VULN_TARGET ?? "";

test.describe("vuln target smoke", () => {
  test("target responds with expected entry surface", async ({ page }) => {
    if (!target) {
      test.skip();
    }

    if (target === "juice-shop") {
      await page.goto("/");
      await expect(page.getByText(/juice shop/i).first()).toBeVisible({
        timeout: 20_000,
      });
      return;
    }

    if (target === "dvwa") {
      await page.goto("/login.php");
      await expect(page.locator("form#login_form")).toBeVisible({
        timeout: 20_000,
      });
      return;
    }

    if (target === "webgoat") {
      const user = process.env.E2E_WEBGOAT_USERNAME ?? "";
      const password = process.env.E2E_WEBGOAT_PASSWORD ?? "";
      if (!user || !password) {
        test.skip(
          true,
          "Set E2E_WEBGOAT_USERNAME and E2E_WEBGOAT_PASSWORD for login smoke (lab placeholders via CI env, not repo files).",
        );
      }
      await page.goto("/WebGoat/login");
      await page.locator('input[name="username"]').fill(user);
      await page.locator('input[name="password"]').fill(password);
      await page.locator('button[type="submit"]').click();
      await expect(page.getByText(/webgoat/i).first()).toBeVisible({
        timeout: 30_000,
      });
      return;
    }

    test.skip(true, `Unknown E2E_VULN_TARGET=${target}`);
  });
});
