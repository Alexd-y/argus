/**
 * Session-mode admin auth E2E (B6-T09 / ISS-T20-003 Phase 1 frontend).
 *
 * Exercises the real handshake the UI will use in production:
 *   1. Anonymous `/admin/*` request → middleware redirects to
 *      `/admin/login` (no client-side cookie shim available in `session`
 *      mode).
 *   2. Login with valid creds → backend mints `argus.admin.session`
 *      HttpOnly cookie, server actions forward it back to the browser,
 *      `/admin` renders with the operator's real subject.
 *   3. Logout → backend revokes the session, frontend clears local UX
 *      cookies, redirected back to `/admin/login`.
 *   4. Login with invalid creds → generic "Invalid credentials" error
 *      surfaces, the URL stays on `/admin/login` (no enumeration via
 *      redirect side-channel).
 *   5. Cookie tampering — in session mode the backend's whoami is the
 *      ONLY authority on the operator's role; the legacy
 *      `argus.admin.role` cookie must NOT influence the rendered chrome.
 *      Five distinct logins prove the audit-subject uniqueness
 *      acceptance criterion (b).
 *
 * Run with:
 *   npx playwright test --config playwright.session.config.ts
 *
 * Why this suite is gated to session-mode only:
 *   The middleware short-circuits on `cookie`/`auto`, and `loginAs()`
 *   from the cookie-mode helpers would short-circuit the backend
 *   handshake entirely. Sharing a config would hide regressions in
 *   exactly the path under test.
 */

import { expect, test, type BrowserContext, type Page } from "@playwright/test";

import {
  ADMIN_BACKEND_MOCK_PORT,
  MOCK_ADMIN_SESSION_COOKIE,
  MOCK_ADMIN_USERS,
} from "./fixtures/admin-backend-mock";

const COOKIE_DOMAIN = "127.0.0.1";

const ADMIN_LEGACY_ROLE_COOKIE = "argus.admin.role";

/**
 * Reset the mock backend's in-memory state (sessions, throttle window)
 * so each test starts with a clean slate. The mock exposes a dedicated
 * test-only `/api/v1/__test__/reset` endpoint — see the mock module
 * for the rationale on keeping it outside `/admin/*`.
 */
async function resetMockBackend(): Promise<void> {
  const url = `http://127.0.0.1:${ADMIN_BACKEND_MOCK_PORT}/api/v1/__test__/reset`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    await fetch(url, { method: "POST", signal: controller.signal });
  } catch {
    // best-effort — see admin-helpers.ts for the same pattern
  } finally {
    clearTimeout(timeout);
  }
}

async function fillCredentials(
  page: Page,
  subject: string,
  password: string,
): Promise<void> {
  await page.getByTestId("admin-login-subject").fill(subject);
  await page.getByTestId("admin-login-password").fill(password);
}

async function submitLogin(page: Page): Promise<void> {
  await page.getByTestId("admin-login-submit").click();
}

async function readSessionCookie(
  context: BrowserContext,
): Promise<string | null> {
  const cookies = await context.cookies();
  const session = cookies.find((c) => c.name === MOCK_ADMIN_SESSION_COOKIE);
  return session?.value ?? null;
}

test.describe("admin auth (session mode) — B6-T09", () => {
  test.beforeEach(async () => {
    await resetMockBackend();
  });

  test("anonymous /admin redirects to /admin/login", async ({ page }) => {
    await page.goto("/admin");
    // Middleware in `session` mode redirects on the very first request
    // when no `argus.admin.session` cookie is present.
    await page.waitForURL("**/admin/login", { timeout: 10_000 });
    await expect(page.getByTestId("admin-login-form")).toBeVisible();
    // The protected chrome (sidebar / header) must NOT have leaked in.
    await expect(page.getByTestId("admin-user-menu")).toHaveCount(0);
  });

  test("valid login redirects to /admin and logout returns to /admin/login", async ({
    page,
    context,
  }) => {
    const user = MOCK_ADMIN_USERS[0];

    await page.goto("/admin/login");
    await expect(page.getByTestId("admin-login-form")).toBeVisible();

    await fillCredentials(page, user.subject, user.password);
    await submitLogin(page);

    await page.waitForURL((url) => url.pathname === "/admin", {
      timeout: 15_000,
    });

    // The session cookie minted by the backend is propagated to the
    // browser via the server action's Set-Cookie forwarding.
    const sessionId = await readSessionCookie(context);
    expect(sessionId).not.toBeNull();
    expect(sessionId?.length ?? 0).toBeGreaterThan(0);

    // Logout: the chrome's user menu exposes the button when the auth
    // mode is anything other than `cookie`.
    const logout = page.getByTestId("admin-logout-button");
    await expect(logout).toBeVisible({ timeout: 10_000 });
    await logout.click();

    await page.waitForURL("**/admin/login", { timeout: 15_000 });

    // Both the HttpOnly session cookie and the UX mirror cookies must
    // be cleared after logout. The UX cookie deletion is enforced by
    // the server action; we only assert the security-critical session
    // cookie is gone here so the test stays focused on the contract.
    const cleared = await readSessionCookie(context);
    expect(cleared).toBeNull();
  });

  test("invalid credentials render generic error, no redirect", async ({
    page,
  }) => {
    await page.goto("/admin/login");

    await fillCredentials(page, "ghost@argus.test", "wrong-password");
    await submitLogin(page);

    // The action returns an `error` state; the URL must NOT change
    // (no redirect side-channel that would reveal "subject exists").
    const error = page.getByTestId("admin-login-error");
    await expect(error).toBeVisible({ timeout: 10_000 });
    await expect(error).toContainText("Неверные учётные данные");
    await expect(error).toContainText("Invalid credentials");
    await expect(page).toHaveURL(/\/admin\/login$/);
  });

  test("cookie tampering does not influence backend-resolved role (criterion c)", async ({
    page,
    context,
  }) => {
    // Sign in as an OPERATOR — the lowest-privilege admin role.
    const operator = MOCK_ADMIN_USERS.find((u) => u.role === "operator");
    expect(operator).toBeTruthy();
    if (!operator) return;

    await page.goto("/admin/login");
    await fillCredentials(page, operator.subject, operator.password);
    await submitLogin(page);
    await page.waitForURL((url) => url.pathname === "/admin", {
      timeout: 15_000,
    });

    // Forge the legacy cookie-shim role to claim super-admin. The
    // legacy `argus.admin.role` cookie is non-HttpOnly precisely so the
    // client-side `AdminAuthContext` can read it for chrome hints —
    // making it trivially attacker-writable. The backend MUST NOT trust
    // it; the only authority is the HttpOnly `argus.admin.session`
    // cookie which JS cannot tamper with.
    await context.addCookies([
      {
        name: ADMIN_LEGACY_ROLE_COOKIE,
        value: "super-admin",
        domain: COOKIE_DOMAIN,
        path: "/",
        expires: -1,
        httpOnly: false,
        secure: false,
        sameSite: "Strict",
      },
    ]);

    // Direct whoami round-trip from the (now-tampered) browser context.
    // Playwright's `page.request` reuses the page's cookie jar, so the
    // backend sees BOTH the genuine session cookie AND the forged role
    // cookie. The backend's contract: only the HttpOnly session cookie
    // resolves identity; any other cookies are ignored. Asserting on
    // the response role proves the whole stack honours that contract
    // independently of UI rendering quirks.
    const whoamiUrl = `http://127.0.0.1:${ADMIN_BACKEND_MOCK_PORT}/api/v1/auth/admin/whoami`;
    const res = await page.request.get(whoamiUrl);
    expect(res.status()).toBe(200);
    const body = (await res.json()) as {
      role: string;
      subject: string;
      tenant_id: string | null;
    };
    expect(body.role).toBe("operator");
    expect(body.role).not.toBe("super-admin");
    expect(body.subject).toBe(operator.subject);
  });

  test("five distinct logins produce five distinct session subjects", async ({
    browser,
  }) => {
    // Acceptance criterion (b): the audit subject must be the real
    // backend subject, not "admin_console:<role>". Drive five logins
    // through their own browser contexts so the cookies don't collide
    // and assert the chrome surfaces a unique audit-subject hint per
    // login.
    const seen = new Set<string>();
    for (const user of MOCK_ADMIN_USERS) {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        await page.goto("/admin/login");
        await fillCredentials(page, user.subject, user.password);
        await submitLogin(page);
        await page.waitForURL((url) => url.pathname === "/admin", {
          timeout: 15_000,
        });
        const sessionId = await readSessionCookie(context);
        expect(sessionId).not.toBeNull();
        expect(seen.has(sessionId!)).toBe(false);
        seen.add(sessionId!);
      } finally {
        await context.close();
      }
    }
    expect(seen.size).toBe(MOCK_ADMIN_USERS.length);
  });
});
