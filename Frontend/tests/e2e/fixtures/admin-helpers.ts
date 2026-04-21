/**
 * Shared helpers for the T27 functional E2E suite.
 *
 * Why a separate helpers module:
 *   `admin-axe.spec.ts` already inlines a session-seeding helper, but T27
 *   adds four spec files with a richer interaction surface (filters,
 *   bulk dialogs, chain-verify drift, RBAC redirects). Centralising
 *   `loginAs`, `goto*` and a `waitForAdminReady` here keeps each spec
 *   focused on assertions instead of plumbing.
 *
 * Important security/test boundary:
 *   These helpers seed the COOKIE that `services/admin/serverSession.ts`
 *   reads, plus the matching `sessionStorage` entry that the client
 *   `AdminAuthContext` hydrates from. The mock backend pinned by
 *   `playwright.mock.config.ts` ignores `X-Admin-Key` enforcement, so
 *   these cookies cannot widen privileges against a real backend — a
 *   real deployment would still need a server-issued session token.
 */

import {
  expect,
  type BrowserContext,
  type Cookie,
  type Page,
} from "@playwright/test";

import {
  ADMIN_BACKEND_MOCK_KEY,
  ADMIN_BACKEND_MOCK_PORT,
  MOCK_TENANT_PRIMARY,
} from "./admin-backend-mock";

/** Closed taxonomy of admin roles the helpers know how to seed. */
export type AdminRole = "operator" | "admin" | "super-admin";

const ADMIN_ROLE_COOKIE = "argus.admin.role";
const ADMIN_TENANT_COOKIE = "argus.admin.tenant";
const ADMIN_SUBJECT_COOKIE = "argus.admin.subject";
const ADMIN_ROLE_STORAGE_KEY = "argus.admin.role";

const COOKIE_DOMAIN = "127.0.0.1";

function makeCookie(name: string, value: string): Cookie {
  return {
    name,
    value,
    domain: COOKIE_DOMAIN,
    path: "/",
    expires: -1,
    httpOnly: false,
    secure: false,
    sameSite: "Strict",
  };
}

export type LoginAsOptions = {
  /**
   * Override the tenant cookie. Defaults to {@link MOCK_TENANT_PRIMARY}
   * for `admin` (so the action layer's tenant binding succeeds), and
   * to no tenant cookie for `super-admin` (cross-tenant view by
   * default). `null` forces "no tenant cookie at all".
   */
  readonly tenantId?: string | null;
  /** Override the audit subject cookie (default: `admin_console:<role>:e2e`). */
  readonly subject?: string;
};

/**
 * Seed cookies and `sessionStorage` so both the server (cookie) and the
 * client (storage) agree on the role for this test. Must be called
 * BEFORE the first `page.goto()` so the very first server render already
 * sees the correct identity.
 *
 * `operator` is supported because some scenarios assert RBAC rejection.
 * The function still seeds the role cookie — the page guard then
 * redirects to `/admin/forbidden`.
 */
export async function loginAs(
  context: BrowserContext,
  role: AdminRole,
  opts: LoginAsOptions = {},
): Promise<void> {
  const subject = opts.subject ?? `admin_console:${role}:e2e`;

  let tenantId: string | null;
  if (opts.tenantId === null) {
    tenantId = null;
  } else if (opts.tenantId === undefined) {
    tenantId = role === "admin" ? MOCK_TENANT_PRIMARY : null;
  } else {
    tenantId = opts.tenantId;
  }

  const cookies: Cookie[] = [
    makeCookie(ADMIN_ROLE_COOKIE, role),
    makeCookie(ADMIN_SUBJECT_COOKIE, subject),
  ];
  if (tenantId) {
    cookies.push(makeCookie(ADMIN_TENANT_COOKIE, tenantId));
  }
  await context.addCookies(cookies);

  // Seed the client-side hydration source too. `AdminAuthContext` reads
  // sessionStorage on mount and overwrites the cookie via document.cookie,
  // so without this seed the very first client render would null out the
  // role cookie before the next request is issued.
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

/** Wait for the admin route guard to release the loading skeleton. */
export async function waitForAdminReady(page: Page): Promise<void> {
  await expect(page.locator('[data-testid="admin-gate-loading"]')).toHaveCount(
    0,
    { timeout: 15_000 },
  );
}

/**
 * Wait for a virtualized table component to settle into its steady state
 * (`aria-busy="false"`). Audit-log and findings tables both use this
 * convention so the helper is shared.
 */
export async function waitForTableSettled(
  page: Page,
  testId: string,
): Promise<void> {
  await expect(page.getByTestId(testId)).toHaveAttribute(
    "aria-busy",
    "false",
    { timeout: 15_000 },
  );
}

/**
 * Build a `/admin/findings` URL with optional filter query params.
 * Mirrors the URL shape that `AdminFindingsClient.writeFiltersToUrl`
 * produces so the page hydrates from the URL the same way it would
 * after a manual filter click.
 */
export type FindingsFilters = {
  readonly tenantId?: string;
  readonly severity?: ReadonlyArray<string>;
  readonly target?: string;
  readonly statusMode?: "open" | "false_positive";
  readonly since?: string;
  readonly until?: string;
};

function buildFindingsUrl(filters: FindingsFilters | undefined): string {
  if (!filters) return "/admin/findings";
  const sp = new URLSearchParams();
  if (filters.tenantId) sp.set("tenant_id", filters.tenantId);
  for (const sev of filters.severity ?? []) sp.append("severity", sev);
  if (filters.target) sp.set("target", filters.target);
  if (filters.statusMode) sp.set("status_mode", filters.statusMode);
  if (filters.since) sp.set("since", filters.since);
  if (filters.until) sp.set("until", filters.until);
  const qs = sp.toString();
  return qs ? `/admin/findings?${qs}` : "/admin/findings";
}

export async function gotoAdminFindings(
  page: Page,
  filters?: FindingsFilters,
): Promise<void> {
  await page.goto(buildFindingsUrl(filters));
  await waitForAdminReady(page);
}

export type AuditLogsFilters = {
  readonly tenantId?: string;
  readonly eventType?: string;
  readonly actorSubject?: string;
  readonly since?: string;
  readonly until?: string;
};

function buildAuditUrl(filters: AuditLogsFilters | undefined): string {
  if (!filters) return "/admin/audit-logs";
  const sp = new URLSearchParams();
  if (filters.tenantId) sp.set("tenant_id", filters.tenantId);
  if (filters.eventType) sp.set("event_type", filters.eventType);
  if (filters.actorSubject) sp.set("actor_subject", filters.actorSubject);
  if (filters.since) sp.set("since", filters.since);
  if (filters.until) sp.set("until", filters.until);
  const qs = sp.toString();
  return qs ? `/admin/audit-logs?${qs}` : "/admin/audit-logs";
}

export async function gotoAdminAuditLogs(
  page: Page,
  filters?: AuditLogsFilters,
): Promise<void> {
  await page.goto(buildAuditUrl(filters));
  await waitForAdminReady(page);
}

export async function gotoAdminScans(page: Page): Promise<void> {
  await page.goto("/admin/scans");
  await waitForAdminReady(page);
}

export async function gotoAdminOperations(page: Page): Promise<void> {
  await page.goto("/admin/operations");
  await waitForAdminReady(page);
}

export async function gotoAdminSchedules(page: Page): Promise<void> {
  await page.goto("/admin/schedules");
  await waitForAdminReady(page);
}

/**
 * Reset the mock backend's in-memory state (kill-switch, throttles,
 * schedules, emergency audit log, scans). Should be called BEFORE each
 * test that mutates state so the suite stays order-independent. The
 * mock is bound to a deterministic loopback port shared by every spec
 * so we hit it via raw fetch — using the `request` fixture here would
 * tunnel through the dev server and bypass the dedicated control
 * endpoint.
 */
/**
 * Seed a scan schedule directly into the mock backend. Bypasses the
 * Next.js server actions so a test that needs a pre-existing schedule
 * (e.g. delete / run-now / maintenance-window flow) doesn't have to
 * walk through the create-editor first. Returns the created schedule's
 * id so the caller can scope its assertions to that row.
 *
 * The mock honours `maintenance_window_cron === "* * * * *"` as a
 * sentinel that the schedule is ALWAYS in its maintenance window —
 * pass that value to exercise the run-now `in_maintenance_window`
 * 409 branch without a real cron parser.
 */
export type SeedScheduleInput = {
  readonly tenantId: string;
  readonly name: string;
  readonly cronExpression?: string;
  readonly targetUrl?: string;
  readonly scanMode?: "lite" | "standard" | "full";
  readonly enabled?: boolean;
  readonly maintenanceWindowCron?: string | null;
};

export async function seedSchedule(input: SeedScheduleInput): Promise<string> {
  const body = {
    tenant_id: input.tenantId,
    name: input.name,
    cron_expression: input.cronExpression ?? "0 * * * *",
    target_url: input.targetUrl ?? "https://example.com",
    scan_mode: input.scanMode ?? "standard",
    enabled: input.enabled ?? true,
    maintenance_window_cron: input.maintenanceWindowCron ?? null,
  };
  const url = `http://127.0.0.1:${ADMIN_BACKEND_MOCK_PORT}/api/v1/admin/scan-schedules`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Admin-Key": ADMIN_BACKEND_MOCK_KEY,
      "X-Admin-Role": "super-admin",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(
      `seedSchedule failed: ${res.status} ${await res.text()}`,
    );
  }
  const created = (await res.json()) as { id?: string };
  if (typeof created.id !== "string") {
    throw new Error("seedSchedule: malformed response (missing id)");
  }
  return created.id;
}

export async function resetMockBackend(): Promise<void> {
  const url = `http://127.0.0.1:${ADMIN_BACKEND_MOCK_PORT}/api/v1/__test__/reset`;
  // Best-effort: a 5s timeout is generous since the handler is a
  // single synchronous in-memory swap. We deliberately do NOT throw on
  // failure — the next test will surface its own assertion error if
  // state wasn't cleared, which gives a clearer diagnostic.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    await fetch(url, { method: "POST", signal: controller.signal });
  } catch {
    // ignore — see comment above
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Assert there is no unhandled-runtime-error overlay on the page. We
 * include this check on every navigation in T27 because a Server Action
 * that raises (rather than returning a closed-taxonomy error) would
 * surface here first — and we never want the operator to see a stack
 * trace.
 */
export async function assertNoLeakOverlay(page: Page): Promise<void> {
  await expect(page.getByText("Unhandled Runtime Error")).toHaveCount(0);
  await expect(page.getByText(/webpack-internal/i)).toHaveCount(0);
}

/**
 * Wait until the findings counter has rendered ANY value. Useful as a
 * "page-is-interactive" gate before clicking buttons that depend on the
 * React Query cache being warm.
 */
export async function waitForFindingsCounter(page: Page): Promise<void> {
  await expect(page.getByTestId("findings-counter")).toBeVisible({
    timeout: 15_000,
  });
}

export async function waitForAuditCounter(page: Page): Promise<void> {
  await expect(page.getByTestId("audit-counter")).toBeVisible({
    timeout: 15_000,
  });
}
