/**
 * Playwright global setup for the admin a11y suite (T26).
 *
 * Boots the mock admin backend (`fixtures/admin-backend-mock.ts`) once
 * for the whole run so the spawned Next.js dev server can hit it via
 * `BACKEND_URL`. The teardown handle is exported as the default export
 * so Playwright invokes it on shutdown — keeping the loopback port free
 * for the next run.
 */

import {
  ADMIN_BACKEND_MOCK_PORT,
  startAdminBackendMock,
  type AdminBackendMock,
} from "./fixtures/admin-backend-mock";

let active: AdminBackendMock | null = null;

async function globalSetup(): Promise<() => Promise<void>> {
  if (active) {
    // Defensive: Playwright may invoke globalSetup twice if a config
    // file is reloaded mid-run. Idempotency keeps the mock alive.
    return async () => undefined;
  }
  const mock = await startAdminBackendMock(ADMIN_BACKEND_MOCK_PORT);
  active = mock;
  // Surface a single line so CI logs make it obvious the mock is up.
  console.log(`[a11y] admin backend mock listening at ${mock.url}`);

  return async () => {
    if (active) {
      await active.stop();
      active = null;
    }
  };
}

export default globalSetup;
