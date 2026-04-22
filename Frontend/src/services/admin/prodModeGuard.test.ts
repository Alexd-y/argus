/**
 * Production-mode guard tests (B6-T09 / ISS-T20-003 follow-up).
 *
 * Covers two layers of defence against the cookie shim leaking into
 * production:
 *
 * 1. ``Frontend/instrumentation.ts``'s ``register()`` hook — fires once
 *    at server boot. Throws if ``NODE_ENV=production`` and
 *    ``NEXT_PUBLIC_ADMIN_AUTH_MODE`` is anything other than ``session``.
 *
 * 2. ``serverSession.ts``'s lazy assertion — fires on the first admin
 *    session resolve. Belt-and-suspenders for environments where the
 *    instrumentation hook is disabled (older Next, custom server,
 *    explicit ``experimental.instrumentationHook=false``).
 *
 * Both layers must stay silent in dev / staging / tests so the legacy
 * cookie shim keeps working for local development. The test grid below
 * pins the four interesting combinations of (NODE_ENV × admin auth mode).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * NODE_ENV is typed as a literal union (`"development" | "production" |
 * "test"`) by `@types/node` augmented for Next.js, so plain assignment
 * trips the TypeScript checker. ``vi.stubEnv`` is the canonical vitest
 * API for mutating it; everything else gets reset by ``vi.unstubAllEnvs``
 * in ``afterEach``.
 */
function setNodeEnv(value: "development" | "production" | "test"): void {
  vi.stubEnv("NODE_ENV", value);
}

const MUTABLE_ENV_KEYS = [
  "NEXT_PUBLIC_ADMIN_AUTH_MODE",
  "BACKEND_URL",
  "ADMIN_API_KEY",
] as const;

type EnvKey = (typeof MUTABLE_ENV_KEYS)[number];

let savedEnv: Partial<Record<EnvKey, string | undefined>> = {};

beforeEach(() => {
  savedEnv = {};
  for (const k of MUTABLE_ENV_KEYS) {
    savedEnv[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  for (const k of MUTABLE_ENV_KEYS) {
    if (savedEnv[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = savedEnv[k];
    }
  }
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

// ──────────────────────────────────────────────────────────────────────
// Layer 1 — instrumentation.ts (Next.js boot hook)
// ──────────────────────────────────────────────────────────────────────

describe("instrumentation.register — Next.js boot guard", () => {
  it("throws in production when ADMIN_AUTH_MODE is 'cookie'", async () => {
    setNodeEnv("production");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "cookie";

    const { register } = await import("../../../instrumentation");
    await expect(register()).rejects.toThrow(
      /ADMIN_AUTH_MODE must be 'session' in production \(got: cookie\)/,
    );
  });

  it("throws in production when ADMIN_AUTH_MODE is 'auto'", async () => {
    setNodeEnv("production");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "auto";

    const { register } = await import("../../../instrumentation");
    await expect(register()).rejects.toThrow(
      /ADMIN_AUTH_MODE must be 'session' in production \(got: auto\)/,
    );
  });

  it("throws in production when ADMIN_AUTH_MODE is unset", async () => {
    setNodeEnv("production");

    const { register } = await import("../../../instrumentation");
    await expect(register()).rejects.toThrow(
      /ADMIN_AUTH_MODE must be 'session' in production \(got: <unset>\)/,
    );
  });

  it("error message references B6-T09 / ISS-T20-003 for traceability", async () => {
    setNodeEnv("production");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "cookie";

    const { register } = await import("../../../instrumentation");
    await expect(register()).rejects.toThrow(/B6-T09 \/ ISS-T20-003/);
  });

  it("does NOT throw in production when ADMIN_AUTH_MODE is exactly 'session'", async () => {
    setNodeEnv("production");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "session";

    const { register } = await import("../../../instrumentation");
    await expect(register()).resolves.toBeUndefined();
  });

  it("normalises whitespace + casing — '  Session  ' is accepted", async () => {
    setNodeEnv("production");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "  Session  ";

    const { register } = await import("../../../instrumentation");
    await expect(register()).resolves.toBeUndefined();
  });

  it("does NOT throw in development with cookie mode (legacy dev loop)", async () => {
    setNodeEnv("development");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "cookie";

    const { register } = await import("../../../instrumentation");
    await expect(register()).resolves.toBeUndefined();
  });

  it("does NOT throw in test environment regardless of mode", async () => {
    setNodeEnv("test");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "auto";

    const { register } = await import("../../../instrumentation");
    await expect(register()).resolves.toBeUndefined();
  });
});

// ──────────────────────────────────────────────────────────────────────
// Layer 2 — serverSession.ts lazy assertion (first-resolve fallback)
// ──────────────────────────────────────────────────────────────────────
//
// The assertion is a module-level singleton — once it has fired (or once
// it has determined the env is safe), subsequent calls are no-ops. We
// reset the flag between tests via the exported test-only helper so each
// case starts from a clean slate.

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: () => undefined,
  }),
  headers: async () => ({
    get: () => null,
  }),
}));

vi.mock("next/navigation", () => ({
  redirect: (to: string) => {
    throw new Error(`NEXT_REDIRECT:${to}`);
  },
}));

describe("serverSession lazy assertion — belt-and-suspenders", () => {
  it("getServerAdminSession throws in production with cookie mode on first call", async () => {
    setNodeEnv("production");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "cookie";

    const { getServerAdminSession, _resetProdModeAssertionForTests } =
      await import("./serverSession");
    _resetProdModeAssertionForTests();

    await expect(getServerAdminSession()).rejects.toThrow(
      /ADMIN_AUTH_MODE must be 'session' in production \(got: cookie\)/,
    );
  });

  it("tryGetServerAdminSession throws in production with auto mode", async () => {
    setNodeEnv("production");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "auto";

    const { tryGetServerAdminSession, _resetProdModeAssertionForTests } =
      await import("./serverSession");
    _resetProdModeAssertionForTests();

    await expect(tryGetServerAdminSession()).rejects.toThrow(
      /ADMIN_AUTH_MODE must be 'session' in production \(got: auto\)/,
    );
  });

  it("only fires once per process — second call is a no-op even if env later flips back", async () => {
    setNodeEnv("development");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "cookie";

    const { getServerAdminSession, _resetProdModeAssertionForTests } =
      await import("./serverSession");
    _resetProdModeAssertionForTests();

    // First call: dev env, no throw, flag is now "armed" so subsequent
    // calls bypass the check.
    await expect(getServerAdminSession()).resolves.toBeDefined();

    // Even if NODE_ENV flips to production mid-process, the assertion
    // has already memoised "safe". This is by design: we guard at boot,
    // not on every request.
    setNodeEnv("production");
    await expect(getServerAdminSession()).resolves.toBeDefined();
  });

  it("does NOT throw in production with session mode", async () => {
    setNodeEnv("production");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "session";

    const { tryGetServerAdminSession, _resetProdModeAssertionForTests } =
      await import("./serverSession");
    _resetProdModeAssertionForTests();

    // Without a session cookie + session mode, tryGet returns null
    // (rather than redirecting). The point of THIS test is simply that
    // the assertion does not throw — null is the expected resolution.
    await expect(tryGetServerAdminSession()).resolves.toBeNull();
  });
});
