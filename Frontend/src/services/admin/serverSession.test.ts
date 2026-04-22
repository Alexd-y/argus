import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type CookieRecord = { name: string; value: string };
type HeaderRecord = Record<string, string>;

const cookieJar: { current: CookieRecord[] } = { current: [] };
const headerStore: { current: HeaderRecord } = { current: {} };

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => {
      const found = cookieJar.current.find((c) => c.name === name);
      return found ? { name, value: found.value } : undefined;
    },
  }),
  headers: async () => ({
    get: (name: string) => {
      const value = headerStore.current[name.toLowerCase()];
      return value ?? null;
    },
  }),
}));

const redirectCalls: string[] = [];
class RedirectError extends Error {
  constructor(public readonly to: string) {
    super(`NEXT_REDIRECT:${to}`);
  }
}

vi.mock("next/navigation", () => ({
  redirect: (to: string) => {
    redirectCalls.push(to);
    throw new RedirectError(to);
  },
}));

import {
  ADMIN_ROLE_COOKIE,
  ADMIN_SUBJECT_COOKIE,
  ADMIN_TENANT_COOKIE,
  getServerAdminSession,
  tryGetServerAdminSession,
} from "./serverSession";

const SAMPLE_TENANT = "00000000-0000-0000-0000-000000000001";

const ENV_KEYS = [
  "NEXT_PUBLIC_ADMIN_DEV_ROLE",
  "NEXT_PUBLIC_ADMIN_DEV_TENANT",
  "NEXT_PUBLIC_ADMIN_DEV_SUBJECT",
  "NEXT_PUBLIC_ADMIN_AUTH_MODE",
  "BACKEND_URL",
  "NEXT_PUBLIC_BACKEND_URL",
  "ADMIN_API_KEY",
] as const;

let savedEnv: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>> =
  {};

function setCookies(records: ReadonlyArray<CookieRecord>) {
  cookieJar.current = [...records];
}

function setHeaders(headers: HeaderRecord) {
  headerStore.current = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
}

beforeEach(() => {
  setCookies([]);
  setHeaders({});
  redirectCalls.length = 0;
  savedEnv = {};
  for (const k of ENV_KEYS) {
    savedEnv[k] = process.env[k];
    delete process.env[k];
  }
  vi.unstubAllGlobals();
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = savedEnv[k];
    }
  }
  vi.unstubAllGlobals();
});

describe("getServerAdminSession — cookie path (primary)", () => {
  it("resolves role + tenant + subject from cookies set by AdminAuthProvider", async () => {
    setCookies([
      { name: ADMIN_ROLE_COOKIE, value: "admin" },
      { name: ADMIN_TENANT_COOKIE, value: SAMPLE_TENANT },
      { name: ADMIN_SUBJECT_COOKIE, value: "alice@argus.test" },
    ]);

    const session = await getServerAdminSession();
    expect(session.role).toBe("admin");
    expect(session.tenantId).toBe(SAMPLE_TENANT);
    expect(session.subject).toBe("alice@argus.test");
  });

  it("returns null role when no cookie / env is set", async () => {
    const session = await getServerAdminSession();
    expect(session.role).toBeNull();
    expect(session.tenantId).toBeNull();
    // Subject still has a deterministic fallback for the audit trail.
    expect(session.subject).toBe("admin_console");
  });

  it("normalises an unknown role cookie to null", async () => {
    setCookies([{ name: ADMIN_ROLE_COOKIE, value: "root" }]);
    const session = await getServerAdminSession();
    expect(session.role).toBeNull();
  });

  it("rejects a malformed tenant cookie (non-UUID) and returns null tenantId", async () => {
    setCookies([
      { name: ADMIN_ROLE_COOKIE, value: "super-admin" },
      { name: ADMIN_TENANT_COOKIE, value: "not-a-uuid" },
    ]);
    const session = await getServerAdminSession();
    expect(session.role).toBe("super-admin");
    expect(session.tenantId).toBeNull();
  });

  it("rejects a subject cookie containing control characters", async () => {
    setCookies([
      { name: ADMIN_ROLE_COOKIE, value: "admin" },
      { name: ADMIN_SUBJECT_COOKIE, value: "evil\u0007subject" },
    ]);
    const session = await getServerAdminSession();
    // Falls back to the role-derived subject.
    expect(session.subject).toBe("admin_console:admin");
  });

  it("trims and length-caps an oversized subject cookie", async () => {
    const long = "x".repeat(500);
    setCookies([
      { name: ADMIN_ROLE_COOKIE, value: "admin" },
      { name: ADMIN_SUBJECT_COOKIE, value: long },
    ]);
    const session = await getServerAdminSession();
    expect(session.subject.length).toBeLessThanOrEqual(256);
    expect(session.subject.startsWith("x")).toBe(true);
  });
});

describe("getServerAdminSession — env fallback path (dev/Playwright)", () => {
  it("falls back to NEXT_PUBLIC_ADMIN_DEV_ROLE when no cookie", async () => {
    process.env.NEXT_PUBLIC_ADMIN_DEV_ROLE = "super-admin";
    const session = await getServerAdminSession();
    expect(session.role).toBe("super-admin");
  });

  it("cookie wins over env when both are set", async () => {
    setCookies([{ name: ADMIN_ROLE_COOKIE, value: "admin" }]);
    process.env.NEXT_PUBLIC_ADMIN_DEV_ROLE = "super-admin";
    const session = await getServerAdminSession();
    expect(session.role).toBe("admin");
  });

  it("falls back to NEXT_PUBLIC_ADMIN_DEV_TENANT and validates the UUID", async () => {
    process.env.NEXT_PUBLIC_ADMIN_DEV_TENANT = SAMPLE_TENANT;
    const session = await getServerAdminSession();
    expect(session.tenantId).toBe(SAMPLE_TENANT);
  });

  it("rejects an invalid env tenant", async () => {
    process.env.NEXT_PUBLIC_ADMIN_DEV_TENANT = "garbage";
    const session = await getServerAdminSession();
    expect(session.tenantId).toBeNull();
  });

  it("derives a deterministic subject from role when no cookie/env subject is set", async () => {
    process.env.NEXT_PUBLIC_ADMIN_DEV_ROLE = "admin";
    const session = await getServerAdminSession();
    expect(session.subject).toBe("admin_console:admin");
  });
});

// ──────────────────────────────────────────────────────────────────────────
// Session-mode tests (B6-T09 / ISS-T20-003 Phase 1 frontend)
// ──────────────────────────────────────────────────────────────────────────

const ADMIN_SESSION_COOKIE = "argus.admin.session";

type StubFetchOpts = {
  status?: number;
  body?: unknown;
  throwOnce?: boolean;
};

function stubBackend(opts: StubFetchOpts): ReturnType<typeof vi.fn> {
  const status = opts.status ?? 200;
  const body = opts.body ?? {
    subject: "alice@argus.test",
    role: "admin",
    tenant_id: SAMPLE_TENANT,
    expires_at: "2099-01-01T00:00:00Z",
  };
  let called = 0;
  const fn = vi.fn(async () => {
    called++;
    if (opts.throwOnce && called === 1) {
      throw new Error("backend offline");
    }
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

describe("getServerAdminSession — session mode", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "session";
    process.env.BACKEND_URL = "http://backend.test";
    process.env.ADMIN_API_KEY = "test-key";
  });

  it("returns the real subject from backend whoami (NOT derived from role)", async () => {
    setCookies([{ name: ADMIN_SESSION_COOKIE, value: "session-abc" }]);
    const fetchMock = stubBackend({
      body: {
        subject: "real.operator@example.com",
        role: "admin",
        tenant_id: SAMPLE_TENANT,
        expires_at: "2099-01-01T00:00:00Z",
      },
    });

    const session = await getServerAdminSession();

    expect(session.source).toBe("session");
    expect(session.subject).toBe("real.operator@example.com");
    expect(session.subject).not.toBe("admin_console:admin");
    expect(session.role).toBe("admin");
    expect(session.tenantId).toBe(SAMPLE_TENANT);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://backend.test/api/v1/auth/admin/whoami");
    expect(init.method).toBe("GET");
    const sentHeaders = init.headers as Record<string, string>;
    expect(sentHeaders["Cookie"]).toBe(`${ADMIN_SESSION_COOKIE}=session-abc`);
    expect(sentHeaders["X-Admin-Key"]).toBe("test-key");
  });

  it("forwards X-Forwarded-For from the inbound request", async () => {
    setCookies([{ name: ADMIN_SESSION_COOKIE, value: "session-abc" }]);
    setHeaders({ "x-forwarded-for": "203.0.113.5, 10.0.0.1" });
    const fetchMock = stubBackend({});

    await getServerAdminSession();

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sentHeaders = init.headers as Record<string, string>;
    expect(sentHeaders["X-Forwarded-For"]).toBe("203.0.113.5, 10.0.0.1");
  });

  it("redirects to /admin/login when the session cookie is missing", async () => {
    const fetchMock = stubBackend({});

    await expect(getServerAdminSession()).rejects.toBeInstanceOf(RedirectError);
    expect(redirectCalls).toEqual(["/admin/login"]);
    // No cookie ⇒ no whoami round-trip.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("redirects to /admin/login on backend 401", async () => {
    setCookies([{ name: ADMIN_SESSION_COOKIE, value: "session-abc" }]);
    stubBackend({ status: 401, body: { detail: "invalid session" } });

    await expect(getServerAdminSession()).rejects.toBeInstanceOf(RedirectError);
    expect(redirectCalls).toEqual(["/admin/login"]);
  });

  it("redirects to /admin/login on backend network error", async () => {
    setCookies([{ name: ADMIN_SESSION_COOKIE, value: "session-abc" }]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }),
    );

    await expect(getServerAdminSession()).rejects.toBeInstanceOf(RedirectError);
    expect(redirectCalls).toEqual(["/admin/login"]);
  });

  it("ignores tampered role/tenant cookies — backend is the only authority", async () => {
    setCookies([
      { name: ADMIN_SESSION_COOKIE, value: "session-abc" },
      { name: ADMIN_ROLE_COOKIE, value: "super-admin" }, // tampered!
      { name: ADMIN_TENANT_COOKIE, value: SAMPLE_TENANT },
    ]);
    stubBackend({
      body: {
        subject: "operator@example.com",
        role: "operator", // backend says operator
        tenant_id: SAMPLE_TENANT,
        expires_at: "2099-01-01T00:00:00Z",
      },
    });

    const session = await getServerAdminSession();
    expect(session.role).toBe("operator"); // not super-admin
    expect(session.source).toBe("session");
  });

  it("rejects a backend payload missing subject (treated as malformed → redirect)", async () => {
    setCookies([{ name: ADMIN_SESSION_COOKIE, value: "session-abc" }]);
    stubBackend({
      body: { role: "admin", tenant_id: SAMPLE_TENANT },
    });

    await expect(getServerAdminSession()).rejects.toBeInstanceOf(RedirectError);
    expect(redirectCalls).toEqual(["/admin/login"]);
  });
});

describe("getServerAdminSession — auto mode", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "auto";
    process.env.BACKEND_URL = "http://backend.test";
  });

  it("uses backend whoami when the session is valid", async () => {
    setCookies([{ name: ADMIN_SESSION_COOKIE, value: "session-abc" }]);
    stubBackend({
      body: {
        subject: "ops@example.com",
        role: "operator",
        tenant_id: SAMPLE_TENANT,
        expires_at: "2099-01-01T00:00:00Z",
      },
    });

    const session = await getServerAdminSession();
    expect(session.source).toBe("session");
    expect(session.subject).toBe("ops@example.com");
  });

  it("falls back to the cookie shim on backend 401 — never throws", async () => {
    setCookies([
      { name: ADMIN_SESSION_COOKIE, value: "stale-session" },
      { name: ADMIN_ROLE_COOKIE, value: "admin" },
    ]);
    stubBackend({ status: 401 });

    const session = await getServerAdminSession();
    expect(session.source).toBe("cookie");
    expect(session.role).toBe("admin");
    // No redirect issued in auto mode.
    expect(redirectCalls).toHaveLength(0);
  });

  it("falls back to the cookie shim when the backend is unreachable", async () => {
    setCookies([
      { name: ADMIN_SESSION_COOKIE, value: "stale-session" },
      { name: ADMIN_ROLE_COOKIE, value: "operator" },
    ]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }),
    );

    const session = await getServerAdminSession();
    expect(session.source).toBe("cookie");
    expect(session.role).toBe("operator");
    expect(redirectCalls).toHaveLength(0);
  });

  it("falls back to the cookie shim with no session cookie at all (legacy dev loop)", async () => {
    process.env.NEXT_PUBLIC_ADMIN_DEV_ROLE = "admin";
    process.env.NEXT_PUBLIC_ADMIN_DEV_TENANT = SAMPLE_TENANT;
    const fetchMock = stubBackend({});

    const session = await getServerAdminSession();
    expect(session.source).toBe("cookie");
    expect(session.role).toBe("admin");
    expect(session.tenantId).toBe(SAMPLE_TENANT);
    // No session cookie means we don't even hit the backend.
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("tryGetServerAdminSession — non-redirecting variant", () => {
  it("returns null in session mode when the cookie is missing instead of redirecting", async () => {
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "session";
    stubBackend({ status: 401 });
    const session = await tryGetServerAdminSession();
    expect(session).toBeNull();
    expect(redirectCalls).toHaveLength(0);
  });

  it("returns the cookie shim in cookie mode", async () => {
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "cookie";
    process.env.NEXT_PUBLIC_ADMIN_DEV_ROLE = "admin";
    const session = await tryGetServerAdminSession();
    expect(session).not.toBeNull();
    expect(session?.source).toBe("cookie");
  });
});
