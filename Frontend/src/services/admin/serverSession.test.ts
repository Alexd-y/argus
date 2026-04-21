import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type CookieRecord = { name: string; value: string };

const cookieJar: { current: CookieRecord[] } = { current: [] };

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => {
      const found = cookieJar.current.find((c) => c.name === name);
      return found ? { name, value: found.value } : undefined;
    },
  }),
}));

import {
  ADMIN_ROLE_COOKIE,
  ADMIN_SUBJECT_COOKIE,
  ADMIN_TENANT_COOKIE,
  getServerAdminSession,
} from "./serverSession";

const SAMPLE_TENANT = "00000000-0000-0000-0000-000000000001";

const ENV_KEYS = [
  "NEXT_PUBLIC_ADMIN_DEV_ROLE",
  "NEXT_PUBLIC_ADMIN_DEV_TENANT",
  "NEXT_PUBLIC_ADMIN_DEV_SUBJECT",
] as const;

let savedEnv: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>> =
  {};

function setCookies(records: ReadonlyArray<CookieRecord>) {
  cookieJar.current = [...records];
}

beforeEach(() => {
  setCookies([]);
  savedEnv = {};
  for (const k of ENV_KEYS) {
    savedEnv[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = savedEnv[k];
    }
  }
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
