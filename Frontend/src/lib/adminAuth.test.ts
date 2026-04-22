import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  buildAuthBackendUrl,
  getAdminAuthMode,
  isExpiredSetCookie,
  parseRetryAfterSeconds,
  parseSetCookie,
  splitSetCookies,
  statusToAuthActionCode,
  validateLoginCredentials,
} from "./adminAuth";

const ENV_KEYS = [
  "NEXT_PUBLIC_ADMIN_AUTH_MODE",
  "BACKEND_URL",
  "NEXT_PUBLIC_BACKEND_URL",
] as const;

let saved: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>> = {};

beforeEach(() => {
  saved = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe("getAdminAuthMode", () => {
  it("returns 'auto' when the env is unset", () => {
    expect(getAdminAuthMode()).toBe("auto");
  });

  it("accepts the three valid modes (case + whitespace tolerant)", () => {
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "  Cookie ";
    expect(getAdminAuthMode()).toBe("cookie");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "SESSION";
    expect(getAdminAuthMode()).toBe("session");
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "auto";
    expect(getAdminAuthMode()).toBe("auto");
  });

  it("downgrades unknown values to the default", () => {
    process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE = "yolo";
    expect(getAdminAuthMode()).toBe("auto");
  });
});

describe("buildAuthBackendUrl", () => {
  it("uses BACKEND_URL when set, trimming a trailing slash", () => {
    process.env.BACKEND_URL = "http://backend.test/";
    expect(buildAuthBackendUrl("/api/v1/auth/admin/login")).toBe(
      "http://backend.test/api/v1/auth/admin/login",
    );
  });

  it("falls back to NEXT_PUBLIC_BACKEND_URL", () => {
    process.env.NEXT_PUBLIC_BACKEND_URL = "http://public-backend.test";
    expect(buildAuthBackendUrl("/api/v1/auth/admin/whoami")).toBe(
      "http://public-backend.test/api/v1/auth/admin/whoami",
    );
  });

  it("uses localhost:8000 as the last-resort default", () => {
    expect(buildAuthBackendUrl("/api/v1/auth/admin/whoami")).toBe(
      "http://localhost:8000/api/v1/auth/admin/whoami",
    );
  });

  it("normalises a path missing its leading slash", () => {
    process.env.BACKEND_URL = "http://backend.test";
    expect(buildAuthBackendUrl("api/v1/auth/admin/login")).toBe(
      "http://backend.test/api/v1/auth/admin/login",
    );
  });
});

describe("validateLoginCredentials", () => {
  it("rejects non-string inputs", () => {
    expect(validateLoginCredentials(null, "p").ok).toBe(false);
    expect(validateLoginCredentials("u", undefined).ok).toBe(false);
    expect(validateLoginCredentials(42, "p").ok).toBe(false);
  });

  it("rejects empty / whitespace-only subject (after trim)", () => {
    expect(validateLoginCredentials("   ", "password").ok).toBe(false);
  });

  it("trims subject but preserves password verbatim", () => {
    const r = validateLoginCredentials("  alice  ", "  pass  ");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.subject).toBe("alice");
      expect(r.password).toBe("  pass  ");
    }
  });

  it("rejects subject longer than 255 chars", () => {
    expect(validateLoginCredentials("x".repeat(256), "p").ok).toBe(false);
  });

  it("rejects password longer than 1024 chars", () => {
    expect(validateLoginCredentials("alice", "x".repeat(1025)).ok).toBe(false);
  });
});

describe("statusToAuthActionCode", () => {
  it.each([
    [401, "invalid_credentials"],
    [403, "invalid_credentials"],
    [422, "invalid_credentials"],
    [429, "rate_limited"],
    [500, "service_unavailable"],
    [502, "service_unavailable"],
    [504, "service_unavailable"],
    [418, "service_unavailable"],
  ] as const)("maps %i → %s", (status, expected) => {
    expect(statusToAuthActionCode(status)).toBe(expected);
  });
});

describe("parseRetryAfterSeconds", () => {
  it("returns the fallback for null / blank header", () => {
    expect(parseRetryAfterSeconds(null, 30)).toBe(30);
    expect(parseRetryAfterSeconds("", 30)).toBe(30);
  });

  it("parses a numeric seconds value and caps at 600", () => {
    expect(parseRetryAfterSeconds("45")).toBe(45);
    expect(parseRetryAfterSeconds("999")).toBe(600);
  });

  it("parses an HTTP-date and computes a positive delta", () => {
    const future = new Date(Date.now() + 90_000).toUTCString();
    const got = parseRetryAfterSeconds(future);
    expect(got).toBeGreaterThan(0);
    expect(got).toBeLessThanOrEqual(600);
  });

  it("falls back when the date is in the past", () => {
    const past = new Date(Date.now() - 60_000).toUTCString();
    expect(parseRetryAfterSeconds(past, 12)).toBe(12);
  });
});

describe("splitSetCookies", () => {
  it("splits a comma-concatenated header without breaking on Expires dates", () => {
    const raw =
      "argus.admin.session=abc; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly, foo=bar; Path=/";
    const parts = splitSetCookies(raw);
    expect(parts).toHaveLength(2);
    expect(parts[0].startsWith("argus.admin.session=abc")).toBe(true);
    expect(parts[1]).toBe("foo=bar; Path=/");
  });

  it("returns a single entry for a header without commas", () => {
    expect(splitSetCookies("a=b; Path=/")).toEqual(["a=b; Path=/"]);
  });
});

describe("parseSetCookie", () => {
  it("extracts every supported attribute", () => {
    const parsed = parseSetCookie(
      "argus.admin.session=abc; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600",
    );
    expect(parsed).not.toBeNull();
    expect(parsed!.name).toBe("argus.admin.session");
    expect(parsed!.value).toBe("abc");
    expect(parsed!.path).toBe("/");
    expect(parsed!.httpOnly).toBe(true);
    expect(parsed!.secure).toBe(true);
    expect(parsed!.sameSite).toBe("strict");
    expect(parsed!.maxAge).toBe(3600);
  });

  it("returns null for a malformed header", () => {
    expect(parseSetCookie("=novalue")).toBeNull();
    expect(parseSetCookie("")).toBeNull();
  });
});

describe("isExpiredSetCookie", () => {
  it("treats Max-Age=0 as expired", () => {
    const parsed = parseSetCookie(
      "argus.admin.session=; Path=/; HttpOnly; Max-Age=0",
    )!;
    expect(isExpiredSetCookie(parsed)).toBe(true);
  });

  it("treats a future Expires as live", () => {
    const future = new Date(Date.now() + 60_000).toUTCString();
    const parsed = parseSetCookie(`a=b; Expires=${future}`)!;
    expect(isExpiredSetCookie(parsed)).toBe(false);
  });

  it("treats a past Expires as expired", () => {
    const past = new Date(Date.now() - 60_000).toUTCString();
    const parsed = parseSetCookie(`a=b; Expires=${past}`)!;
    expect(isExpiredSetCookie(parsed)).toBe(true);
  });
});
