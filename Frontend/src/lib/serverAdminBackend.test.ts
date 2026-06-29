import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type CookieRecord = { name: string; value: string };

const cookieJar: { current: CookieRecord[] } = { current: [] };
const headerStore: { current: Record<string, string> } = { current: {} };

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => {
      const found = cookieJar.current.find((c) => c.name === name);
      return found ? { name, value: found.value } : undefined;
    },
  }),
  headers: async () => ({
    get: (name: string) => headerStore.current[name.toLowerCase()] ?? null,
  }),
}));

import { ADMIN_SESSION_COOKIE } from "./adminAuth";
import { callAdminBackendJson } from "./serverAdminBackend";

describe("callAdminBackendJson", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    vi.unstubAllEnvs();
    globalThis.fetch = originalFetch;
    cookieJar.current = [];
    headerStore.current = {};
  });

  beforeEach(() => {
    vi.stubEnv("BACKEND_URL", "http://backend.test");
    vi.stubEnv("ADMIN_API_KEY", "test-admin-key");
    cookieJar.current = [];
    headerStore.current = {};
  });

  it("returns 503 when neither ADMIN_API_KEY nor a session cookie is present", async () => {
    vi.stubEnv("ADMIN_API_KEY", "");
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock;

    const res = await callAdminBackendJson<unknown>("/tenants");

    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.status).toBe(503);
      expect(res.error).toMatch(/unavailable/i);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards the admin session cookie and X-Forwarded-For when present", async () => {
    cookieJar.current = [{ name: ADMIN_SESSION_COOKIE, value: "sess-123" }];
    headerStore.current = { "x-forwarded-for": "203.0.113.7" };
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 }));
    globalThis.fetch = fetchMock;

    await callAdminBackendJson("/tenants");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v1/admin/tenants",
      expect.objectContaining({
        headers: expect.objectContaining({
          "X-Admin-Key": "test-admin-key",
          Cookie: `${ADMIN_SESSION_COOKIE}=sess-123`,
          "X-Forwarded-For": "203.0.113.7",
        }),
      }),
    );
  });

  it("authenticates via session cookie even when ADMIN_API_KEY is unset", async () => {
    vi.stubEnv("ADMIN_API_KEY", "");
    cookieJar.current = [{ name: ADMIN_SESSION_COOKIE, value: "sess-xyz" }];
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 }));
    globalThis.fetch = fetchMock;

    const res = await callAdminBackendJson<void>("/tenants");

    expect(res.ok).toBe(true);
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = options.headers as Record<string, string>;
    expect(headers.Cookie).toBe(`${ADMIN_SESSION_COOKIE}=sess-xyz`);
    expect(headers["X-Admin-Key"]).toBeUndefined();
  });

  it("builds URL as {base}/api/v1/admin{path} and prefixes path when needed", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    globalThis.fetch = fetchMock;

    await callAdminBackendJson("tenants");
    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v1/admin/tenants",
      expect.objectContaining({
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-Admin-Key": "test-admin-key",
        }),
        cache: "no-store",
      }),
    );

    fetchMock.mockClear();
    await callAdminBackendJson("/tenants/foo");
    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v1/admin/tenants/foo",
      expect.any(Object),
    );
  });

  it("returns ok for 204 without reading JSON body", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    globalThis.fetch = fetchMock;

    const res = await callAdminBackendJson<void>("/x");
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.data).toBeUndefined();
  });

  it("maps JSON error detail via normalizeAdminDetailError", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "Not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      }),
    );
    globalThis.fetch = fetchMock;

    const res = await callAdminBackendJson<unknown>("/missing");
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.status).toBe(404);
      expect(res.error).toBe("Not found");
    }
  });
});
