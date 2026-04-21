import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { callAdminBackendJson } from "./serverAdminBackend";

describe("callAdminBackendJson", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    vi.unstubAllEnvs();
    globalThis.fetch = originalFetch;
  });

  beforeEach(() => {
    vi.stubEnv("BACKEND_URL", "http://backend.test");
    vi.stubEnv("ADMIN_API_KEY", "test-admin-key");
  });

  it("returns 503 when ADMIN_API_KEY is not set", async () => {
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
