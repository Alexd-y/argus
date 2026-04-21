import { beforeEach, describe, expect, it, vi } from "vitest";

import { AdminFindingsError } from "@/lib/adminFindings";
import type { ServerAdminSession } from "@/services/admin/serverSession";

const callAdminBackendJson = vi.fn();
vi.mock("@/lib/serverAdminBackend", () => ({
  callAdminBackendJson: (...args: unknown[]) => callAdminBackendJson(...args),
}));

const sessionMock = vi.fn<() => Promise<ServerAdminSession>>();
vi.mock("@/services/admin/serverSession", () => ({
  getServerAdminSession: () => sessionMock(),
}));

import { listAdminFindingsAction } from "./actions";

const SAMPLE_TENANT = "00000000-0000-0000-0000-000000000001";
const OTHER_TENANT = "00000000-0000-0000-0000-000000000002";

function okEnvelope(items: unknown[] = []) {
  return {
    ok: true as const,
    status: 200,
    data: {
      items,
      total: items.length,
      limit: 50,
      offset: 0,
      has_more: false,
      next_cursor: null,
    },
  };
}

function err(status: number, body: unknown = {}) {
  return { ok: false as const, status, data: body };
}

beforeEach(() => {
  callAdminBackendJson.mockReset();
  sessionMock.mockReset();
});

describe("listAdminFindingsAction — identity propagation (S0-1, S1-3)", () => {
  it("throws AdminFindingsError('unauthorized') when no role is resolved", async () => {
    sessionMock.mockResolvedValue({
      role: null,
      tenantId: null,
      subject: "anon",
    });

    await expect(listAdminFindingsAction({})).rejects.toBeInstanceOf(
      AdminFindingsError,
    );
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("propagates X-Admin-Role and X-Operator-Subject from the server session, never from the caller", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(okEnvelope());

    await listAdminFindingsAction({
      tenantId: OTHER_TENANT,
    });

    expect(callAdminBackendJson).toHaveBeenCalledTimes(1);
    const [, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string> },
    ];
    expect(init.headers["X-Admin-Role"]).toBe("super-admin");
    expect(init.headers["X-Operator-Subject"]).toBe(
      "admin_console:super-admin",
    );
    // X-Admin-Tenant comes from the URL choice for super-admin.
    expect(init.headers["X-Admin-Tenant"]).toBe(OTHER_TENANT);
  });
});

describe("listAdminFindingsAction — S1-6 admin tenant binding", () => {
  it("returns an empty page (NEVER cross-tenant data) when admin has no session-bound tenant", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: null,
      subject: "admin_console:admin",
    });

    const out = await listAdminFindingsAction({});
    expect(out.items).toEqual([]);
    expect(out.total).toBe(0);
    expect(out.has_more).toBe(false);
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("ignores admin caller's `tenantId` and uses session.tenantId instead", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: SAMPLE_TENANT,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(okEnvelope());

    await listAdminFindingsAction({
      tenantId: OTHER_TENANT,
    });

    const [path, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string> },
    ];
    // `tenant_id` in the URL must come from the session, not the caller.
    expect(path).toContain(`tenant_id=${SAMPLE_TENANT}`);
    expect(path).not.toContain(OTHER_TENANT);
    expect(init.headers["X-Admin-Tenant"]).toBe(SAMPLE_TENANT);
  });

  it("super-admin without a tenantId fires a cross-tenant query (no tenant_id in URL, no X-Admin-Tenant)", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(okEnvelope());

    await listAdminFindingsAction({});

    const [path, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string> },
    ];
    expect(path).not.toContain("tenant_id=");
    expect(init.headers["X-Admin-Tenant"]).toBeUndefined();
  });
});

describe("listAdminFindingsAction — query string mapping (S1-1, S1-2)", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(okEnvelope());
  });

  it("maps UI `target` to backend `q` (free-text), trimmed (S1-1)", async () => {
    await listAdminFindingsAction({ target: "  example.com  " });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("q=example.com");
    expect(path).not.toContain("target=");
  });

  it("does NOT send `q=` when target is empty / blank", async () => {
    await listAdminFindingsAction({ target: "   " });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).not.toContain("q=");
  });

  it("maps statusMode='open' → false_positive=false (S1-2)", async () => {
    await listAdminFindingsAction({ statusMode: "open" });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("false_positive=false");
  });

  it("maps statusMode='false_positive' → false_positive=true (S1-2)", async () => {
    await listAdminFindingsAction({ statusMode: "false_positive" });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("false_positive=true");
  });

  it("does NOT send false_positive when statusMode='all' (or absent)", async () => {
    await listAdminFindingsAction({ statusMode: "all" });
    const [pathAll] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(pathAll).not.toContain("false_positive=");

    callAdminBackendJson.mockClear();
    await listAdminFindingsAction({});
    const [pathAbsent] = callAdminBackendJson.mock.calls[0] as [
      string,
      unknown,
    ];
    expect(pathAbsent).not.toContain("false_positive=");
  });

  it("appends each severity individually (multi-value query)", async () => {
    await listAdminFindingsAction({ severity: ["critical", "high"] });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("severity=critical");
    expect(path).toContain("severity=high");
  });

  it("passes through cursor as a numeric offset (server pagination contract)", async () => {
    await listAdminFindingsAction({ cursor: "100", limit: 25 });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("offset=100");
    expect(path).toContain("limit=25");
  });

  it("ignores non-numeric cursor without throwing", async () => {
    await listAdminFindingsAction({ cursor: "not-a-number" });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).not.toContain("offset=");
  });
});

describe("listAdminFindingsAction — error taxonomy (no internal leaks)", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
  });

  it("translates 401 → unauthorized", async () => {
    callAdminBackendJson.mockResolvedValue(err(401));
    await expect(listAdminFindingsAction({})).rejects.toMatchObject({
      code: "unauthorized",
    });
  });

  it("translates 403 → forbidden", async () => {
    callAdminBackendJson.mockResolvedValue(err(403));
    await expect(listAdminFindingsAction({})).rejects.toMatchObject({
      code: "forbidden",
    });
  });

  it("translates 429 → rate_limited", async () => {
    callAdminBackendJson.mockResolvedValue(err(429));
    await expect(listAdminFindingsAction({})).rejects.toMatchObject({
      code: "rate_limited",
    });
  });

  it("translates 503 → network_error (transport / missing ADMIN_API_KEY)", async () => {
    callAdminBackendJson.mockResolvedValue(err(503));
    await expect(listAdminFindingsAction({})).rejects.toMatchObject({
      code: "network_error",
    });
  });

  it("translates 4xx → invalid_input", async () => {
    callAdminBackendJson.mockResolvedValue(err(422));
    await expect(listAdminFindingsAction({})).rejects.toMatchObject({
      code: "invalid_input",
    });
  });

  it("translates schema-mismatch (200 OK with malformed items) → server_error", async () => {
    // The envelope schema is intentionally lax (`{ totally: "broken" }` → empty
    // page) for backward-compat with T24's `{ findings: [...] }`. To exercise
    // the safeParse failure path we feed in an `items` array whose row breaks
    // the inner `AdminFindingItemSchema` (severity must be a known enum).
    callAdminBackendJson.mockResolvedValue({
      ok: true,
      status: 200,
      data: {
        items: [
          {
            id: "broken",
            tenant_id: SAMPLE_TENANT,
            scan_id: "scan-x",
            severity: "world-ending", // ← outside closed enum
            title: "bogus",
          },
        ],
        total: 1,
      },
    });
    await expect(listAdminFindingsAction({})).rejects.toMatchObject({
      code: "server_error",
    });
  });

  it("never echoes raw backend body / Zod issues to the caller", async () => {
    callAdminBackendJson.mockResolvedValue({
      ok: false,
      status: 500,
      data: { detail: "stack trace at /app/admin/views.py:42" },
    });
    try {
      await listAdminFindingsAction({});
    } catch (e) {
      expect(e).toBeInstanceOf(AdminFindingsError);
      expect(String(e)).not.toMatch(/stack trace|views\.py/);
    }
  });
});
