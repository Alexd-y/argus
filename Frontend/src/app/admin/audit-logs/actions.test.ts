import { beforeEach, describe, expect, it, vi } from "vitest";

import { AdminAuditLogsError } from "@/lib/adminAuditLogs";
import type { ServerAdminSession } from "@/services/admin/serverSession";

const callAdminBackendJson = vi.fn();
vi.mock("@/lib/serverAdminBackend", () => ({
  callAdminBackendJson: (...args: unknown[]) => callAdminBackendJson(...args),
}));

const sessionMock = vi.fn<() => Promise<ServerAdminSession>>();
vi.mock("@/services/admin/serverSession", () => ({
  getServerAdminSession: () => sessionMock(),
}));

import { listAdminAuditLogsAction, verifyAuditChainAction } from "./actions";

const SAMPLE_TENANT = "00000000-0000-0000-0000-000000000001";
const OTHER_TENANT = "00000000-0000-0000-0000-000000000002";
const SAMPLE_TS = "2026-04-21T08:00:00Z";

function okList(items: unknown[] = []) {
  return {
    ok: true as const,
    status: 200,
    data: items,
  };
}

function okEnvelope(items: unknown[] = [], next_cursor: string | null = null) {
  return {
    ok: true as const,
    status: 200,
    data: { items, total: items.length, next_cursor },
  };
}

function okVerify(extra?: Partial<Record<string, unknown>>) {
  return {
    ok: true as const,
    status: 200,
    data: {
      ok: true,
      verified_count: 7,
      last_verified_index: 6,
      drift_event_id: null,
      drift_detected_at: null,
      effective_since: SAMPLE_TS,
      effective_until: SAMPLE_TS,
      ...extra,
    },
  };
}

function err(status: number, body: unknown = {}) {
  return { ok: false as const, status, data: body, error: "x" };
}

beforeEach(() => {
  callAdminBackendJson.mockReset();
  sessionMock.mockReset();
});

describe("listAdminAuditLogsAction — identity propagation", () => {
  it("throws AdminAuditLogsError('unauthorized') when no role is resolved", async () => {
    sessionMock.mockResolvedValue({
      role: null,
      tenantId: null,
      subject: "anon",
    });

    await expect(listAdminAuditLogsAction({})).rejects.toBeInstanceOf(
      AdminAuditLogsError,
    );
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("throws AdminAuditLogsError('forbidden') for the operator role", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: SAMPLE_TENANT,
      subject: "ops",
    });

    await expect(listAdminAuditLogsAction({})).rejects.toMatchObject({
      code: "forbidden",
    });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("propagates X-Admin-Role / X-Operator-Subject from the session, never from caller hints", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(okList());

    await listAdminAuditLogsAction({ tenantId: OTHER_TENANT });

    expect(callAdminBackendJson).toHaveBeenCalledTimes(1);
    const [, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string> },
    ];
    expect(init.headers["X-Admin-Role"]).toBe("super-admin");
    expect(init.headers["X-Operator-Subject"]).toBe(
      "admin_console:super-admin",
    );
    expect(init.headers["X-Admin-Tenant"]).toBe(OTHER_TENANT);
  });
});

describe("listAdminAuditLogsAction — admin tenant binding", () => {
  it("returns an empty page (no backend call) when admin has no session-bound tenant", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: null,
      subject: "admin_console:admin",
    });

    const out = await listAdminAuditLogsAction({});
    expect(out.items).toEqual([]);
    expect(out.total).toBe(0);
    expect(out.next_cursor).toBeNull();
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("ignores admin caller's tenantId and uses session.tenantId instead", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: SAMPLE_TENANT,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(okList());

    await listAdminAuditLogsAction({ tenantId: OTHER_TENANT });

    const [path, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string> },
    ];
    expect(path).toContain(`tenant_id=${SAMPLE_TENANT}`);
    expect(path).not.toContain(OTHER_TENANT);
    expect(init.headers["X-Admin-Tenant"]).toBe(SAMPLE_TENANT);
  });

  it("super-admin without a tenantId fires a cross-tenant query (no tenant_id, no X-Admin-Tenant)", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(okList());

    await listAdminAuditLogsAction({});

    const [path, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string> },
    ];
    expect(path).not.toContain("tenant_id=");
    expect(init.headers["X-Admin-Tenant"]).toBeUndefined();
  });
});

describe("listAdminAuditLogsAction — query string mapping", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(okList());
  });

  it("maps actorSubject to backend `q` (substring search)", async () => {
    await listAdminAuditLogsAction({ actorSubject: "  alice  " });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("q=alice");
    expect(path).not.toContain("actor_subject=");
  });

  it("forwards eventType verbatim under `event_type`", async () => {
    await listAdminAuditLogsAction({ eventType: "scan.start" });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("event_type=scan.start");
  });

  it("forwards since/until ISO timestamps", async () => {
    await listAdminAuditLogsAction({
      since: "2026-04-01T00:00:00Z",
      until: "2026-04-21T00:00:00Z",
    });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("since=");
    expect(path).toContain("until=");
  });

  it("translates cursor → offset (numeric pagination contract)", async () => {
    await listAdminAuditLogsAction({ cursor: "100", limit: 25 });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("offset=100");
    expect(path).toContain("limit=25");
  });

  it("ignores non-numeric cursor without throwing", async () => {
    await listAdminAuditLogsAction({ cursor: "definitely-not-a-number" });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).not.toContain("offset=");
  });

  it("omits empty filter values (no `q=&event_type=` noise)", async () => {
    await listAdminAuditLogsAction({
      actorSubject: "",
      eventType: " ",
      since: "",
      until: "",
    });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).not.toContain("q=");
    expect(path).not.toContain("event_type=");
    expect(path).not.toContain("since=");
    expect(path).not.toContain("until=");
  });
});

describe("listAdminAuditLogsAction — cursor synthesis", () => {
  it("synthesises next_cursor when the backend returns a full bare-array page", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    const items = Array.from({ length: 50 }).map((_, i) => ({
      id: `id-${i}`,
      created_at: SAMPLE_TS,
      action: "scan.start",
    }));
    callAdminBackendJson.mockResolvedValue(okList(items));

    const out = await listAdminAuditLogsAction({ limit: 50 });
    expect(out.items).toHaveLength(50);
    expect(out.next_cursor).toBe("50");
  });

  it("does NOT synthesise next_cursor when items.length < limit", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    const items = Array.from({ length: 10 }).map((_, i) => ({
      id: `id-${i}`,
      created_at: SAMPLE_TS,
      action: "scan.start",
    }));
    callAdminBackendJson.mockResolvedValue(okList(items));

    const out = await listAdminAuditLogsAction({ limit: 50 });
    expect(out.next_cursor).toBeNull();
  });

  it("respects an existing next_cursor from a wrapped envelope", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(
      okEnvelope(
        [{ id: "id-0", created_at: SAMPLE_TS, action: "scan.start" }],
        "opaque-cursor",
      ),
    );

    const out = await listAdminAuditLogsAction({ limit: 50 });
    expect(out.next_cursor).toBe("opaque-cursor");
  });

  it("offsets from the requested cursor on subsequent pages", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    const items = Array.from({ length: 50 }).map((_, i) => ({
      id: `id-${i}`,
      created_at: SAMPLE_TS,
      action: "scan.start",
    }));
    callAdminBackendJson.mockResolvedValue(okList(items));

    const out = await listAdminAuditLogsAction({ limit: 50, cursor: "100" });
    expect(out.next_cursor).toBe("150");
  });
});

describe("listAdminAuditLogsAction — error taxonomy", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
  });

  it("translates 401 → unauthorized", async () => {
    callAdminBackendJson.mockResolvedValue(err(401));
    await expect(listAdminAuditLogsAction({})).rejects.toMatchObject({
      code: "unauthorized",
    });
  });

  it("translates 403 → forbidden", async () => {
    callAdminBackendJson.mockResolvedValue(err(403));
    await expect(listAdminAuditLogsAction({})).rejects.toMatchObject({
      code: "forbidden",
    });
  });

  it("translates 429 → rate_limited", async () => {
    callAdminBackendJson.mockResolvedValue(err(429));
    await expect(listAdminAuditLogsAction({})).rejects.toMatchObject({
      code: "rate_limited",
    });
  });

  it("translates 503 → network_error (transport / missing ADMIN_API_KEY)", async () => {
    callAdminBackendJson.mockResolvedValue(err(503));
    await expect(listAdminAuditLogsAction({})).rejects.toMatchObject({
      code: "network_error",
    });
  });

  it("translates 4xx → invalid_input (422)", async () => {
    callAdminBackendJson.mockResolvedValue(err(422));
    await expect(listAdminAuditLogsAction({})).rejects.toMatchObject({
      code: "invalid_input",
    });
  });

  it("translates schema mismatch → server_error (no internal echo)", async () => {
    callAdminBackendJson.mockResolvedValue({
      ok: true,
      status: 200,
      data: { items: [{ id: "x" /* missing created_at */ }] },
    });
    await expect(listAdminAuditLogsAction({})).rejects.toMatchObject({
      code: "server_error",
    });
  });

  it("never echoes raw backend body / Zod issues to the caller", async () => {
    callAdminBackendJson.mockResolvedValue({
      ok: false,
      status: 500,
      data: { detail: "stack trace at /app/admin/audit.py:42" },
    });
    try {
      await listAdminAuditLogsAction({});
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(AdminAuditLogsError);
      expect(String(e)).not.toMatch(/stack trace|audit\.py/);
    }
  });
});

describe("verifyAuditChainAction", () => {
  it("forbids the operator role", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: SAMPLE_TENANT,
      subject: "ops",
    });
    await expect(verifyAuditChainAction({})).rejects.toMatchObject({
      code: "forbidden",
    });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("refuses admin without a session-bound tenant (closed taxonomy)", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: null,
      subject: "admin_console:admin",
    });
    await expect(verifyAuditChainAction({})).rejects.toMatchObject({
      code: "forbidden",
    });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("posts an empty body and forwards filter params via query string", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(okVerify());

    await verifyAuditChainAction({
      tenantId: OTHER_TENANT,
      eventType: "scan.start",
      since: "2026-04-01T00:00:00Z",
      until: "2026-04-21T00:00:00Z",
    });

    expect(callAdminBackendJson).toHaveBeenCalledTimes(1);
    const [path, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { method: string; body: string; headers: Record<string, string> },
    ];
    expect(init.method).toBe("POST");
    expect(init.body).toBe("{}");
    expect(path).toContain(`tenant_id=${OTHER_TENANT}`);
    expect(path).toContain("event_type=scan.start");
    expect(path).toContain("since=");
    expect(path).toContain("until=");
    expect(init.headers["X-Admin-Tenant"]).toBe(OTHER_TENANT);
    expect(init.headers["X-Operator-Subject"]).toBe(
      "admin_console:super-admin",
    );
  });

  it("returns the parsed AuditChainVerifyResponse on success", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(okVerify({ verified_count: 99 }));
    const out = await verifyAuditChainAction({});
    expect(out.ok).toBe(true);
    expect(out.verified_count).toBe(99);
  });

  it("translates upstream errors via the closed taxonomy", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(err(503));
    await expect(verifyAuditChainAction({})).rejects.toMatchObject({
      code: "network_error",
    });
  });

  it("treats malformed verify response as server_error", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue({
      ok: true,
      status: 200,
      data: { ok: "yes-please" /* wrong type */ },
    });
    await expect(verifyAuditChainAction({})).rejects.toMatchObject({
      code: "server_error",
    });
  });
});
