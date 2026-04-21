import { beforeEach, describe, expect, it, vi } from "vitest";

import { ThrottleActionError } from "@/lib/adminOperations";
import type { ServerAdminSession } from "@/services/admin/serverSession";

const callAdminBackendJson = vi.fn();
vi.mock("@/lib/serverAdminBackend", () => ({
  callAdminBackendJson: (...args: unknown[]) => callAdminBackendJson(...args),
}));

const sessionMock = vi.fn<() => Promise<ServerAdminSession>>();
vi.mock("@/services/admin/serverSession", () => ({
  getServerAdminSession: () => sessionMock(),
}));

import {
  getEmergencyStatusAction,
  listEmergencyAuditTrailAction,
  resumeTenantAction,
  throttleTenantAction,
} from "./actions";

const TENANT_A = "00000000-0000-0000-0000-000000000001";
const TENANT_B = "00000000-0000-0000-0000-000000000002";
const REASON = "operator-supplied throttle reason";

function ok(data: unknown, status = 200) {
  return { ok: true as const, status, data };
}

function err(status: number, body: unknown = {}) {
  return { ok: false as const, status, error: "redacted", data: body };
}

function throttleResponse(over: Partial<Record<string, unknown>> = {}) {
  return {
    status: "throttled",
    tenant_id: over.tenant_id ?? TENANT_A,
    duration_minutes: over.duration_minutes ?? 60,
    expires_at: over.expires_at ?? "2026-04-22T01:00:00Z",
    audit_id: over.audit_id ?? "audit-1",
  };
}

function statusResponse(over: Partial<Record<string, unknown>> = {}) {
  return {
    global_state: over.global_state ?? { active: false, reason: null },
    tenant_throttles: over.tenant_throttles ?? [],
    queried_at: over.queried_at ?? "2026-04-22T00:00:00Z",
  };
}

beforeEach(() => {
  callAdminBackendJson.mockReset();
  sessionMock.mockReset();
});

// ---------------------------------------------------------------------------
// throttleTenantAction — input validation
// ---------------------------------------------------------------------------

describe("throttleTenantAction — input validation", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
  });

  it("rejects non-UUID tenantId with validation_failed (no backend call)", async () => {
    await expect(
      throttleTenantAction({
        tenantId: "not-a-uuid",
        durationMinutes: 60,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("rejects too-short reason as validation_failed", async () => {
    await expect(
      throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 60,
        reason: "short",
      }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("rejects too-long reason as validation_failed", async () => {
    await expect(
      throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 60,
        reason: "x".repeat(501),
      }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("rejects unknown duration with duration_not_allowed", async () => {
    await expect(
      throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 30,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "duration_not_allowed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("rejects 0 (manual-resume sentinel) with duration_not_allowed", async () => {
    await expect(
      throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 0,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "duration_not_allowed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// throttleTenantAction — RBAC enforcement (S0-1, S1-6)
// ---------------------------------------------------------------------------

describe("throttleTenantAction — RBAC", () => {
  it("rejects an unauthenticated session with unauthorized", async () => {
    sessionMock.mockResolvedValue({
      role: null,
      tenantId: null,
      subject: "anon",
    });

    await expect(
      throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 60,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "unauthorized" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("rejects operator role as forbidden (no backend call)", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: TENANT_A,
      subject: "admin_console:operator",
    });

    await expect(
      throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 60,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("admin role: refuses cross-tenant throttle as forbidden", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });

    await expect(
      throttleTenantAction({
        tenantId: TENANT_B,
        durationMinutes: 60,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("admin role with no session-bound tenant: forbidden", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: null,
      subject: "admin_console:admin",
    });

    await expect(
      throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 60,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("super-admin: targets the caller-supplied tenant and forwards identity headers", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(
      ok(throttleResponse({ tenant_id: TENANT_B })),
    );

    const out = await throttleTenantAction({
      tenantId: TENANT_B,
      durationMinutes: 240,
      reason: REASON,
    });

    expect(out.tenant_id).toBe(TENANT_B);
    expect(out.status).toBe("throttled");
    expect(callAdminBackendJson).toHaveBeenCalledTimes(1);
    const [path, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string>; body: string; method: string },
    ];
    expect(path).toBe("/system/emergency/throttle");
    expect(init.method).toBe("POST");
    expect(init.headers["X-Admin-Role"]).toBe("super-admin");
    expect(init.headers["X-Admin-Tenant"]).toBe(TENANT_B);
    expect(init.headers["X-Operator-Subject"]).toBe(
      "admin_console:super-admin",
    );
    const body = JSON.parse(init.body);
    expect(body).toEqual({
      tenant_id: TENANT_B,
      duration_minutes: 240,
      reason: REASON,
    });
  });

  it("admin role: pins to session.tenantId even if caller forges a different one", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(
      ok(throttleResponse({ tenant_id: TENANT_A })),
    );

    const out = await throttleTenantAction({
      tenantId: TENANT_A,
      durationMinutes: 15,
      reason: REASON,
    });

    expect(out.tenant_id).toBe(TENANT_A);
    const [, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string>; body: string },
    ];
    expect(init.headers["X-Admin-Tenant"]).toBe(TENANT_A);
  });
});

// ---------------------------------------------------------------------------
// throttleTenantAction — backend-error taxonomy
// ---------------------------------------------------------------------------

describe("throttleTenantAction — backend response taxonomy", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
  });

  it("propagates 200 success body via Zod parse", async () => {
    callAdminBackendJson.mockResolvedValue(ok(throttleResponse()));
    const out = await throttleTenantAction({
      tenantId: TENANT_A,
      durationMinutes: 60,
      reason: REASON,
    });
    expect(out).toEqual(throttleResponse());
  });

  it.each([
    [401, "unauthorized"],
    [403, "forbidden"],
    [404, "tenant_not_found"],
    [409, "already_active"],
    [422, "validation_failed"],
    [429, "rate_limited"],
    [503, "store_unavailable"],
    [500, "server_error"],
  ] as const)("translates HTTP %s to '%s'", async (status, code) => {
    callAdminBackendJson.mockResolvedValue(err(status));
    await expect(
      throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 60,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code });
  });

  it("translates malformed envelope (200 OK, missing fields) → server_error", async () => {
    callAdminBackendJson.mockResolvedValue(ok({ totally: "wrong" }));
    await expect(
      throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 60,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "server_error" });
  });

  it("never echoes raw backend body / Zod issues to the caller", async () => {
    callAdminBackendJson.mockResolvedValue({
      ok: false,
      status: 500,
      error:
        'Traceback (most recent call last):\n  File "/app/admin/views.py"',
    });
    try {
      await throttleTenantAction({
        tenantId: TENANT_A,
        durationMinutes: 60,
        reason: REASON,
      });
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(ThrottleActionError);
      expect(String((e as Error).message)).not.toMatch(
        /Traceback|views\.py|admin\/views/,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// getEmergencyStatusAction
// ---------------------------------------------------------------------------

describe("getEmergencyStatusAction", () => {
  it("admin: scopes the GET to session.tenantId regardless of caller arg", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(ok(statusResponse()));

    await getEmergencyStatusAction({ tenantId: TENANT_B });

    const [path, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string>; method: string },
    ];
    expect(path).toBe(`/system/emergency/status?tenant_id=${TENANT_A}`);
    expect(init.method).toBe("GET");
    expect(init.headers["X-Admin-Role"]).toBe("admin");
    expect(init.headers["X-Admin-Tenant"]).toBe(TENANT_A);
  });

  it("admin without session tenant: forbidden", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: null,
      subject: "admin_console:admin",
    });

    await expect(
      getEmergencyStatusAction({ tenantId: TENANT_A }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("super-admin without tenant: cross-tenant view (no tenant_id query)", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(ok(statusResponse()));

    await getEmergencyStatusAction({});

    const [path, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string> },
    ];
    expect(path).toBe("/system/emergency/status");
    expect(init.headers["X-Admin-Tenant"]).toBeUndefined();
  });

  it("super-admin with tenant: scopes the GET to that tenant", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(ok(statusResponse()));

    await getEmergencyStatusAction({ tenantId: TENANT_B });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toBe(`/system/emergency/status?tenant_id=${TENANT_B}`);
  });

  it("operator: forbidden", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: TENANT_A,
      subject: "admin_console:operator",
    });
    await expect(getEmergencyStatusAction({})).rejects.toMatchObject({
      code: "forbidden",
    });
  });

  it("invalid envelope from backend: server_error", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(ok({ wrong: "shape" }));
    await expect(getEmergencyStatusAction({})).rejects.toMatchObject({
      code: "server_error",
    });
  });
});

// ---------------------------------------------------------------------------
// listEmergencyAuditTrailAction
// ---------------------------------------------------------------------------

describe("listEmergencyAuditTrailAction", () => {
  it("admin: scopes audit list to session.tenantId, clamps limit to default", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(
      ok({ items: [], limit: 25, has_more: false }),
    );

    await listEmergencyAuditTrailAction({ tenantId: TENANT_B });

    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain(`tenant_id=${TENANT_A}`);
    expect(path).toContain("limit=25");
  });

  it("clamps limit to MAX_AUDIT_LIMIT when caller passes too high", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(
      ok({ items: [], limit: 200, has_more: false }),
    );

    await listEmergencyAuditTrailAction({ limit: 5000 });

    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("limit=200");
  });

  it("clamps limit to 1 when caller passes 0 or negative", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(
      ok({ items: [], limit: 1, has_more: false }),
    );

    await listEmergencyAuditTrailAction({ limit: 0 });
    const [path] = callAdminBackendJson.mock.calls[0] as [string, unknown];
    expect(path).toContain("limit=1");
  });
});

// ---------------------------------------------------------------------------
// resumeTenantAction (ISS-T29-001 carry-over)
// ---------------------------------------------------------------------------

describe("resumeTenantAction — carry-over", () => {
  it("authenticated admin: throws not_implemented (no backend call)", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });

    await expect(
      resumeTenantAction({ tenantId: TENANT_A }),
    ).rejects.toMatchObject({ code: "not_implemented" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("operator: gets forbidden BEFORE the not_implemented branch", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: TENANT_A,
      subject: "admin_console:operator",
    });
    await expect(
      resumeTenantAction({ tenantId: TENANT_A }),
    ).rejects.toMatchObject({ code: "forbidden" });
  });
});
