import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScanActionError } from "@/lib/adminScans";
import type { ServerAdminSession } from "@/services/admin/serverSession";

const callAdminBackendJson = vi.fn();
vi.mock("@/lib/serverAdminBackend", () => ({
  callAdminBackendJson: (...args: unknown[]) => callAdminBackendJson(...args),
}));

const sessionMock = vi.fn<() => Promise<ServerAdminSession>>();
vi.mock("@/services/admin/serverSession", () => ({
  getServerAdminSession: () => sessionMock(),
}));

import { cancelAdminScan } from "./actions";

const SCAN_A = "11111111-1111-1111-1111-111111111111";
const TENANT_A = "00000000-0000-0000-0000-000000000001";
const TENANT_B = "00000000-0000-0000-0000-000000000002";
const REASON = "manual operator stop via kill-switch";

function ok(
  overrides: {
    cancelled_count?: number;
    skipped_terminal_count?: number;
    not_found_count?: number;
    audit_id?: string;
    results?: Array<{
      scan_id: string;
      status: "cancelled" | "skipped_terminal" | "not_found";
    }>;
  } = {},
) {
  return {
    ok: true as const,
    status: 200,
    data: {
      cancelled_count: overrides.cancelled_count ?? 1,
      skipped_terminal_count: overrides.skipped_terminal_count ?? 0,
      not_found_count: overrides.not_found_count ?? 0,
      audit_id: overrides.audit_id ?? "audit-1",
      results: overrides.results ?? [
        { scan_id: SCAN_A, status: "cancelled" as const },
      ],
    },
  };
}

function err(status: number, body: unknown = {}) {
  return { ok: false as const, status, error: "x", data: body };
}

beforeEach(() => {
  callAdminBackendJson.mockReset();
  sessionMock.mockReset();
});

describe("cancelAdminScan — input validation", () => {
  it("rejects non-UUID scanId with validation_failed (no backend call)", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });

    await expect(
      cancelAdminScan({
        scanId: "not-a-uuid",
        tenantId: TENANT_A,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("rejects too-short reason as validation_failed", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });

    await expect(
      cancelAdminScan({
        scanId: SCAN_A,
        tenantId: TENANT_A,
        reason: "short",
      }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });
});

describe("cancelAdminScan — RBAC (S0-1, S1-6)", () => {
  it("rejects an unauthenticated session with unauthorized", async () => {
    sessionMock.mockResolvedValue({
      role: null,
      tenantId: null,
      subject: "anon",
    });

    await expect(
      cancelAdminScan({
        scanId: SCAN_A,
        tenantId: TENANT_A,
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
      cancelAdminScan({
        scanId: SCAN_A,
        tenantId: TENANT_A,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("admin role: refuses cross-tenant cancel as forbidden", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });

    await expect(
      cancelAdminScan({
        scanId: SCAN_A,
        tenantId: TENANT_B,
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
    callAdminBackendJson.mockResolvedValue(ok());

    const out = await cancelAdminScan({
      scanId: SCAN_A,
      tenantId: TENANT_B,
      reason: REASON,
    });

    expect(out.status).toBe("cancelled");
    expect(callAdminBackendJson).toHaveBeenCalledTimes(1);
    const [path, init] = callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string>; body: string },
    ];
    expect(path).toBe("/scans/bulk-cancel");
    expect(init.headers["X-Admin-Role"]).toBe("super-admin");
    expect(init.headers["X-Admin-Tenant"]).toBe(TENANT_B);
    expect(init.headers["X-Operator-Subject"]).toBe(
      "admin_console:super-admin",
    );
    const body = JSON.parse(init.body);
    expect(body).toEqual({ tenant_id: TENANT_B, scan_ids: [SCAN_A] });
  });
});

describe("cancelAdminScan — backend response taxonomy", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
  });

  it("propagates status='cancelled' on a successful cancel", async () => {
    callAdminBackendJson.mockResolvedValue(ok());
    const out = await cancelAdminScan({
      scanId: SCAN_A,
      tenantId: TENANT_A,
      reason: REASON,
    });
    expect(out).toEqual({
      status: "cancelled",
      scanId: SCAN_A,
      auditId: "audit-1",
    });
  });

  it("propagates status='skipped_terminal' when the scan is already terminal", async () => {
    callAdminBackendJson.mockResolvedValue(
      ok({
        cancelled_count: 0,
        skipped_terminal_count: 1,
        results: [{ scan_id: SCAN_A, status: "skipped_terminal" }],
      }),
    );
    const out = await cancelAdminScan({
      scanId: SCAN_A,
      tenantId: TENANT_A,
      reason: REASON,
    });
    expect(out.status).toBe("skipped_terminal");
  });

  it("propagates status='not_found' when the backend cannot find the scan", async () => {
    callAdminBackendJson.mockResolvedValue(
      ok({
        cancelled_count: 0,
        not_found_count: 1,
        results: [{ scan_id: SCAN_A, status: "not_found" }],
      }),
    );
    const out = await cancelAdminScan({
      scanId: SCAN_A,
      tenantId: TENANT_A,
      reason: REASON,
    });
    expect(out.status).toBe("not_found");
  });

  it.each([
    [401, "unauthorized"],
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [422, "validation_failed"],
    [429, "rate_limited"],
    [503, "network_error"],
    [500, "server_error"],
  ] as const)("translates HTTP %s to '%s'", async (status, code) => {
    callAdminBackendJson.mockResolvedValue(err(status));
    await expect(
      cancelAdminScan({
        scanId: SCAN_A,
        tenantId: TENANT_A,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code });
  });

  it("translates malformed envelope (200 OK, missing results) → server_error", async () => {
    callAdminBackendJson.mockResolvedValue({
      ok: true,
      status: 200,
      data: { totally: "wrong" },
    });
    await expect(
      cancelAdminScan({
        scanId: SCAN_A,
        tenantId: TENANT_A,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "server_error" });
  });

  it("never echoes raw backend body / Zod issues to the caller", async () => {
    callAdminBackendJson.mockResolvedValue({
      ok: false,
      status: 500,
      error:
        "Traceback (most recent call last):\n  File \"/app/admin/views.py\"",
      data: {
        detail: "Traceback (most recent call last):\n  File \"/app/admin/views.py\"",
      },
    });
    try {
      await cancelAdminScan({
        scanId: SCAN_A,
        tenantId: TENANT_A,
        reason: REASON,
      });
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(ScanActionError);
      expect(String((e as Error).message)).not.toMatch(
        /Traceback|views\.py/,
      );
    }
  });
});
