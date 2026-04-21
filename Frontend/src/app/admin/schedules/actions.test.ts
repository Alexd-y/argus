import { beforeEach, describe, expect, it, vi } from "vitest";

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
  createScheduleAction,
  deleteScheduleAction,
  listSchedulesAction,
  runNowAction,
  updateScheduleAction,
} from "./actions";

const TENANT_A = "11111111-1111-1111-1111-111111111111";
const TENANT_B = "22222222-2222-2222-2222-222222222222";
const SCHEDULE_ID = "33333333-3333-4333-8333-333333333333";
const REASON = "manual run for soak testing window";

const SCHEDULE_FIXTURE = {
  id: SCHEDULE_ID,
  tenant_id: TENANT_A,
  name: "Daily scan",
  cron_expression: "0 * * * *",
  target_url: "https://example.com",
  scan_mode: "standard",
  enabled: true,
  maintenance_window_cron: null,
  last_run_at: null,
  next_run_at: "2026-04-22T01:00:00Z",
  created_at: "2026-04-22T00:00:00Z",
  updated_at: "2026-04-22T00:00:00Z",
};

const RUN_NOW_FIXTURE = {
  schedule_id: SCHEDULE_ID,
  enqueued_task_id: "task-abc",
  bypassed_maintenance_window: false,
  enqueued_at: "2026-04-22T00:00:00Z",
  audit_id: "audit-xyz",
};

function ok(data: unknown, status = 200) {
  return { ok: true as const, status, data };
}

function err(
  status: number,
  body: { detail?: unknown } = {},
) {
  return {
    ok: false as const,
    status,
    error: "redacted",
    detail: body.detail,
  };
}

beforeEach(() => {
  callAdminBackendJson.mockReset();
  sessionMock.mockReset();
});

// ---------------------------------------------------------------------------
// listSchedulesAction
// ---------------------------------------------------------------------------

describe("listSchedulesAction", () => {
  it("admin operator → forces own session tenant in query + header", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(
      ok({ items: [], total: 0, limit: 50, offset: 0 }),
    );

    const r = await listSchedulesAction({ tenantId: TENANT_B });
    expect(r.items).toEqual([]);

    const [path, init] = callAdminBackendJson.mock.calls[0];
    expect(path).toContain(`tenant_id=${TENANT_A}`);
    expect((init as { headers: Record<string, string> }).headers["X-Admin-Tenant"]).toBe(
      TENANT_A,
    );
  });

  it("super-admin + null tenantId → no tenant_id query param + no header", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(
      ok({ items: [], total: 0, limit: 50, offset: 0 }),
    );

    await listSchedulesAction({ tenantId: null });
    const [path, init] = callAdminBackendJson.mock.calls[0];
    expect(path).not.toContain("tenant_id=");
    expect(
      (init as { headers: Record<string, string> }).headers["X-Admin-Tenant"],
    ).toBeUndefined();
  });

  it("operator role with no tenant → forbidden", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: null,
      subject: "admin_console:operator",
    });
    await expect(listSchedulesAction({})).rejects.toMatchObject({
      code: "forbidden",
    });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("unauthenticated → unauthorized", async () => {
    sessionMock.mockResolvedValue({
      role: null,
      tenantId: null,
      subject: "admin_console",
    });
    await expect(listSchedulesAction({})).rejects.toMatchObject({
      code: "unauthorized",
    });
  });

  it("503 transport → store_unavailable", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(err(503));
    await expect(listSchedulesAction({})).rejects.toMatchObject({
      code: "store_unavailable",
    });
  });

  it("response shape drift → server_error (never crashes the route)", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(ok({ unexpected: true }));
    await expect(listSchedulesAction({})).rejects.toMatchObject({
      code: "server_error",
    });
  });
});

// ---------------------------------------------------------------------------
// createScheduleAction
// ---------------------------------------------------------------------------

describe("createScheduleAction", () => {
  const VALID_INPUT = {
    tenantId: TENANT_A,
    name: "Daily scan",
    cronExpression: "0 * * * *",
    targetUrl: "https://example.com",
    scanMode: "standard" as const,
    enabled: true,
    maintenanceWindowCron: null as string | null,
  };

  it("operator → forbidden BEFORE Zod (no input probing)", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: TENANT_A,
      subject: "admin_console:operator",
    });
    await expect(createScheduleAction({ garbage: 1 })).rejects.toMatchObject({
      code: "forbidden",
    });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("admin tries another tenant → forbidden", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    await expect(
      createScheduleAction({ ...VALID_INPUT, tenantId: TENANT_B }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("super-admin can create on any tenant", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValue(ok(SCHEDULE_FIXTURE, 201));
    const r = await createScheduleAction({ ...VALID_INPUT, tenantId: TENANT_B });
    expect(r.id).toBe(SCHEDULE_ID);
  });

  it("409 → schedule_name_conflict", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(
      err(409, { detail: "schedule_name_conflict" }),
    );
    await expect(createScheduleAction(VALID_INPUT)).rejects.toMatchObject({
      code: "schedule_name_conflict",
    });
  });

  it("422 + invalid_cron_expression → invalid_cron_expression", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    callAdminBackendJson.mockResolvedValue(
      err(422, { detail: "invalid_cron_expression" }),
    );
    await expect(createScheduleAction(VALID_INPUT)).rejects.toMatchObject({
      code: "invalid_cron_expression",
    });
  });

  it("invalid Zod input → validation_failed (no backend call)", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
    await expect(
      createScheduleAction({ ...VALID_INPUT, name: "" }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// updateScheduleAction
// ---------------------------------------------------------------------------

describe("updateScheduleAction", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
  });

  it("404 → schedule_not_found (cross-tenant probe protection)", async () => {
    callAdminBackendJson.mockResolvedValue(
      err(404, { detail: "schedule_not_found" }),
    );
    await expect(
      updateScheduleAction(SCHEDULE_ID, { enabled: false }),
    ).rejects.toMatchObject({ code: "schedule_not_found" });
  });

  it("non-UUID schedule id → validation_failed (no backend call)", async () => {
    await expect(
      updateScheduleAction("not-a-uuid", { enabled: false }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("only sends snake_case keys for fields the operator changed", async () => {
    callAdminBackendJson.mockResolvedValue(ok(SCHEDULE_FIXTURE));
    await updateScheduleAction(SCHEDULE_ID, {
      enabled: false,
      cronExpression: "*/30 * * * *",
    });
    const [, init] = callAdminBackendJson.mock.calls[0];
    const body = JSON.parse((init as { body: string }).body);
    expect(body).toEqual({
      enabled: false,
      cron_expression: "*/30 * * * *",
    });
    expect(body).not.toHaveProperty("name");
  });
});

// ---------------------------------------------------------------------------
// deleteScheduleAction
// ---------------------------------------------------------------------------

describe("deleteScheduleAction", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
  });

  it("204 → resolves to undefined", async () => {
    callAdminBackendJson.mockResolvedValue(ok(undefined, 204));
    await expect(deleteScheduleAction(SCHEDULE_ID)).resolves.toBeUndefined();
  });

  it("404 → schedule_not_found", async () => {
    callAdminBackendJson.mockResolvedValue(
      err(404, { detail: "schedule_not_found" }),
    );
    await expect(deleteScheduleAction(SCHEDULE_ID)).rejects.toMatchObject({
      code: "schedule_not_found",
    });
  });

  it("operator → forbidden", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: TENANT_A,
      subject: "admin_console:operator",
    });
    await expect(deleteScheduleAction(SCHEDULE_ID)).rejects.toMatchObject({
      code: "forbidden",
    });
  });
});

// ---------------------------------------------------------------------------
// runNowAction
// ---------------------------------------------------------------------------

describe("runNowAction", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: TENANT_A,
      subject: "admin_console:admin",
    });
  });

  it("202 → returns RunNowResponse", async () => {
    callAdminBackendJson.mockResolvedValue(ok(RUN_NOW_FIXTURE, 202));
    const r = await runNowAction(SCHEDULE_ID, {
      bypassMaintenanceWindow: false,
      reason: REASON,
    });
    expect(r.enqueued_task_id).toBe("task-abc");
  });

  it("409 + in_maintenance_window → in_maintenance_window", async () => {
    callAdminBackendJson.mockResolvedValue(
      err(409, { detail: "in_maintenance_window" }),
    );
    await expect(
      runNowAction(SCHEDULE_ID, {
        bypassMaintenanceWindow: false,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "in_maintenance_window" });
  });

  it("409 + emergency_active → emergency_active", async () => {
    callAdminBackendJson.mockResolvedValue(
      err(409, { detail: "emergency_active" }),
    );
    await expect(
      runNowAction(SCHEDULE_ID, {
        bypassMaintenanceWindow: false,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "emergency_active" });
  });

  it("Zod failure → validation_failed", async () => {
    await expect(
      runNowAction(SCHEDULE_ID, {
        bypassMaintenanceWindow: false,
        reason: "short",
      }),
    ).rejects.toMatchObject({ code: "validation_failed" });
  });

  it("non-UUID → validation_failed", async () => {
    await expect(
      runNowAction("nope", {
        bypassMaintenanceWindow: false,
        reason: REASON,
      }),
    ).rejects.toMatchObject({ code: "validation_failed" });
  });
});
