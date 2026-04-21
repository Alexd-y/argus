import { describe, expect, it } from "vitest";

import {
  ScheduleActionError,
  detailToScheduleActionCode,
  isUuid,
  mapScheduleBackendError,
  scheduleActionErrorMessage,
  shortUuid,
  statusToScheduleActionCode,
  ScheduleCreateInputSchema,
  ScheduleUpdateInputSchema,
  RunNowInputSchema,
} from "./adminSchedules";

const VALID_UUID = "11111111-2222-4333-8444-555555555555";

describe("statusToScheduleActionCode", () => {
  it("maps 401 → unauthorized", () => {
    expect(statusToScheduleActionCode(401)).toBe("unauthorized");
  });
  it("maps 403 → forbidden", () => {
    expect(statusToScheduleActionCode(403)).toBe("forbidden");
  });
  it("maps 404 → schedule_not_found", () => {
    expect(statusToScheduleActionCode(404)).toBe("schedule_not_found");
  });
  it("maps 409 → schedule_name_conflict (default)", () => {
    expect(statusToScheduleActionCode(409)).toBe("schedule_name_conflict");
  });
  it("maps 422 → invalid_cron_expression", () => {
    expect(statusToScheduleActionCode(422)).toBe("invalid_cron_expression");
  });
  it("maps 400 → validation_failed", () => {
    expect(statusToScheduleActionCode(400)).toBe("validation_failed");
  });
  it("maps 503 → store_unavailable", () => {
    expect(statusToScheduleActionCode(503)).toBe("store_unavailable");
  });
  it("falls back to server_error for unknown status", () => {
    expect(statusToScheduleActionCode(599)).toBe("server_error");
  });
});

describe("detailToScheduleActionCode", () => {
  it("returns null for non-string detail", () => {
    expect(detailToScheduleActionCode(null)).toBeNull();
    expect(detailToScheduleActionCode(undefined)).toBeNull();
    expect(detailToScheduleActionCode(42)).toBeNull();
    expect(detailToScheduleActionCode({})).toBeNull();
  });
  it("returns null for empty string", () => {
    expect(detailToScheduleActionCode("")).toBeNull();
    expect(detailToScheduleActionCode("   ")).toBeNull();
  });
  it("maps T33 snake_case tokens", () => {
    expect(detailToScheduleActionCode("schedule_not_found")).toBe(
      "schedule_not_found",
    );
    expect(detailToScheduleActionCode("schedule_name_conflict")).toBe(
      "schedule_name_conflict",
    );
    expect(detailToScheduleActionCode("invalid_cron_expression")).toBe(
      "invalid_cron_expression",
    );
    expect(detailToScheduleActionCode("invalid_maintenance_window_cron")).toBe(
      "invalid_maintenance_window_cron",
    );
    expect(detailToScheduleActionCode("in_maintenance_window")).toBe(
      "in_maintenance_window",
    );
    expect(detailToScheduleActionCode("emergency_active")).toBe(
      "emergency_active",
    );
    expect(detailToScheduleActionCode("forbidden")).toBe("forbidden");
    expect(detailToScheduleActionCode("tenant_id_required")).toBe(
      "tenant_required",
    );
    expect(detailToScheduleActionCode("tenant_header_required")).toBe(
      "tenant_required",
    );
    expect(detailToScheduleActionCode("tenant_mismatch")).toBe(
      "tenant_mismatch",
    );
    expect(detailToScheduleActionCode("tenant_not_found")).toBe(
      "validation_failed",
    );
  });
  it("returns null for unknown tokens (caller falls back to status mapping)", () => {
    expect(detailToScheduleActionCode("entirely_unknown_thing")).toBeNull();
  });
  it("normalizes to lowercase", () => {
    expect(detailToScheduleActionCode("SCHEDULE_NOT_FOUND")).toBe(
      "schedule_not_found",
    );
  });
});

describe("mapScheduleBackendError", () => {
  it("prefers detail-based code over status-based code", () => {
    const err = mapScheduleBackendError({
      status: 409,
      detail: "in_maintenance_window",
    });
    expect(err).toBeInstanceOf(ScheduleActionError);
    expect(err.code).toBe("in_maintenance_window");
    expect(err.status).toBe(409);
  });
  it("falls back to status mapping when detail is unknown", () => {
    const err = mapScheduleBackendError({ status: 422, detail: "weird" });
    expect(err.code).toBe("invalid_cron_expression");
  });
  it("disambiguates 409 emergency_active vs schedule_name_conflict", () => {
    expect(
      mapScheduleBackendError({ status: 409, detail: "emergency_active" }).code,
    ).toBe("emergency_active");
    expect(
      mapScheduleBackendError({ status: 409 }).code,
    ).toBe("schedule_name_conflict");
  });
});

describe("scheduleActionErrorMessage", () => {
  it("returns RU sentence for ScheduleActionError", () => {
    const err = new ScheduleActionError("schedule_not_found", 404);
    expect(scheduleActionErrorMessage(err)).toMatch(/не найдено/i);
  });
  it("falls back to server_error for plain Error / unknown", () => {
    expect(scheduleActionErrorMessage(new Error("boom"))).toMatch(
      /Не удалось/i,
    );
    expect(scheduleActionErrorMessage("string")).toMatch(/Не удалось/i);
    expect(scheduleActionErrorMessage(null)).toMatch(/Не удалось/i);
  });
  it("never echoes the raw error message", () => {
    const err = new Error("internal stack trace leaks");
    expect(scheduleActionErrorMessage(err)).not.toContain("stack trace");
  });
});

describe("isUuid / shortUuid", () => {
  it("accepts valid UUID", () => {
    expect(isUuid(VALID_UUID)).toBe(true);
  });
  it("rejects bad inputs", () => {
    expect(isUuid("not-a-uuid")).toBe(false);
    expect(isUuid("")).toBe(false);
    expect(isUuid(`${VALID_UUID} `)).toBe(false);
  });
  it("shortens UUID to 8 chars + ellipsis", () => {
    expect(shortUuid(VALID_UUID)).toBe("11111111…");
  });
  it("returns short ids unchanged", () => {
    expect(shortUuid("abc")).toBe("abc");
  });
});

describe("ScheduleCreateInputSchema", () => {
  const baseInput = {
    tenantId: VALID_UUID,
    name: "  Daily scan  ",
    cronExpression: "0 * * * *",
    targetUrl: "https://example.com",
    scanMode: "standard" as const,
    enabled: true,
    maintenanceWindowCron: null,
  };

  it("trims name + cron + targetUrl", () => {
    const parsed = ScheduleCreateInputSchema.parse(baseInput);
    expect(parsed.name).toBe("Daily scan");
  });

  it("rejects bad tenantId", () => {
    const r = ScheduleCreateInputSchema.safeParse({
      ...baseInput,
      tenantId: "nope",
    });
    expect(r.success).toBe(false);
  });

  it("rejects bad targetUrl shape", () => {
    const r = ScheduleCreateInputSchema.safeParse({
      ...baseInput,
      targetUrl: "javascript:alert(1)",
    });
    expect(r.success).toBe(false);
  });

  it("converts empty maintenance string to null", () => {
    const parsed = ScheduleCreateInputSchema.parse({
      ...baseInput,
      maintenanceWindowCron: "  ",
    });
    expect(parsed.maintenanceWindowCron).toBeNull();
  });
});

describe("ScheduleUpdateInputSchema", () => {
  it("accepts partial updates", () => {
    const r = ScheduleUpdateInputSchema.parse({ enabled: false });
    expect(r.enabled).toBe(false);
    expect(r.name).toBeUndefined();
  });

  it("trims name", () => {
    const r = ScheduleUpdateInputSchema.parse({ name: "  abc  " });
    expect(r.name).toBe("abc");
  });

  it("rejects bad targetUrl", () => {
    const r = ScheduleUpdateInputSchema.safeParse({
      targetUrl: "javascript:alert(1)",
    });
    expect(r.success).toBe(false);
  });
});

describe("RunNowInputSchema", () => {
  it("requires reason >= 10 chars", () => {
    const r = RunNowInputSchema.safeParse({
      bypassMaintenanceWindow: false,
      reason: "short",
    });
    expect(r.success).toBe(false);
  });
  it("trims reason then checks length", () => {
    const r = RunNowInputSchema.parse({
      bypassMaintenanceWindow: true,
      reason: "  emergency lift maintenance window  ",
    });
    expect(r.reason).toBe("emergency lift maintenance window");
  });
});
