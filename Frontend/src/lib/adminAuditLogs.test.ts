import { describe, expect, it } from "vitest";

import {
  AdminAuditLogsError,
  AuditChainVerifyResponseSchema,
  AuditLogItemSchema,
  AuditLogsListResponseSchema,
  adminAuditLogsErrorMessage,
  hasChainMarkers,
  prettyPrintDetails,
  statusToAdminAuditLogsCode,
} from "./adminAuditLogs";

const SAMPLE_TENANT = "00000000-0000-0000-0000-000000000001";
const SAMPLE_ID = "11111111-1111-1111-1111-111111111111";
const SAMPLE_TS = "2026-04-21T08:00:00Z";

describe("AuditLogItemSchema — wire normalisation", () => {
  it("normalises the legacy wire shape (action / user_id) into UI fields", () => {
    const parsed = AuditLogItemSchema.parse({
      id: SAMPLE_ID,
      created_at: SAMPLE_TS,
      action: "scan.start",
      user_id: "alice",
      tenant_id: SAMPLE_TENANT,
      resource_type: "scan",
      resource_id: "abc",
      details: { foo: "bar" },
    });
    expect(parsed.event_type).toBe("scan.start");
    expect(parsed.actor_subject).toBe("alice");
    expect(parsed.tenant_id).toBe(SAMPLE_TENANT);
  });

  it("prefers public field names when both wire and public names are present", () => {
    const parsed = AuditLogItemSchema.parse({
      id: SAMPLE_ID,
      created_at: SAMPLE_TS,
      action: "scan.start",
      event_type: "scan.start.public",
      user_id: "alice",
      actor_subject: "alice@public",
    });
    expect(parsed.event_type).toBe("scan.start.public");
    expect(parsed.actor_subject).toBe("alice@public");
  });

  it("lifts severity from `details.severity` when no top-level field is present", () => {
    const parsed = AuditLogItemSchema.parse({
      id: SAMPLE_ID,
      created_at: SAMPLE_TS,
      action: "policy.deny",
      details: { severity: "HIGH" },
    });
    expect(parsed.severity).toBe("high");
  });

  it("returns null severity when neither top-level nor details carry a known value", () => {
    const parsed = AuditLogItemSchema.parse({
      id: SAMPLE_ID,
      created_at: SAMPLE_TS,
      action: "policy.deny",
      details: { unrelated: 1 },
    });
    expect(parsed.severity).toBeNull();
  });

  it("rejects a payload missing the required `id` field", () => {
    expect(() =>
      AuditLogItemSchema.parse({
        created_at: SAMPLE_TS,
        action: "scan.start",
      }),
    ).toThrow();
  });
});

describe("AuditLogsListResponseSchema — envelope + bare-array tolerance", () => {
  it("accepts the wrapped envelope and surfaces total / next_cursor", () => {
    const parsed = AuditLogsListResponseSchema.parse({
      items: [
        {
          id: SAMPLE_ID,
          created_at: SAMPLE_TS,
          action: "scan.start",
        },
      ],
      total: 1,
      next_cursor: "50",
    });
    expect(parsed.items).toHaveLength(1);
    expect(parsed.total).toBe(1);
    expect(parsed.next_cursor).toBe("50");
  });

  it("accepts a bare array (current Phase-1 backend) and synthesises empty cursor", () => {
    const parsed = AuditLogsListResponseSchema.parse([
      {
        id: SAMPLE_ID,
        created_at: SAMPLE_TS,
        action: "scan.start",
      },
    ]);
    expect(parsed.items).toHaveLength(1);
    expect(parsed.next_cursor).toBeNull();
    expect(parsed.total).toBe(1);
  });

  it("converts an empty next_cursor string into null", () => {
    const parsed = AuditLogsListResponseSchema.parse({
      items: [],
      next_cursor: "",
    });
    expect(parsed.next_cursor).toBeNull();
  });

  it("rejects malformed items (closed-taxonomy contract)", () => {
    expect(() =>
      AuditLogsListResponseSchema.parse({
        items: [{ created_at: SAMPLE_TS }],
      }),
    ).toThrow();
  });
});

describe("AuditChainVerifyResponseSchema", () => {
  it("parses the OK shape from T25", () => {
    const parsed = AuditChainVerifyResponseSchema.parse({
      ok: true,
      verified_count: 12,
      last_verified_index: 11,
      drift_event_id: null,
      drift_detected_at: null,
      effective_since: SAMPLE_TS,
      effective_until: SAMPLE_TS,
    });
    expect(parsed.ok).toBe(true);
    expect(parsed.verified_count).toBe(12);
  });

  it("parses the DRIFT shape with attribution", () => {
    const parsed = AuditChainVerifyResponseSchema.parse({
      ok: false,
      verified_count: 5,
      last_verified_index: 4,
      drift_event_id: "evt-x",
      drift_detected_at: SAMPLE_TS,
      effective_since: SAMPLE_TS,
      effective_until: SAMPLE_TS,
    });
    expect(parsed.ok).toBe(false);
    expect(parsed.drift_event_id).toBe("evt-x");
    expect(parsed.drift_detected_at).toBe(SAMPLE_TS);
  });

  it("rejects negative last_verified_index outside the allowed sentinel (-1)", () => {
    expect(() =>
      AuditChainVerifyResponseSchema.parse({
        ok: true,
        verified_count: 0,
        last_verified_index: -2,
        drift_event_id: null,
        drift_detected_at: null,
        effective_since: SAMPLE_TS,
        effective_until: SAMPLE_TS,
      }),
    ).toThrow();
  });
});

describe("hasChainMarkers", () => {
  it("returns true when `_event_hash` is a string", () => {
    expect(
      hasChainMarkers({ _event_hash: "deadbeef", _prev_event_hash: null }),
    ).toBe(true);
  });

  it("returns true when only `_prev_event_hash` is a string", () => {
    expect(hasChainMarkers({ _prev_event_hash: "abc" })).toBe(true);
  });

  it("returns false for arrays / null / scalars", () => {
    expect(hasChainMarkers(null)).toBe(false);
    expect(hasChainMarkers([])).toBe(false);
    expect(hasChainMarkers("not-an-object")).toBe(false);
    expect(hasChainMarkers({ _event_hash: 42 })).toBe(false);
  });
});

describe("prettyPrintDetails", () => {
  it("returns em-dash for null/undefined", () => {
    expect(prettyPrintDetails(null)).toBe("—");
    expect(prettyPrintDetails(undefined)).toBe("—");
  });

  it("pretty-prints JSON with stable indentation", () => {
    const out = prettyPrintDetails({ foo: 1, bar: [2, 3] });
    expect(out).toContain('"foo": 1');
    expect(out).toContain('"bar"');
    expect(out.split("\n").length).toBeGreaterThan(1);
  });
});

describe("error taxonomy", () => {
  it("statusToAdminAuditLogsCode maps standard HTTP codes correctly", () => {
    expect(statusToAdminAuditLogsCode(401)).toBe("unauthorized");
    expect(statusToAdminAuditLogsCode(403)).toBe("forbidden");
    expect(statusToAdminAuditLogsCode(429)).toBe("rate_limited");
    expect(statusToAdminAuditLogsCode(400)).toBe("invalid_input");
    expect(statusToAdminAuditLogsCode(422)).toBe("invalid_input");
    expect(statusToAdminAuditLogsCode(500)).toBe("server_error");
  });

  it("adminAuditLogsErrorMessage returns a localised RU sentence per code", () => {
    expect(
      adminAuditLogsErrorMessage(new AdminAuditLogsError("forbidden", 403)),
    ).toMatch(/прав/);
    expect(
      adminAuditLogsErrorMessage(new AdminAuditLogsError("rate_limited", 429)),
    ).toMatch(/Слишком/);
    expect(
      adminAuditLogsErrorMessage(new AdminAuditLogsError("network_error", 503)),
    ).toMatch(/Сеть/);
    // Unknown / non-AdminAuditLogsError errors fall back to the generic
    // server-error sentence.
    expect(adminAuditLogsErrorMessage(new Error("boom"))).toMatch(/Не удалось/);
  });
});
