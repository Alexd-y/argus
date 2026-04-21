import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  AdminFindingsError,
  BulkFindingsActionError,
  type BulkFindingTarget,
} from "@/lib/adminFindings";
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
  bulkMarkFalsePositiveFindingsAction,
  bulkSuppressFindingsAction,
  listAdminFindingsAction,
} from "./actions";

const SAMPLE_TENANT = "00000000-0000-0000-0000-000000000001";
const OTHER_TENANT = "00000000-0000-0000-0000-000000000002";
const FINDING_A = "11111111-1111-1111-1111-111111111111";
const FINDING_B = "22222222-2222-2222-2222-222222222222";
const FINDING_C = "33333333-3333-3333-3333-333333333333";

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

// ────────────────────────────────────────────────────────────────────────────
// Bulk findings actions (T21)
// ────────────────────────────────────────────────────────────────────────────

function bulkOk(overrides: {
  suppressed_count?: number;
  skipped_already_suppressed_count?: number;
  not_found_count?: number;
  audit_id?: string;
  results?: Array<{
    finding_id: string;
    status: "suppressed" | "skipped_already_suppressed" | "not_found";
  }>;
} = {}) {
  return {
    ok: true as const,
    status: 200,
    data: {
      suppressed_count: overrides.suppressed_count ?? 1,
      skipped_already_suppressed_count:
        overrides.skipped_already_suppressed_count ?? 0,
      not_found_count: overrides.not_found_count ?? 0,
      audit_id: overrides.audit_id ?? "audit-1",
      results: overrides.results ?? [
        { finding_id: FINDING_A, status: "suppressed" },
      ],
    },
  };
}

describe("bulkSuppressFindingsAction — RBAC + identity propagation (T21)", () => {
  it("operator role is rejected with BulkFindingsActionError('forbidden') and never reaches the backend", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: SAMPLE_TENANT,
      subject: "admin_console:operator",
    });

    await expect(
      bulkSuppressFindingsAction({
        targets: [{ id: FINDING_A, tenant_id: SAMPLE_TENANT }],
        reason: "duplicate",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("unauthenticated session is rejected with BulkFindingsActionError('unauthorized')", async () => {
    sessionMock.mockResolvedValue({
      role: null,
      tenantId: null,
      subject: "anon",
    });

    await expect(
      bulkSuppressFindingsAction({
        targets: [{ id: FINDING_A, tenant_id: SAMPLE_TENANT }],
        reason: "duplicate",
      }),
    ).rejects.toBeInstanceOf(BulkFindingsActionError);
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("admin role: forbids cross-tenant selection (every id must belong to session tenant)", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: SAMPLE_TENANT,
      subject: "admin_console:admin",
    });

    await expect(
      bulkSuppressFindingsAction({
        targets: [
          { id: FINDING_A, tenant_id: SAMPLE_TENANT },
          { id: FINDING_B, tenant_id: OTHER_TENANT },
        ],
        reason: "duplicate",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("admin role with no session-bound tenant is rejected as forbidden", async () => {
    sessionMock.mockResolvedValue({
      role: "admin",
      tenantId: null,
      subject: "admin_console:admin",
    });

    await expect(
      bulkSuppressFindingsAction({
        targets: [{ id: FINDING_A, tenant_id: SAMPLE_TENANT }],
        reason: "duplicate",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("super-admin: fans out one POST per tenant when selection is cross-tenant", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson
      .mockResolvedValueOnce(
        bulkOk({
          suppressed_count: 1,
          audit_id: "audit-T1",
          results: [{ finding_id: FINDING_A, status: "suppressed" }],
        }),
      )
      .mockResolvedValueOnce(
        bulkOk({
          suppressed_count: 1,
          audit_id: "audit-T2",
          results: [{ finding_id: FINDING_B, status: "suppressed" }],
        }),
      );

    const result = await bulkSuppressFindingsAction({
      targets: [
        { id: FINDING_A, tenant_id: SAMPLE_TENANT },
        { id: FINDING_B, tenant_id: OTHER_TENANT },
      ],
      reason: "duplicate",
      comment: "T21 cross-tenant test",
    });

    expect(callAdminBackendJson).toHaveBeenCalledTimes(2);
    expect(result.affected_count).toBe(2);
    expect(result.audit_ids).toEqual(
      expect.arrayContaining(["audit-T1", "audit-T2"]),
    );
    expect(result.failure_reason_taxonomy).toBeNull();

    // Both calls must include the matching X-Admin-Tenant + comment-bearing reason.
    const headers0 = (callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string>; body: string },
    ])[1].headers;
    const body0 = JSON.parse(
      (callAdminBackendJson.mock.calls[0] as [
        string,
        { headers: Record<string, string>; body: string },
      ])[1].body,
    );
    expect(headers0["X-Admin-Tenant"]).toBe(SAMPLE_TENANT);
    expect(body0.tenant_id).toBe(SAMPLE_TENANT);
    expect(body0.finding_ids).toEqual([FINDING_A]);
    expect(body0.reason).toContain("duplicate");
    expect(body0.reason).toContain("T21 cross-tenant test");
  });

  it("propagates X-Admin-Role + X-Operator-Subject from the session, never the caller", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValueOnce(bulkOk());

    await bulkSuppressFindingsAction({
      targets: [{ id: FINDING_A, tenant_id: SAMPLE_TENANT }],
      reason: "risk_accepted",
    });

    const init = (callAdminBackendJson.mock.calls[0] as [
      string,
      { headers: Record<string, string> },
    ])[1];
    expect(init.headers["X-Admin-Role"]).toBe("super-admin");
    expect(init.headers["X-Operator-Subject"]).toBe(
      "admin_console:super-admin",
    );
  });
});

describe("bulkSuppressFindingsAction — input validation", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
  });

  it("rejects an empty selection without hitting the backend", async () => {
    await expect(
      bulkSuppressFindingsAction({ targets: [], reason: "duplicate" }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("rejects a selection larger than 100 items (matches backend cap)", async () => {
    const targets: BulkFindingTarget[] = Array.from({ length: 101 }).map(
      (_, i) => ({
        id: `00000000-0000-0000-0000-${String(i + 1).padStart(12, "0")}`,
        tenant_id: SAMPLE_TENANT,
      }),
    );
    await expect(
      bulkSuppressFindingsAction({ targets, reason: "duplicate" }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("rejects an unknown reason string outside the closed taxonomy", async () => {
    await expect(
      bulkSuppressFindingsAction({
        targets: [{ id: FINDING_A, tenant_id: SAMPLE_TENANT }],
        // @ts-expect-error — feeding an off-taxonomy literal on purpose.
        reason: "make_it_disappear",
      }),
    ).rejects.toMatchObject({ code: "validation_failed" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });

  it("filters out non-UUID ids pre-flight (skipped go straight to failed_ids)", async () => {
    callAdminBackendJson.mockResolvedValueOnce(
      bulkOk({
        suppressed_count: 1,
        results: [{ finding_id: FINDING_A, status: "suppressed" }],
      }),
    );

    const result = await bulkSuppressFindingsAction({
      targets: [
        { id: FINDING_A, tenant_id: SAMPLE_TENANT },
        { id: "not-a-uuid", tenant_id: SAMPLE_TENANT },
      ],
      reason: "duplicate",
    });

    expect(result.failed_ids).toContain("not-a-uuid");
    // The good id still went through.
    const body = JSON.parse(
      (callAdminBackendJson.mock.calls[0] as [
        string,
        { body: string },
      ])[1].body,
    );
    expect(body.finding_ids).toEqual([FINDING_A]);
  });
});

describe("bulkSuppressFindingsAction — partial / total backend failures", () => {
  beforeEach(() => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
  });

  it("aggregates per-tenant `not_found` items into failed_ids", async () => {
    callAdminBackendJson.mockResolvedValueOnce(
      bulkOk({
        suppressed_count: 1,
        not_found_count: 1,
        results: [
          { finding_id: FINDING_A, status: "suppressed" },
          { finding_id: FINDING_B, status: "not_found" },
        ],
      }),
    );

    const result = await bulkSuppressFindingsAction({
      targets: [
        { id: FINDING_A, tenant_id: SAMPLE_TENANT },
        { id: FINDING_B, tenant_id: SAMPLE_TENANT },
      ],
      reason: "duplicate",
    });

    expect(result.affected_count).toBe(1);
    expect(result.failed_ids).toContain(FINDING_B);
    expect(result.failure_reason_taxonomy).toBeNull();
  });

  it("treats a tenant-level 403 as a complete failure for that tenant (failure_reason_taxonomy=forbidden)", async () => {
    callAdminBackendJson
      .mockResolvedValueOnce({ ok: false, status: 403, data: {} })
      .mockResolvedValueOnce(bulkOk());

    const result = await bulkSuppressFindingsAction({
      targets: [
        { id: FINDING_A, tenant_id: SAMPLE_TENANT },
        { id: FINDING_C, tenant_id: OTHER_TENANT },
      ],
      reason: "duplicate",
    });

    expect(result.failure_reason_taxonomy).toBe("forbidden");
    expect(result.failed_ids).toContain(FINDING_A);
  });

  it("translates malformed envelope (200 OK, wrong shape) into server_error in failure_reason_taxonomy", async () => {
    callAdminBackendJson.mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: { totally: "wrong" },
    });

    const result = await bulkSuppressFindingsAction({
      targets: [{ id: FINDING_A, tenant_id: SAMPLE_TENANT }],
      reason: "duplicate",
    });

    expect(result.failure_reason_taxonomy).toBe("server_error");
    expect(result.affected_count).toBe(0);
    expect(result.failed_ids).toContain(FINDING_A);
  });
});

describe("bulkMarkFalsePositiveFindingsAction (T21)", () => {
  it("pins the backend reason to the literal `false_positive` (semantic distinct from generic suppress)", async () => {
    sessionMock.mockResolvedValue({
      role: "super-admin",
      tenantId: null,
      subject: "admin_console:super-admin",
    });
    callAdminBackendJson.mockResolvedValueOnce(bulkOk());

    await bulkMarkFalsePositiveFindingsAction({
      targets: [{ id: FINDING_A, tenant_id: SAMPLE_TENANT }],
      comment: "auto-triage rule",
    });

    const body = JSON.parse(
      (callAdminBackendJson.mock.calls[0] as [
        string,
        { body: string },
      ])[1].body,
    );
    expect(body.reason).toMatch(/^false_positive/);
    expect(body.reason).toContain("auto-triage rule");
  });

  it("inherits the same operator/role gate (operator → forbidden, no backend call)", async () => {
    sessionMock.mockResolvedValue({
      role: "operator",
      tenantId: SAMPLE_TENANT,
      subject: "admin_console:operator",
    });

    await expect(
      bulkMarkFalsePositiveFindingsAction({
        targets: [{ id: FINDING_A, tenant_id: SAMPLE_TENANT }],
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    expect(callAdminBackendJson).not.toHaveBeenCalled();
  });
});
