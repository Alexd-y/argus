import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  AdminFindingsError,
  adminFindingsErrorMessage,
  buildAdminFindingsUrl,
  compareFindings,
  listAdminFindings,
  sortFindings,
  type AdminFindingItem,
} from "./adminFindings";

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

type BackendFinding = {
  id?: string;
  tenant_id?: string;
  scan_id?: string;
  severity?: string;
  title?: string;
  cvss?: number | null;
  cvss_score?: number | null;
  created_at?: string | null;
  updated_at?: string | null;
};

function happyBackendBody(items: ReadonlyArray<BackendFinding> = []) {
  return {
    findings: items.map((it, idx) => ({
      id: it.id ?? `f-${idx}`,
      tenant_id: it.tenant_id ?? "00000000-0000-0000-0000-000000000001",
      scan_id: it.scan_id ?? "scan-1",
      severity: it.severity ?? "high",
      title: it.title ?? `Finding ${idx}`,
      cvss: it.cvss ?? it.cvss_score ?? null,
      created_at: it.created_at ?? it.updated_at ?? "2026-04-21T10:00:00Z",
    })),
    total: 100,
    limit: 50,
    offset: 0,
    has_more: true,
  };
}

beforeEach(() => {
  vi.useRealTimers();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("buildAdminFindingsUrl", () => {
  it("encodes filters into the query string and skips empty inputs", () => {
    const url = buildAdminFindingsUrl({
      tenantId: "00000000-0000-0000-0000-000000000001",
      severity: ["critical", "high"],
      status: ["open"],
      target: " example.com ",
      since: "2026-04-01",
      until: "2026-04-21",
      limit: 25,
    });
    expect(url).toContain("/api/v1/admin/findings?");
    expect(url).toContain(
      "tenant_id=00000000-0000-0000-0000-000000000001",
    );
    expect(url).toContain("severity=critical");
    expect(url).toContain("severity=high");
    expect(url).toContain("status=open");
    expect(url).toContain("target=example.com");
    expect(url).toContain("since=2026-04-01");
    expect(url).toContain("until=2026-04-21");
    expect(url).toContain("limit=25");
  });

  it("omits reserved kev_listed and ssvc_action when null", () => {
    const url = buildAdminFindingsUrl({
      kevListed: null,
      ssvcAction: null,
    });
    expect(url).not.toContain("kev_listed");
    expect(url).not.toContain("ssvc_action");
  });

  it("includes kev_listed and ssvc_action only when explicitly set", () => {
    const url = buildAdminFindingsUrl({
      kevListed: true,
      ssvcAction: "act",
    });
    expect(url).toContain("kev_listed=true");
    expect(url).toContain("ssvc_action=act");
  });
});

describe("listAdminFindings", () => {
  it("parses a happy GET, mapping cvss → cvss_score and synthesising next_cursor", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      jsonResponse(
        happyBackendBody([
          { id: "f-1", severity: "critical", cvss: 9.8, title: "RCE" },
        ]),
      ),
    );

    const out = await listAdminFindings({}, { fetchImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(out.items).toHaveLength(1);
    const item = out.items[0];
    expect(item.id).toBe("f-1");
    expect(item.severity).toBe("critical");
    expect(item.cvss_score).toBe(9.8);
    expect(item.kev_listed).toBeNull();
    expect(item.ssvc_action).toBeNull();
    expect(out.total).toBe(100);
    expect(out.has_more).toBe(true);
    // next_cursor is synthesised from offset + items.length (0 + 1 = "1")
    expect(out.next_cursor).toBe("1");
  });

  it("rejects malformed payloads (item missing required id) with a closed-taxonomy server_error", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      jsonResponse({
        findings: [
          {
            tenant_id: "t1",
            scan_id: "s1",
            severity: "high",
            title: "no id field at all",
          },
        ],
        total: 1,
        limit: 50,
        offset: 0,
        has_more: false,
      }),
    );

    const err = await listAdminFindings({}, { fetchImpl }).catch((e) => e);
    expect(err).toBeInstanceOf(AdminFindingsError);
    expect((err as AdminFindingsError).code).toBe("server_error");
    expect(adminFindingsErrorMessage(err)).toMatch(/Не удалось загрузить/);
  });

  it("rejects items with unknown severity values via the strict enum schema", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      jsonResponse({
        findings: [
          {
            id: "f-1",
            tenant_id: "t1",
            scan_id: "s1",
            severity: "world-ending",
            title: "bogus",
          },
        ],
      }),
    );

    const err = await listAdminFindings({}, { fetchImpl }).catch((e) => e);
    expect(err).toBeInstanceOf(AdminFindingsError);
    expect((err as AdminFindingsError).code).toBe("server_error");
  });

  it("propagates 401 → unauthorized closed-taxonomy code", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response("", { status: 401 }));
    const err = await listAdminFindings({}, { fetchImpl }).catch((e) => e);
    expect(err).toBeInstanceOf(AdminFindingsError);
    expect((err as AdminFindingsError).code).toBe("unauthorized");
    expect(adminFindingsErrorMessage(err)).toMatch(/Сессия/);
  });

  it("propagates 403 / 429 / 422 / 500 to forbidden / rate_limited / invalid_input / server_error", async () => {
    const cases: ReadonlyArray<[number, string]> = [
      [403, "forbidden"],
      [429, "rate_limited"],
      [422, "invalid_input"],
      [400, "invalid_input"],
      [500, "server_error"],
      [503, "server_error"],
    ];
    for (const [status, code] of cases) {
      const fetchImpl = vi
        .fn()
        .mockResolvedValue(new Response("", { status }));
      const err = await listAdminFindings({}, { fetchImpl }).catch((e) => e);
      expect((err as AdminFindingsError).code).toBe(code);
    }
  });

  it("forwards the cursor in the next request (cursor pagination)", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(happyBackendBody()));
    await listAdminFindings({ cursor: "abc-123", limit: 50 }, { fetchImpl });
    const calledUrl = fetchImpl.mock.calls[0][0] as string;
    expect(calledUrl).toContain("cursor=abc-123");
    expect(calledUrl).toContain("limit=50");
  });

  it("aborts via AbortController so React Query can cancel races", async () => {
    const ctrl = new AbortController();
    const fetchImpl: typeof fetch = vi.fn(
      (_url: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal;
          if (signal) {
            signal.addEventListener("abort", () => {
              reject(new DOMException("aborted", "AbortError"));
            });
          }
        }),
    ) as unknown as typeof fetch;

    const promise = listAdminFindings(
      {},
      { fetchImpl, signal: ctrl.signal },
    );
    ctrl.abort();
    const err = await promise.catch((e) => e);
    expect(err).toBeInstanceOf(DOMException);
    expect((err as DOMException).name).toBe("AbortError");
  });

  it("maps non-DOM transport failures to network_error (no leak)", async () => {
    const fetchImpl = vi
      .fn()
      .mockRejectedValue(new TypeError("fetch failed: ECONNREFUSED 127.0.0.1:8000"));
    const err = await listAdminFindings({}, { fetchImpl }).catch((e) => e);
    expect(err).toBeInstanceOf(AdminFindingsError);
    expect((err as AdminFindingsError).code).toBe("network_error");
    expect(adminFindingsErrorMessage(err)).not.toMatch(/ECONNREFUSED/);
  });

  it("attaches operator headers when provided", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(happyBackendBody()));
    await listAdminFindings(
      {},
      {
        fetchImpl,
        operatorRole: "super-admin",
        operatorTenantId: "00000000-0000-0000-0000-000000000001",
        operatorSubject: "user-7",
      },
    );
    const init = fetchImpl.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Operator-Role"]).toBe("super-admin");
    expect(headers["X-Admin-Role"]).toBe("super-admin");
    expect(headers["X-Tenant-ID"]).toBe(
      "00000000-0000-0000-0000-000000000001",
    );
    expect(headers["X-Operator-Subject"]).toBe("user-7");
  });
});

describe("sortFindings / compareFindings", () => {
  const make = (over: Partial<AdminFindingItem>): AdminFindingItem => ({
    id: over.id ?? "f",
    tenant_id: "t",
    scan_id: "s",
    severity: over.severity ?? "low",
    status: null,
    target: null,
    title: "t",
    cve_ids: null,
    cvss_score: over.cvss_score ?? null,
    epss_score: over.epss_score ?? null,
    kev_listed: null,
    ssvc_action: over.ssvc_action ?? null,
    discovered_at: null,
    updated_at: over.updated_at ?? null,
  });

  it("sorts by SSVC action first when present, descending (Act > Attend > Track* > Track)", () => {
    const sorted = sortFindings([
      make({ id: "track", ssvc_action: "track" }),
      make({ id: "act", ssvc_action: "act" }),
      make({ id: "attend", ssvc_action: "attend" }),
      make({ id: "track-star", ssvc_action: "track-star" }),
    ]);
    expect(sorted.map((s) => s.id)).toEqual([
      "act",
      "attend",
      "track-star",
      "track",
    ]);
  });

  it("falls back to severity → cvss → epss → updated_at when ssvc absent", () => {
    const sorted = sortFindings([
      make({ id: "old", severity: "high", updated_at: "2025-01-01" }),
      make({ id: "new", severity: "high", updated_at: "2026-04-21" }),
      make({ id: "crit", severity: "critical" }),
      make({ id: "med-hi-cvss", severity: "medium", cvss_score: 9.5 }),
      make({ id: "med-lo-cvss", severity: "medium", cvss_score: 1.0 }),
    ]);
    expect(sorted[0].id).toBe("crit");
    expect(sorted[1].id).toBe("new");
    expect(sorted[2].id).toBe("old");
    expect(sorted[3].id).toBe("med-hi-cvss");
    expect(sorted[4].id).toBe("med-lo-cvss");
  });

  it("sinks null SSVC actions below any present action", () => {
    const a = make({ id: "ssvc", severity: "info", ssvc_action: "track" });
    const b = make({ id: "no-ssvc", severity: "critical" });
    expect(compareFindings(a, b)).toBeLessThan(0);
  });
});
