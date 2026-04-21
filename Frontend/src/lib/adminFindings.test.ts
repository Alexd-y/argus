import { describe, expect, it } from "vitest";

import {
  AdminFindingsError,
  AdminFindingsListResponseSchema,
  adminFindingsErrorMessage,
  compareFindings,
  isFindingStatusMode,
  sortFindings,
  statusToAdminFindingsCode,
  type AdminFindingItem,
} from "./adminFindings";

const SAMPLE_TENANT = "00000000-0000-0000-0000-000000000001";

describe("adminFindings — error taxonomy", () => {
  it("maps HTTP statuses to closed-taxonomy codes", () => {
    expect(statusToAdminFindingsCode(401)).toBe("unauthorized");
    expect(statusToAdminFindingsCode(403)).toBe("forbidden");
    expect(statusToAdminFindingsCode(429)).toBe("rate_limited");
    expect(statusToAdminFindingsCode(400)).toBe("invalid_input");
    expect(statusToAdminFindingsCode(422)).toBe("invalid_input");
    expect(statusToAdminFindingsCode(500)).toBe("server_error");
    expect(statusToAdminFindingsCode(503)).toBe("server_error");
  });

  it("renders Russian sentences for every code, never the original message", () => {
    const network = adminFindingsErrorMessage(
      new AdminFindingsError("network_error"),
    );
    expect(network).toMatch(/Сеть/);
    const forbidden = adminFindingsErrorMessage(
      new AdminFindingsError("forbidden", 403),
    );
    expect(forbidden).toMatch(/Недостаточно/);
    const unknown = adminFindingsErrorMessage(new Error("ECONNRESET 127.0.0.1"));
    expect(unknown).not.toMatch(/ECONNRESET/);
    expect(unknown).toMatch(/Не удалось/);
  });
});

describe("adminFindings — schema", () => {
  it("accepts the legacy `findings` envelope and synthesises a cursor", () => {
    const out = AdminFindingsListResponseSchema.parse({
      findings: [
        {
          id: "f-1",
          tenant_id: SAMPLE_TENANT,
          scan_id: "scan-1",
          severity: "Critical",
          title: "RCE",
          cvss: 9.8,
          created_at: "2026-04-21T10:00:00Z",
        },
      ],
      total: 100,
      limit: 50,
      offset: 0,
      has_more: true,
    });

    expect(out.items).toHaveLength(1);
    expect(out.items[0].id).toBe("f-1");
    expect(out.items[0].severity).toBe("critical");
    expect(out.items[0].cvss_score).toBe(9.8);
    expect(out.items[0].kev_listed).toBeNull();
    expect(out.next_cursor).toBe("1");
  });

  it("rejects unknown severities outside the closed enum", () => {
    expect(() =>
      AdminFindingsListResponseSchema.parse({
        findings: [
          {
            id: "f-1",
            tenant_id: SAMPLE_TENANT,
            scan_id: "scan-1",
            severity: "world-ending",
            title: "bogus",
          },
        ],
      }),
    ).toThrow();
  });
});

describe("isFindingStatusMode", () => {
  it("accepts the closed tri-state and rejects everything else", () => {
    expect(isFindingStatusMode("all")).toBe(true);
    expect(isFindingStatusMode("open")).toBe(true);
    expect(isFindingStatusMode("false_positive")).toBe(true);
    expect(isFindingStatusMode("OPEN")).toBe(false);
    expect(isFindingStatusMode("fixed")).toBe(false);
    expect(isFindingStatusMode(null)).toBe(false);
    expect(isFindingStatusMode(undefined)).toBe(false);
    expect(isFindingStatusMode(0)).toBe(false);
  });
});

describe("sortFindings / compareFindings", () => {
  const make = (over: Partial<AdminFindingItem>): AdminFindingItem => ({
    id: over.id ?? "f",
    tenant_id: SAMPLE_TENANT,
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

  it("treats unparsable updated_at as 0 so the comparator stays total (S2-2)", () => {
    // Two items identical except for updated_at; one is malformed. The malformed
    // one must NOT bubble up via NaN propagation that breaks Array.sort().
    const goodNew = make({
      id: "good-new",
      severity: "low",
      updated_at: "2026-04-21T00:00:00Z",
    });
    const malformed = make({
      id: "bad",
      severity: "low",
      updated_at: "tomorrow at noon",
    });
    const ancient = make({
      id: "ancient",
      severity: "low",
      updated_at: "2000-01-01T00:00:00Z",
    });

    const sorted = sortFindings([malformed, ancient, goodNew]);

    // Malformed ts collapses to 0 → sinks below any parsable ts; the only
    // requirement is that the sort is deterministic and the malformed value
    // never lands strictly above a parsable, recent timestamp.
    expect(sorted[0].id).toBe("good-new");
    expect(sorted[sorted.length - 1].id).toBe("bad");

    // Direct comparator invariants — neither return value is NaN.
    expect(Number.isNaN(compareFindings(goodNew, malformed))).toBe(false);
    expect(Number.isNaN(compareFindings(malformed, ancient))).toBe(false);
    // goodNew is newer than ancient → strictly negative (comes first).
    expect(compareFindings(goodNew, ancient)).toBeLessThan(0);
    // malformed (ts=0) is older than ancient (ts=946684800000) → strictly positive.
    expect(compareFindings(malformed, ancient)).toBeGreaterThan(0);
  });
});
