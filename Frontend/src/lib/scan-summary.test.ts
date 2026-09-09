import { describe, expect, it } from "vitest";
import {
  backendSeverityToBand,
  censusFromFindings,
  severityBandOf,
} from "./scan-results";
import type { CheckPriority, CheckStatus, Finding, ScanResults, SeverityKey } from "./scan-results";
import { severityBreakdown, severityCount } from "./scan-summary";

function results(partial: Partial<ScanResults>): ScanResults {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
    passed: 0,
    technologies: [],
    sslIssues: null,
    headerIssues: null,
    subdomains: null,
    leaksFound: false,
    leaks: [],
    findings: [],
    totalFindings: 0,
    ...partial,
  };
}

function check(status: CheckStatus, priority: CheckPriority, severity?: SeverityKey) {
  return { status, priority, severity };
}

describe("backendSeverityToBand", () => {
  it("maps high to high (not important) and preserves medium/low separately", () => {
    expect(backendSeverityToBand("high")).toBe("high");
    expect(backendSeverityToBand("medium")).toBe("medium");
    expect(backendSeverityToBand("low")).toBe("low");
  });

  it("keeps info as informational and never folds it into low", () => {
    expect(backendSeverityToBand("info")).toBe("informational");
    expect(backendSeverityToBand("informational")).toBe("informational");
    expect(backendSeverityToBand("none")).toBe("informational");
  });

  it("maps blank / unrecognised severity to unknown, never low or info", () => {
    expect(backendSeverityToBand("")).toBe("unknown");
    expect(backendSeverityToBand(null)).toBe("unknown");
    expect(backendSeverityToBand("weird")).toBe("unknown");
  });
});

describe("severityBandOf", () => {
  it("prefers an explicit band over the priority-derived one", () => {
    expect(severityBandOf({ severity: "informational", priority: "critical" })).toBe("informational");
  });

  it("falls back to priority when no explicit band is present", () => {
    expect(severityBandOf({ priority: "important" })).toBe("high");
    expect(severityBandOf({ priority: "optional" })).toBe("low");
  });
});

describe("censusFromFindings", () => {
  it("counts by severity band; passed checks are excluded from totalFindings", () => {
    const census = censusFromFindings([
      check("fail", "critical", "critical"),
      check("fail", "important", "high"),
      check("fail", "medium", "medium"),
      check("fail", "optional", "low"),
      check("fail", "optional", "informational"),
      check("fail", "optional", "unknown"),
      check("pass", "optional", "low"),
    ]);
    expect(census).toMatchObject({
      critical: 1,
      high: 1,
      medium: 1,
      low: 1,
      info: 1,
      unknown: 1,
      passed: 1,
      totalFindings: 6,
    });
    // Sum of bands equals the finding population (passed checks not counted).
    expect(census.critical + census.high + census.medium + census.low + census.info + census.unknown).toBe(
      census.totalFindings,
    );
  });

  it("does not fold informational or unknown into low", () => {
    const census = censusFromFindings([
      check("fail", "optional", "informational"),
      check("fail", "optional", "unknown"),
    ]);
    expect(census.low).toBe(0);
    expect(census.info).toBe(1);
    expect(census.unknown).toBe(1);
  });
});

describe("severityBreakdown", () => {
  it("exposes all six bands including Informational and Unknown with one denominator", () => {
    const slices = severityBreakdown(
      results({ critical: 1, high: 2, medium: 0, low: 1, info: 3, unknown: 1, totalFindings: 8 }),
    );
    const byKey = Object.fromEntries(slices.map((s) => [s.key, s]));
    expect(slices.map((s) => s.key)).toEqual([
      "critical",
      "high",
      "medium",
      "low",
      "informational",
      "unknown",
    ]);
    // High is labelled High (not "Important"); Medium/Low are not merged.
    expect(byKey.high.label).toBe("High");
    expect(byKey.high.count).toBe(2);
    expect(byKey.informational.count).toBe(3);
    expect(byKey.unknown.count).toBe(1);
    // Percentages use the single canonical denominator (totalFindings === 8).
    expect(byKey.high.pct).toBe(25);
  });
});

describe("severityCount", () => {
  const key = (k: SeverityKey) => k;
  it("reads each band from the aggregate", () => {
    const r = results({ critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 6, totalFindings: 21 });
    expect(severityCount(r, key("critical"))).toBe(5);
    expect(severityCount(r, key("informational"))).toBe(1);
    expect(severityCount(r, key("unknown"))).toBe(6);
  });
});

// Ensure the shared type still resolves (compile-time guard for the fixture Finding).
export const _typeGuard: Finding["severity"] = "high";
