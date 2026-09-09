import type { CheckPriority, Finding, ScanResults, SeverityKey } from "./scan-results";
import { severityBandOf } from "./scan-results";

export type { SeverityKey } from "./scan-results";

export interface SeveritySlice {
  key: SeverityKey;
  label: string;
  count: number;
  /** Percentage of the single canonical population denominator (total findings). */
  pct: number;
}

export interface CategorySlice {
  groupId: string;
  group: string;
  open: number;
  checks: number;
  bySeverity: Record<SeverityKey, number>;
}

/** Ordered severity bands shown in the donut / legend (severity-descending). */
const SEVERITY_DISPLAY: ReadonlyArray<{ key: SeverityKey; label: string }> = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "informational", label: "Informational" },
  { key: "unknown", label: "Unknown" },
];

function emptyBands(): Record<SeverityKey, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0, unknown: 0 };
}

const PRIORITY_RANK: Record<CheckPriority, number> = {
  critical: 0,
  important: 1,
  medium: 2,
  optional: 3,
};

export function pct(part: number, whole: number): number {
  if (whole <= 0) return 0;
  return Math.round((part / whole) * 100);
}

/** Active-risk findings (critical→low). Informational/unknown are shown but not "open". */
export function openFindingCount(results: ScanResults): number {
  return results.critical + results.high + results.medium + results.low;
}

/** Count for one band, read from the single backend-provided aggregate. */
export function severityCount(results: ScanResults, key: SeverityKey): number {
  switch (key) {
    case "critical":
      return results.critical;
    case "high":
      return results.high;
    case "medium":
      return results.medium;
    case "low":
      return results.low;
    case "informational":
      return results.info;
    case "unknown":
      return results.unknown;
    default: {
      const _exhaustive: never = key;
      return _exhaustive;
    }
  }
}

export function severityBreakdown(results: ScanResults): SeveritySlice[] {
  const total = results.totalFindings;
  return SEVERITY_DISPLAY.map(({ key, label }) => {
    const count = severityCount(results, key);
    return { key, label, count, pct: pct(count, total) };
  });
}

export function categoryBreakdown(findings: Finding[], limit = 6): CategorySlice[] {
  const byGroup = new Map<string, CategorySlice>();
  for (const finding of findings) {
    const entry =
      byGroup.get(finding.groupId) ??
      {
        groupId: finding.groupId,
        group: finding.group,
        open: 0,
        checks: 0,
        bySeverity: emptyBands(),
      };
    entry.checks += 1;
    if (finding.status === "fail") {
      entry.open += 1;
      entry.bySeverity[severityBandOf(finding)] += 1;
    }
    byGroup.set(finding.groupId, entry);
  }
  return [...byGroup.values()]
    .sort((a, b) => b.open - a.open || a.groupId.localeCompare(b.groupId))
    .slice(0, limit);
}

export function topPriorityFindings(findings: Finding[], limit = 5): Finding[] {
  return findings
    .filter((finding) => finding.status === "fail")
    .slice()
    .sort(
      (a, b) =>
        PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] ||
        (b.riskScore ?? 0) - (a.riskScore ?? 0)
    )
    .slice(0, limit);
}
