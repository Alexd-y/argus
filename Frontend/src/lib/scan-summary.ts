import type { CheckPriority, Finding, ScanResults } from "./scan-results";

export type SeverityKey = "critical" | "important" | "optional";

export interface SeveritySlice {
  key: SeverityKey;
  label: string;
  count: number;
  pctOfTotal: number;
  pctOfOpen: number;
}

export interface CategorySlice {
  groupId: string;
  group: string;
  open: number;
  checks: number;
  bySeverity: Record<SeverityKey, number>;
}

function severityOf(priority: CheckPriority): SeverityKey {
  if (priority === "critical") return "critical";
  if (priority === "important") return "important";
  return "optional";
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

export function openFindingCount(results: ScanResults): number {
  return results.critical + results.high + results.medium + results.low;
}

export function severityBreakdown(results: ScanResults): SeveritySlice[] {
  const open = openFindingCount(results);
  const raw: Array<{ key: SeverityKey; label: string; count: number }> = [
    { key: "critical", label: "Critical", count: results.critical },
    { key: "important", label: "Important", count: results.high },
    { key: "optional", label: "Optional", count: results.medium + results.low },
  ];
  return raw.map((slice) => ({
    ...slice,
    pctOfTotal: pct(slice.count, results.totalFindings),
    pctOfOpen: pct(slice.count, open),
  }));
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
        bySeverity: { critical: 0, important: 0, optional: 0 },
      };
    entry.checks += 1;
    if (finding.status === "fail") {
      entry.open += 1;
      entry.bySeverity[severityOf(finding.priority)] += 1;
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
