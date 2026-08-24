import { normalizeHostname } from "./domain-verification";
import type { ScanTier } from "./scan-tiers";
import type { CheckPriority, CheckStatus, Finding, FindingProbe, ScanResults } from "./scan-results";
import {
  apexHostname,
  censusFromFindings,
  midgardWriteupId,
  sampleSubdomainsFor,
  subdomainsForTier,
  withTierAccess,
} from "./scan-results";

export const LIVE_FINDINGS_HOST = "alleksy.com";
export const LIVE_FINDINGS_URL =
  "https://raw.githubusercontent.com/swe/jsoncsvdata/refs/heads/master/ragnarok_findings_demo.json";

const FETCH_TIMEOUT_MS = 15_000;
const CACHE_TTL_MS = 60_000;

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

interface FrameworkMapping {
  id?: string | null;
  name?: string | null;
}

export interface CanonicalFinding {
  id: string;
  ragnarok: {
    title: string;
    description?: string | null;
    summary?: string | null;
    severity: "critical" | "high" | "medium" | "low" | "info";
    status: string;
    category?: string | null;
    impact?: string | null;
    recommendation?: string | null;
    riskScore?: number | null;
  };
  source: {
    id: string;
    name: string;
    type?: string | null;
    findingId?: string | null;
  };
  target?: {
    host?: string | null;
    hostname?: string | null;
    ipAddress?: string | null;
    port?: number | null;
    protocol?: string | null;
    scheme?: string | null;
    url?: string | null;
    path?: string | null;
    resource?: string | null;
  };
  classification?: {
    owasp?: unknown[];
    cwe?: unknown[];
    tags?: string[];
    cve?: string[];
    frameworkMappings?: Record<string, FrameworkMapping[]>;
  };
  evidence?: {
    summary?: string | null;
    matcher?: string | null;
    matchedAt?: string | null;
    extractedResults?: string[];
    assessmentMethod?: string[];
  };
  remediation?: {
    solution?: string | null;
    steps?: string[];
    suggestedOwner?: string | null;
    validation?: string | null;
    references?: string[];
  };
  metadata?: {
    synthetic?: boolean;
  };
}

export interface DemoFindingsPayload {
  agent?: { name?: string; schemaVersion?: string; assessmentType?: string };
  summary?: {
    total?: number;
    bySeverity?: Record<string, number>;
  };
  frameworks?: { id?: string; name?: string }[];
  findings: CanonicalFinding[];
}

const globalForFindings = globalThis as unknown as {
  liveFindingsCache?: { fetchedAt: number; payload: DemoFindingsPayload };
};

export function isLiveFindingsTarget(target: string): boolean {
  return normalizeHostname(target) === LIVE_FINDINGS_HOST;
}

function isCanonicalFinding(value: unknown): value is CanonicalFinding {
  if (!value || typeof value !== "object") return false;
  const row = value as CanonicalFinding;
  return (
    typeof row.id === "string" &&
    typeof row.ragnarok?.title === "string" &&
    typeof row.ragnarok?.severity === "string" &&
    typeof row.source?.id === "string" &&
    typeof row.source?.name === "string"
  );
}

function isDemoPayload(value: unknown): value is DemoFindingsPayload {
  return !!value && typeof value === "object" && Array.isArray((value as DemoFindingsPayload).findings);
}

export async function fetchDemoFindings(): Promise<DemoFindingsPayload> {
  const cached = globalForFindings.liveFindingsCache;
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.payload;
  }

  const response = await fetch(LIVE_FINDINGS_URL, {
    cache: "no-store",
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { Accept: "application/json" },
  });

  if (!response.ok) {
    throw new Error(`Findings API returned ${response.status}`);
  }

  const payload: unknown = await response.json();
  if (!isDemoPayload(payload) || !payload.findings.every(isCanonicalFinding)) {
    throw new Error("Findings API returned an unexpected payload");
  }

  globalForFindings.liveFindingsCache = { fetchedAt: Date.now(), payload };
  return payload;
}

function findingHost(finding: CanonicalFinding): string {
  return normalizeHostname(finding.target?.hostname || finding.target?.host || "");
}

function scopeFindings(findings: CanonicalFinding[], targetHost: string): CanonicalFinding[] {
  const matching = findings.filter((item) => {
    const host = findingHost(item);
    return !host || host === targetHost || host.endsWith(`.${targetHost}`);
  });
  if (matching.length > 0) return matching;
  return findings;
}

function titleCaseCategory(category: string | null | undefined): string {
  if (!category) return "Uncategorized";
  return category
    .split(/[-_]/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function priorityFromSeverity(severity: CanonicalFinding["ragnarok"]["severity"]): CheckPriority {
  if (severity === "critical") return "critical";
  if (severity === "high") return "important";
  if (severity === "medium") return "medium";
  return "optional";
}

function statusFromCanonical(finding: CanonicalFinding): CheckStatus {
  const status = finding.ragnarok.status;
  if (status === "resolved" || status === "accepted" || status === "false_positive") return "pass";
  if (finding.ragnarok.severity === "info") return "pass";
  if (status === "ignored") return "warning";
  return "fail";
}

function displayName(finding: CanonicalFinding, duplicates: number): string {
  const title = finding.ragnarok.title;
  if (duplicates <= 1) return title;
  if (finding.target?.port) return `${title} (${finding.target.port})`;
  if (finding.target?.resource) return `${title} (${finding.target.resource})`;
  if (finding.evidence?.matchedAt) return `${title} (${finding.evidence.matchedAt})`;
  return title;
}

function cweLabel(item: unknown): string | null {
  if (typeof item === "number") return `CWE-${item}`;
  if (typeof item === "string" && item.trim()) {
    return item.startsWith("CWE-") ? item : `CWE-${item}`;
  }
  if (item && typeof item === "object" && "id" in item) {
    const id = (item as { id: unknown }).id;
    if (typeof id === "number" || (typeof id === "string" && id.trim())) return `CWE-${id}`;
  }
  return null;
}

function owaspLabel(item: unknown): string | null {
  if (typeof item === "string" && item.trim()) return item;
  if (item && typeof item === "object") {
    const row = item as { id?: unknown; name?: unknown };
    const name = typeof row.name === "string" ? row.name.trim() : "";
    const id = typeof row.id === "string" ? row.id.trim() : "";
    if (name && id) return `${id} ${name}`;
    if (name) return name;
    if (id) return id;
  }
  return null;
}

function frameworkLines(mappings: Record<string, FrameworkMapping[]> | undefined): string[] {
  if (!mappings) return [];
  return Object.entries(mappings).flatMap(([framework, items]) => {
    const labels = (items ?? [])
      .map((item) => [item.id, item.name].filter(Boolean).join(" "))
      .map((label) => label.trim())
      .filter(Boolean);
    if (!labels.length) return [];
    return [`${framework.toUpperCase()}: ${labels.join("; ")}`];
  });
}

function evidenceText(finding: CanonicalFinding): string {
  const lines: string[] = [];
  const host = finding.target?.hostname || finding.target?.host;
  const resource = finding.target?.resource;
  const url = finding.target?.url;
  const port = finding.target?.port;
  const matcher = finding.evidence?.matcher;
  const matchedAt = finding.evidence?.matchedAt;
  const summary = finding.evidence?.summary;
  const extracted = finding.evidence?.extractedResults ?? [];
  const methods = finding.evidence?.assessmentMethod ?? [];
  const cwes = (finding.classification?.cwe ?? []).map(cweLabel).filter((item): item is string => !!item);
  const owasp = (finding.classification?.owasp ?? []).map(owaspLabel).filter((item): item is string => !!item);
  const cves = finding.classification?.cve ?? [];

  if (finding.source.name) lines.push(`Source: ${finding.source.name}`);
  if (finding.source.findingId) lines.push(`Control ID: ${finding.source.findingId}`);
  if (url) lines.push(`URL: ${url}`);
  else if (host && port) lines.push(`Target: ${host}:${port}`);
  else if (host) lines.push(`Target: ${host}`);
  if (resource) lines.push(`Resource: ${resource}`);
  if (summary) lines.push(summary);
  if (matcher) lines.push(`Matcher: ${matcher}`);
  if (matchedAt && matchedAt !== resource) lines.push(`Matched at: ${matchedAt}`);
  for (const item of extracted) lines.push(item);
  if (methods.length) lines.push(`Assessment: ${methods.join(", ")}`);
  if (cwes.length) lines.push(`CWE: ${cwes.join(", ")}`);
  if (owasp.length) lines.push(`OWASP: ${owasp.join(", ")}`);
  if (cves.length) lines.push(`CVE: ${cves.join(", ")}`);
  lines.push(...frameworkLines(finding.classification?.frameworkMappings));
  if (finding.metadata?.synthetic) lines.push("Synthetic demo finding.");

  return lines.join("\n");
}

function explanationText(finding: CanonicalFinding): string {
  const description = finding.ragnarok.description?.trim() || finding.ragnarok.title;
  const impact = finding.ragnarok.impact?.trim();
  return impact ? `${description}\n\nImpact: ${impact}` : description;
}

function remediationText(finding: CanonicalFinding): string {
  const lines: string[] = [];
  const solution = finding.ragnarok.recommendation?.trim() || finding.remediation?.solution?.trim();
  if (solution) lines.push(solution);
  const steps = finding.remediation?.steps ?? [];
  steps.forEach((step, index) => {
    if (step.trim()) lines.push(`${index + 1}. ${step.trim()}`);
  });
  if (finding.remediation?.suggestedOwner) {
    lines.push(`Owner: ${finding.remediation.suggestedOwner}`);
  }
  if (finding.remediation?.validation) {
    lines.push(`Validation: ${finding.remediation.validation}`);
  }
  return lines.join("\n");
}

function isTechnicalFinding(finding: CanonicalFinding): boolean {
  return Boolean(
    finding.target?.port ||
      finding.target?.url ||
      finding.target?.host ||
      finding.target?.hostname ||
      finding.evidence?.matcher
  );
}

function probeFromCanonical(finding: CanonicalFinding): FindingProbe | undefined {
  if (!isTechnicalFinding(finding)) return undefined;

  const host = finding.target?.hostname || finding.target?.host || "";
  const port = finding.target?.port ?? (finding.target?.scheme === "http" ? 80 : 443);
  return {
    port,
    templatePath: finding.source.id,
    templateId: finding.source.findingId || finding.source.id,
    matcher: finding.evidence?.matcher || finding.source.type || finding.source.id,
    matchedAt: finding.evidence?.matchedAt || finding.target?.url || `${host}:${port}`,
    ipAddress: finding.target?.ipAddress || "",
    tags: finding.classification?.tags ?? [],
    extractedResults: finding.evidence?.extractedResults ?? [],
  };
}

function mapCanonicalToFindings(findings: CanonicalFinding[]): Finding[] {
  const scoped = scopeFindings(findings, LIVE_FINDINGS_HOST);
  const titleCounts = new Map<string, number>();
  for (const item of scoped) {
    titleCounts.set(item.ragnarok.title, (titleCounts.get(item.ragnarok.title) ?? 0) + 1);
  }

  const groups = new Map<string, CanonicalFinding[]>();
  for (const item of scoped) {
    const key = item.ragnarok.category || "uncategorized";
    const list = groups.get(key) ?? [];
    list.push(item);
    groups.set(key, list);
  }

  const orderedGroups = [...groups.entries()].sort((a, b) => {
    const aRank = Math.min(...a[1].map((item) => SEVERITY_RANK[item.ragnarok.severity] ?? 9));
    const bRank = Math.min(...b[1].map((item) => SEVERITY_RANK[item.ragnarok.severity] ?? 9));
    if (aRank !== bRank) return aRank - bRank;
    return a[0].localeCompare(b[0]);
  });

  const mapped: Finding[] = [];
  orderedGroups.forEach(([category, items], groupIndex) => {
    const groupId = String(groupIndex + 1);
    const group = titleCaseCategory(category);
    items
      .sort((a, b) => {
        const rank = (SEVERITY_RANK[a.ragnarok.severity] ?? 9) - (SEVERITY_RANK[b.ragnarok.severity] ?? 9);
        if (rank !== 0) return rank;
        return (b.ragnarok.riskScore ?? 0) - (a.ragnarok.riskScore ?? 0);
      })
      .forEach((item, index) => {
        const description = item.ragnarok.description?.trim() || item.ragnarok.title;
        mapped.push({
          id: `${groupId}.${index + 1}`,
          groupId,
          group,
          name: displayName(item, titleCounts.get(item.ragnarok.title) ?? 1),
          status: statusFromCanonical(item),
          priority: priorityFromSeverity(item.ragnarok.severity),
          headline: description,
          explanation: explanationText(item),
          evidence: evidenceText(item),
          remediation: remediationText(item),
          detailLevel: "full",
          access: "full",
          probe: probeFromCanonical(item),
          riskScore: item.ragnarok.riskScore ?? null,
        });
      });
  });

  return mapped;
}

function technologiesFromPayload(payload: DemoFindingsPayload, isFree: boolean): string[] {
  const frameworks = (payload.frameworks ?? [])
    .map((item) => item.name?.trim())
    .filter((name): name is string => Boolean(name));
  if (frameworks.length) return isFree ? frameworks.slice(0, 1) : frameworks;
  return isFree ? ["HTTPS"] : ["HTTPS", "TLS"];
}

function rewriteDemoLabels(value: string, target: string): string {
  return value.replaceAll("example.com", target);
}

function retargetFindings(findings: Finding[], target: string): Finding[] {
  const host = normalizeHostname(target);
  if (!host || host === "example.com") return findings;
  return findings.map((item) => ({
    ...item,
    name: rewriteDemoLabels(item.name, host),
    headline: rewriteDemoLabels(item.headline, host),
    explanation: rewriteDemoLabels(item.explanation, host),
    evidence: rewriteDemoLabels(item.evidence, host),
    remediation: rewriteDemoLabels(item.remediation, host),
    probe: item.probe
      ? {
          ...item.probe,
          matchedAt: rewriteDemoLabels(item.probe.matchedAt, host),
          extractedResults: item.probe.extractedResults.map((result) => rewriteDemoLabels(result, host)),
        }
      : undefined,
  }));
}

export function resultsFromCanonical(
  payload: DemoFindingsPayload,
  tier: ScanTier,
  target = LIVE_FINDINGS_HOST
): ScanResults {
  const all = mapCanonicalToFindings(payload.findings);
  if (all.length === 0) {
    throw new Error("Findings API returned no mappable findings");
  }

  const listed = withTierAccess(all, tier, midgardWriteupId(all));
  const census = censusFromFindings(all);
  const failed = all.filter((item) => item.status === "fail");
  const isFree = tier === "free";
  const hostHints = payload.findings.flatMap((item) => {
    const hosts = [item.target?.hostname, item.target?.host, item.target?.url];
    return hosts.filter((value): value is string => Boolean(value));
  });
  const discovered = subdomainsForTier(tier, hostHints, target);
  const demoHost = ["alleksy.com", "example.com"].includes(apexHostname(target));
  const subdomains =
    discovered === null
      ? null
      : discovered.length > 0
        ? discovered
        : demoHost
          ? sampleSubdomainsFor(target)
          : [];

  return {
    ...census,
    info: payload.summary?.bySeverity?.info ?? all.filter((item) => item.status === "pass").length,
    technologies: technologiesFromPayload(payload, isFree),
    sslIssues: isFree
      ? null
      : failed.filter((item) => item.group.toLowerCase().includes("cryptograph")).length,
    headerIssues: isFree
      ? null
      : failed.filter((item) => /header|web security/.test(item.group.toLowerCase())).length,
    subdomains,
    leaksFound: false,
    leaks: [],
    findings: retargetFindings(listed, target),
  };
}
