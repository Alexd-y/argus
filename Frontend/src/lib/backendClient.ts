/**
 * Server-side proxy client for the ARGUS backend (`/api/v1`).
 *
 * Used by the Next.js route handlers to forward scan operations to the real
 * backend instead of the in-memory demo scanner. It is *opt-in* via
 * `ARGUS_USE_BACKEND` so the self-contained Ragnarök demo keeps working when no
 * backend is configured. Secrets (API keys, MinIO creds, lease signing
 * material, internal URLs) are never sent to the browser — this module runs on
 * the server only.
 */

import "server-only";
import type { ScanTier } from "./scan-tiers";
import type { CheckPriority, Finding, ScanResults } from "./scan-results";
import { censusFromFindings, midgardWriteupId, withTierAccess } from "./scan-results";
import type { ScanData, ScanStatus } from "./scan-types";
import type { ScanProfile } from "./types";

/** Ragnarök billing tier → canonical scan profile. */
export function tierToScanProfile(tier: ScanTier): ScanProfile {
  switch (tier) {
    case "free":
      return "quick";
    case "standard":
      return "light";
    case "premium":
      return "deep";
    default: {
      const _never: never = tier;
      return "quick";
    }
  }
}

/** Canonical scan_profile → Ragnarök billing tier (inverse of tierToScanProfile). */
function scanProfileToTier(profile: unknown): ScanTier {
  switch (profile) {
    case "light":
      return "standard";
    case "deep":
      return "premium";
    case "quick":
    default:
      return "free";
  }
}

/**
 * Map the backend scan `status` enum to the frontend {@link ScanStatus}.
 *
 * Backend uses queued/running/completed/failed/cancelled; the public UI models
 * pending/running/complete/failed. Unknown values fall back to "running" so the
 * progress view (not a dead end) is shown while we poll.
 */
function mapBackendStatus(raw: unknown): ScanStatus {
  switch (raw) {
    case "queued":
    case "pending":
      return "pending";
    case "completed":
    case "complete":
      return "complete";
    case "failed":
    case "error":
    case "cancelled":
    case "canceled":
      return "failed";
    case "running":
    default:
      return "running";
  }
}

/** Derive the 0-based stage index from the reported progress (0-100). */
function stageIndexFromProgress(progress: number, stageCount = 5): number {
  if (!Number.isFinite(progress) || progress <= 0) return 0;
  const idx = Math.floor((progress / 100) * stageCount);
  return Math.min(Math.max(idx, 0), stageCount - 1);
}

/**
 * Adapt a backend `ScanDetailResponse` (raw JSON) into the frontend
 * {@link ScanData} shape the public scan page renders. Missing fields default
 * safely so the running/pending view never crashes (e.g. `getTierConfig`
 * throws on an unknown tier).
 */
export function mapBackendScanToScanData(raw: Record<string, unknown>): ScanData {
  const status = mapBackendStatus(raw.status);
  const progressRaw = typeof raw.progress === "number" ? raw.progress : 0;
  const progress = status === "complete" ? 100 : Math.min(Math.max(progressRaw, 0), 100);
  const tier = scanProfileToTier(raw.scan_profile);
  const createdAt =
    typeof raw.created_at === "string" ? raw.created_at : new Date().toISOString();
  const phase =
    (typeof raw.stage === "string" && raw.stage) ||
    (typeof raw.phase === "string" && raw.phase) ||
    "";

  return {
    id: String(raw.id ?? ""),
    target: typeof raw.target === "string" ? raw.target : "",
    email: typeof raw.email === "string" ? raw.email : "",
    tier,
    status,
    stage: phase,
    stageIndex: status === "complete" ? 5 : stageIndexFromProgress(progress),
    progress,
    error: typeof raw.error === "string" ? raw.error : null,
    results: null,
    parentScanId: null,
    darkWebMonitoring: false,
    paid: tier !== "free",
    quota: null,
    createdAt,
    completedAt: status === "complete" ? createdAt : null,
  };
}

/**
 * Resolve the server-only backend API key used to authenticate proxy calls.
 *
 * The public frontend talks to the backend directly (not via the nginx gateway
 * that injects the key), so the Node route handlers must present a valid
 * `X-API-Key` themselves. Read from server-only env (never `NEXT_PUBLIC_*`), so
 * the secret is never shipped to the browser. `ARGUS_API_KEYS` may be a
 * comma-separated list — the first entry (key or `key:tenant`) is used.
 */
export function getBackendApiKey(): string | null {
  const direct =
    process.env.BACKEND_API_KEY ||
    process.env.ARGUS_GATEWAY_API_KEY ||
    process.env.ADMIN_API_KEY ||
    "";
  const trimmed = direct.trim();
  if (trimmed) return trimmed;

  const list = (process.env.ARGUS_API_KEYS || "").split(",");
  for (const entry of list) {
    const first = entry.trim();
    if (first) return first;
  }
  return null;
}

/** Build the auth headers for backend proxy calls (empty when no key set). */
function backendAuthHeaders(): Record<string, string> {
  const key = getBackendApiKey();
  return key ? { "X-API-Key": key } : {};
}

/**
 * Build the `X-Tenant-ID` header only when a concrete tenant is known.
 *
 * The backend derives the tenant from the authenticated API key and rejects a
 * mismatching `X-Tenant-ID` (403). A placeholder like `"default"` never matches
 * the key's bound tenant, so we omit the header unless a real id is supplied.
 */
function tenantHeader(explicit?: string): Record<string, string> {
  const tenant = (explicit || process.env.NEXT_PUBLIC_TENANT_ID || "").trim();
  return tenant ? { "X-Tenant-ID": tenant } : {};
}

/** Resolve the server-only backend base URL (never exposed to the browser). */
export function getBackendBaseUrl(): string | null {
  const raw =
    process.env.BACKEND_URL ||
    process.env.ARGUS_BACKEND_URL ||
    process.env.NEXT_PUBLIC_BACKEND_URL ||
    "";
  const trimmed = raw.trim().replace(/\/$/, "");
  if (!trimmed) return null;
  // Ensure the /api/v1 prefix is present exactly once.
  if (trimmed.endsWith("/api/v1")) return trimmed;
  return `${trimmed}/api/v1`;
}

function _truthy(raw: string | undefined): boolean {
  const v = (raw || "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

/**
 * Whether scan operations proxy to the real backend.
 *
 * Production default: enabled whenever a backend URL is configured. The mock
 * demo scanner is only used when no backend is configured (offline dev) or when
 * `ARGUS_DEMO_MODE` is explicitly set. `ARGUS_USE_BACKEND` forces it on.
 */
export function isBackendProxyEnabled(): boolean {
  if (_truthy(process.env.ARGUS_DEMO_MODE)) {
    return false;
  }
  if (_truthy(process.env.ARGUS_USE_BACKEND)) {
    return getBackendBaseUrl() !== null;
  }
  return getBackendBaseUrl() !== null;
}

export interface ProxyCreateScanInput {
  target: string;
  email: string;
  tier: ScanTier;
  engagementId?: string;
  labLeaseId?: string;
  tenantId?: string;
  correlationId?: string;
}

export interface BackendCreateScanResponse {
  scan_id: string;
  status: string;
  message?: string;
}

export interface BackendProxyError {
  status: number;
  code: string;
  error: string;
  details?: unknown;
}

function randomId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `cid-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/**
 * Forward a scan-create to backend `POST /api/v1/scans` using the canonical
 * `scan_profile`. Returns the backend response or throws a normalized
 * {@link BackendProxyError} (never a stack trace or secret).
 */
export async function proxyCreateScan(
  input: ProxyCreateScanInput
): Promise<BackendCreateScanResponse> {
  const base = getBackendBaseUrl();
  if (!base) {
    throw <BackendProxyError>{
      status: 503,
      code: "backend_unavailable",
      error: "Backend is not configured",
    };
  }

  const scanProfile = tierToScanProfile(input.tier);
  const body: Record<string, unknown> = {
    target: input.target,
    email: input.email,
    scan_profile: scanProfile,
  };
  if (scanProfile === "deep") {
    if (input.engagementId) body.engagement_id = input.engagementId;
    if (input.labLeaseId) body.lab_lease_id = input.labLeaseId;
  }

  let res: Response;
  try {
    res = await fetch(`${base}/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...backendAuthHeaders(),
        // Only forward X-Tenant-ID when a real tenant is supplied. Sending a
        // bogus "default" collides with the API key's bound tenant and yields
        // 403 Tenant mismatch; omitting it lets the backend derive it from the key.
        ...tenantHeader(input.tenantId),
        "X-Correlation-ID": input.correlationId || randomId(),
        "Idempotency-Key": randomId(),
      },
      body: JSON.stringify(body),
      cache: "no-store",
    });
  } catch {
    throw <BackendProxyError>{
      status: 502,
      code: "backend_unreachable",
      error: "Could not reach the scan backend",
    };
  }

  if (!res.ok) {
    let parsed: { error?: string; code?: string; details?: unknown } | null = null;
    try {
      parsed = (await res.json()) as { error?: string; code?: string; details?: unknown };
    } catch {
      // non-JSON error
    }
    throw <BackendProxyError>{
      status: res.status,
      code: parsed?.code || "scan_create_failed",
      error: parsed?.error || `Scan create failed (${res.status})`,
      details: parsed?.details,
    };
  }

  return (await res.json()) as BackendCreateScanResponse;
}

/** GET backend `/api/v1/scans/:id` — status passthrough for the proxy path. */
export async function proxyGetScanStatus(
  scanId: string,
  opts?: { tenantId?: string }
): Promise<Record<string, unknown>> {
  const base = getBackendBaseUrl();
  if (!base) {
    throw <BackendProxyError>{ status: 503, code: "backend_unavailable", error: "Backend not configured" };
  }
  const res = await fetch(`${base}/scans/${encodeURIComponent(scanId)}`, {
    headers: {
      "Content-Type": "application/json",
      ...backendAuthHeaders(),
      ...tenantHeader(opts?.tenantId),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    let parsed: { error?: string; code?: string } | null = null;
    try {
      parsed = (await res.json()) as { error?: string; code?: string };
    } catch {
      // ignore
    }
    throw <BackendProxyError>{
      status: res.status,
      code: parsed?.code || "scan_status_failed",
      error: parsed?.error || `Scan status failed (${res.status})`,
    };
  }
  return (await res.json()) as Record<string, unknown>;
}

/** Raw backend finding shape (subset of `api.schemas.Finding` we consume). */
interface BackendFinding {
  finding_id?: string | null;
  severity?: string | null;
  title?: string | null;
  description?: string | null;
  cwe?: string | null;
  cvss?: number | null;
  owasp_category?: string | null;
  confidence?: string | null;
  evidence_refs?: unknown;
  reproducible_steps?: string | null;
  applicability_notes?: string | null;
  adversarial_score?: number | null;
  raw_request?: string | null;
  raw_response?: string | null;
  affected_endpoint?: string | null;
  affected_parameter?: string | null;
}

/** OWASP Top 10:2025 short id → human-readable title (mirror of backend). */
const OWASP_TOP10_2025_TITLES: Record<string, string> = {
  A01: "Broken Access Control",
  A02: "Security Misconfiguration",
  A03: "Software Supply Chain Failures",
  A04: "Cryptographic Failures",
  A05: "Injection",
  A06: "Insecure Design",
  A07: "Authentication Failures",
  A08: "Software or Data Integrity Failures",
  A09: "Security Logging & Alerting Failures",
  A10: "Mishandling of Exceptional Conditions",
};

/** Human-readable group label for a backend `owasp_category` (A01…A10). */
function owaspGroupLabel(category: unknown): string {
  const key = String(category ?? "").trim().toUpperCase();
  if (!key) return "Other Findings";
  return OWASP_TOP10_2025_TITLES[key] ?? key;
}

/** Report summary subset the public scan page consumes (mirror of `ReportSummary`). */
interface BackendReportSummary {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  technologies?: unknown;
  sslIssues?: number;
  headerIssues?: number;
  leaksFound?: boolean;
}

/** Subset of `ReportListResponse` we read for scan-result enrichment. */
interface BackendReport {
  summary?: BackendReportSummary;
  technologies?: unknown;
}

/** Backend severity → Ragnarök finding priority bucket. */
function severityToPriority(severity: unknown): CheckPriority {
  switch (String(severity ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "important";
    case "medium":
      return "medium";
    default:
      // low / info / unknown
      return "optional";
  }
}

/**
 * GET backend `/api/v1/scans/:id/findings`. Returns [] on any error so a
 * completed scan still renders (empty results view) instead of dead-ending.
 */
export async function proxyGetScanFindings(
  scanId: string,
  opts?: { tenantId?: string }
): Promise<BackendFinding[]> {
  const base = getBackendBaseUrl();
  if (!base) return [];
  try {
    const res = await fetch(`${base}/scans/${encodeURIComponent(scanId)}/findings`, {
      headers: {
        "Content-Type": "application/json",
        ...backendAuthHeaders(),
        ...tenantHeader(opts?.tenantId),
      },
      cache: "no-store",
    });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? (data as BackendFinding[]) : [];
  } catch {
    return [];
  }
}

/**
 * GET backend `/api/v1/reports?target=:target` and return the most recent report
 * (technologies + severity/ssl/header/leak summary). Returns null on any error so
 * enrichment is best-effort and never blocks the scan page.
 */
export async function proxyGetReportByTarget(
  target: string,
  opts?: { tenantId?: string }
): Promise<BackendReport | null> {
  const base = getBackendBaseUrl();
  if (!base || !target.trim()) return null;
  try {
    const res = await fetch(`${base}/reports?target=${encodeURIComponent(target)}`, {
      headers: {
        "Content-Type": "application/json",
        ...backendAuthHeaders(),
        ...tenantHeader(opts?.tenantId),
      },
      cache: "no-store",
    });
    if (!res.ok) return null;
    const data = await res.json();
    // Backend orders reports by created_at DESC, so the first item is newest.
    return Array.isArray(data) && data.length > 0 ? (data[0] as BackendReport) : null;
  } catch {
    return null;
  }
}

/** Coerce an unknown value into a string[] (drops non-strings). */
function toStringList(raw: unknown): string[] {
  return Array.isArray(raw) ? raw.filter((x): x is string => typeof x === "string") : [];
}

/** An empty {@link ScanResults} so the completed view renders with zero findings. */
export function emptyScanResults(): ScanResults {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    passed: 0,
    technologies: [],
    sslIssues: null,
    headerIssues: null,
    subdomains: null,
    leaksFound: false,
    leaks: [],
    findings: [],
    totalFindings: 0,
  };
}

/**
 * Map backend findings into the frontend {@link ScanResults} the public scan
 * page renders. Groups by OWASP category (human-readable titles), derives
 * severity counts, applies tier-based access gating (free = titles + one full
 * writeup, premium = full), and merges the optional report summary
 * (technologies / SSL / header / leak signals) when available.
 */
export function mapBackendFindingsToResults(
  raw: BackendFinding[],
  tier: ScanTier,
  report?: BackendReport | null
): ScanResults {
  if ((!Array.isArray(raw) || raw.length === 0) && !report) return emptyScanResults();

  const summary = report?.summary;
  const technologies = toStringList(report?.technologies).length
    ? toStringList(report?.technologies)
    : toStringList(summary?.technologies);
  const sslIssues = typeof summary?.sslIssues === "number" ? summary.sslIssues : null;
  const headerIssues = typeof summary?.headerIssues === "number" ? summary.headerIssues : null;
  const leaksFound = Boolean(summary?.leaksFound);
  const info = typeof summary?.info === "number" ? summary.info : 0;

  const findingsRaw = Array.isArray(raw) ? raw : [];
  const groupIds = new Map<string, string>();
  const full: Finding[] = findingsRaw.map((bf, index) => {
    const groupLabel = owaspGroupLabel(bf.owasp_category);
    let groupId = groupIds.get(groupLabel);
    if (!groupId) {
      groupId = String(groupIds.size + 1);
      groupIds.set(groupLabel, groupId);
    }
    const evidenceParts = [
      ...(Array.isArray(bf.evidence_refs) ? bf.evidence_refs.map(String) : []),
      bf.affected_endpoint ? `Endpoint: ${bf.affected_endpoint}` : "",
      bf.affected_parameter ? `Parameter: ${bf.affected_parameter}` : "",
      bf.raw_request ? `REQUEST:\n${bf.raw_request}` : "",
      bf.raw_response ? `RESPONSE:\n${bf.raw_response}` : "",
    ].filter(Boolean);

    return {
      id: bf.finding_id || String(index + 1),
      groupId,
      group: groupLabel,
      name: bf.title || "Untitled finding",
      status: "fail" as const,
      priority: severityToPriority(bf.severity),
      headline: bf.title || "",
      explanation: bf.description || "",
      evidence: evidenceParts.join("\n\n"),
      remediation: bf.applicability_notes || bf.reproducible_steps || "",
      detailLevel: "full" as const,
      access: "full" as const,
      riskScore: bf.adversarial_score ?? bf.cvss ?? null,
    };
  });

  const census = censusFromFindings(full);
  const findings = withTierAccess(full, tier, midgardWriteupId(full));

  return {
    critical: census.critical,
    high: census.high,
    medium: census.medium,
    low: census.low,
    info,
    passed: census.passed,
    technologies,
    sslIssues,
    headerIssues,
    // Subdomains and the detailed credential-leak list are not exposed by the
    // backend for quick-profile scans; wire dedicated recon endpoints later.
    subdomains: null,
    leaksFound,
    leaks: [],
    findings,
    totalFindings: census.totalFindings,
  };
}
