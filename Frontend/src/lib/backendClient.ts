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
import type {
  CheckPriority,
  Finding,
  FindingCompliance,
  ScanBaseline,
  ScanBaselineControl,
  ScanResults,
} from "./scan-results";
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
  evidence_type?: string | null;
  proof_of_concept?: Record<string, unknown> | null;
  reproducible_steps?: string | null;
  applicability_notes?: string | null;
  adversarial_score?: number | null;
  affected_asset?: string | null;
  affected_endpoint?: string | null;
  affected_parameter?: string | null;
  raw_request?: string | null;
  raw_response?: string | null;
  http_method?: string | null;
  response_status?: number | null;
  observed_impact?: string | null;
  verification_command?: string | null;
  tool_name?: string | null;
  tool_version?: string | null;
  tool_command?: string | null;
  tool_output_excerpt?: string | null;
  compliance?: Array<{ framework?: string | null; control_id?: string | null; control_name?: string | null }> | null;
}

/**
 * Internal cross-reference identifiers (e.g. `finding_3`, `surf_1`, `EV-0001`)
 * that the analysis pipeline stores in `evidence_refs`. They are opaque join
 * keys, not human-readable evidence, so unresolvable ones must never be
 * surfaced verbatim in the public scan report.
 */
const OPAQUE_EVIDENCE_REF_RE =
  /^(?:finding|surf(?:ace)?|ev|evd|evidence|item|row|node)[-_:]?\d+$/i;

/** Resolvable intra-scan finding pointer emitted by the backend persist layer. */
const FINDING_REF_PREFIX = "finding:";

/** VA evidence-bundle artifact collections → human-readable labels. */
const ARTIFACT_LABELS: Record<string, string> = {
  endpoint_inventory: "Endpoint inventory",
  api_surface: "API surface",
  intel_findings: "Intel finding",
  route_inventory: "Route inventory",
  route_and_workflow: "Route/workflow",
  params_inventory: "Params inventory",
  forms_inventory: "Forms inventory",
  headers_tls: "Headers/TLS",
  js_findings: "JS finding",
  anomalies: "Anomaly",
  live_hosts: "Live host",
  dns_summary: "DNS summary",
  threat_scenarios: "Threat scenario",
  trust_boundaries: "Trust boundary",
  entry_points: "Entry point",
  application_flows: "Application flow",
  critical_assets: "Critical asset",
};

/** Prettify a bundle-artifact locator: `row_3` → `row 3`, `path_/api` → `/api`, `item_0` → `#0`. */
function prettyArtifactLocator(locator: string): string {
  const row = /^row_(\d+)$/i.exec(locator);
  if (row) return `row ${row[1]}`;
  const item = /^item_(\d+)$/i.exec(locator);
  if (item) return `#${item[1]}`;
  const path = /^path_(.+)$/i.exec(locator);
  if (path) return path[1];
  return locator.replace(/_/g, " ");
}

/**
 * Prettify an `evidence_ref`, resolving intra-scan finding pointers to the
 * referenced finding's title, or return `null` when it is an opaque internal id
 * with no presentable form.
 */
function formatEvidenceRef(ref: string, findingsById: Map<string, BackendFinding>): string | null {
  const trimmed = ref.trim();
  if (!trimmed) return null;
  // "finding:<uuid>" → resolve to the referenced finding's title.
  if (trimmed.toLowerCase().startsWith(FINDING_REF_PREFIX)) {
    const target = findingsById.get(trimmed.slice(FINDING_REF_PREFIX.length));
    return target?.title ? `Related finding: ${target.title}` : null;
  }
  // "tool:nuclei" → "Detected by: nuclei".
  const toolMatch = /^tool:(.+)$/i.exec(trimmed);
  if (toolMatch) return `Detected by: ${toolMatch[1].trim()}`;
  // "<collection>:<locator>" bundle artifact → readable label.
  const artifactMatch = /^([a-z_]+):(.+)$/i.exec(trimmed);
  if (artifactMatch) {
    const label = ARTIFACT_LABELS[artifactMatch[1].toLowerCase()];
    if (label) return `${label} (${prettyArtifactLocator(artifactMatch[2])})`;
  }
  // Drop remaining opaque identifiers.
  if (OPAQUE_EVIDENCE_REF_RE.test(trimmed)) return null;
  if (/[:_](?:row|item)_?\d+$/i.test(trimmed)) return null;
  // A bare single token with no whitespace, URL, or dotted host is almost
  // certainly an internal id rather than presentable evidence.
  if (!/\s/.test(trimmed) && !/^https?:\/\//i.test(trimmed) && !trimmed.includes(".")) {
    return null;
  }
  return trimmed;
}

/** Extract readable lines from a structured `proof_of_concept` payload. */
function pocLines(poc: Record<string, unknown> | null | undefined): string[] {
  if (!poc || typeof poc !== "object") return [];
  const str = (key: string): string => (typeof poc[key] === "string" ? (poc[key] as string).trim() : "");
  const lines: string[] = [];
  const parameter = str("parameter");
  const payload = str("payload");
  const curl = str("curl_command") || str("curl");
  const javascript = str("javascript_code");
  const request = str("request");
  const response = str("response");
  if (parameter) lines.push(`Parameter: ${parameter}`);
  if (payload) lines.push(`Payload: ${payload}`);
  if (curl) lines.push(`cURL:\n${curl}`);
  if (javascript) lines.push(`Script:\n${javascript}`);
  if (request) lines.push(`REQUEST:\n${request}`);
  if (response) lines.push(`RESPONSE:\n${response}`);
  return lines;
}

/**
 * Build a human-readable Evidence block for a finding from the meaningful
 * backend fields (endpoint, tool, proof-of-concept, raw request/response,
 * scanner output). Opaque `evidence_refs` ids are filtered out so the UI never
 * shows raw join keys like `finding_3`.
 */
function buildEvidence(bf: BackendFinding, findingsById: Map<string, BackendFinding>): string {
  const lines: string[] = [];

  if (bf.affected_endpoint) lines.push(`Endpoint: ${bf.affected_endpoint}`);
  else if (bf.affected_asset) lines.push(`Asset: ${bf.affected_asset}`);
  if (bf.affected_parameter) lines.push(`Parameter: ${bf.affected_parameter}`);
  if (bf.http_method) lines.push(`Method: ${bf.http_method}`);
  if (typeof bf.response_status === "number") lines.push(`Response status: ${bf.response_status}`);
  if (bf.tool_name) {
    lines.push(`Tool: ${bf.tool_name}${bf.tool_version ? ` ${bf.tool_version}` : ""}`);
  }
  if (bf.tool_command) lines.push(`Command:\n${bf.tool_command}`);
  if (bf.observed_impact) lines.push(`Observed impact: ${bf.observed_impact}`);

  lines.push(...pocLines(bf.proof_of_concept));

  if (bf.raw_request) lines.push(`REQUEST:\n${bf.raw_request}`);
  if (bf.raw_response) lines.push(`RESPONSE:\n${bf.raw_response}`);
  if (bf.tool_output_excerpt) lines.push(`Scanner output:\n${bf.tool_output_excerpt}`);
  if (bf.verification_command) lines.push(`Verify:\n${bf.verification_command}`);

  const refs = (Array.isArray(bf.evidence_refs) ? bf.evidence_refs : [])
    .map((ref) => formatEvidenceRef(String(ref), findingsById))
    .filter((ref): ref is string => Boolean(ref));
  lines.push(...refs);

  return lines.join("\n");
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

const _SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function severityRank(severity: unknown): number {
  return _SEVERITY_RANK[String(severity ?? "").toLowerCase()] ?? 0;
}

const _TLS_GROUP = "Transport Security";
const _TLS_RE = /\b(tls|ssl|cipher|certificate|hsts)\b/i;

// Block 4d — dedicated recon sections. Findings from the DNS/email-security
// recon (Block 2) otherwise fall into the generic OWASP "Security
// Misconfiguration" bucket; classify them into their own named groups so the
// report renders distinct DNS / DNSSEC / Email Security / Data Exposure sections.
const _DATA_EXPOSURE_GROUP = "Data Exposure";
const _EMAIL_GROUP = "Email Security";
const _DNSSEC_GROUP = "DNSSEC";
const _DNS_GROUP = "DNS";
const _DATA_EXPOSURE_RE = /exposed credentials|known breach|data breach|cwe-359/i;
const _EMAIL_RE = /\b(spf|dmarc|dkim)\b/i;
const _DNSSEC_RE = /dnssec|cwe-350/i;
const _DNS_RE = /zone transfer|\baxfr\b|\bcaa\b|dns record|dns zone|cwe-538/i;

/** Dedicated recon-section group for a finding, or null if it is not one. Ordered
 * by specificity so, e.g., a CAA finding (mentions "certificates") lands in DNS
 * rather than Transport Security. */
function reconSectionGroup(blob: string): string | null {
  if (_DATA_EXPOSURE_RE.test(blob)) return _DATA_EXPOSURE_GROUP;
  if (_EMAIL_RE.test(blob)) return _EMAIL_GROUP;
  if (_DNSSEC_RE.test(blob)) return _DNSSEC_GROUP;
  if (_DNS_RE.test(blob)) return _DNS_GROUP;
  return null;
}

/** Group label with transport-security unification and dedicated recon sections
 * (Block 4.2/4d): DNS/DNSSEC/Email/Data-Exposure findings get their own named
 * group; all TLS/SSL findings collapse into a single "Transport Security" group;
 * everything else falls back to the OWASP bucket. */
function groupLabelForFinding(bf: BackendFinding): string {
  const blob = `${bf.title ?? ""} ${bf.description ?? ""} ${bf.cwe ?? ""}`;
  const section = reconSectionGroup(blob);
  if (section) return section;
  if (_TLS_RE.test(blob)) return _TLS_GROUP;
  return owaspGroupLabel(bf.owasp_category);
}

/** Map backend `compliance` (snake_case) into typed {@link FindingCompliance}. */
function mapFindingCompliance(bf: BackendFinding): FindingCompliance[] | undefined {
  if (!Array.isArray(bf.compliance) || bf.compliance.length === 0) return undefined;
  const out = bf.compliance
    .filter((c): c is NonNullable<typeof c> => Boolean(c) && Boolean(c.control_id || c.framework))
    .map((c) => ({
      framework: String(c.framework ?? ""),
      controlId: String(c.control_id ?? ""),
      controlName: String(c.control_name ?? ""),
    }));
  return out.length ? out : undefined;
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
  baseline?: unknown;
}

/** Map the backend `report.baseline` dict into the typed {@link ScanBaseline}. */
function mapBaseline(raw: unknown): ScanBaseline | null {
  if (!raw || typeof raw !== "object") return null;
  const b = raw as Record<string, unknown>;
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
  const controlsRaw = Array.isArray(b.controls) ? b.controls : [];
  const controls: ScanBaselineControl[] = controlsRaw
    .filter((c): c is Record<string, unknown> => Boolean(c) && typeof c === "object")
    .map((c) => {
      const status = c.status === "pass" || c.status === "fail" ? c.status : "not_assessed";
      return {
        id: String(c.id ?? ""),
        title: String(c.title ?? c.id ?? ""),
        category: String(c.category ?? ""),
        executed: Boolean(c.executed),
        passed: Boolean(c.passed),
        status,
      };
    });
  if (controls.length === 0) return null;
  return {
    total: num(b.total),
    executed: num(b.executed),
    passed: num(b.passed),
    coverage: num(b.coverage),
    passRate: num(b.pass_rate),
    controls,
  };
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

/** Successful backend report download (bytes + passthrough headers). */
export interface ProxyReportDownload {
  ok: true;
  status: number;
  contentType: string;
  contentDisposition: string | null;
  body: ArrayBuffer;
}

/** Normalized backend report-download failure (never a stack trace or secret). */
export interface ProxyReportError {
  ok: false;
  status: number;
  code: string;
  error: string;
}

/**
 * GET backend `/api/v1/scans/:id/report?format=&tier=` and return the rendered
 * artifact bytes with the backend's `Content-Type`/`Content-Disposition` so the
 * Next route can stream a real PDF instead of the in-memory demo builder.
 *
 * The backend already applies tier fallback + on-demand regeneration, so a
 * completed scan yields a downloadable report even when the requested tier
 * legitimately has no artifact (e.g. Valhalla for quick scans).
 */
export async function proxyDownloadScanReport(
  scanId: string,
  opts?: { format?: string; tier?: string; tenantId?: string }
): Promise<ProxyReportDownload | ProxyReportError> {
  const base = getBackendBaseUrl();
  if (!base) {
    return { ok: false, status: 503, code: "backend_unavailable", error: "Backend not configured" };
  }
  const format = (opts?.format || "pdf").trim();
  const tier = (opts?.tier || "midgard").trim();
  const url =
    `${base}/scans/${encodeURIComponent(scanId)}/report` +
    `?format=${encodeURIComponent(format)}&tier=${encodeURIComponent(tier)}`;

  let res: Response;
  try {
    res = await fetch(url, {
      headers: {
        ...backendAuthHeaders(),
        ...tenantHeader(opts?.tenantId),
      },
      cache: "no-store",
    });
  } catch {
    return { ok: false, status: 502, code: "backend_unreachable", error: "Could not reach the report backend" };
  }

  if (!res.ok) {
    let code = "report_unavailable";
    let error = `Report unavailable (${res.status})`;
    try {
      const parsed = (await res.json()) as { error?: string; code?: string; message?: string };
      if (parsed?.error) error = String(parsed.error);
      if (parsed?.message) error = String(parsed.message);
      if (parsed?.code) code = String(parsed.code);
    } catch {
      // non-JSON backend error — keep the generic message
    }
    return { ok: false, status: res.status, code, error };
  }

  return {
    ok: true,
    status: res.status,
    contentType: res.headers.get("content-type") || "application/octet-stream",
    contentDisposition: res.headers.get("content-disposition"),
    body: await res.arrayBuffer(),
  };
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
    baseline: null,
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
  // Index findings by their stable id so intra-scan cross-references
  // (`finding:<uuid>`) in evidence_refs resolve to the referenced finding.
  const findingsById = new Map<string, BackendFinding>();
  for (const bf of findingsRaw) {
    if (bf.finding_id) findingsById.set(String(bf.finding_id), bf);
  }
  const groupIds = new Map<string, string>();
  // Block 4.3: sort by severity (critical→info), then CVSS desc, so the report
  // leads with the most impactful findings.
  const sortedRaw = [...findingsRaw].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      (b.cvss ?? 0) - (a.cvss ?? 0)
  );
  const full: Finding[] = sortedRaw.map((bf, index) => {
    const groupLabel = groupLabelForFinding(bf);
    let groupId = groupIds.get(groupLabel);
    if (!groupId) {
      groupId = String(groupIds.size + 1);
      groupIds.set(groupLabel, groupId);
    }
    return {
      id: bf.finding_id || String(index + 1),
      groupId,
      group: groupLabel,
      name: bf.title || "Untitled finding",
      status: "fail" as const,
      priority: severityToPriority(bf.severity),
      headline: bf.title || "",
      explanation: bf.description || "",
      evidence: buildEvidence(bf, findingsById),
      remediation: bf.applicability_notes || bf.reproducible_steps || "",
      detailLevel: "full" as const,
      access: "full" as const,
      riskScore: bf.adversarial_score ?? bf.cvss ?? null,
      compliance: mapFindingCompliance(bf),
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
    baseline: mapBaseline(report?.baseline),
  };
}
