/** Scan / engagement / LAB API client — /api/v1/* (proxied via next.config rewrites). */

export type ExecutionMode = "production" | "lab_unrestricted" | "quick";

export type ScanDepth = "quick" | "standard" | "deep" | "lab";

/** Map immutable execution profile to scan depth. Quick must not fall through to standard. */
export function scanModeForExecution(mode: ExecutionMode): ScanDepth {
  switch (mode) {
    case "production":
      return "standard";
    case "lab_unrestricted":
      return "lab";
    case "quick":
      return "quick";
    default: {
      const _exhaustive: never = mode;
      return _exhaustive;
    }
  }
}

export function isLabExecution(mode: ExecutionMode): boolean {
  switch (mode) {
    case "lab_unrestricted":
      return true;
    case "production":
    case "quick":
      return false;
    default: {
      const _exhaustive: never = mode;
      return _exhaustive;
    }
  }
}

export function isQuickExecution(mode: ExecutionMode): boolean {
  switch (mode) {
    case "quick":
      return true;
    case "production":
    case "lab_unrestricted":
      return false;
    default: {
      const _exhaustive: never = mode;
      return _exhaustive;
    }
  }
}

export const COVERAGE_UNTESTED_NOT_SAFE =
  "Untested coverage is not evidence of safety. Absence of a finding does not mean the asset is secure.";

export function coverageReasonLabel(code: string | null | undefined): string {
  if (!code) return "—";
  switch (code) {
    case "executed":
      return "Executed";
    case "budget_partial":
      return "Partial (budget)";
    case "fingerprint_mismatch":
      return "Fingerprint mismatch";
    case "not_scheduled_by_quick_profile":
      return "Not scheduled by Quick profile";
    case "deadline_reached":
      return "Deadline reached";
    case "tool_error":
      return "Tool error";
    default:
      return code.replace(/_/g, " ");
  }
}

export type CoverageStatus =
  | "planned"
  | "running"
  | "covered_no_finding"
  | "covered_with_finding"
  | "partial"
  | "blocked"
  | "not_applicable"
  | "not_tested";

export type DiffStatus =
  | "new"
  | "unchanged"
  | "changed"
  | "resolved_candidate"
  | "resolved"
  | "regressed"
  | "not_tested";

export interface ExecutionModeResponse {
  engagement_id: string;
  tenant_id: string;
  mode: ExecutionMode;
  first_execution_at: string | null;
}

export interface LabScopeManifestResponse {
  manifest_id: string;
  tenant_id: string;
  engagement_id: string;
  mode: ExecutionMode;
  asset_ids?: string[];
  cidrs?: string[];
  dns_suffixes?: string[];
  k8s_namespace?: string | null;
  vm_network_ids?: string[];
  internet_attached?: boolean;
  capture_full?: boolean;
  expires_at: string;
  created_by?: string;
  created_at?: string;
  signature?: string | null;
}

export interface LabLeaseResponse {
  lease_id: string;
  tenant_id: string;
  engagement_id: string;
  manifest_id: string;
  mode: ExecutionMode;
  status: "active" | "expired" | "revoked" | "kill_switched";
  issued_at: string;
  expires_at: string;
  kill_switch_cleared: boolean;
  boundary_proof?: string;
  capture_full?: boolean;
  policy?: {
    requires_approval?: boolean;
    outcome?: string;
    allowed_tools?: string | string[];
    allowed_actions?: string | string[];
    reason?: string;
  };
}

export interface CoverageRequirement {
  id: string;
  tenant_id: string;
  scan_id: string;
  asset_id: string;
  capability_id: string;
  required_evidence_types?: string[];
}

export interface CoverageResult {
  requirement_id: string;
  tenant_id: string;
  scan_id: string;
  asset_id: string;
  capability_id: string;
  status: CoverageStatus;
  execution_evidence_id?: string | null;
  blocked_reason?: string | null;
  finding_id?: string | null;
  recorded_at?: string | null;
  reason_code?: string | null;
  template_ids?: string[];
  evidence_ids?: string[];
}

export interface ScanBudgetView {
  wall_clock_budget_seconds: number;
  discovery_budget_seconds?: number;
  fingerprint_budget_seconds?: number;
  verification_budget_seconds?: number;
  ai_budget_seconds?: number;
  report_budget_seconds?: number;
  request_budget?: number;
  per_host_budget?: number;
  concurrency_budget?: number;
  reserve_for_validation_percent?: number;
}

export interface ScanDetailResponse {
  id: string;
  status: string;
  progress: number;
  phase: string;
  target: string;
  created_at: string;
  deadline_at?: string | null;
  quick_profile?: string | null;
  budget?: ScanBudgetView | null;
  stage?: string | null;
  execution_mode?: ExecutionMode;
}

export interface ScanFinding {
  finding_id?: string | null;
  severity: string;
  title: string;
  description?: string;
  confidence?: string;
  cwe?: string | null;
  validation_status?: string;
}

export interface QuickCreateOptions {
  profile?: "compact" | "balanced" | "extended";
  severity_floor?: "critical" | "high" | "medium" | "low" | "info";
  enable_ai?: boolean;
  enable_oast?: boolean;
  enable_headless_on_signal?: boolean;
  wall_clock_budget_seconds?: number;
  ai_budget_seconds?: number;
  authenticated_context_id?: string;
  cloud_llm_allowed?: boolean;
}

export interface ScanCoverageResponse {
  scan_id: string;
  requirements: CoverageRequirement[];
  results: CoverageResult[];
}

export interface ScanDiffEntry {
  finding_key: string;
  status: DiffStatus;
  baseline_state?: string | null;
  current_state?: string | null;
}

export interface ScanDiffResponse {
  scan_id: string;
  baseline_id: string;
  entries: ScanDiffEntry[];
}

const getBaseUrl = () =>
  typeof window !== "undefined"
    ? ""
    : process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function getTenantId(): string {
  if (typeof window !== "undefined") {
    const stored = localStorage.getItem("tenant_id");
    if (stored) return stored;
  }
  return process.env.NEXT_PUBLIC_TENANT_ID || "default";
}

export async function fetchV1<T>(
  path: string,
  options: RequestInit = {},
  tenantId?: string
): Promise<T> {
  const url = `${getBaseUrl()}/api/v1${path}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Tenant-Id": tenantId ?? getTenantId(),
    ...(options.headers as Record<string, string>),
  };

  const res = await fetch(url, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    const detail = (err as { detail?: string | Record<string, unknown> }).detail;
    const message =
      typeof detail === "string"
        ? detail
        : detail
          ? JSON.stringify(detail)
          : "Request failed";
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}

export const scanApi = {
  getExecutionMode: (engagementId: string, tenantId?: string) =>
    fetchV1<ExecutionModeResponse>(
      `/engagements/${encodeURIComponent(engagementId)}/execution-mode`,
      {},
      tenantId
    ),

  setExecutionMode: (
    engagementId: string,
    mode: ExecutionMode,
    tenantId?: string
  ) =>
    fetchV1<ExecutionModeResponse>(
      `/engagements/${encodeURIComponent(engagementId)}/execution-mode`,
      { method: "POST", body: JSON.stringify({ mode }) },
      tenantId
    ),

  createLabScope: (
    engagementId: string,
    body: {
      cidrs?: string[];
      dns_suffixes?: string[];
      k8s_namespace?: string;
      vm_network_ids?: string[];
      internet_attached?: boolean;
      capture_full?: boolean;
      expires_in_hours?: number;
    },
    tenantId?: string
  ) =>
    fetchV1<LabScopeManifestResponse>(
      `/engagements/${encodeURIComponent(engagementId)}/lab-scope`,
      { method: "POST", body: JSON.stringify(body) },
      tenantId
    ),

  createLabLease: (
    engagementId: string,
    body: { target: string; kill_switch_cleared?: boolean },
    tenantId?: string
  ) =>
    fetchV1<LabLeaseResponse>(
      `/engagements/${encodeURIComponent(engagementId)}/lab-lease`,
      { method: "POST", body: JSON.stringify(body) },
      tenantId
    ),

  createScan: (body: {
    target: string;
    email?: string;
    scan_mode?: string;
    execution_mode?: ExecutionMode;
    quick?: QuickCreateOptions;
    options?: Record<string, unknown>;
  }) =>
    fetchV1<{ scan_id: string; status: string; message?: string }>("/scans", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  getScan: (scanId: string) =>
    fetchV1<ScanDetailResponse>(`/scans/${encodeURIComponent(scanId)}`),

  cancelScan: (scanId: string) =>
    fetchV1<{ scan_id: string; status: string; message?: string }>(
      `/scans/${encodeURIComponent(scanId)}/cancel`,
      { method: "POST" }
    ),

  getFindings: (scanId: string) =>
    fetchV1<ScanFinding[]>(`/scans/${encodeURIComponent(scanId)}/findings`),

  getCoverage: (scanId: string) =>
    fetchV1<ScanCoverageResponse>(
      `/scans/${encodeURIComponent(scanId)}/coverage`
    ),

  getDiff: (scanId: string, baselineId: string) =>
    fetchV1<ScanDiffResponse>(
      `/scans/${encodeURIComponent(scanId)}/diff/${encodeURIComponent(baselineId)}`
    ),

  listNucleiProfiles: () =>
    fetchV1<{ profiles: Array<Record<string, unknown>> }>("/nuclei/profiles"),

  listNucleiTemplates: () =>
    fetchV1<{ templates: Array<Record<string, unknown>> }>("/nuclei/templates"),

  getRagTrace: (scanId: string) =>
    fetchV1<{
      scan_id: string;
      query: string;
      citations: Array<Record<string, unknown>>;
      collection: string;
    }>(`/rag/traces/${encodeURIComponent(scanId)}`),

  getOastTrace: (scanId: string) =>
    fetchV1<{
      scan_id: string;
      interactions: Array<Record<string, unknown>>;
    }>(`/oast/traces/${encodeURIComponent(scanId)}`),

  getLabExecution: (executionId: string) =>
    fetchV1<Record<string, unknown>>(
      `/lab/executions/${encodeURIComponent(executionId)}`
    ),
};
