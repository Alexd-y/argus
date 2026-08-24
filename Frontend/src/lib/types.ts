/**
 * ARGUS API types (from docs/api-contracts.md).
 */

export interface ScanOptions {
  scanType: "quick" | "light" | "deep" | "lab";
  reportFormat: "pdf" | "html" | "json" | "xml" | "md";
  rateLimit: "slow" | "normal" | "fast" | "aggressive";
  ports: string;
  followRedirects: boolean;
  vulnerabilities: {
    xss: boolean;
    sqli: boolean;
    csrf: boolean;
    ssrf: boolean;
    lfi: boolean;
    rce: boolean;
    idor?: boolean;
    ssti?: boolean;
    xxe?: boolean;
    headers?: boolean;
  };
  authentication: {
    enabled: boolean;
    type: "basic" | "bearer" | "cookie";
    username: string;
    password: string;
    token: string;
  };
  scope: {
    maxDepth: number;
    includeSubs: boolean;
    excludePatterns: string;
  };
  advanced: {
    timeout: number;
    userAgent: "chrome" | "firefox" | "mobile" | "bot";
    proxy: string;
    customHeaders: string;
  };
  active_injection_mode?: "quick" | "standard" | "deep" | "maximum" | "lab";
  intentional_vulnerable_lab?: boolean;
  lab_profile?: string;
  lab_allowed_targets?: string[];
  argus_lab_allowed_targets?: string;
  scan_approval_flags?: Record<string, boolean>;
}

export type ExecutionMode = "production" | "lab_unrestricted" | "quick";

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

export interface QuickBudgetView {
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

/** Canonical external scan profile — the only value the UI should select. */
export type ScanProfile = "quick" | "light" | "deep";

export interface CreateScanRequest {
  target: string;
  email: string;
  /** Canonical profile (preferred). Backend derives scan_mode/execution_mode. */
  scan_profile?: ScanProfile;
  /** Required when scan_profile=deep (LAB). */
  engagement_id?: string;
  lab_lease_id?: string;
  /** Legacy (deprecated when scan_profile is set) — kept for backward compat. */
  scan_mode?: "quick" | "standard" | "deep" | "lab";
  execution_mode?: ExecutionMode;
  quick?: QuickCreateOptions;
  options: ScanOptions;
}

export interface CreateScanResponse {
  scan_id: string;
  status: string;
  message?: string;
}

export interface ScanStatus {
  id: string;
  status: string;
  progress: number;
  phase: string;
  target: string;
  created_at: string;
  scan_profile?: ScanProfile;
  resolved_scan_mode?: string;
  execution_mode?: ExecutionMode;
  nuclei_profile?: string;
  engagement_id?: string;
  lab_lease_id?: string;
  profile_version?: string;
  report_snapshot_version?: string;
  deadline_at?: string;
  quick_profile?: "compact" | "balanced" | "extended";
  budget?: QuickBudgetView;
  stage?: string;
}

export interface SSEEventPayload {
  event?: string;
  phase?: string;
  progress?: number;
  message?: string;
  data?: unknown;
}

export interface ScanListItem {
  id: string;
  status: string;
  progress: number;
  phase: string;
  target: string;
  email?: string;
  created_at: string;
  scan_mode?: string;
}

export interface ScanCoverageResultItem {
  requirement_id?: string;
  capability_id?: string;
  status?: string;
  reason_code?: string;
  evidence_ids?: string[];
  finding_id?: string;
}

export interface ScanCoverage {
  scan_id: string;
  requirements: unknown[];
  results: ScanCoverageResultItem[];
}

export interface GenerateReportResponse {
  report_id: string;
  task_id?: string;
}

export interface ReportListItem {
  report_id: string;
  scan_id?: string | null;
  tier?: string;
  generation_status?: string;
  created_at?: string;
  requested_formats?: string[] | null;
}

export interface ReportSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  technologies: string[];
  sslIssues: number;
  headerIssues: number;
  leaksFound: boolean;
}

export interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  cwe?: string;
  cvss?: number;
}

export interface Report {
  report_id: string;
  target: string;
  summary: ReportSummary;
  findings: Finding[];
  technologies: string[];
  /** GET /reports/:id — optional; list rows may omit */
  created_at?: string;
  scan_id?: string | null;
  generation_status?: string;
  tier?: string;
  requested_formats?: string[] | null;
  [key: string]: unknown;
}
