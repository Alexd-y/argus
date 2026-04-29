/**
 * ARGUS API types (from docs/api-contracts.md).
 */

export interface ScanOptions {
  scanType: "quick" | "light" | "deep" | "lab";
  reportFormat: "pdf" | "html" | "json" | "xml";
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

export interface CreateScanRequest {
  target: string;
  email: string;
  scan_mode?: "quick" | "standard" | "deep" | "lab";
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
}

export interface SSEEventPayload {
  event?: string;
  phase?: string;
  progress?: number;
  message?: string;
  data?: unknown;
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
