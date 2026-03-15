/**
 * ARGUS API types (from docs/api-contracts.md).
 */

export interface ScanOptions {
  scanType: "quick" | "light" | "deep";
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
}

export interface CreateScanRequest {
  target: string;
  email: string;
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
  [key: string]: unknown;
}
