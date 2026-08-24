/**
 * ARGUS scan API client — the single typed client for the real backend
 * (`/api/v1`). Replaces the mock Map/setTimeout scanner in the production data
 * path: every function here performs a real async fetch against the backend
 * contract (docs/api-contracts.md).
 *
 * Errors are normalized to `Error(message)` where `message` is the backend's
 * machine-readable `error` field — never a stack trace (see api.ts).
 */

import { apiUrl, getSseApiBaseUrl } from "./api";
import type {
  CreateScanRequest,
  CreateScanResponse,
  Finding,
  GenerateReportResponse,
  ReportListItem,
  ScanCoverage,
  ScanListItem,
  ScanProfile,
  ScanStatus,
  SSEEventPayload,
} from "./types";
import type { ScanTier } from "./scan-tiers";

/** Ragnarök billing tier → canonical scan profile (Quick/Light/Deep). */
export function mapTierToScanProfile(tier: ScanTier): ScanProfile {
  switch (tier) {
    case "free":
      return "quick";
    case "standard":
      return "light";
    case "premium":
      return "deep";
    default: {
      // Exhaustiveness guard: a new tier must be mapped explicitly.
      const _never: never = tier;
      return "quick";
    }
  }
}

function randomId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `cid-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/** Tenant id resolved for browser requests (localStorage or env fallback). */
function tenantId(): string {
  if (typeof window !== "undefined") {
    try {
      const stored = window.localStorage.getItem("tenant_id");
      if (stored && stored.trim()) return stored.trim();
    } catch {
      // localStorage unavailable (SSR / privacy mode) — fall through
    }
  }
  if (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_TENANT_ID) {
    return process.env.NEXT_PUBLIC_TENANT_ID;
  }
  return "default";
}

function contextHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "X-Tenant-ID": tenantId(),
    "X-Correlation-ID": randomId(),
    ...extra,
  };
}

async function readError(res: Response, fallback: string): Promise<never> {
  let body: { error?: string; code?: string } | null = null;
  try {
    body = (await res.json()) as { error?: string; code?: string };
  } catch {
    // non-JSON error body
  }
  throw new Error(body?.error ?? `${fallback} (${res.status})`);
}

/**
 * POST /scans — create a scan. Sends tenant/correlation/idempotency headers.
 * The body is exactly the request contract (no client-side mutation).
 */
export async function createScan(
  request: CreateScanRequest,
  init?: { signal?: AbortSignal; idempotencyKey?: string }
): Promise<CreateScanResponse> {
  const res = await fetch(apiUrl("/scans"), {
    method: "POST",
    body: JSON.stringify(request),
    headers: contextHeaders({ "Idempotency-Key": init?.idempotencyKey ?? randomId() }),
    signal: init?.signal,
  });
  if (!res.ok) {
    return readError(res, "Failed to create scan");
  }
  return res.json() as Promise<CreateScanResponse>;
}

/** GET /scans/:id — current status (IDOR-safe on the backend by tenant). */
export async function getScanStatus(
  scanId: string,
  init?: { signal?: AbortSignal }
): Promise<ScanStatus> {
  const res = await fetch(apiUrl(`/scans/${encodeURIComponent(scanId)}`), {
    method: "GET",
    headers: contextHeaders(),
    signal: init?.signal,
  });
  if (!res.ok) {
    return readError(res, "Failed to load scan");
  }
  return res.json() as Promise<ScanStatus>;
}

/** POST /scans/:id/cancel. */
export async function cancelScan(scanId: string): Promise<{ scan_id: string; status: string }> {
  const res = await fetch(apiUrl(`/scans/${encodeURIComponent(scanId)}/cancel`), {
    method: "POST",
    headers: contextHeaders(),
  });
  if (!res.ok) {
    return readError(res, "Failed to cancel scan");
  }
  return res.json() as Promise<{ scan_id: string; status: string }>;
}

/** GET /scans — list scans for the tenant. */
export async function listScans(init?: { signal?: AbortSignal }): Promise<ScanListItem[]> {
  const res = await fetch(apiUrl("/scans"), {
    method: "GET",
    headers: contextHeaders(),
    signal: init?.signal,
  });
  if (!res.ok) {
    return readError(res, "Failed to list scans");
  }
  return res.json() as Promise<ScanListItem[]>;
}

/** GET /scans/:id/findings — findings for a scan. */
export async function getFindings(
  scanId: string,
  opts?: { severity?: string; validatedOnly?: boolean; signal?: AbortSignal }
): Promise<Finding[]> {
  const qs = new URLSearchParams();
  if (opts?.severity) qs.set("severity", opts.severity);
  if (opts?.validatedOnly) qs.set("validated_only", "true");
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  const res = await fetch(apiUrl(`/scans/${encodeURIComponent(scanId)}/findings${suffix}`), {
    method: "GET",
    headers: contextHeaders(),
    signal: opts?.signal,
  });
  if (!res.ok) {
    return readError(res, "Failed to load findings");
  }
  return res.json() as Promise<Finding[]>;
}

/** GET /scans/:id/coverage — coverage (tested / not_assessed capabilities). */
export async function getScanCoverage(
  scanId: string,
  init?: { signal?: AbortSignal }
): Promise<ScanCoverage> {
  const res = await fetch(apiUrl(`/scans/${encodeURIComponent(scanId)}/coverage`), {
    method: "GET",
    headers: contextHeaders(),
    signal: init?.signal,
  });
  if (!res.ok) {
    return readError(res, "Failed to load coverage");
  }
  return res.json() as Promise<ScanCoverage>;
}

/** POST /scans/:id/reports/generate-all — enqueue all canonical report formats. */
export async function generateAllReports(scanId: string): Promise<GenerateReportResponse> {
  const res = await fetch(apiUrl(`/scans/${encodeURIComponent(scanId)}/reports/generate-all`), {
    method: "POST",
    headers: contextHeaders(),
  });
  if (!res.ok) {
    return readError(res, "Failed to generate reports");
  }
  return res.json() as Promise<GenerateReportResponse>;
}

/** GET /reports — list reports for the tenant. */
export async function listReports(init?: { signal?: AbortSignal }): Promise<ReportListItem[]> {
  const res = await fetch(apiUrl("/reports"), {
    method: "GET",
    headers: contextHeaders(),
    signal: init?.signal,
  });
  if (!res.ok) {
    return readError(res, "Failed to list reports");
  }
  return res.json() as Promise<ReportListItem[]>;
}

/** Build a report download URL (for an anchor / streaming endpoint). */
export function reportDownloadUrl(
  reportId: string,
  format: "pdf" | "json" | "md" | "xml" | "html" = "pdf"
): string {
  return apiUrl(`/reports/${encodeURIComponent(reportId)}/download?format=${encodeURIComponent(format)}`);
}

/**
 * Subscribe to `GET /scans/:id/events` (SSE). Returns an unsubscribe callback.
 * `onError` is invoked when the stream drops so callers can fall back to polling.
 */
export function subscribeScanEvents(
  scanId: string,
  onEvent: (payload: SSEEventPayload) => void,
  onError?: () => void
): () => void {
  if (typeof EventSource === "undefined") {
    onError?.();
    return () => {};
  }
  const base = getSseApiBaseUrl();
  const url = `${base}/scans/${encodeURIComponent(scanId)}/events`;
  const source = new EventSource(url, { withCredentials: false });

  source.onmessage = (evt: MessageEvent) => {
    try {
      onEvent(JSON.parse(evt.data) as SSEEventPayload);
    } catch {
      // ignore malformed frames
    }
  };
  source.onerror = () => {
    source.close();
    onError?.();
  };

  return () => source.close();
}
