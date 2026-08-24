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
        "X-Tenant-ID": input.tenantId || process.env.NEXT_PUBLIC_TENANT_ID || "default",
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
      "X-Tenant-ID": opts?.tenantId || process.env.NEXT_PUBLIC_TENANT_ID || "default",
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
