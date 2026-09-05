/**
 * Scan-quota API client (Block 4.6) — typed access to the backend quota
 * endpoints (`GET /api/v1/quota`, `POST /api/v1/quota/checkout`). Mirrors the
 * backend `QuotaResponse` / `CheckoutResponse` contracts.
 */

import { apiUrl } from "./api";
import type { ScanTier } from "./scan-tiers";

/** Mirrors the backend `QuotaResponse` (frontend ScanQuota shape). */
export interface QuotaSnapshot {
  included: number;
  extra: number;
  extraCap: number;
  used: number;
  remaining: number;
  capacity: number;
  periodEnd: string;
  canRetest: boolean;
  canBuyExtra: boolean;
}

export interface CheckoutResult {
  url: string | null;
  stubbed: boolean;
  reason: string | null;
}

/** GET /api/v1/quota — current tenant scan quota. */
export async function getQuota(tier?: ScanTier): Promise<QuotaSnapshot> {
  const qs = tier ? `?tier=${encodeURIComponent(tier)}` : "";
  const res = await fetch(apiUrl(`/quota${qs}`), {
    method: "GET",
    headers: { Accept: "application/json" },
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error(`Failed to load quota (${res.status})`);
  }
  return (await res.json()) as QuotaSnapshot;
}

/** POST /api/v1/quota/checkout — start a Stripe checkout for extra scans.
 * When Stripe is unconfigured the backend returns `{ stubbed: true }`. */
export async function startScanCheckout(
  quantity = 1,
  tier?: ScanTier
): Promise<CheckoutResult> {
  const res = await fetch(apiUrl(`/quota/checkout`), {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    credentials: "include",
    body: JSON.stringify({ quantity, tier: tier ?? null }),
  });
  if (!res.ok) {
    throw new Error(`Failed to start checkout (${res.status})`);
  }
  const data = (await res.json()) as CheckoutResult;
  // If Stripe returned a hosted URL, redirect the browser to complete payment.
  if (data.url && typeof window !== "undefined") {
    window.location.assign(data.url);
  }
  return data;
}
