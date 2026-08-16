import Stripe from "stripe";
import type { ScanTier } from "./scan-tiers";

export function getStripe(): Stripe {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    throw new Error("STRIPE_SECRET_KEY is not configured");
  }
  return new Stripe(key);
}

export function getStripePriceId(tier: ScanTier): string | null {
  const raw =
    tier === "standard"
      ? process.env.STRIPE_PRICE_ASGARD
      : tier === "premium"
        ? process.env.STRIPE_PRICE_VALHALLA
        : undefined;

  if (!raw) return null;

  // Ignore .env.example placeholders and other invalid IDs
  const id = raw.trim();
  if (!/^price_[a-zA-Z0-9]+$/.test(id) || id.includes("...")) {
    return null;
  }

  return id;
}

export function getBaseUrl(): string {
  return process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
}
