import Stripe from "stripe";
import type { ScanTier } from "./scan-tiers";

export function getStripe(): Stripe {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    throw new Error("STRIPE_SECRET_KEY is not configured");
  }
  return new Stripe(key);
}

function catalogEnv(tier: ScanTier, extra: boolean): string | undefined {
  if (tier === "standard") {
    return extra
      ? process.env.STRIPE_PRODUCT_ASGARD_EXTRA ?? process.env.STRIPE_PRICE_ASGARD_EXTRA
      : process.env.STRIPE_PRODUCT_ASGARD ?? process.env.STRIPE_PRICE_ASGARD;
  }
  if (tier === "premium") {
    return extra
      ? process.env.STRIPE_PRODUCT_VALHALLA_EXTRA ?? process.env.STRIPE_PRICE_VALHALLA_EXTRA
      : process.env.STRIPE_PRODUCT_VALHALLA ?? process.env.STRIPE_PRICE_VALHALLA;
  }
  return undefined;
}

function asId(raw: string | undefined, prefix: "price" | "prod"): string | null {
  if (!raw) return null;
  const id = raw.trim();
  if (!new RegExp(`^${prefix}_[a-zA-Z0-9]+$`).test(id) || id.includes("...")) {
    return null;
  }
  return id;
}

function priceIdOf(value: string | Stripe.Price | Stripe.DeletedProduct | Stripe.Product | null | undefined): string | null {
  if (!value) return null;
  if (typeof value === "string") return asId(value, "price");
  if ("object" in value && value.object === "price") return asId(value.id, "price");
  return null;
}

async function priceForProduct(productId: string, extra: boolean): Promise<string | null> {
  const stripe = getStripe();
  const product = await stripe.products.retrieve(productId);
  const defaultPrice = priceIdOf(product.default_price);

  if (defaultPrice) {
    const price = await stripe.prices.retrieve(defaultPrice);
    const isRecurring = price.type === "recurring";
    if (extra ? !isRecurring : isRecurring) return defaultPrice;
  }

  const prices = await stripe.prices.list({
    product: productId,
    active: true,
    type: extra ? "one_time" : "recurring",
    limit: 10,
  });

  return prices.data[0]?.id ?? null;
}

export async function resolveStripePriceId(tier: ScanTier, extra = false): Promise<string | null> {
  const raw = catalogEnv(tier, extra);
  const priceId = asId(raw, "price");
  if (priceId) return priceId;

  const productId = asId(raw, "prod");
  if (!productId) return null;

  return priceForProduct(productId, extra);
}

export function missingCatalogMessage(tier: ScanTier, extra: boolean): string {
  const raw = catalogEnv(tier, extra)?.trim();
  if (!raw) {
    return extra
      ? "Extra scan product is not configured"
      : "Stripe product is not configured for this tier";
  }
  if (raw.startsWith("prod_")) {
    return extra
      ? "This Stripe product has no one-time extra-scan price"
      : "This Stripe product has no recurring monthly price";
  }
  return extra
    ? "Extra scan product is not configured"
    : "Stripe product is not configured for this tier";
}

export function getBaseUrl(): string {
  const url = process.env.NEXT_PUBLIC_BASE_URL;
  if (!url) {
    throw new Error("NEXT_PUBLIC_BASE_URL is not configured");
  }
  return url;
}
