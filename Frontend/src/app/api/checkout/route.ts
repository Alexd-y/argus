import { NextRequest, NextResponse } from "next/server";
import { getTierConfig } from "@/lib/scan-tiers";
import { getScan } from "@/lib/scans";
import { getStripe, getStripePriceId, getBaseUrl } from "@/lib/stripe";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { scanId } = body;

    if (!scanId || typeof scanId !== "string") {
      return NextResponse.json({ error: "Scan ID is required" }, { status: 400 });
    }

    const scan = getScan(scanId);
    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    if (scan.tier === "free") {
      return NextResponse.json({ error: "Free scans do not require payment" }, { status: 400 });
    }

    if (scan.paid) {
      return NextResponse.json({ error: "Scan results already unlocked" }, { status: 400 });
    }

    if (scan.status !== "complete") {
      return NextResponse.json({ error: "Scan must be complete before unlocking" }, { status: 400 });
    }

    const tierConfig = getTierConfig(scan.tier);
    const baseUrl = getBaseUrl();
    const priceId = getStripePriceId(scan.tier);

    const lineItems = priceId
      ? [{ price: priceId, quantity: 1 }]
      : [
          {
            price_data: {
              currency: tierConfig.currency ?? "cad",
              product_data: {
                name: `${tierConfig.name} Report — ${tierConfig.tagline}`,
                description: `Monthly subscription — unlock full ${tierConfig.name} scan results`,
              },
              unit_amount: tierConfig.priceCents!,
              recurring: { interval: "month" as const },
            },
            quantity: 1,
          },
        ];

    const session = await getStripe().checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      customer_email: scan.email,
      line_items: lineItems,
      metadata: {
        scanId: scan.id,
        tier: scan.tier,
        target: scan.target,
        email: scan.email,
      },
      subscription_data: {
        metadata: {
          scanId: scan.id,
          tier: scan.tier,
          target: scan.target,
        },
      },
      success_url: `${baseUrl}/api/checkout/complete?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}/scan/${scan.id}?canceled=true`,
    });

    if (!session.url) {
      return NextResponse.json({ error: "Failed to create checkout session" }, { status: 500 });
    }

    return NextResponse.json({ url: session.url });
  } catch (error) {
    console.error("Checkout error:", error);
    let message = "Failed to create checkout session";
    if (error instanceof Error) {
      if (error.message.includes("STRIPE_SECRET_KEY")) {
        message = "Payment system is not configured";
      } else if (error.message.includes("No such price")) {
        message =
          "Invalid Stripe price ID in .env.local — remove STRIPE_PRICE_ASGARD / STRIPE_PRICE_VALHALLA or paste real price_ IDs from your Stripe Dashboard";
      }
    }
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
