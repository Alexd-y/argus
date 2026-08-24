import { NextRequest, NextResponse } from "next/server";
import { isPaidTier } from "@/lib/scan-tiers";
import { getScanQuota } from "@/lib/scan-quota";
import { getScan } from "@/lib/scans";
import { getStripe, resolveStripePriceId, missingCatalogMessage, getBaseUrl } from "@/lib/stripe";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { scanId, kind } = body as { scanId?: unknown; kind?: unknown };

    if (!scanId || typeof scanId !== "string") {
      return NextResponse.json({ error: "Scan ID is required" }, { status: 400 });
    }

    const scan = getScan(scanId);
    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    if (!isPaidTier(scan.tier)) {
      return NextResponse.json({ error: "Free scans do not require payment" }, { status: 400 });
    }

    const checkoutKind = kind === "extra_scan" ? "extra_scan" : "unlock";
    const baseUrl = getBaseUrl();

    if (checkoutKind === "extra_scan") {
      if (!scan.paid) {
        return NextResponse.json({ error: "Subscribe before buying extra scans" }, { status: 400 });
      }

      const quota = getScanQuota(scan);
      if (quota && quota.remaining > 0) {
        return NextResponse.json(
          { error: "You still have scans remaining this month", quota },
          { status: 400 }
        );
      }

      if (quota && !quota.canBuyExtra) {
        return NextResponse.json(
          {
            error: `Extra scan limit reached (${quota.extraCap} additional this period)`,
            code: "EXTRA_CAP_REACHED",
            quota,
          },
          { status: 400 }
        );
      }

      const extraPriceId = await resolveStripePriceId(scan.tier, true);
      if (!extraPriceId) {
        return NextResponse.json({ error: missingCatalogMessage(scan.tier, true) }, { status: 500 });
      }

      const session = await getStripe().checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"],
        customer_email: scan.email,
        line_items: [{ price: extraPriceId, quantity: 1 }],
        metadata: {
          scanId: scan.id,
          tier: scan.tier,
          target: scan.target,
          email: scan.email,
          kind: "extra_scan",
        },
        success_url: `${baseUrl}/api/checkout/complete?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${baseUrl}/scan/${scan.id}?canceled=true`,
      });

      if (!session.url) {
        return NextResponse.json({ error: "Failed to create checkout session" }, { status: 500 });
      }

      return NextResponse.json({ url: session.url });
    }

    if (scan.paid) {
      return NextResponse.json({ error: "Scan results already unlocked" }, { status: 400 });
    }

    if (scan.status !== "complete") {
      return NextResponse.json({ error: "Scan must be complete before unlocking" }, { status: 400 });
    }

    const priceId = await resolveStripePriceId(scan.tier);
    if (!priceId) {
      return NextResponse.json({ error: missingCatalogMessage(scan.tier, false) }, { status: 500 });
    }

    const session = await getStripe().checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      customer_email: scan.email,
      line_items: [{ price: priceId, quantity: 1 }],
      metadata: {
        scanId: scan.id,
        tier: scan.tier,
        target: scan.target,
        email: scan.email,
        kind: "unlock",
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
      } else if (error.message.includes("No such price") || error.message.includes("No such product")) {
        message = "Invalid Stripe product. Check the product ID in .env.local.";
      }
    }
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
