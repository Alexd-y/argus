import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";
import { addBonusCredits, attachSubscriptionId, resetPeriodBySubscriptionId } from "@/lib/scan-quota";
import { getStripe } from "@/lib/stripe";
import { getScan, markScanPaid } from "@/lib/scans";

export const runtime = "nodejs";

function subscriptionIdFrom(session: Stripe.Checkout.Session): string | null {
  if (!session.subscription) return null;
  return typeof session.subscription === "string" ? session.subscription : session.subscription.id;
}

export async function POST(req: NextRequest) {
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) {
    console.error("STRIPE_WEBHOOK_SECRET is not configured");
    return NextResponse.json({ error: "Webhook not configured" }, { status: 500 });
  }

  const body = await req.text();
  const signature = req.headers.get("stripe-signature");

  if (!signature) {
    return NextResponse.json({ error: "Missing signature" }, { status: 400 });
  }

  let event: Stripe.Event;
  try {
    event = getStripe().webhooks.constructEvent(body, signature, webhookSecret);
  } catch (err) {
    console.error("Webhook signature verification failed:", err);
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;
    const scanId = session.metadata?.scanId;
    const kind = session.metadata?.kind;
    const paid = session.payment_status === "paid";

    if (scanId && paid) {
      const scan = getScan(scanId);
      if (kind === "extra_scan") {
        if (scan) {
          addBonusCredits(scan, 1, session.id);
        }
      } else {
        const subscriptionId = subscriptionIdFrom(session);
        markScanPaid(scanId, subscriptionId);
        if (scan && subscriptionId) {
          attachSubscriptionId(scan.email, scan.target, subscriptionId);
        }
      }
    }
  }

  if (event.type === "invoice.paid") {
    const invoice = event.data.object as Stripe.Invoice;
    const billingReason = invoice.billing_reason;
    const subscription = invoice.parent?.subscription_details?.subscription;
    const subscriptionId =
      typeof subscription === "string"
        ? subscription
        : subscription && typeof subscription === "object"
          ? subscription.id
          : null;

    if (billingReason === "subscription_cycle" && subscriptionId) {
      resetPeriodBySubscriptionId(subscriptionId);
    }
  }

  return NextResponse.json({ received: true });
}
