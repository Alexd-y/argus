import { NextRequest, NextResponse } from "next/server";
import { addBonusCredits, attachSubscriptionId } from "@/lib/scan-quota";
import { getScan, markScanPaid, isScanUnlocked } from "@/lib/scans";
import { getStripe, getBaseUrl } from "@/lib/stripe";

function subscriptionIdFrom(session: { subscription?: string | { id: string } | null }): string | null {
  if (!session.subscription) return null;
  return typeof session.subscription === "string" ? session.subscription : session.subscription.id;
}

export async function GET(req: NextRequest) {
  const sessionId = req.nextUrl.searchParams.get("session_id");
  const baseUrl = getBaseUrl();

  if (!sessionId) {
    return NextResponse.redirect(`${baseUrl}/?error=missing_session`);
  }

  try {
    const session = await getStripe().checkout.sessions.retrieve(sessionId);
    const scanId = session.metadata?.scanId;
    const kind = session.metadata?.kind;

    if (!scanId) {
      return NextResponse.redirect(`${baseUrl}/?error=invalid_session`);
    }

    const scan = getScan(scanId);
    if (!scan) {
      return NextResponse.redirect(`${baseUrl}/?error=scan_not_found`);
    }

    const paid = session.payment_status === "paid";

    if (kind === "extra_scan") {
      if (paid) {
        addBonusCredits(scan, 1, sessionId);
      }
      return NextResponse.redirect(`${baseUrl}/scan/${scanId}${paid ? "?credits=1" : ""}`);
    }

    if (paid) {
      const subscriptionId = subscriptionIdFrom(session);
      markScanPaid(scanId, subscriptionId);
      if (subscriptionId) {
        attachSubscriptionId(scan.email, scan.target, subscriptionId);
      }
    }

    const updated = getScan(scanId);
    const unlocked = updated ? isScanUnlocked(updated) && updated.tier !== "free" : false;
    const query = unlocked ? "?unlocked=true" : "";

    return NextResponse.redirect(`${baseUrl}/scan/${scanId}${query}`);
  } catch (error) {
    console.error("Checkout complete error:", error);
    return NextResponse.redirect(`${baseUrl}/?error=checkout_failed`);
  }
}
