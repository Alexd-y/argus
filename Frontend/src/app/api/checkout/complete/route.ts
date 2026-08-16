import { NextRequest, NextResponse } from "next/server";
import { getScan, markScanPaid, isScanUnlocked } from "@/lib/scans";
import { getStripe, getBaseUrl } from "@/lib/stripe";

export async function GET(req: NextRequest) {
  const sessionId = req.nextUrl.searchParams.get("session_id");
  const baseUrl = getBaseUrl();

  if (!sessionId) {
    return NextResponse.redirect(`${baseUrl}/?error=missing_session`);
  }

  try {
    const session = await getStripe().checkout.sessions.retrieve(sessionId);
    const { scanId } = session.metadata || {};

    if (!scanId) {
      return NextResponse.redirect(`${baseUrl}/?error=invalid_session`);
    }

    const scan = getScan(scanId);
    if (!scan) {
      return NextResponse.redirect(`${baseUrl}/?error=scan_not_found`);
    }

    if (session.payment_status === "paid" || session.status === "complete") {
      markScanPaid(scanId);
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
