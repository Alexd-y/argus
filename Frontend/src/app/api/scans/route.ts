import { NextRequest, NextResponse } from "next/server";
import { createScan, toScanResponse } from "@/lib/scans";
import type { ScanTier } from "@/lib/scan-tiers";
import { isValidEmail } from "@/lib/validation";
import { emailMatchesTarget } from "@/lib/domain-verification";
import { isVerificationValid } from "@/lib/verification-store";

const VALID_TIERS: ScanTier[] = ["free", "standard", "premium"];

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { target, email, tier, parentScanId, darkWebMonitoring, verificationId } = body;

    if (!target || typeof target !== "string") {
      return NextResponse.json({ error: "Target is required" }, { status: 400 });
    }

    if (!email || !isValidEmail(email)) {
      return NextResponse.json({ error: "Valid email is required" }, { status: 400 });
    }

    if (!tier || !VALID_TIERS.includes(tier)) {
      return NextResponse.json({ error: "Invalid tier" }, { status: 400 });
    }

    const trimmedEmail = email.trim();
    const trimmedTarget = target.trim();

    if (!emailMatchesTarget(trimmedEmail, trimmedTarget)) {
      if (!verificationId || !isVerificationValid(verificationId, trimmedTarget, trimmedEmail)) {
        return NextResponse.json(
          { error: "Domain ownership verification required", code: "VERIFICATION_REQUIRED" },
          { status: 403 }
        );
      }
    }

    const scan = createScan({
      target: trimmedTarget,
      email: trimmedEmail,
      tier,
      parentScanId: parentScanId || undefined,
      darkWebMonitoring: Boolean(darkWebMonitoring),
    });

    return NextResponse.json({
      id: scan.id,
      url: `/scan/${scan.id}`,
      scan: toScanResponse(scan),
    });
  } catch {
    return NextResponse.json({ error: "Failed to create scan" }, { status: 500 });
  }
}
