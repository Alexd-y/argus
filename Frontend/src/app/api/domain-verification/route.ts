import { NextRequest, NextResponse } from "next/server";
import {
  createVerification,
  getVerification,
  markVerificationVerified,
} from "@/lib/verification-store";
import { verifyOwnershipToken } from "@/lib/verify-ownership";
import {
  emailMatchesTarget,
  isIpAddress,
  normalizeHostname,
  verificationFileUrl,
  VERIFICATION_RELATIVE_HOST,
} from "@/lib/domain-verification";
import { isValidEmail } from "@/lib/validation";

export const runtime = "nodejs";

export async function POST(req: NextRequest) {
  try {
    const { target, email, verificationId, token } = await req.json();

    if (!target || typeof target !== "string") {
      return NextResponse.json({ error: "Target is required" }, { status: 400 });
    }

    if (!email || !isValidEmail(email)) {
      return NextResponse.json({ error: "Valid email is required" }, { status: 400 });
    }

    if (emailMatchesTarget(email, target)) {
      return NextResponse.json({ required: false });
    }

    if (isIpAddress(target)) {
      return NextResponse.json(
        {
          error:
            "Ownership verification is only available for domain names. Use an email on the target domain, or scan by hostname.",
        },
        { status: 400 }
      );
    }

    const existing =
      typeof verificationId === "string" && typeof token === "string"
        ? { id: verificationId, token }
        : undefined;

    const verification = createVerification(target, email, existing);
    const published = await verifyOwnershipToken(target, verification.token);
    if (published.verified) {
      markVerificationVerified(verification.id);
      return NextResponse.json({
        required: false,
        alreadyVerified: true,
        verificationId: verification.id,
        method: published.method,
      });
    }

    return NextResponse.json({
      required: true,
      verificationId: verification.id,
      recordHost: verification.recordHost,
      recordValue: verification.token,
      target: verification.target,
      relativeHost: VERIFICATION_RELATIVE_HOST,
      fileUrl: verificationFileUrl(verification.target),
    });
  } catch {
    return NextResponse.json({ error: "Failed to create verification" }, { status: 500 });
  }
}

export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("id");
  if (!id) {
    return NextResponse.json({ error: "Verification ID is required" }, { status: 400 });
  }

  const record = getVerification(id);
  if (!record) {
    return NextResponse.json({ error: "Verification not found" }, { status: 404 });
  }

  return NextResponse.json({
    verificationId: record.id,
    recordHost: record.recordHost,
    recordValue: record.token,
    target: record.target,
    verified: record.verified,
    relativeHost: VERIFICATION_RELATIVE_HOST,
    hostname: normalizeHostname(record.target),
    fileUrl: verificationFileUrl(record.target),
  });
}
