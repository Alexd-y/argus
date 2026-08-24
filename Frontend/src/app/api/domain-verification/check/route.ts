import { NextRequest, NextResponse } from "next/server";
import {
  createVerification,
  getVerification,
  markVerificationVerified,
} from "@/lib/verification-store";
import { isIpAddress, isVerificationToken } from "@/lib/domain-verification";
import { verifyOwnershipToken } from "@/lib/verify-ownership";
import { isValidEmail } from "@/lib/validation";

export const runtime = "nodejs";

export async function POST(req: NextRequest) {
  try {
    const { verificationId, target, email, token } = await req.json();

    if (!verificationId || typeof verificationId !== "string") {
      return NextResponse.json({ error: "Verification ID is required" }, { status: 400 });
    }

    let record = getVerification(verificationId);

    if (
      !record &&
      typeof target === "string" &&
      typeof email === "string" &&
      isValidEmail(email) &&
      isVerificationToken(String(token ?? ""))
    ) {
      record = createVerification(target, email, { id: verificationId, token });
    }

    if (!record) {
      return NextResponse.json({ error: "Verification not found" }, { status: 404 });
    }

    if (isIpAddress(record.target)) {
      return NextResponse.json(
        { verified: false, error: "Ownership verification is only available for domain names." },
        { status: 400 }
      );
    }

    try {
      const result = await verifyOwnershipToken(record.target, record.token);

      if (!result.verified) {
        return NextResponse.json(
          {
            verified: false,
            checkedNames: result.checkedNames,
            fileUrl: result.fileUrl,
            error: result.error,
          },
          { status: 400 }
        );
      }

      markVerificationVerified(record.id);
      return NextResponse.json({
        verified: true,
        verificationId: record.id,
        method: result.method,
        checkedNames: result.checkedNames,
        fileUrl: result.fileUrl,
      });
    } catch {
      return NextResponse.json(
        {
          verified: false,
          error:
            "Could not verify ownership. Confirm the DNS record or file is published and try again in a few minutes.",
        },
        { status: 400 }
      );
    }
  } catch {
    return NextResponse.json({ error: "Verification check failed" }, { status: 500 });
  }
}
