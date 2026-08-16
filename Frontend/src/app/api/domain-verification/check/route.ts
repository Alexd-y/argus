import { NextRequest, NextResponse } from "next/server";
import { promises as dns } from "dns";
import { getVerification, markVerificationVerified } from "@/lib/verification-store";

export async function POST(req: NextRequest) {
  try {
    const { verificationId } = await req.json();

    if (!verificationId || typeof verificationId !== "string") {
      return NextResponse.json({ error: "Verification ID is required" }, { status: 400 });
    }

    const record = getVerification(verificationId);
    if (!record) {
      return NextResponse.json({ error: "Verification not found" }, { status: 404 });
    }

    if (record.verified) {
      return NextResponse.json({ verified: true, verificationId: record.id });
    }

    try {
      const txtRecords = await dns.resolveTxt(record.recordHost);
      const flat = txtRecords.map((parts) => parts.join("")).map((v) => v.trim());
      const found = flat.some((value) => value === record.token);

      if (!found) {
        return NextResponse.json(
          {
            verified: false,
            error:
              "TXT record not found yet. DNS changes can take a few minutes to propagate.",
          },
          { status: 400 }
        );
      }

      markVerificationVerified(verificationId);
      return NextResponse.json({ verified: true, verificationId });
    } catch {
      return NextResponse.json(
        {
          verified: false,
          error:
            "Could not resolve TXT record. Confirm the record is published and try again in a few minutes.",
        },
        { status: 400 }
      );
    }
  } catch {
    return NextResponse.json({ error: "Verification check failed" }, { status: 500 });
  }
}
