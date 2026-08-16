import { NextRequest, NextResponse } from "next/server";
import { createVerification } from "@/lib/verification-store";
import { emailMatchesTarget } from "@/lib/domain-verification";
import { isValidEmail } from "@/lib/validation";

export async function POST(req: NextRequest) {
  try {
    const { target, email } = await req.json();

    if (!target || typeof target !== "string") {
      return NextResponse.json({ error: "Target is required" }, { status: 400 });
    }

    if (!email || !isValidEmail(email)) {
      return NextResponse.json({ error: "Valid email is required" }, { status: 400 });
    }

    if (emailMatchesTarget(email, target)) {
      return NextResponse.json({ required: false });
    }

    const verification = createVerification(target, email);

    return NextResponse.json({
      required: true,
      verificationId: verification.id,
      recordHost: verification.recordHost,
      recordValue: verification.token,
      target: verification.target,
    });
  } catch {
    return NextResponse.json({ error: "Failed to create verification" }, { status: 500 });
  }
}
