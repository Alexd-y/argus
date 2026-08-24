import { NextRequest, NextResponse } from "next/server";
import { createScan, getScan, toScanResponse } from "@/lib/scans";
import type { ScanTier } from "@/lib/scan-tiers";
import { includesDarkWebMonitoring, isPaidTier } from "@/lib/scan-tiers";
import {
  isBackendProxyEnabled,
  proxyCreateScan,
  type BackendProxyError,
} from "@/lib/backendClient";
import { isValidEmail } from "@/lib/validation";
import { emailMatchesTarget, normalizeHostname } from "@/lib/domain-verification";
import { expectedVerificationToken, isVerificationValid } from "@/lib/verification-store";
import { verifyOwnershipToken } from "@/lib/verify-ownership";
import { consumeCredit, getScanQuota } from "@/lib/scan-quota";

export const runtime = "nodejs";

const VALID_TIERS: ScanTier[] = ["free", "standard", "premium"];

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { target, email, tier, parentScanId, verificationId, darkWebMonitoring, retest } = body;

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
    const trimmedTarget = normalizeHostname(target.trim());

    if (!trimmedTarget) {
      return NextResponse.json({ error: "Target is required" }, { status: 400 });
    }

    // Opt-in real backend path (ARGUS_USE_BACKEND). Forwards to backend
    // POST /api/v1/scans with the canonical scan_profile; no mock scanner.
    // Retest/quota/stripe remain demo-only features handled below.
    if (!retest && isBackendProxyEnabled()) {
      try {
        const created = await proxyCreateScan({
          target: trimmedTarget,
          email: trimmedEmail,
          tier,
          engagementId: typeof body.engagement_id === "string" ? body.engagement_id : undefined,
          labLeaseId: typeof body.lab_lease_id === "string" ? body.lab_lease_id : undefined,
          correlationId: req.headers.get("x-correlation-id") ?? undefined,
        });
        return NextResponse.json({
          id: created.scan_id,
          url: `/scan/${created.scan_id}`,
          scan: { id: created.scan_id, status: created.status, target: trimmedTarget, tier },
        });
      } catch (e) {
        const err = e as BackendProxyError;
        return NextResponse.json(
          { error: err.error, code: err.code, details: err.details },
          { status: err.status || 502 }
        );
      }
    }

    const parent =
      typeof parentScanId === "string" && parentScanId ? getScan(parentScanId) : null;

    if (retest) {
      if (!parent) {
        return NextResponse.json({ error: "Original scan not found" }, { status: 404 });
      }
      if (
        parent.target !== trimmedTarget ||
        parent.email.trim().toLowerCase() !== trimmedEmail.toLowerCase()
      ) {
        return NextResponse.json({ error: "Retest must use the same target and email" }, { status: 400 });
      }
      if (!parent.paid || !isPaidTier(parent.tier)) {
        return NextResponse.json({ error: "Subscribe to retest this target" }, { status: 403 });
      }

      const quota = getScanQuota(parent);
      if (!quota?.canRetest) {
        return NextResponse.json(
          {
            error: "No scans remaining this month",
            code: "QUOTA_EXCEEDED",
            quota,
          },
          { status: 402 }
        );
      }

      const consumed = consumeCredit(parent);
      if (!consumed.ok) {
        return NextResponse.json(
          {
            error: "No scans remaining this month",
            code: "QUOTA_EXCEEDED",
            quota: getScanQuota(parent),
          },
          { status: 402 }
        );
      }

      const scan = createScan({
        target: trimmedTarget,
        email: trimmedEmail,
        tier: parent.tier,
        parentScanId: parent.id,
        darkWebMonitoring: parent.darkWebMonitoring,
        paid: true,
        quotaCharged: true,
        quotaSource: consumed.source,
      });

      return NextResponse.json({
        id: scan.id,
        url: `/scan/${scan.id}`,
        scan: toScanResponse(scan),
      });
    }

    if (!emailMatchesTarget(trimmedEmail, trimmedTarget)) {
      const sessionOk =
        typeof verificationId === "string" &&
        isVerificationValid(verificationId, trimmedTarget, trimmedEmail);
      const published = sessionOk
        ? { verified: true }
        : await verifyOwnershipToken(
            trimmedTarget,
            expectedVerificationToken(trimmedTarget, trimmedEmail)
          );

      if (!sessionOk && !published.verified) {
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
      parentScanId: parent?.id,
      darkWebMonitoring: includesDarkWebMonitoring(tier, darkWebMonitoring),
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
