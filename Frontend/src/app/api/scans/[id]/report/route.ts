import { NextRequest, NextResponse } from "next/server";
import { getScan, isScanUnlocked } from "@/lib/scans";
import { getTierConfig } from "@/lib/scan-tiers";
import { buildReportPdf } from "@/lib/report";

export const runtime = "nodejs";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const scan = getScan(id);

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  if (scan.status !== "complete") {
    return NextResponse.json({ error: "Report not ready" }, { status: 400 });
  }

  if (!isScanUnlocked(scan)) {
    return NextResponse.json(
      { error: "Subscribe to unlock and download the full report" },
      { status: 403 }
    );
  }

  const tier = getTierConfig(scan.tier);
  const body = buildReportPdf(scan);
  const safeTarget = scan.target.replace(/[^a-zA-Z0-9.-]/g, "_");
  const filename = `ragnarok-${safeTarget}-${tier.slug}.pdf`;

  return new NextResponse(Buffer.from(body), {
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}
