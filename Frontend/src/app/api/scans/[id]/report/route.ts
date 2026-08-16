import { NextRequest, NextResponse } from "next/server";
import { getScan, isScanUnlocked } from "@/lib/scans";
import { getTierConfig } from "@/lib/scan-tiers";
import { buildReportText } from "@/lib/report";

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
  const body = buildReportText(scan);
  const safeTarget = scan.target.replace(/[^a-zA-Z0-9.-]/g, "_");
  const filename = `ragnarok-${safeTarget}-${tier.name.toLowerCase()}.txt`;

  return new NextResponse(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}
