import { NextRequest, NextResponse } from "next/server";
import { getScan, isScanUnlocked } from "@/lib/scans";
import { getTierConfig } from "@/lib/scan-tiers";
import { buildReportPdf } from "@/lib/report";
import { isBackendProxyEnabled, proxyDownloadScanReport } from "@/lib/backendClient";

export const runtime = "nodejs";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  // Real backend path: stream the server-rendered artifact from ARGUS. The
  // in-memory getScan() store below only holds mock demo scans, so for a real
  // backend scan it returns null and the request 404s with a JSON body — which
  // the browser saves as "report.json" ("file not available"). Proxy the actual
  // PDF instead (the backend handles auth, tier fallback and on-demand regen).
  if (isBackendProxyEnabled()) {
    const { searchParams } = new URL(req.url);
    const format = searchParams.get("format") || "pdf";
    const tier = searchParams.get("tier") || "midgard";
    const result = await proxyDownloadScanReport(id, { format, tier });
    if (result.ok) {
      return new NextResponse(Buffer.from(result.body), {
        headers: {
          "Content-Type": result.contentType,
          "Content-Disposition":
            result.contentDisposition ??
            `attachment; filename="argus-report-${id}.${format}"`,
        },
      });
    }
    return NextResponse.json(
      { error: result.error, code: result.code },
      { status: result.status }
    );
  }

  // Demo/offline fallback: build the PDF from the in-memory mock scan.
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
