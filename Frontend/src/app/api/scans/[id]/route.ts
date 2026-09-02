import { NextRequest, NextResponse } from "next/server";
import { getScan, toScanResponse } from "@/lib/scans";
import {
  isBackendProxyEnabled,
  mapBackendFindingsToResults,
  mapBackendScanToScanData,
  proxyGetReportByTarget,
  proxyGetScanFindings,
  proxyGetScanStatus,
  type BackendProxyError,
} from "@/lib/backendClient";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  // Opt-in real backend status passthrough (ARGUS_USE_BACKEND).
  if (isBackendProxyEnabled()) {
    try {
      const tenantId = req.headers.get("x-tenant-id") ?? undefined;
      const status = await proxyGetScanStatus(id, { tenantId });
      // Adapt the backend ScanDetailResponse to the frontend ScanData shape the
      // scan page renders (status enum, tier, stageIndex, …). Without this the
      // page receives an unmatched status and renders a blank body.
      const scanData = mapBackendScanToScanData(status);

      // On completion, fetch the real findings + report summary and populate
      // `results` — otherwise ScanSuccess renders `null` (the blank/black screen
      // at the end of a scan). Both fetches are best-effort (never throw).
      if (scanData.status === "complete") {
        const [findings, report] = await Promise.all([
          proxyGetScanFindings(id, { tenantId }),
          proxyGetReportByTarget(scanData.target, { tenantId }),
        ]);
        scanData.results = mapBackendFindingsToResults(findings, scanData.tier, report);
      }

      return NextResponse.json(scanData);
    } catch (e) {
      const err = e as BackendProxyError;
      return NextResponse.json(
        { error: err.error, code: err.code },
        { status: err.status || 502 }
      );
    }
  }

  const scan = getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  return NextResponse.json(toScanResponse(scan));
}
