import { NextRequest, NextResponse } from "next/server";
import { getScan, toScanResponse } from "@/lib/scans";
import {
  isBackendProxyEnabled,
  mapBackendScanToScanData,
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
      const status = await proxyGetScanStatus(id, {
        tenantId: req.headers.get("x-tenant-id") ?? undefined,
      });
      // Adapt the backend ScanDetailResponse to the frontend ScanData shape the
      // scan page renders (status enum, tier, stageIndex, …). Without this the
      // page receives an unmatched status and renders a blank body.
      return NextResponse.json(mapBackendScanToScanData(status));
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
