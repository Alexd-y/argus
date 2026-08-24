import { NextRequest, NextResponse } from "next/server";
import { getScan, toScanResponse } from "@/lib/scans";
import {
  isBackendProxyEnabled,
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
      return NextResponse.json(status);
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
