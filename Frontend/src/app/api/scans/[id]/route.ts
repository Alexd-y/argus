import { NextRequest, NextResponse } from "next/server";
import { getScan, toScanResponse } from "@/lib/scans";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const scan = getScan(id);

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  return NextResponse.json(toScanResponse(scan));
}
