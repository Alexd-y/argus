"use client";

import { useParams } from "next/navigation";

import { LabUnrestrictedBadge } from "@/components/lab/LabUnrestrictedBadge";
import { LabWorkspace } from "@/components/lab/LabWorkspace";

export default function ScanExecutionPage() {
  const params = useParams<{ scanId: string }>();
  const scanId = typeof params.scanId === "string" ? params.scanId : "";

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100">
      <header className="flex items-center justify-between border-b border-neutral-800 px-4 py-3">
        <h1 className="text-sm font-semibold text-white">Scan {scanId}</h1>
        <LabUnrestrictedBadge />
      </header>
      <LabWorkspace title="Scan execution" initialScanId={scanId} />
    </div>
  );
}
