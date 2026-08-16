"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { ScanData } from "@/lib/scan-types";
import { getTierConfig } from "@/lib/scan-tiers";

interface ScanFailedProps {
  scan: ScanData;
}

export function ScanFailed({ scan }: ScanFailedProps) {
  const router = useRouter();
  const [retrying, setRetrying] = useState(false);
  const tier = getTierConfig(scan.tier);

  const handleRetry = async () => {
    setRetrying(true);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: scan.target,
          email: scan.email,
          tier: scan.tier,
          parentScanId: scan.id,
          darkWebMonitoring: scan.darkWebMonitoring,
        }),
      });
      const data = await res.json();
      if (data.url) {
        router.push(data.url);
      }
    } finally {
      setRetrying(false);
    }
  };

  return (
    <div className="space-y-6 text-center py-4">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-500/10 border border-red-500/30">
        <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      </div>

      <div>
        <h2 className="text-xl text-white font-medium mb-2">Scan Failed</h2>
        <p className="text-neutral-500 text-xs mb-1">
          Target: <span className="text-neutral-300">{scan.target}</span>
        </p>
        <p className="text-neutral-500 text-xs mb-4">
          Tier: <span className="text-neutral-300">{tier.name}</span>
        </p>
        <div className="border border-red-500/30 bg-red-500/5 rounded p-4 text-left max-w-md mx-auto">
          <p className="text-sm text-red-300">
            {scan.error || "An unexpected error occurred during the scan."}
          </p>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 justify-center max-w-md mx-auto">
        <button
          onClick={handleRetry}
          disabled={retrying}
          className="flex-1 cursor-pointer bg-[#A655F7] px-4 py-2.5 text-white font-medium hover:bg-[#b875f8] disabled:opacity-60 rounded-sm glitch-hover"
        >
          {retrying ? "Starting..." : "Retry Scan"}
        </button>
        <a
          href="/"
          className="flex-1 cursor-pointer px-4 py-2.5 text-neutral-400 border border-neutral-700 hover:border-[#A655F7]/50 hover:text-white rounded-sm text-center"
        >
          Back to Home
        </a>
      </div>

      <p className="text-xs text-neutral-600">
        Need help?{" "}
        <a href="https://svalbard.ca/support" className="text-[#A655F7] hover:text-[#b875f8] underline">
          Contact support
        </a>
      </p>
    </div>
  );
}
