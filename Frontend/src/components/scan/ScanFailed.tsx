"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { ScanData } from "@/lib/scan-types";
import { getTierConfig, isPaidTier } from "@/lib/scan-tiers";

interface ScanFailedProps {
  scan: ScanData;
}

/**
 * A time-budget timeout is NOT a hard error — the scan simply ran past the
 * (time-boxed) tier's budget before finishing. It is recoverable (retry or run a
 * deeper, unbounded tier), so it is presented as an amber "timed out" state with
 * clear next steps instead of a red dead-end. Any other failure keeps the red
 * "Scan Failed" treatment.
 */
function isTimeoutError(message: string | null): boolean {
  return /time budget|timed?\s*out|exceeded its time/i.test(message || "");
}

export function ScanFailed({ scan }: ScanFailedProps) {
  const router = useRouter();
  const [retrying, setRetrying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tier = getTierConfig(scan.tier);
  const timedOut = isTimeoutError(scan.error);
  // A deeper, unbounded tier is only an upsell when the current one is time-boxed
  // (the free/Overview tier). Paid tiers run without a deadline, so a timeout
  // there is an operational issue, not something a bigger tier would fix.
  const offerDeeperTier = timedOut && !isPaidTier(scan.tier);

  const handleRetry = async () => {
    setRetrying(true);
    setError(null);
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
          retest: scan.paid && scan.tier !== "free",
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Could not retry scan");
        return;
      }
      if (data.url) {
        router.push(data.url);
      }
    } catch {
      setError("Could not retry scan. Try again.");
    } finally {
      setRetrying(false);
    }
  };

  const accent = timedOut
    ? { ring: "bg-amber-500/10 border-amber-500/30", icon: "text-amber-400", box: "border-amber-500/30 bg-amber-500/5", text: "text-amber-200" }
    : { ring: "bg-red-500/10 border-red-500/30", icon: "text-red-400", box: "border-red-500/30 bg-red-500/5", text: "text-red-300" };

  const heading = timedOut ? "Scan Timed Out" : "Scan Failed";
  const defaultMessage = timedOut
    ? "This scan ran past its time budget before finishing."
    : "An unexpected error occurred during the scan.";
  const helper = timedOut
    ? offerDeeperTier
      ? "The Overview tier is time-boxed, so a complex target can run past it. Retry, or run a deeper tier for an unbounded scan."
      : "Retry the scan — this tier runs without a fixed deadline, so a timeout usually clears on a second run."
    : null;

  return (
    <div className="space-y-6 text-center py-4">
      <div className={`inline-flex items-center justify-center w-16 h-16 rounded-full border ${accent.ring}`}>
        {timedOut ? (
          <svg className={`w-8 h-8 ${accent.icon}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        ) : (
          <svg className={`w-8 h-8 ${accent.icon}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        )}
      </div>

      <div>
        <h2 className="text-xl text-white font-medium mb-2">{heading}</h2>
        <p className="text-neutral-500 text-xs mb-1">
          Target: <span className="text-neutral-300">{scan.target}</span>
        </p>
        <p className="text-neutral-500 text-xs mb-4">
          Tier: <span className="text-neutral-300">{tier.name}</span>
        </p>
        <div className={`border rounded p-4 text-left max-w-md mx-auto ${accent.box}`}>
          <p className={`text-sm ${accent.text}`}>{scan.error || defaultMessage}</p>
          {helper && <p className="text-xs text-neutral-400 mt-2">{helper}</p>}
        </div>
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 justify-center max-w-md mx-auto">
        <button
          onClick={handleRetry}
          disabled={retrying}
          className="flex-1 cursor-pointer bg-[#A655F7] px-4 py-2.5 text-white font-medium hover:bg-[#b875f8] disabled:opacity-60 rounded-sm glitch-hover"
        >
          {retrying ? "Starting..." : "Retry Scan"}
        </button>
        {offerDeeperTier ? (
          <Link
            href="/pricing"
            className="flex-1 cursor-pointer px-4 py-2.5 text-white border border-[#A655F7]/50 hover:border-[#A655F7] hover:bg-[#A655F7]/10 rounded-sm text-center"
          >
            Run a deeper tier
          </Link>
        ) : (
          <Link
            href="/"
            className="flex-1 cursor-pointer px-4 py-2.5 text-neutral-400 border border-neutral-700 hover:border-[#A655F7]/50 hover:text-white rounded-sm text-center"
          >
            Back to Home
          </Link>
        )}
      </div>

      {offerDeeperTier && (
        <Link href="/" className="inline-block text-xs text-neutral-500 hover:text-neutral-300 underline">
          Back to Home
        </Link>
      )}

      <p className="text-xs text-neutral-600">
        Need help?{" "}
        <a href="https://svalbard.ca/support" className="text-[#A655F7] hover:text-[#b875f8] underline">
          Contact support
        </a>
      </p>
    </div>
  );
}
