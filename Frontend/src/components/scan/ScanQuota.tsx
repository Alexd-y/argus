"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { ScanData } from "@/lib/scan-types";
import { quotaSlots, type ScanQuota } from "@/lib/scan-quota";
import { getExtraScanCtaLabel } from "@/lib/scan-tiers";
import { formatReportDayAndMonth } from "@/lib/report-date";

interface ScanQuotaSectionProps {
  scan: ScanData;
  sample?: boolean;
}

function QuotaPips({ quota }: { quota: ScanQuota }) {
  return (
    <div className="flex gap-1">
      {quotaSlots(quota).map((slot) => {
        const tone = slot.used
          ? "bg-neutral-800 border-neutral-700"
          : slot.extra
            ? "border-[#A655F7]/50 bg-[#A655F7]/20"
            : "border-emerald-500/50 bg-emerald-500/20";
        return (
          <span
            key={slot.index}
            className={`h-1.5 w-full max-w-6 border rounded-sm ${tone}`}
            title={`Scan ${slot.index + 1}: ${slot.used ? "used" : slot.extra ? "extra" : "ready"}`}
          />
        );
      })}
    </div>
  );
}

export function ScanQuotaTile({ scan, sample = false }: ScanQuotaSectionProps) {
  const router = useRouter();
  const quota = scan.quota;
  const [retesting, setRetesting] = useState(false);
  const [buying, setBuying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [quotaExceeded, setQuotaExceeded] = useState(false);

  if (!quota) return null;

  const remaining = quotaExceeded ? 0 : quota.remaining;
  const used = quotaExceeded ? quota.capacity : quota.used;
  const extraAtCap = quota.extra >= quota.extraCap;
  const displayQuota: ScanQuota = {
    ...quota,
    remaining,
    used,
    canRetest: remaining > 0,
    canBuyExtra: remaining === 0 && !extraAtCap,
  };
  const canRetest = !sample && remaining > 0;
  const canBuyExtra = !sample && displayQuota.canBuyExtra;
  const atExtraCap = !sample && remaining === 0 && extraAtCap;

  const handleRetest = async () => {
    setRetesting(true);
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
          retest: true,
        }),
      });
      const data = await res.json();
      if (data.code === "QUOTA_EXCEEDED") {
        setQuotaExceeded(true);
        setError(
          extraAtCap
            ? `No scans remaining. Extra scan limit reached (${quota.extraCap} additional this period).`
            : "No scans remaining this period. Buy an extra scan to retest."
        );
        return;
      }
      if (!res.ok) {
        setError(data.error || "Could not start retest");
        return;
      }
      if (typeof data.url === "string") router.push(data.url);
    } catch {
      setError("Could not start retest. Try again.");
    } finally {
      setRetesting(false);
    }
  };

  const handleBuyExtra = async () => {
    setBuying(true);
    setError(null);
    try {
      const res = await fetch("/api/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId: scan.id, kind: "extra_scan" }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Checkout failed");
        return;
      }
      if (data.url) router.push(data.url);
    } catch {
      setError("Could not reach payment service. Try again.");
    } finally {
      setBuying(false);
    }
  };

  return (
    <div className="bg-neutral-900 px-4 py-3.5">
      <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-2">Scans this period</div>

      <div className="flex items-baseline justify-between gap-3">
        <p className="text-xs text-neutral-300 tabular-nums">
          <span className="text-white">{remaining}</span> of {displayQuota.capacity} remaining
        </p>
        {canRetest ? (
          <button
            type="button"
            onClick={handleRetest}
            disabled={retesting}
            className="flex-shrink-0 cursor-pointer bg-[#A655F7] px-2.5 py-1 text-white text-[11px] font-medium hover:bg-[#b875f8] rounded-sm disabled:opacity-60"
          >
            {retesting ? "Starting..." : "Retest"}
          </button>
        ) : canBuyExtra ? (
          <button
            type="button"
            onClick={handleBuyExtra}
            disabled={buying}
            className="flex-shrink-0 cursor-pointer bg-[#A655F7] px-2.5 py-1 text-white text-[11px] font-medium hover:bg-[#b875f8] rounded-sm disabled:opacity-60"
          >
            {buying ? "Redirecting..." : getExtraScanCtaLabel(scan.tier, quota.extra)}
          </button>
        ) : null}
      </div>

      <div className="mt-2.5">
        <QuotaPips quota={displayQuota} />
      </div>

      <p className="text-[10px] text-neutral-500 mt-2.5">
        {atExtraCap
          ? `Additional limit reached (${quota.extraCap} of ${quota.extraCap})`
          : quota.extra > 0
            ? `${quota.extra} of ${quota.extraCap} additional bought`
            : `Up to ${quota.extraCap} additional`}
        {` · resets ${formatReportDayAndMonth(quota.periodEnd)}`}
      </p>
      {error ? <p className="text-[11px] text-red-400 mt-2">{error}</p> : null}
    </div>
  );
}
