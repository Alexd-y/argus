"use client";

import Link from "next/link";
import type { ScanData } from "@/lib/scan-types";
import { getTierConfig } from "@/lib/scan-tiers";
import { SCAN_STAGES } from "@/lib/scan-tiers";

interface ScanRunningProps {
  scan: ScanData;
  scanUrl: string;
}

function formatElapsed(createdAt: string): string {
  const ms = Date.now() - new Date(createdAt).getTime();
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
}

export function ScanRunning({ scan, scanUrl }: ScanRunningProps) {
  const tier = getTierConfig(scan.tier);

  return (
    <div className="space-y-4">
      <div className="text-center mb-6">
        <div className="inline-flex items-center gap-2 text-amber-400 mb-2">
          <div className="h-3 w-3 rounded-full bg-amber-400 pulse-glow glow-amber" />
          <span className="font-medium">Scan in Progress</span>
        </div>
        <p className="text-xs text-neutral-500 mb-1">
          Target: <span className="text-neutral-300">{scan.target}</span>
        </p>
        <p className="text-xs text-neutral-500 mb-1">
          Tier: <span className="text-neutral-300">{tier.name}</span>
        </p>
        <p className="text-xs text-neutral-500">
          Report will be sent to: <span className="text-neutral-300">{scan.email}</span>
        </p>
        {scan.darkWebMonitoring && (
          <p className="text-xs text-[#E3CAFE] mt-1">Dark Web Monitoring enabled</p>
        )}
      </div>

      <div className="border border-blue-500/30 bg-blue-500/5 rounded p-3 text-left">
        <div className="flex items-start gap-2">
          <svg className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="flex-1 text-xs space-y-1.5">
            <p className="text-blue-300">You can safely close this page.</p>
            <p className="text-neutral-400">
              We&apos;ll email you at <span className="text-white">{scan.email}</span> when the scan completes.
            </p>
            <p className="text-neutral-400">
              Return anytime at:{" "}
              <a href={scanUrl} className="text-[#A655F7] hover:text-[#b875f8] underline break-all">
                {scanUrl}
              </a>
            </p>
          </div>
        </div>
      </div>

      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-neutral-400">Progress</span>
          <span className="text-xs text-neutral-400">{Math.round(scan.progress)}%</span>
        </div>
        <div className="h-2 bg-neutral-950 rounded-full overflow-hidden border border-neutral-700">
          <div
            className="h-full bg-gradient-to-r from-[#A655F7] to-[#E3CAFE] transition-all duration-300"
            style={{ width: `${scan.progress}%` }}
          />
        </div>
        <p className="text-[11px] text-neutral-600 mt-2 text-right">
          Elapsed: {formatElapsed(scan.createdAt)}
        </p>
      </div>

      <div className="space-y-2">
        {SCAN_STAGES.map((stageName, index) => {
          const isComplete = index < scan.stageIndex;
          const isCurrent = index === scan.stageIndex;
          return (
            <div
              key={stageName}
              className={`flex items-center gap-3 px-3 py-2 rounded ${
                isComplete
                  ? "bg-emerald-500/10 border border-emerald-500/30"
                  : isCurrent
                  ? "bg-amber-500/10 border border-amber-500/30"
                  : "bg-neutral-950 border border-neutral-700"
              }`}
            >
              {isComplete ? (
                <svg className="w-4 h-4 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              ) : isCurrent ? (
                <div className="w-4 h-4 border-2 border-amber-400 border-t-transparent rounded-full animate-spin flex-shrink-0" />
              ) : (
                <div className="w-4 h-4 border-2 border-neutral-600 rounded-full flex-shrink-0" />
              )}
              <span
                className={`text-xs ${
                  isComplete ? "text-emerald-400" : isCurrent ? "text-amber-400" : "text-neutral-500"
                }`}
              >
                {stageName}
              </span>
            </div>
          );
        })}
      </div>

      <Link
        href="/"
        className="block w-full text-center cursor-pointer bg-[#A655F7] px-4 py-2.5 text-white font-medium hover:bg-[#b875f8] rounded-sm glitch-hover text-sm"
      >
        Start another scan
      </Link>
      <p className="text-[11px] text-neutral-600 text-center">
        This scan keeps running in the background. We&apos;ll still email you when it finishes.
      </p>
    </div>
  );
}
