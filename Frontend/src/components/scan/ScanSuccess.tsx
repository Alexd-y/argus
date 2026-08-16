"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { ScanData } from "@/lib/scan-types";
import { getTierConfig, getUpgradeTiers } from "@/lib/scan-tiers";
import { isScanUnlocked } from "@/lib/scans";
import { PLACEHOLDER_FINDINGS } from "@/lib/scan-results";
import { ServicesSection } from "@/components/scan/ServicesSection";

interface ScanSuccessProps {
  scan: ScanData;
}

function AlertGrid({
  results,
  locked = false,
}: {
  results: NonNullable<ScanData["results"]>;
  locked?: boolean;
}) {
  return (
    <>
      <div className={`hidden sm:grid sm:grid-cols-5 gap-3 ${locked ? "opacity-70" : ""}`}>
        <div className="border border-red-500/30 bg-red-500/5 rounded p-4 text-center">
          <div className="text-2xl font-bold text-red-400">{results.critical}</div>
          <div className="text-xs text-red-400/70 uppercase tracking-wider mt-1">Critical</div>
        </div>
        <div className="border border-orange-500/30 bg-orange-500/5 rounded p-4 text-center">
          <div className="text-2xl font-bold text-orange-400">{results.high}</div>
          <div className="text-xs text-orange-400/70 uppercase tracking-wider mt-1">High</div>
        </div>
        <div className="border border-amber-500/30 bg-amber-500/5 rounded p-4 text-center">
          <div className="text-2xl font-bold text-amber-400">{results.medium}</div>
          <div className="text-xs text-amber-400/70 uppercase tracking-wider mt-1">Medium</div>
        </div>
        <div className="border border-blue-500/30 bg-blue-500/5 rounded p-4 text-center">
          <div className="text-2xl font-bold text-blue-400">{results.low}</div>
          <div className="text-xs text-blue-400/70 uppercase tracking-wider mt-1">Low</div>
        </div>
        <div className="border border-neutral-700 bg-neutral-900 rounded p-4 text-center">
          <div className="text-2xl font-bold text-neutral-400">{results.info}</div>
          <div className="text-xs text-neutral-500 uppercase tracking-wider mt-1">Info</div>
        </div>
      </div>
      <div className={`sm:hidden grid grid-cols-3 gap-2 ${locked ? "opacity-70" : ""}`}>
        <div className="border border-red-500/30 bg-red-500/5 rounded p-3 text-center">
          <div className="text-xl font-bold text-red-400">{results.critical}</div>
          <div className="text-[10px] text-red-400/70 uppercase tracking-wider mt-1">Critical</div>
        </div>
        <div className="border border-orange-500/30 bg-orange-500/5 rounded p-3 text-center">
          <div className="text-xl font-bold text-orange-400">{results.high}</div>
          <div className="text-[10px] text-orange-400/70 uppercase tracking-wider mt-1">High</div>
        </div>
        <div className="border border-amber-500/30 bg-amber-500/5 rounded p-3 text-center">
          <div className="text-xl font-bold text-amber-400">{results.medium}</div>
          <div className="text-[10px] text-amber-400/70 uppercase tracking-wider mt-1">Medium</div>
        </div>
      </div>
    </>
  );
}

export function ScanSuccess({ scan }: ScanSuccessProps) {
  const router = useRouter();
  const [loadingTier, setLoadingTier] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);
  const [checkoutError, setCheckoutError] = useState<string | null>(null);
  const tier = getTierConfig(scan.tier);
  const upgradeTiers = getUpgradeTiers(scan.tier);
  const results = scan.results;
  const needsUnlock = scan.tier !== "free" && !scan.paid;
  const isUnlocked = isScanUnlocked(scan);
  const findings = isUnlocked ? results! : PLACEHOLDER_FINDINGS;

  const handleUnlock = async () => {
    setUnlocking(true);
    setCheckoutError(null);
    try {
      const res = await fetch("/api/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId: scan.id }),
      });
      const data = await res.json();
      if (!res.ok) {
        setCheckoutError(data.error || "Checkout failed");
        return;
      }
      if (data.url) router.push(data.url);
    } catch {
      setCheckoutError("Could not reach payment service. Try again.");
    } finally {
      setUnlocking(false);
    }
  };

  const handleUpgradeScan = async (upgradeTier: "standard" | "premium") => {
    setLoadingTier(upgradeTier);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: scan.target,
          email: scan.email,
          tier: upgradeTier,
          parentScanId: scan.id,
          darkWebMonitoring: scan.darkWebMonitoring,
        }),
      });
      const data = await res.json();
      if (data.url) router.push(data.url);
    } finally {
      setLoadingTier(null);
    }
  };

  if (!results) return null;

  return (
    <div className="space-y-8 sm:space-y-10">
      <div className="border border-emerald-500/30 bg-emerald-500/5 rounded p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <div className="h-3 w-3 rounded-full bg-emerald-500 pulse-glow glow-emerald flex-shrink-0" />
              <span className="text-emerald-400 font-medium">Scan Complete</span>
            </div>
            <p className="text-white text-base sm:text-lg font-mono truncate">{scan.target}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2 sm:justify-end">
            <span className="text-xs text-neutral-300 border border-neutral-700 bg-neutral-900 px-2.5 py-1 rounded">
              {tier.name}
            </span>
            {scan.paid && scan.tier !== "free" && (
              <span className="text-xs text-emerald-400 border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 rounded">
                Unlocked
              </span>
            )}
            {isUnlocked && (
              <a
                href={`/api/scans/${scan.id}/report`}
                download
                className="text-xs text-white border border-[#A655F7]/50 bg-[#A655F7]/10 hover:bg-[#A655F7]/20 px-2.5 py-1 rounded transition-colors"
              >
                Download Report
              </a>
            )}
          </div>
        </div>
      </div>

      <section>
        <h2 className="text-lg text-white mb-4">Security Alerts Found</h2>
        <AlertGrid results={results} locked={needsUnlock} />
      </section>

      <section className={`relative ${needsUnlock ? "min-h-[280px]" : ""}`}>
        {needsUnlock && (
          <div className="absolute inset-0 z-10 flex items-center justify-center bg-neutral-950/90 rounded backdrop-blur-sm border border-[#A655F7]/30">
            <div className="text-center px-6 sm:px-10 py-6 max-w-md">
              <p className="text-base text-white font-medium mb-2">Full report locked</p>
              <p className="text-xs text-neutral-400 mb-4 leading-relaxed">
                Your {tier.name} scan of <span className="text-neutral-300">{scan.target}</span> is complete.
                Subscribe to unlock the full report — technologies, SSL/TLS analysis, breach details,
                remediation steps, and downloadable results.
              </p>
              <button
                onClick={handleUnlock}
                disabled={unlocking}
                className="cursor-pointer bg-[#A655F7] px-6 py-3 text-white text-sm font-medium hover:bg-[#b875f8] rounded-sm glitch-hover disabled:opacity-60 mb-3"
              >
                {unlocking ? "Redirecting..." : `Buy Report — ${tier.priceLabel}`}
              </button>
              <p className="text-[11px] text-neutral-600">Cancel anytime. Billed monthly.</p>
              {checkoutError && (
                <p className="text-xs text-red-400 mt-3">{checkoutError}</p>
              )}
            </div>
          </div>
        )}
        <h2 className="text-lg text-white mb-4">Findings Summary</h2>
        {!isUnlocked && (
          <p className="text-[11px] text-neutral-600 mb-3">
            Sample layout — your target-specific findings appear after purchase.
          </p>
        )}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4 mb-4">
          <div className="border border-neutral-800 bg-neutral-900 rounded p-3 sm:p-4">
            <div className="text-xs text-neutral-500 uppercase tracking-wider mb-2">Technologies</div>
            <div className="flex flex-wrap gap-2">
              {findings.technologies.map((tech, i) => (
                <span key={i} className="text-xs bg-neutral-800 text-neutral-300 px-2 py-1 rounded">
                  {tech}
                </span>
              ))}
            </div>
          </div>
          <div className="border border-neutral-800 bg-neutral-900 rounded p-3 sm:p-4">
            <div className="text-xs text-neutral-500 uppercase tracking-wider mb-2">SSL/TLS</div>
            <div className="text-white">
              {findings.sslIssues === null
                ? "Not included in Midgard"
                : `${findings.sslIssues} issues found`}
            </div>
          </div>
          <div className="border border-neutral-800 bg-neutral-900 rounded p-3 sm:p-4">
            <div className="text-xs text-neutral-500 uppercase tracking-wider mb-2">Data Breaches</div>
            <div className={findings.leaksFound ? "text-red-400" : "text-emerald-400"}>
              {findings.leaksFound ? "Detected" : "None found"}
            </div>
          </div>
        </div>

        {findings.headerIssues !== null && findings.headerIssues > 0 && (
          <div className="border border-neutral-800 bg-neutral-900 rounded p-3 sm:p-4 mb-4">
            <div className="text-xs text-neutral-500 uppercase tracking-wider mb-2">HTTP Security Headers</div>
            <div className="text-white">{findings.headerIssues} issues found</div>
          </div>
        )}

        {isUnlocked && findings.leakEmails && findings.leakEmails.length > 0 && (
          <div className="border border-neutral-800 bg-neutral-900 rounded p-4 mb-4">
            <div className="text-xs text-neutral-500 uppercase tracking-wider mb-2">Leaked Emails</div>
            <ul className="space-y-1">
              {findings.leakEmails.map((e, i) => (
                <li key={i} className="text-xs text-neutral-400 font-mono">{e}</li>
              ))}
            </ul>
          </div>
        )}

        {isUnlocked && findings.remediationNotes && findings.remediationNotes.length > 0 && (
          <div className="border border-neutral-800 bg-neutral-900 rounded p-4 sm:p-6">
            <h3 className="text-white font-medium mb-3">Remediation Highlights</h3>
            <ul className="space-y-2">
              {findings.remediationNotes.map((note, i) => (
                <li key={i} className="text-xs text-neutral-400 flex items-start gap-2">
                  <span className="text-emerald-400 mt-0.5">✓</span>
                  {note}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <section className="border border-neutral-800 bg-neutral-900 rounded p-4 sm:p-6">
        <h2 className="text-white font-medium mb-4">What&apos;s included in your {tier.name} report</h2>
        <ul className="space-y-2">
          {tier.features.map((feature, i) => (
            <li key={i} className="flex items-start gap-2 text-xs">
              <span className={feature.included ? "text-emerald-400" : "text-neutral-600"}>
                {feature.included ? "✓" : "×"}
              </span>
              <span className={feature.included ? "text-neutral-300" : "text-neutral-600 line-through"}>
                {feature.text}
              </span>
            </li>
          ))}
        </ul>
      </section>

      {upgradeTiers.length > 0 && (
        <section>
          <h2 className="text-lg text-white mb-2">Upgrade to a higher tier</h2>
          <p className="text-xs text-neutral-500 mb-4">
            Compare what you get above {tier.name}. Start a new scan at a higher tier — pay only when you unlock results.
          </p>
          <div className={`grid grid-cols-1 gap-4 ${upgradeTiers.length > 1 ? "lg:grid-cols-2" : ""}`}>
            {upgradeTiers.map((upgradeTier) => (
              <div
                key={upgradeTier.id}
                className={`border rounded-lg overflow-hidden ${
                  upgradeTier.popular
                    ? "border-[#A655F7] bg-[#A655F7]/5"
                    : "border-neutral-800 bg-neutral-900"
                }`}
              >
                {upgradeTier.popular && (
                  <div className="bg-[#A655F7] text-white text-[9px] uppercase tracking-wider text-center py-1 font-medium">
                    Most popular
                  </div>
                )}
                <div className="p-4 sm:p-5">
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div>
                      <h3 className="text-white font-medium">{upgradeTier.name}</h3>
                      <p className="text-[10px] text-neutral-500 mt-0.5">{upgradeTier.tagline}</p>
                    </div>
                    <p className="text-sm font-bold text-white flex-shrink-0">{upgradeTier.priceLabel}</p>
                  </div>
                  <ul className="space-y-2 mb-4">
                    {upgradeTier.features.map((f, i) => (
                      <li key={i} className="flex items-start gap-2 text-[11px]">
                        <span className={f.included ? "text-emerald-400" : "text-neutral-600"}>
                          {f.included ? "✓" : "×"}
                        </span>
                        <span className={f.included ? "text-neutral-400" : "text-neutral-600"}>{f.text}</span>
                      </li>
                    ))}
                  </ul>
                  <button
                    onClick={() => handleUpgradeScan(upgradeTier.id as "standard" | "premium")}
                    disabled={loadingTier === upgradeTier.id}
                    className={`w-full py-2.5 rounded text-sm font-medium cursor-pointer disabled:opacity-60 ${
                      upgradeTier.popular
                        ? "bg-[#A655F7] text-white hover:bg-[#b875f8]"
                        : "bg-neutral-800 text-white hover:bg-neutral-700 border border-neutral-700"
                    }`}
                  >
                    {loadingTier === upgradeTier.id
                      ? "Starting..."
                      : `Run ${upgradeTier.name} Scan`}
                  </button>
                  <p className="text-[10px] text-neutral-600 text-center mt-2">Billed when you unlock results</p>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <ServicesSection />

      {isUnlocked && (
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <a
            href={`/api/scans/${scan.id}/report`}
            download
            className="cursor-pointer border border-neutral-700 bg-neutral-900 px-6 py-2.5 text-white font-medium hover:border-[#A655F7]/50 hover:bg-neutral-800 rounded-sm text-sm text-center"
          >
            Download Report
          </a>
          <a
            href="/"
            className="cursor-pointer bg-[#A655F7] px-6 py-2.5 text-white font-medium hover:bg-[#b875f8] rounded-sm glitch-hover text-sm text-center"
          >
            Scan Another Target
          </a>
        </div>
      )}

      {!isUnlocked && (
        <div className="flex justify-center pt-2">
          <a
            href="/"
            className="cursor-pointer bg-[#A655F7] px-6 py-2.5 text-white font-medium hover:bg-[#b875f8] rounded-sm glitch-hover text-sm"
          >
            Scan Another Target
          </a>
        </div>
      )}
    </div>
  );
}
