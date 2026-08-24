"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { ScanData } from "@/lib/scan-types";
import { getUnlockBody, getUnlockCtaLabel, getUpgradeTiers, includesSubdomainDiscovery, isScanUnlocked } from "@/lib/scan-tiers";
import type { Finding } from "@/lib/scan-results";
import { groupFindings } from "@/lib/scan-results";
import { Reveal } from "@/components/Reveal";
import { CredentialExposure } from "@/components/scan/CredentialExposure";
import { FindingDossier } from "@/components/scan/FindingDossier";
import { ScanExecutiveHeader } from "@/components/scan/ScanExecutiveHeader";
import { ServicesSection } from "@/components/scan/ServicesSection";
import { SubdomainsSection } from "@/components/scan/SubdomainsSection";

const FINDINGS_ANCHOR = "findings";
const LEAKS_ANCHOR = "dark-web";
const SUBDOMAINS_ANCHOR = "subdomains";

interface ScanSuccessProps {
  scan: ScanData;
  sample?: boolean;
}

function defaultOpenIds(findings: Finding[]): string[] {
  const writeup = findings.find((item) => item.access === "basic" || item.access === "full");
  const first = writeup ?? findings[0];
  return first ? [first.id] : [];
}

export function ScanSuccess({ scan, sample = false }: ScanSuccessProps) {
  const router = useRouter();
  const [loadingTier, setLoadingTier] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);
  const [checkoutError, setCheckoutError] = useState<string | null>(null);
  const upgradeTiers = getUpgradeTiers(scan.tier);
  const results = scan.results;
  const needsUnlock = !sample && scan.tier !== "free" && !scan.paid;
  const isUnlocked = sample || isScanUnlocked(scan);
  const findings = results?.findings ?? [];
  const [openIds, setOpenIds] = useState<string[]>(() => defaultOpenIds(findings));

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

  const toggleFinding = (id: string) => {
    setOpenIds((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id]
    );
  };

  if (!results) return null;

  const groups = groupFindings(findings);
  const leaks = scan.darkWebMonitoring ? (results.leaks ?? []) : [];

  return (
    <div className="space-y-8 sm:space-y-10">
      <ScanExecutiveHeader
        scan={scan}
        results={results}
        sample={sample}
        needsUnlock={needsUnlock}
        isUnlocked={isUnlocked}
        unlocking={unlocking}
        onUnlock={handleUnlock}
        findingsAnchor={FINDINGS_ANCHOR}
        leaksAnchor={LEAKS_ANCHOR}
        subdomainsAnchor={SUBDOMAINS_ANCHOR}
      />

      {needsUnlock && (
        <Reveal className="border border-[#A655F7]/40 bg-[#A655F7]/5 rounded-sm px-4 py-4 sm:px-5">
          <p className="text-sm text-white mb-1">Unlock this report and keep rescanning</p>
          <p className="text-xs text-neutral-400 mb-3 leading-relaxed">
            {getUnlockBody(scan.tier, scan.target)}
          </p>
          <button
            type="button"
            onClick={handleUnlock}
            disabled={unlocking}
            className="cursor-pointer bg-[#A655F7] px-4 py-2 text-white text-sm font-medium hover:bg-[#b875f8] rounded-sm disabled:opacity-60"
          >
            {unlocking ? "Redirecting..." : getUnlockCtaLabel(scan.tier)}
          </button>
          {checkoutError && <p className="text-xs text-red-400 mt-3">{checkoutError}</p>}
        </Reveal>
      )}

      <section id={FINDINGS_ANCHOR} className="space-y-8 scroll-mt-6">
        {groups.map((group) => (
          <div key={group.groupId}>
            <Reveal>
              <h2 className="text-white text-base mb-3">
                {group.groupId}. {group.group}
              </h2>
            </Reveal>
            <div className="space-y-2">
              {group.findings.map((item, index) => (
                <Reveal key={item.id} delay={Math.min(index, 4) * 50}>
                  <FindingDossier
                    finding={item}
                    open={openIds.includes(item.id)}
                    locked={needsUnlock}
                    tier={scan.tier}
                    onToggle={() => toggleFinding(item.id)}
                  />
                </Reveal>
              ))}
            </div>
          </div>
        ))}
      </section>

      <Reveal>
        <SubdomainsSection
          target={scan.target}
          subdomains={results.subdomains}
          included={includesSubdomainDiscovery(scan.tier)}
          anchor={SUBDOMAINS_ANCHOR}
        />
      </Reveal>

      {leaks.length > 0 && (
        <Reveal>
          <CredentialExposure leaks={leaks} anchor={LEAKS_ANCHOR} />
        </Reveal>
      )}

      {!sample && upgradeTiers.length > 0 && (
        <Reveal>
          <section>
            <h2 className="text-white text-base mb-1">Scan wider</h2>
            <p className="text-xs text-neutral-500 mb-4">
              Run a new scan at a higher level. The scan runs first — you pay only when you unlock
              that report.
            </p>
            <div
              className={`grid grid-cols-1 gap-4 ${upgradeTiers.length > 1 ? "lg:grid-cols-2" : ""}`}
            >
              {upgradeTiers.map((upgradeTier) => (
                <div
                  key={upgradeTier.id}
                  className={`border rounded-sm overflow-hidden ${
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
                      <h3 className="text-white font-medium">{upgradeTier.name}</h3>
                      <p className="text-sm text-white flex-shrink-0">{upgradeTier.priceLabel}</p>
                    </div>
                    <ul className="space-y-2 mb-4">
                      {upgradeTier.features.map((feature) => (
                        <li key={feature.text} className="flex items-start gap-2 text-[11px]">
                          <span className={feature.included ? "text-emerald-400" : "text-neutral-600"}>
                            {feature.included ? "✓" : "×"}
                          </span>
                          <span className={feature.included ? "text-neutral-400" : "text-neutral-600"}>{feature.text}</span>
                        </li>
                      ))}
                    </ul>
                    <button
                      type="button"
                      onClick={() => handleUpgradeScan(upgradeTier.id as "standard" | "premium")}
                      disabled={loadingTier === upgradeTier.id}
                      className={`w-full py-2.5 rounded-sm text-sm font-medium cursor-pointer disabled:opacity-60 ${
                        upgradeTier.popular
                          ? "bg-[#A655F7] text-white hover:bg-[#b875f8]"
                          : "bg-neutral-800 text-white hover:bg-neutral-700 border border-neutral-700"
                      }`}
                    >
                      {loadingTier === upgradeTier.id ? "Starting..." : `Run ${upgradeTier.name} Scan`}
                    </button>
                    <p className="text-[10px] text-neutral-600 text-center mt-2">Billed when you unlock the report</p>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </Reveal>
      )}

      {!sample && (
        <Reveal>
          <ServicesSection
            target={scan.target}
            critical={results.critical}
            important={results.high}
          />
        </Reveal>
      )}

      <Reveal className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
        {isUnlocked && !sample && (
          <a
            href={`/api/scans/${scan.id}/report`}
            download
            className="cursor-pointer border border-neutral-700 bg-neutral-900 px-6 py-2.5 text-white font-medium hover:border-[#A655F7]/50 hover:bg-neutral-800 rounded-sm text-sm text-center"
          >
            Download PDF
          </a>
        )}
        <Link
          href="/"
          className="cursor-pointer bg-[#A655F7] px-6 py-2.5 text-white font-medium hover:bg-[#b875f8] rounded-sm glitch-hover text-sm text-center"
        >
          {sample ? "Run your own scan" : "Scan Another Target"}
        </Link>
      </Reveal>
    </div>
  );
}
