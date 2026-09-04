"use client";

import type { ReactNode } from "react";
import type { ScanData } from "@/lib/scan-types";
import type { ScanResults } from "@/lib/scan-results";
import { summarizeLeaks } from "@/lib/scan-results";
import { getTierConfig, getUnlockCtaLabel } from "@/lib/scan-tiers";
import {
  categoryBreakdown,
  openFindingCount,
  pct,
  severityBreakdown,
  topPriorityFindings,
} from "@/lib/scan-summary";
import { formatReportDate } from "@/lib/report-date";
import { SeverityDonut } from "@/components/scan/SeverityDonut";
import { CategoryBars } from "@/components/scan/CategoryBars";
import { TopFindingsList } from "@/components/scan/TopFindingsList";
import { ScanQuotaTile } from "@/components/scan/ScanQuota";

const META_COLUMNS: Record<number, string> = {
  1: "",
  2: "sm:grid-cols-2",
  3: "sm:grid-cols-2 lg:grid-cols-3",
  4: "sm:grid-cols-2 lg:grid-cols-4",
};

interface ScanExecutiveHeaderProps {
  scan: ScanData;
  results: ScanResults;
  sample: boolean;
  needsUnlock: boolean;
  isUnlocked: boolean;
  unlocking: boolean;
  onUnlock: () => void;
  findingsAnchor: string;
  leaksAnchor: string;
  subdomainsAnchor: string;
}

function Icon({ path, className = "" }: { path: ReactNode; className?: string }) {
  return (
    <svg
      className={`h-3.5 w-3.5 ${className}`}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      {path}
    </svg>
  );
}

const ICONS = {
  globe: (
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M4 12h16M12 4c2.2 2.2 2.2 13.8 0 16-2.2-2.2-2.2-13.8 0-16z" />
    </>
  ),
  calendar: (
    <>
      <rect x="4" y="5" width="16" height="15" rx="1" />
      <path d="M4 10h16M9 3v3M15 3v3" />
    </>
  ),
  receipt: (
    <>
      <rect x="4" y="6" width="16" height="12" rx="1" />
      <path d="M4 10h16M7 14h4" />
    </>
  ),
} as const;

interface Tile {
  label: string;
  value: number;
  sub: string;
  tone: { border: string; label: string; value: string };
  wide?: boolean;
}

function MetaChip({
  icon,
  label,
  value,
  valueClass,
  mark,
  wrap = false,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  valueClass: string;
  mark?: ReactNode;
  /** Lets long values (such as deep subdomains) break across lines instead of clipping. */
  wrap?: boolean;
}) {
  return (
    <div className="flex min-w-0 items-center gap-2 border border-neutral-800 bg-neutral-950 rounded-sm px-2.5 py-1.5">
      <span className="text-neutral-600 flex-shrink-0">
        <Icon path={icon} />
      </span>
      <span className="min-w-0">
        <span className="block text-[9px] uppercase tracking-wider text-neutral-500">{label}</span>
        <span className={`flex items-center gap-1.5 text-[11px] ${valueClass}`}>
          {mark}
          <span className={wrap ? "min-w-0 break-all" : "whitespace-nowrap"}>{value}</span>
        </span>
      </span>
    </div>
  );
}

function Panel({
  title,
  children,
  delay,
}: {
  title: string;
  children: ReactNode;
  delay: number;
}) {
  return (
    <div
      className="border border-neutral-800 bg-neutral-900 rounded-sm px-4 py-4 rise-in"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-4">{title}</div>
      {children}
    </div>
  );
}

export function ScanExecutiveHeader({
  scan,
  results,
  sample,
  needsUnlock,
  isUnlocked,
  unlocking,
  onUnlock,
  findingsAnchor,
  leaksAnchor,
  subdomainsAnchor,
}: ScanExecutiveHeaderProps) {
  const tier = getTierConfig(scan.tier);
  const total = results.totalFindings;
  const open = openFindingCount(results);
  const severity = severityBreakdown(results);
  const categories = categoryBreakdown(results.findings);
  const priorities = topPriorityFindings(results.findings);
  const leaks = scan.darkWebMonitoring ? (results.leaks ?? []) : [];
  const leakSummary = summarizeLeaks(leaks);
  const showQuota = Boolean(scan.quota) && isUnlocked;
  const metaCells = 2 + (scan.darkWebMonitoring ? 1 : 0) + (showQuota ? 1 : 0);
  // Past this width the target no longer fits beside the date and payment
  // chips, so it takes a line of its own rather than pushing them around.
  const longTarget = scan.target.length > 30;

  const payment = sample
    ? { label: "Sample", className: "text-neutral-300", mark: null }
    : needsUnlock
      ? { label: "Unpaid", className: "text-amber-400", mark: null }
      : scan.tier === "free"
        ? { label: "Free tier", className: "text-neutral-200", mark: null }
        : {
            label: "Paid",
            className: "text-emerald-400",
            mark: (
              <span className="h-1.5 w-1.5 flex-shrink-0 rounded-full bg-emerald-500 glow-emerald" />
            ),
          };

  const targetChip = (
    <MetaChip
      icon={ICONS.globe}
      label="Target"
      value={scan.target}
      valueClass="text-[#E3CAFE]"
      wrap
    />
  );

  const baseline = results.baseline ?? null;
  const passedTile: Tile = baseline
    ? {
        label: "Baseline pass rate",
        value: Math.round(baseline.passRate * 100),
        sub: `${Math.round(baseline.coverage * 100)}% coverage · ${baseline.passed}/${baseline.total} controls`,
        tone: {
          border: "border-emerald-500/30 bg-emerald-500/[0.06]",
          label: "text-emerald-300",
          value: "text-emerald-400",
        },
        wide: true,
      }
    : {
        label: "Passed",
        value: results.passed,
        sub: `${pct(results.passed, total)}% pass rate`,
        tone: {
          border: "border-emerald-500/30 bg-emerald-500/[0.06]",
          label: "text-emerald-300",
          value: "text-emerald-400",
        },
        wide: true,
      };

  const tiles: Tile[] = [
    {
      label: "Total findings",
      value: total,
      sub: "Across all categories",
      tone: {
        border: "border-[#A655F7]/30 bg-[#A655F7]/[0.06]",
        label: "text-[#E3CAFE]",
        value: "text-white",
      },
    },
    {
      label: "Critical",
      value: results.critical,
      sub: `${pct(results.critical, total)}% of total`,
      tone: {
        border: "border-red-500/30 bg-red-500/[0.06]",
        label: "text-red-300",
        value: "text-red-400",
      },
    },
    {
      label: "Important",
      value: results.high,
      sub: `${pct(results.high, total)}% of total`,
      tone: {
        border: "border-orange-500/30 bg-orange-500/[0.06]",
        label: "text-orange-300",
        value: "text-orange-400",
      },
    },
    {
      label: "Optional",
      value: results.medium + results.low,
      sub: `${pct(results.medium + results.low, total)}% of total`,
      tone: {
        border: "border-amber-500/30 bg-amber-500/[0.05]",
        label: "text-amber-300",
        value: "text-amber-400",
      },
    },
    passedTile,
  ];

  return (
    <section className="space-y-2 sm:space-y-3">
      <div className="border border-neutral-800 bg-neutral-900 rounded-sm px-4 sm:px-5 py-4 rise-in">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex min-w-0 items-stretch gap-3">
            <span className="w-0.5 flex-shrink-0 bg-[#A655F7]" aria-hidden="true" />
            <div className="min-w-0">
              <h1 className="text-white text-lg sm:text-xl leading-tight">{tier.name} report</h1>
              <p className="text-[11px] text-neutral-400 mt-1.5 leading-relaxed max-w-md">
                {tier.reportSummary}
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-2.5 lg:items-end">
            <div className="flex flex-col gap-2">
              <div className="flex flex-col gap-2 sm:flex-row lg:justify-end">
                {longTarget ? null : targetChip}
                <MetaChip
                  icon={ICONS.calendar}
                  label="Assessment date"
                  value={formatReportDate(scan.completedAt ?? scan.createdAt)}
                  valueClass="text-neutral-200"
                />
                <MetaChip
                  icon={ICONS.receipt}
                  label="Payment"
                  value={payment.label}
                  valueClass={payment.className}
                  mark={payment.mark}
                />
              </div>
              {longTarget ? targetChip : null}
            </div>

            <div className="flex flex-wrap items-center gap-2 lg:justify-end">
              {isUnlocked && !sample ? (
                <a
                  href={`/api/scans/${scan.id}/report`}
                  download
                  className="text-xs text-white bg-[#A655F7] hover:bg-[#b875f8] px-3 py-2 rounded-sm transition-colors"
                >
                  Download PDF
                </a>
              ) : needsUnlock ? (
                <button
                  type="button"
                  onClick={onUnlock}
                  disabled={unlocking}
                  className="text-xs text-white bg-[#A655F7] hover:bg-[#b875f8] px-3 py-2 rounded-sm disabled:opacity-60 cursor-pointer"
                >
                  {unlocking ? "Redirecting..." : getUnlockCtaLabel(scan.tier)}
                </button>
              ) : null}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-2 sm:gap-3">
        {tiles.map((tile, index) => (
          <div
            key={tile.label}
            className={`border rounded-sm px-4 py-3.5 rise-in ${tile.tone.border} ${
              tile.wide ? "col-span-2 lg:col-span-1" : ""
            }`}
            style={{ animationDelay: `${60 + index * 60}ms` }}
          >
            <div className={`text-[10px] uppercase tracking-wider truncate ${tile.tone.label}`}>
              {tile.label}
            </div>
            <div className={`text-3xl mt-2.5 leading-none tabular-nums ${tile.tone.value}`}>
              {tile.value}
            </div>
            <div className="text-[10px] text-neutral-500 mt-1.5">{tile.sub}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-2 sm:gap-3">
        <Panel title="Findings by severity" delay={360}>
          <SeverityDonut slices={severity} open={open} />
        </Panel>
        <Panel title="Findings by category" delay={420}>
          <CategoryBars rows={categories} />
        </Panel>
        <Panel title="Top priority findings" delay={480}>
          <TopFindingsList findings={priorities} anchor={findingsAnchor} />
        </Panel>
      </div>

      <div
        className="border border-neutral-800 bg-neutral-900 rounded-sm overflow-hidden rise-in"
        style={{ animationDelay: "540ms" }}
      >
        <div className={`grid grid-cols-1 gap-px bg-neutral-800 ${META_COLUMNS[metaCells]}`}>
          {scan.darkWebMonitoring && (
            <div className="bg-neutral-900 px-4 py-3.5">
              <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-2">Dark web</div>
              <div className="space-y-1">
                {leakSummary.accounts === 0 ? (
                  <p className="text-xs text-neutral-300">No leaked accounts found</p>
                ) : (
                  <>
                    <p className="text-xs text-neutral-300">
                      <a href={`#${leaksAnchor}`} className="text-red-400 hover:text-red-300">
                        {leakSummary.accounts} leaked account{leakSummary.accounts === 1 ? "" : "s"}
                      </a>
                      {leakSummary.sources > 0
                        ? ` across ${leakSummary.sources} breach dump${leakSummary.sources === 1 ? "" : "s"}`
                        : ""}
                    </p>
                    <p className="text-xs text-neutral-500">
                      {scan.tier === "premium"
                        ? `${leakSummary.plaintext} plaintext · ${leakSummary.hashed} hashed password${
                            leakSummary.hashed === 1 ? "" : "s"
                          }`
                        : `Passwords and hashes are detailed on ${getTierConfig("premium").name}.`}
                    </p>
                  </>
                )}
              </div>
            </div>
          )}
          <div className="bg-neutral-900 px-4 py-3.5">
            <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-2">
              {scan.tier === "free" ? "SSL / headers" : scan.tier === "standard" ? "TLS / headers" : "Hardening"}
            </div>
            {scan.tier === "free" ? (
              <p className="text-xs text-neutral-600">Included on {getTierConfig("standard").name}</p>
            ) : (
              <p className="text-xs text-neutral-300">
                TLS 1.2 / 1.3
                {results.sslIssues != null ? ` · ${results.sslIssues} TLS issue${results.sslIssues === 1 ? "" : "s"}` : ""}
                {results.headerIssues != null
                  ? ` · ${results.headerIssues} header issue${results.headerIssues === 1 ? "" : "s"}`
                  : ""}
              </p>
            )}
          </div>
          <div className="bg-neutral-900 px-4 py-3.5">
            <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-2">Subdomains</div>
            {results.subdomains == null ? (
              <p className="text-xs text-neutral-600">
                <a href={`#${subdomainsAnchor}`} className="hover:text-neutral-400">
                  Included on {getTierConfig("premium").name}
                </a>
              </p>
            ) : results.subdomains.length === 0 ? (
              <p className="text-xs text-neutral-300">None discovered · apex scanned</p>
            ) : (
              <p className="text-xs text-neutral-300">
                <a href={`#${subdomainsAnchor}`} className="text-[#E3CAFE] hover:text-white">
                  {results.subdomains.length} discovered
                </a>
                {" · scanned"}
              </p>
            )}
          </div>
          {showQuota ? <ScanQuotaTile scan={scan} sample={sample} /> : null}
        </div>
      </div>
    </section>
  );
}
