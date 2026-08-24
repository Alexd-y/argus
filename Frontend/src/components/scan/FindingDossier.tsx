"use client";

import type { ReactNode } from "react";
import { Collapse } from "@/components/Collapse";
import type { ScanTier } from "@/lib/scan-tiers";
import { getTierConfig } from "@/lib/scan-tiers";
import type { CheckPriority, CheckStatus, Finding, FindingProbe } from "@/lib/scan-results";

const STATUS_BAR: Record<CheckStatus, string> = {
  fail: "border-red-500/40 bg-red-500/10 text-red-300",
  pass: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  warning: "border-amber-500/40 bg-amber-500/10 text-amber-300",
};

const PRIORITY_PILL: Record<CheckPriority, string> = {
  critical: "border-red-500/40 text-red-400 bg-red-500/10",
  important: "border-orange-500/40 text-orange-400 bg-orange-500/10",
  medium: "border-amber-500/40 text-amber-400 bg-amber-500/10",
  optional: "border-neutral-700 text-neutral-400 bg-neutral-900",
};

function ProbeField({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-medium text-neutral-400 mb-1">{label}</div>
      <div className="text-xs text-neutral-200">{children}</div>
    </div>
  );
}

function ProbeWell({ children }: { children: ReactNode }) {
  return (
    <div className="bg-neutral-950 border border-neutral-800 rounded-sm px-2.5 py-1.5 font-mono text-[11px] text-neutral-300 break-all">
      {children}
    </div>
  );
}

function FindingProbeCard({ probe }: { probe: FindingProbe }) {
  return (
    <div className="border border-neutral-800 bg-neutral-950/80 rounded-sm px-3 py-3 space-y-4">
      <div className="text-[10px] uppercase tracking-wider text-neutral-500">Scanner output</div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-4">
        <ProbeField label="Port">
          <span className="text-[#A655F7] font-medium">{probe.port}</span>
        </ProbeField>
        <ProbeField label="Template Path">
          <ProbeWell>{probe.templatePath}</ProbeWell>
        </ProbeField>
        <ProbeField label="Template ID">
          <span className="font-mono text-neutral-200">{probe.templateId}</span>
        </ProbeField>
        <ProbeField label="Matcher">
          <span className="font-mono text-neutral-200">{probe.matcher}</span>
        </ProbeField>
        <ProbeField label="Matched At">
          <ProbeWell>{probe.matchedAt}</ProbeWell>
        </ProbeField>
        <ProbeField label="IP Address">
          <span className="font-mono text-neutral-200">{probe.ipAddress}</span>
        </ProbeField>
      </div>
      {probe.tags.length > 0 && (
        <div>
          <div className="text-[10px] font-medium text-neutral-400 mb-1.5">Tags</div>
          <div className="flex flex-wrap gap-1.5">
            {probe.tags.map((tag) => (
              <span
                key={tag}
                className="text-[10px] border border-[#A655F7]/40 bg-[#A655F7]/10 text-[#E3CAFE] px-2 py-0.5 rounded-full"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}
      {probe.extractedResults.length > 0 && (
        <div>
          <div className="text-[10px] font-medium text-neutral-400 mb-1.5">Extracted Results</div>
          <div className="bg-neutral-950 border border-neutral-800 rounded-sm px-3 py-2 font-mono text-[11px] text-neutral-300 space-y-1">
            {probe.extractedResults.map((result) => (
              <div key={result}>{result}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

interface FindingDossierProps {
  finding: Finding;
  open: boolean;
  locked: boolean;
  tier: ScanTier;
  onToggle: () => void;
}

export function FindingDossier({ finding, open, locked, tier, onToggle }: FindingDossierProps) {
  const access = locked ? "title" : finding.access;
  const showWriteup = !locked && (access === "basic" || access === "full");

  return (
    <div className="border border-neutral-800 bg-neutral-900 rounded-sm overflow-hidden">
      <button
        type="button"
        aria-expanded={open}
        onClick={onToggle}
        className={`w-full cursor-pointer text-left px-4 py-3 flex items-start gap-3 transition-colors hover:bg-neutral-800/60 ${
          open ? "bg-neutral-800/40" : ""
        }`}
      >
        <svg
          className={`mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-neutral-500 transition-transform duration-300 ease-out ${
            open ? "rotate-90" : ""
          }`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        <span className="text-[11px] text-neutral-500 font-mono flex-shrink-0 pt-0.5">{finding.id}</span>
        <span className="text-sm text-white min-w-0 flex-1">{finding.name}</span>
        <span
          className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded-sm border flex-shrink-0 ${PRIORITY_PILL[finding.priority]}`}
        >
          {finding.priority}
        </span>
      </button>
      <Collapse open={open} className="border-t border-neutral-800 px-4 py-4 space-y-3">
        <div className={`rounded-sm border px-3 py-2 text-xs ${STATUS_BAR[finding.status]}`}>
          {finding.headline}
        </div>
        {locked ? (
          <p className="text-[11px] text-neutral-500">
            Subscribe to unlock the full explanation, evidence, and remediation for this check.
          </p>
        ) : access === "title" ? (
          <p className="text-[11px] text-neutral-500">
            {finding.priority === "optional" || finding.priority === "medium"
              ? `Low-severity findings are unlocked on ${getTierConfig("premium").name}, with step-by-step fixes and scanner output.`
              : tier === "free"
                ? `${getTierConfig("free").name} includes one complete writeup. ${getTierConfig("standard").name} unlocks this one.`
                : `${getTierConfig("premium").name} unlocks this writeup.`}
          </p>
        ) : showWriteup ? (
          <>
            <p className="text-xs text-neutral-300 leading-relaxed">{finding.explanation}</p>
            {finding.evidence && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-1">Evidence</div>
                <pre className="text-[11px] text-neutral-400 font-mono leading-relaxed bg-neutral-950 border border-neutral-800 rounded-sm px-3 py-2 whitespace-pre-wrap">
                  {finding.evidence}
                </pre>
              </div>
            )}
            {access === "full" && finding.probe && <FindingProbeCard probe={finding.probe} />}
            <div>
              <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-1">
                {access === "full" ? "Step-by-step remediation" : "Remediation"}
              </div>
              <p className="text-xs text-neutral-300 leading-relaxed whitespace-pre-wrap">{finding.remediation}</p>
            </div>
          </>
        ) : null}
      </Collapse>
    </div>
  );
}
