"use client";

import React, { Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useReport } from "@/hooks/useReport";
import { getPublicReportUiMessage, reportErrorKind } from "@/lib/reports";

type PlanType = "free" | "standard" | "premium";

interface PlanFeature {
  text: string;
  included: boolean;
}

interface Plan {
  id: PlanType;
  name: string;
  nameRu: string;
  price: number | null;
  priceLabel: string;
  description: string;
  features: PlanFeature[];
  buttonText: string;
  popular?: boolean;
}

const plans: Plan[] = [
  {
    id: "free",
    name: "Midgard",
    nameRu: "Surface-level overview",
    price: null,
    priceLabel: "Free",
    description: "Overview of discovered issues without details or recommendations",
    buttonText: "Download Free",
    features: [
      { text: "Basic server technology information", included: true },
      { text: "Web server, CMS, main frameworks detected", included: true },
      { text: "Issue count by category", included: true },
      { text: "1-2 critical vulnerabilities with minimal description", included: true },
      { text: "Data breach check (yes/no only)", included: true },
      { text: "Detailed vulnerability descriptions", included: false },
      { text: "Remediation recommendations", included: false },
      { text: "Leaked email addresses list", included: false },
    ],
  },
  {
    id: "standard",
    name: "Asgard",
    nameRu: "Deep insights & guidance",
    price: 166,
    priceLabel: "$154",
    description: "Detailed analysis with remediation recommendations",
    buttonText: "Purchase Report",
    popular: true,
    features: [
      { text: "Full list of outdated technologies and versions", included: true },
      { text: "Detailed medium & high severity vulnerability descriptions", included: true },
      { text: "Leaked email addresses (partially masked)", included: true },
      { text: "Basic remediation recommendations", included: true },
      { text: "SSL/TLS configuration analysis", included: true },
      { text: "HTTP security headers analysis", included: true },
      { text: "Links to official documentation", included: true },
      { text: "Low severity vulnerability analysis", included: false },
      { text: "Step-by-step remediation instructions", included: false },
      { text: "Password leak information", included: false },
    ],
  },
  {
    id: "premium",
    name: "Valhalla",
    nameRu: "Elite full protection",
    price: 273,
    priceLabel: "$273",
    description: "Complete audit with step-by-step instructions and follow-up scan",
    buttonText: "Purchase Report",
    features: [
      { text: "Everything from Asgard report", included: true },
      { text: "Password leak information (hashed)", included: true },
      { text: "Detailed analysis of ALL vulnerabilities including low severity", included: true },
      { text: "Step-by-step remediation for each issue", included: true },
      { text: "Fix prioritization roadmap", included: true },
      { text: "Server configuration analysis", included: true },
      { text: "Hardening recommendations", included: true },
      { text: "Follow-up scan after 30 days", included: true },
    ],
  },
];

const DEFAULT_SUMMARY = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
  technologies: [] as string[],
  sslIssues: 0,
  headerIssues: 0,
  leaksFound: false,
};

function ReportPageContent() {
  const searchParams = useSearchParams();
  const targetParam = searchParams.get("target");
  const idParam = searchParams.get("id");
  const { report, loading, error, refetch, valhallaHtmlDownloadUrl } = useReport(targetParam, idParam);
  const hasQuery = Boolean(targetParam || idParam);
  const errKind = reportErrorKind(error, hasQuery);
  const errorTitle =
    errKind === "missing"
      ? "Link incomplete"
      : errKind === "not_found"
        ? "Report not found"
        : "Unable to load report";

  const site = report?.target ?? targetParam ?? "Unknown Target";
  const scanSummary = report?.summary ?? DEFAULT_SUMMARY;

  if (loading) {
    return (
      <div className="flex min-h-screen flex-col bg-neutral-950 font-mono text-sm">
        <header className="border-b border-neutral-800 bg-neutral-900">
          <div className="mx-auto flex h-12 max-w-5xl items-center justify-between px-4 sm:px-6">
            <div className="flex items-center gap-2">
              <Link href="/" className="glitch-text text-white font-semibold tracking-wide cursor-pointer" data-text="RAGNAROK">RAGNAROK</Link>
            </div>
          </div>
        </header>
        <main className="flex-1 flex items-center justify-center">
          <div className="text-neutral-400">Loading report...</div>
        </main>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex min-h-screen flex-col bg-neutral-950 font-mono text-sm">
        <header className="border-b border-neutral-800 bg-neutral-900">
          <div className="mx-auto flex h-12 max-w-5xl items-center justify-between px-4 sm:px-6">
            <div className="flex items-center gap-2">
              <Link href="/" className="glitch-text text-white font-semibold tracking-wide cursor-pointer" data-text="RAGNAROK">RAGNAROK</Link>
            </div>
          </div>
        </header>
        <main className="flex-1 flex items-center justify-center px-4">
          <div className="text-center max-w-md">
            <div className="mb-4 text-red-400">{errorTitle}</div>
            <p className="text-neutral-400 text-sm mb-6">
              {getPublicReportUiMessage(error)}
            </p>
            <div className="flex gap-3 justify-center">
              <button
                onClick={refetch}
                className="cursor-pointer px-4 py-2 text-sm bg-neutral-800 text-white hover:bg-neutral-700 rounded"
              >
                Retry
              </button>
              <Link href="/" className="cursor-pointer px-4 py-2 text-sm text-neutral-400 hover:text-white">
                Back to Scanner
              </Link>
            </div>
          </div>
        </main>
      </div>
    );
  }

  if (!report) {
    return null;
  }

  return (
    <div className="flex min-h-screen flex-col bg-neutral-950 font-mono text-sm">
      <header className="border-b border-neutral-800 bg-neutral-900">
        <div className="mx-auto flex h-12 max-w-5xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-2">
            <Link href="/" className="glitch-text text-white font-semibold tracking-wide cursor-pointer" data-text="RAGNAROK">RAGNAROK</Link>
            <span className="text-neutral-500 text-xs hidden sm:inline">by</span>
            <a href="https://svalbard.ca" className="text-neutral-400 text-xs hover:text-[#E3CAFE] cursor-pointer hidden sm:inline">Svalbard Security</a>
          </div>
          <nav className="flex items-center gap-1 text-xs">
            <a href="https://svalbard.ca/docs" className="cursor-pointer px-2 sm:px-3 py-1.5 text-neutral-400 hover:text-[#E3CAFE] hover:bg-[#393A84]/20 rounded">
              Docs
            </a>
            <a href="https://svalbard.ca/support" className="cursor-pointer px-2 sm:px-3 py-1.5 text-neutral-400 hover:text-[#E3CAFE] hover:bg-[#393A84]/20 rounded">
              Support
            </a>
          </nav>
        </div>
      </header>

      <main className="flex-1 px-4 sm:px-6 py-6 sm:py-10">
        <div className="mx-auto max-w-5xl">
          <div className="mb-6 sm:mb-8 border border-emerald-500/30 bg-emerald-500/5 rounded p-3 sm:p-4">
            <div className="flex items-center gap-3">
              <div className="h-3 w-3 rounded-full bg-emerald-500 pulse-glow glow-emerald flex-shrink-0" />
              <div className="min-w-0">
                <span className="text-emerald-400 font-medium">Scan Complete</span>
                <span className="text-neutral-500 ml-2 sm:ml-3 text-xs block sm:inline truncate">Target: {site}</span>
              </div>
            </div>
          </div>

          <div className="mb-8 sm:mb-10">
            <h2 className="text-lg text-white mb-4">Issues Discovered</h2>
            <div className="hidden sm:grid sm:grid-cols-5 gap-3">
              <div className="border border-red-500/30 bg-red-500/5 rounded p-4 text-center">
                <div className="text-2xl font-bold text-red-400">{scanSummary.critical}</div>
                <div className="text-xs text-red-400/70 uppercase tracking-wider mt-1">Critical</div>
              </div>
              <div className="border border-orange-500/30 bg-orange-500/5 rounded p-4 text-center">
                <div className="text-2xl font-bold text-orange-400">{scanSummary.high}</div>
                <div className="text-xs text-orange-400/70 uppercase tracking-wider mt-1">High</div>
              </div>
              <div className="border border-amber-500/30 bg-amber-500/5 rounded p-4 text-center">
                <div className="text-2xl font-bold text-amber-400">{scanSummary.medium}</div>
                <div className="text-xs text-amber-400/70 uppercase tracking-wider mt-1">Medium</div>
              </div>
              <div className="border border-blue-500/30 bg-blue-500/5 rounded p-4 text-center">
                <div className="text-2xl font-bold text-blue-400">{scanSummary.low}</div>
                <div className="text-xs text-blue-400/70 uppercase tracking-wider mt-1">Low</div>
              </div>
              <div className="border border-neutral-700 bg-neutral-900 rounded p-4 text-center">
                <div className="text-2xl font-bold text-neutral-400">{scanSummary.info}</div>
                <div className="text-xs text-neutral-500 uppercase tracking-wider mt-1">Info</div>
              </div>
            </div>
            <div className="sm:hidden space-y-2">
              <div className="grid grid-cols-3 gap-2">
                <div className="border border-red-500/30 bg-red-500/5 rounded p-3 text-center">
                  <div className="text-xl font-bold text-red-400">{scanSummary.critical}</div>
                  <div className="text-[10px] text-red-400/70 uppercase tracking-wider mt-1">Critical</div>
                </div>
                <div className="border border-orange-500/30 bg-orange-500/5 rounded p-3 text-center">
                  <div className="text-xl font-bold text-orange-400">{scanSummary.high}</div>
                  <div className="text-[10px] text-orange-400/70 uppercase tracking-wider mt-1">High</div>
                </div>
                <div className="border border-amber-500/30 bg-amber-500/5 rounded p-3 text-center">
                  <div className="text-xl font-bold text-amber-400">{scanSummary.medium}</div>
                  <div className="text-[10px] text-amber-400/70 uppercase tracking-wider mt-1">Medium</div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="border border-blue-500/30 bg-blue-500/5 rounded p-3 text-center">
                  <div className="text-xl font-bold text-blue-400">{scanSummary.low}</div>
                  <div className="text-[10px] text-blue-400/70 uppercase tracking-wider mt-1">Low</div>
                </div>
                <div className="border border-neutral-700 bg-neutral-900 rounded p-3 text-center">
                  <div className="text-xl font-bold text-neutral-400">{scanSummary.info}</div>
                  <div className="text-[10px] text-neutral-500 uppercase tracking-wider mt-1">Info</div>
                </div>
              </div>
            </div>
          </div>

          <div className="mb-8 sm:mb-10 grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4">
            <div className="border border-neutral-800 bg-neutral-900 rounded p-3 sm:p-4">
              <div className="text-xs text-neutral-500 uppercase tracking-wider mb-2">Technologies</div>
              <div className="flex flex-wrap gap-2">
                {scanSummary.technologies.map((tech, i) => (
                  <span key={i} className="text-xs bg-neutral-800 text-neutral-300 px-2 py-1 rounded">
                    {tech}
                  </span>
                ))}
              </div>
            </div>
            <div className="border border-neutral-800 bg-neutral-900 rounded p-3 sm:p-4">
              <div className="text-xs text-neutral-500 uppercase tracking-wider mb-2">SSL/TLS</div>
              <div className="text-white">{scanSummary.sslIssues} issues found</div>
            </div>
            <div className="border border-neutral-800 bg-neutral-900 rounded p-3 sm:p-4">
              <div className="text-xs text-neutral-500 uppercase tracking-wider mb-2">Data Breaches</div>
              <div className={scanSummary.leaksFound ? "text-red-400" : "text-emerald-400"}>
                {scanSummary.leaksFound ? "Detected" : "None found"}
              </div>
            </div>
          </div>

          {!valhallaHtmlDownloadUrl ? (
            <div className="mb-8 sm:mb-12 border border-amber-500/30 bg-amber-500/5 rounded-lg p-4 sm:p-6">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                  <h2 className="text-white font-medium mb-1">Report not ready yet</h2>
                  <p className="text-neutral-400 text-sm leading-relaxed">
                    The full Valhalla HTML report is still being generated. Download options will appear here when it is ready.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={refetch}
                  className="shrink-0 cursor-pointer px-4 py-2 text-sm bg-neutral-800 text-white hover:bg-neutral-700 rounded border border-neutral-700"
                >
                  Check again
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="mb-6 sm:mb-8 text-center">
                <h1 className="text-xl sm:text-2xl text-white mb-2">Choose Your Report</h1>
                <p className="text-neutral-500 text-sm sm:text-base px-2">
                  Get detailed analysis and remediation recommendations for discovered vulnerabilities
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6 mb-8 sm:mb-12">
                {plans.map((plan) => (
                  <div
                    key={plan.id}
                    className={`relative border rounded-lg overflow-hidden transition-all ${
                      plan.popular
                        ? "border-[#A655F7] bg-[#A655F7]/5"
                        : "border-neutral-800 bg-neutral-900 hover:border-neutral-700"
                    }`}
                  >
                    {plan.popular && (
                      <div className="absolute top-0 left-0 right-0 bg-[#A655F7] text-white text-xs text-center py-1 font-medium uppercase tracking-wider">
                        Most Popular
                      </div>
                    )}

                    <div className={`p-6 ${plan.popular ? "pt-10" : ""}`}>
                      <div className="mb-4">
                        <h3 className="text-white font-medium mb-1">{plan.name}</h3>
                        <p className="text-xs text-neutral-500">{plan.nameRu}</p>
                      </div>

                      <div className="mb-4">
                        <span
                          className={`text-3xl font-bold ${plan.price === null ? "text-emerald-400" : "text-white"}`}
                        >
                          {plan.priceLabel}
                        </span>
                      </div>

                      <p className="text-xs text-neutral-400 mb-6 leading-relaxed">{plan.description}</p>

                      <div className="space-y-3 mb-6">
                        {plan.features.map((feature, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <span
                              className={`text-xs mt-0.5 ${feature.included ? "text-emerald-400" : "text-neutral-600"}`}
                            >
                              {feature.included ? "✓" : "×"}
                            </span>
                            <span
                              className={`text-xs ${feature.included ? "text-neutral-300" : "text-neutral-600 line-through"}`}
                            >
                              {feature.text}
                            </span>
                          </div>
                        ))}
                      </div>

                      {valhallaHtmlDownloadUrl ? (
                        <a
                          href={valhallaHtmlDownloadUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={`w-full py-3 rounded text-sm font-medium transition-all cursor-pointer block text-center ${
                            plan.popular
                              ? "bg-[#A655F7] text-white hover:bg-[#b875f8] glitch-hover"
                              : "bg-neutral-800 text-white hover:bg-neutral-700 border border-neutral-700 hover:border-[#A655F7]/50"
                          }`}
                        >
                          {plan.buttonText}
                        </a>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>

              <div className="mb-8 sm:mb-12 border border-neutral-800 bg-neutral-900 rounded p-4 sm:p-6">
                <h3 className="text-white font-medium mb-4">What You Get in Each Report</h3>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6 text-xs">
                  <div>
                    <div className="text-neutral-300 uppercase tracking-wider mb-1">Midgard</div>
                    <div className="text-neutral-400 text-[10px] mb-2">Surface-level overview</div>
                    <p className="text-neutral-400 leading-relaxed">
                      Facts only about discovered issues. No recommendations — you&apos;ll know WHAT was found,
                      but not HOW to fix it.
                    </p>
                  </div>
                  <div>
                    <div className="text-[#A655F7] uppercase tracking-wider mb-1">Asgard</div>
                    <div className="text-[#c9a0fa] text-[10px] mb-2">Deep insights & guidance</div>
                    <p className="text-neutral-400 leading-relaxed">
                      General recommendations: &quot;upgrade to version X&quot;, &quot;enable HTTPS&quot;.
                      Links to documentation. No case-specific instructions.
                    </p>
                  </div>
                  <div>
                    <div className="text-amber-400 uppercase tracking-wider mb-1">Valhalla</div>
                    <div className="text-amber-300 text-[10px] mb-2">Elite full protection</div>
                    <p className="text-neutral-400 leading-relaxed">
                      Detailed instructions with prioritization. What to fix first,
                      step-by-step actions for each issue.
                    </p>
                  </div>
                </div>
              </div>
            </>
          )}

          <div className="mb-8 sm:mb-12">
            <div className="border border-neutral-800 bg-neutral-900 rounded-lg overflow-hidden">
              <div className="border-b border-neutral-800 bg-neutral-950 px-4 sm:px-6 py-3 sm:py-4">
                <h2 className="text-base sm:text-lg text-white">Need Help With Remediation?</h2>
                <p className="text-neutral-500 text-xs mt-1">Our experts can help fix all discovered issues</p>
              </div>

              <div className="p-4 sm:p-6">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6 mb-6">
                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-12 h-12 flex items-center justify-center">
                      <svg className="w-8 h-8 text-[#A655F7]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
                      </svg>
                    </div>
                    <div>
                      <h4 className="text-white text-sm font-medium mb-1">Consultation</h4>
                      <p className="text-xs text-neutral-500 leading-relaxed">Expert review of your specific situation</p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-12 h-12 flex items-center justify-center">
                      <svg className="w-8 h-8 text-[#A655F7]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                    </div>
                    <div>
                      <h4 className="text-white text-sm font-medium mb-1">Remediation Service</h4>
                      <p className="text-xs text-neutral-500 leading-relaxed">We fix all discovered issues for you</p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-12 h-12 flex items-center justify-center">
                      <svg className="w-8 h-8 text-[#A655F7]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </div>
                    <div>
                      <h4 className="text-white text-sm font-medium mb-1">Retainer</h4>
                      <p className="text-xs text-neutral-500 leading-relaxed">Ongoing security monitoring and support</p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-12 h-12 flex items-center justify-center">
                      <svg className="w-8 h-8 text-[#A655F7]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <div>
                      <h4 className="text-white text-sm font-medium mb-1">Post-Fix Audit</h4>
                      <p className="text-xs text-neutral-500 leading-relaxed">Verification that everything was fixed correctly</p>
                    </div>
                  </div>
                </div>

                <div className="text-center">
                  <button className="bg-[#A655F7] text-white px-8 py-3 rounded text-sm font-medium hover:bg-[#b875f8] glitch-hover cursor-pointer">
                    Contact Us
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="text-center">
            <Link
              href="/"
              className="inline-flex items-center gap-2 text-xs text-neutral-500 hover:text-[#E3CAFE] cursor-pointer"
            >
              ← Back to Scanner
            </Link>
          </div>
        </div>
      </main>

      <footer className="border-t border-neutral-800 bg-neutral-900">
        <div className="mx-auto max-w-5xl px-4 sm:px-6 py-4">
          <div className="flex flex-col sm:flex-row sm:flex-wrap items-center justify-between gap-2 sm:gap-4 text-xs">
            <div className="flex items-center gap-2 sm:gap-4">
              <span className="text-neutral-400">Svalbard Security Inc.</span>
              <span className="text-neutral-700 hidden sm:inline">|</span>
              <a href="mailto:info@svalbard.ca" className="cursor-pointer text-neutral-500 hover:text-[#E3CAFE]">
                info@svalbard.ca
              </a>
            </div>
            <div className="flex items-center gap-3 sm:gap-4 text-neutral-500">
              <a href="https://svalbard.ca/terms" target="_blank" rel="noopener noreferrer" className="cursor-pointer hover:text-[#E3CAFE]">Terms</a>
              <a href="https://svalbard.ca/privacy" target="_blank" rel="noopener noreferrer" className="cursor-pointer hover:text-[#E3CAFE]">Privacy</a>
              <span>© {new Date().getFullYear()}</span>
            </div>
          </div>
          <p className="mt-3 text-xs text-neutral-600 leading-relaxed text-center sm:text-left">
            Authorized testing only. Unauthorized access to computer systems is illegal.
          </p>
        </div>
      </footer>
    </div>
  );
}

export default function ReportPage() {
  return (
    <Suspense fallback={<div className="flex min-h-screen items-center justify-center bg-neutral-950 text-neutral-400">Loading...</div>}>
      <ReportPageContent />
    </Suspense>
  );
}
