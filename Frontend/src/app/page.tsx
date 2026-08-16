"use client";

import React, { useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import type { ScanTier } from "@/lib/scan-tiers";
import { getScanCtaLabel } from "@/lib/scan-tiers";
import { emailMatchesTarget } from "@/lib/domain-verification";
import { validateTarget, extractHostname, isValidEmail } from "@/lib/validation";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { TierSelector } from "@/components/TierSelector";
import { DomainVerification } from "@/components/DomainVerification";

function Tooltip({ children }: { children: React.ReactNode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const buttonRef = React.useRef<HTMLButtonElement>(null);

  const handleClick = () => {
    if (buttonRef.current) {
      const rect = buttonRef.current.getBoundingClientRect();
      setPosition({
        top: rect.bottom + 8,
        left: Math.min(rect.left, window.innerWidth - 280),
      });
    }
    setIsOpen(!isOpen);
  };

  return (
    <div className="inline-flex items-center">
      <button
        ref={buttonRef}
        type="button"
        onClick={handleClick}
        onBlur={() => setIsOpen(false)}
        className="ml-1.5 inline-flex h-3.5 w-3.5 cursor-pointer items-center justify-center rounded-full border border-neutral-600 text-[9px] leading-none text-neutral-500 hover:border-[#A655F7] hover:text-[#A655F7]"
      >
        ?
      </button>
      {isOpen && (
        <div
          className="fixed z-[100] w-72 rounded-lg border border-neutral-700 bg-neutral-900 p-4 text-xs shadow-2xl"
          style={{ top: position.top, left: position.left }}
        >
          {children}
        </div>
      )}
    </div>
  );
}

interface VerificationState {
  verificationId: string;
  recordHost: string;
  recordValue: string;
  target: string;
}

export default function Home() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [protocol, setProtocol] = useState<"https" | "http">("https");
  const [email, setEmail] = useState("");
  const [tier, setTier] = useState<ScanTier>("free");
  const [darkWebMonitoring, setDarkWebMonitoring] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [verification, setVerification] = useState<VerificationState | null>(null);
  const [verifiedId, setVerifiedId] = useState<string | null>(null);

  const validation = useMemo(() => validateTarget(target), [target]);
  const emailValid = isValidEmail(email);
  const normalizedTarget = useMemo(
    () => (validation.valid ? extractHostname(target, protocol) : ""),
    [target, protocol, validation.valid]
  );

  const startScan = async (verificationId?: string | null) => {
    const res = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: normalizedTarget,
        email: email.trim(),
        tier,
        darkWebMonitoring,
        verificationId: verificationId || undefined,
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      setSubmitError(data.error || "Failed to start scan");
      return;
    }
    router.push(data.url);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validation.valid || !emailValid) return;

    setSubmitting(true);
    setSubmitError(null);

    try {
      if (emailMatchesTarget(email, normalizedTarget)) {
        await startScan();
        return;
      }

      if (verifiedId) {
        await startScan(verifiedId);
        return;
      }

      const res = await fetch("/api/domain-verification", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: normalizedTarget, email: email.trim() }),
      });
      const data = await res.json();

      if (!res.ok) {
        setSubmitError(data.error || "Verification check failed");
        return;
      }

      if (!data.required) {
        await startScan();
        return;
      }

      setVerification({
        verificationId: data.verificationId,
        recordHost: data.recordHost,
        recordValue: data.recordValue,
        target: data.target,
      });
    } catch {
      setSubmitError("Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleVerified = async (verificationId: string) => {
    setVerifiedId(verificationId);
    setVerification(null);
    setSubmitting(true);
    setSubmitError(null);
    try {
      await startScan(verificationId);
    } catch {
      setSubmitError("Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleReset = () => {
    setTarget("");
    setEmail("");
    setTier("free");
    setDarkWebMonitoring(false);
    setSubmitError(null);
    setVerification(null);
    setVerifiedId(null);
  };

  return (
    <div className="flex min-h-screen flex-col bg-neutral-950 font-mono text-sm">
      <Header />

      <main className="flex flex-1 items-center justify-center px-4 sm:px-6 py-8 sm:py-12">
        <div className="w-full max-w-xl">
          <div className="border border-neutral-800 bg-neutral-900 rounded">
            <div className="flex items-center justify-between border-b border-neutral-800 px-4 py-3">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-[#A655F7] pulse-glow" />
                <span className="text-white">Ragnarok Testing System</span>
              </div>
              <span className="text-xs text-neutral-600 flicker">v1.0.8</span>
            </div>

            <div className="p-5">
              {verification ? (
                <DomainVerification
                  target={verification.target}
                  email={email.trim()}
                  recordHost={verification.recordHost}
                  recordValue={verification.recordValue}
                  verificationId={verification.verificationId}
                  onVerified={handleVerified}
                  onCancel={() => setVerification(null)}
                />
              ) : (
                <form onSubmit={handleSubmit}>
                  <div className="mb-5">
                    <div className="mb-2 flex items-center justify-between">
                      <div className="flex items-center">
                        <label className="text-xs text-neutral-400 uppercase tracking-wider">Target</label>
                        <Tooltip>
                          <p className="text-neutral-300 mb-2">Enter the URL or IP address of the target system.</p>
                          <p className="text-neutral-500 text-[11px]">
                            Example: <span className="text-neutral-300 font-mono">example.com</span>
                          </p>
                        </Tooltip>
                      </div>
                      {validation.type !== "empty" && (
                        <span className={`text-xs ${validation.valid ? "text-emerald-400" : "text-amber-400"}`}>
                          {validation.message}
                        </span>
                      )}
                    </div>
                    <div className="flex">
                      <div className="relative">
                        <select
                          value={protocol}
                          onChange={(e) => setProtocol(e.target.value as "https" | "http")}
                          className={`h-full cursor-pointer appearance-none bg-neutral-800 border pl-2 pr-6 py-2.5 text-xs text-neutral-300 focus:outline-none focus:border-[#A655F7] focus:z-10 focus:relative rounded-l-sm hover:bg-neutral-700/50 min-w-[72px] transition-colors ${
                            validation.type === "empty"
                              ? "border-neutral-700"
                              : validation.valid
                              ? "border-neutral-700 border-r-emerald-500/50"
                              : "border-neutral-700 border-r-amber-500/50"
                          }`}
                        >
                          <option value="https">https://</option>
                          <option value="http">http://</option>
                        </select>
                        <div className="pointer-events-none absolute inset-y-0 right-2 flex items-center">
                          <svg className="h-3 w-3 text-neutral-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </div>
                      </div>
                      <input
                        type="text"
                        value={target}
                        onChange={(e) => {
                          setTarget(e.target.value);
                          setVerifiedId(null);
                        }}
                        placeholder="example.com"
                        spellCheck={false}
                        className={`flex-1 min-w-0 -ml-px cursor-text bg-neutral-950 border px-3 py-2.5 text-white placeholder:text-neutral-600 focus:outline-none focus:relative focus:z-10 rounded-r-sm ${
                          validation.type === "empty"
                            ? "border-neutral-700 focus:border-[#A655F7]"
                            : validation.valid
                            ? "border-emerald-500/50 focus:border-emerald-500"
                            : "border-amber-500/50 focus:border-amber-500"
                        }`}
                      />
                    </div>
                  </div>

                  <TierSelector selected={tier} onSelect={setTier} />

                  <div className="mb-5">
                    <label
                      className={`flex items-start gap-3 cursor-pointer border px-3 py-2.5 rounded-sm transition-all ${
                        darkWebMonitoring
                          ? "border-[#A655F7]/50 bg-[#A655F7]/5"
                          : "border-neutral-700 bg-neutral-950 hover:border-neutral-600 hover:bg-neutral-900"
                      }`}
                      onClick={() => setDarkWebMonitoring(!darkWebMonitoring)}
                    >
                      <div
                        className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border transition-colors ${
                          darkWebMonitoring
                            ? "border-[#A655F7] bg-[#A655F7]"
                            : "border-neutral-600 bg-neutral-900"
                        }`}
                      >
                        {darkWebMonitoring && (
                          <svg className="h-3 w-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </div>
                      <div>
                        <div
                          className={`text-xs uppercase tracking-wider transition-colors ${
                            darkWebMonitoring ? "text-[#E3CAFE]" : "text-neutral-400"
                          }`}
                        >
                          Dark Web Monitoring
                        </div>
                        <div
                          className={`text-[11px] mt-0.5 transition-colors ${
                            darkWebMonitoring ? "text-neutral-500" : "text-neutral-600"
                          }`}
                        >
                          Scan the Dark Web for exposed data related to your target
                        </div>
                      </div>
                    </label>
                  </div>

                  <div className="mb-5">
                    <div className="mb-2 flex items-center">
                      <label className="text-xs text-neutral-400 uppercase tracking-wider">Email for Report</label>
                      <Tooltip>
                        <p className="text-neutral-300 mb-2">We&apos;ll send the scan report to this email when complete.</p>
                        <p className="text-neutral-500 text-[11px] mt-2">
                          Use an email on the target domain to skip DNS verification, e.g.{" "}
                          <span className="text-neutral-300">you@example.com</span> for example.com.
                        </p>
                      </Tooltip>
                    </div>
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value);
                        setVerifiedId(null);
                      }}
                      placeholder="your@email.com"
                      spellCheck={false}
                      className="w-full cursor-text bg-neutral-950 border border-neutral-700 px-3 py-2.5 text-white placeholder:text-neutral-600 focus:outline-none focus:border-[#A655F7] rounded-sm"
                    />
                  </div>

                  {submitError && (
                    <div className="mb-4 border border-red-500/30 bg-red-500/5 rounded p-3 text-xs text-red-300">
                      {submitError}
                    </div>
                  )}

                  <div className="flex items-center gap-3">
                    <button
                      type="submit"
                      disabled={!validation.valid || !emailValid || submitting}
                      className="flex-1 cursor-pointer bg-[#A655F7] px-4 py-2.5 text-white font-medium hover:bg-[#b875f8] disabled:bg-neutral-800 disabled:text-neutral-500 disabled:cursor-not-allowed rounded-sm glitch-hover"
                    >
                      {submitting ? "Starting..." : getScanCtaLabel(tier)}
                    </button>
                    <button
                      type="button"
                      onClick={handleReset}
                      className="cursor-pointer px-4 py-2.5 text-neutral-400 border border-neutral-700 hover:border-[#A655F7]/50 hover:text-white active:bg-neutral-800 rounded-sm transition-colors"
                    >
                      Reset
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
}
