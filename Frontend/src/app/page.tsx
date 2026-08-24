"use client";

import React, { useState, useMemo, useEffect, useLayoutEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import type { ScanTier } from "@/lib/scan-tiers";
import { getScanCtaLabel, getTierConfig } from "@/lib/scan-tiers";
import { emailMatchesTarget } from "@/lib/domain-verification";
import { validateTarget, extractHostname, inferProtocol, isValidEmail } from "@/lib/validation";
import {
  loadScanSession,
  saveScanSession,
  clearScanSession,
  type VerificationChallenge,
} from "@/lib/scan-session";
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

export default function Home() {
  const router = useRouter();
  const skipPersist = useRef(false);
  const emailInputRef = useRef<HTMLInputElement>(null);
  const dismissedVerification = useRef(false);
  const [restoreEpoch, setRestoreEpoch] = useState(0);
  const [target, setTarget] = useState("");
  const [protocol, setProtocol] = useState<"https" | "http">("https");
  const [email, setEmail] = useState("");
  const [tier, setTier] = useState<ScanTier>("free");
  const [darkWebMonitoring, setDarkWebMonitoring] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [verification, setVerification] = useState<VerificationChallenge | null>(null);
  const [challenge, setChallenge] = useState<VerificationChallenge | null>(null);
  const [verifiedId, setVerifiedId] = useState<string | null>(null);

  useLayoutEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect -- hydrate from localStorage after mount */
    const stored = loadScanSession();
    if (stored) {
      setTarget(stored.target);
      setProtocol(stored.protocol);
      setEmail(stored.email);
      setTier(stored.tier);
      setDarkWebMonitoring(stored.darkWebMonitoring);
      setVerification(stored.verification);
      setChallenge(stored.challenge);
      setVerifiedId(stored.verifiedId);
    }
    setRestoreEpoch(1);
    /* eslint-enable react-hooks/set-state-in-effect */

    const pending = stored?.challenge;
    if (!pending || !stored?.email) return;

    let cancelled = false;
    void fetch("/api/domain-verification", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: pending.target,
        email: stored.email,
        verificationId: pending.verificationId,
        token: pending.recordValue,
      }),
    })
      .then(async (res) => {
        const data = await res.json().catch(() => null);
        if (cancelled || dismissedVerification.current || !res.ok || !data) return;
        if (!data.required) {
          if (typeof data.verificationId === "string") {
            setVerifiedId(data.verificationId);
          }
          setVerification(null);
          return;
        }

        if (typeof data.verificationId === "string" && data.recordValue) {
          const nextChallenge: VerificationChallenge = {
            verificationId: data.verificationId,
            recordHost: data.recordHost,
            recordValue: data.recordValue,
            target: data.target,
          };
          setChallenge(nextChallenge);
          if (stored.verification) setVerification(nextChallenge);
        }
      })
      .catch(() => {
        // UI already comes from localStorage; server re-seed is best-effort
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (restoreEpoch < 1 || skipPersist.current) return;
    saveScanSession({
      target,
      protocol,
      email,
      tier,
      darkWebMonitoring,
      verification,
      challenge,
      verifiedId,
    });
  }, [
    restoreEpoch,
    target,
    protocol,
    email,
    tier,
    darkWebMonitoring,
    verification,
    challenge,
    verifiedId,
  ]);

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
      if (data.code === "VERIFICATION_REQUIRED") {
        setVerifiedId(null);
        if (challenge) {
          setVerification(challenge);
        }
        setSubmitError("Domain ownership verification required");
        return;
      }
      setSubmitError(data.error || "Failed to start scan");
      return;
    }
    if (typeof data.id !== "string" || typeof data.url !== "string") {
      setSubmitError("Failed to start scan");
      return;
    }
    skipPersist.current = true;
    clearScanSession();
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
        body: JSON.stringify({
          target: normalizedTarget,
          email: email.trim(),
          verificationId: challenge?.verificationId,
          token: challenge?.recordValue,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        setSubmitError(data.error || "Verification check failed");
        return;
      }

      if (!data.required) {
        await startScan(data.verificationId);
        return;
      }

      const nextChallenge: VerificationChallenge = {
        verificationId: data.verificationId,
        recordHost: data.recordHost,
        recordValue: data.recordValue,
        target: data.target,
      };
      setChallenge(nextChallenge);
      setVerification(nextChallenge);
    } catch {
      setSubmitError("Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleVerified = async (verificationId: string) => {
    setVerifiedId(verificationId);
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

  const invalidateOwnership = () => {
    dismissedVerification.current = true;
    setVerifiedId(null);
    setVerification(null);
    setChallenge(null);
  };

  const handleReset = () => {
    skipPersist.current = false;
    dismissedVerification.current = true;
    clearScanSession();
    setTarget("");
    setEmail("");
    setTier("free");
    setProtocol("https");
    setDarkWebMonitoring(false);
    setSubmitError(null);
    setVerification(null);
    setChallenge(null);
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
                <span className="text-white">Ragnarøk Testing System</span>
              </div>
              <span className="text-xs text-neutral-600 flicker">v1.1.0</span>
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
                  onCancel={() => {
                    dismissedVerification.current = true;
                    setVerification(null);
                  }}
                />
              ) : (
              <form onSubmit={handleSubmit}>
                  <div className="mb-5">
                    <div className="mb-2 flex items-center justify-between">
                      <div className="flex items-center">
                        <label className="text-xs text-neutral-400 uppercase tracking-wider">Target</label>
                        <Tooltip>
                          <p className="text-neutral-300 mb-2">Enter a public domain, URL, or IP address.</p>
                          <p className="text-neutral-500 text-[11px]">
                            Example: <span className="text-neutral-300 font-mono">example.com</span>
                          </p>
                          <p className="text-neutral-500 text-[11px] mt-2">
                            HTTPS is used unless you paste an http:// URL.
                          </p>
                        </Tooltip>
                      </div>
                      {validation.type !== "empty" && (
                        <span className={`text-xs ${validation.valid ? "text-emerald-400" : "text-amber-400"}`}>
                          {validation.message}
                        </span>
                      )}
                    </div>
                    <input
                        type="text"
                        value={target}
                        onChange={(e) => {
                          const value = e.target.value;
                          setTarget(value);
                          setProtocol(inferProtocol(value));
                          invalidateOwnership();
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Tab" && !e.shiftKey) {
                            e.preventDefault();
                            emailInputRef.current?.focus();
                          }
                        }}
                        placeholder="example.com"
                        spellCheck={false}
                        autoComplete="url"
                        className={`w-full cursor-text bg-neutral-950 border px-3 py-2.5 text-white placeholder:text-neutral-600 focus:outline-none rounded-sm ${
                          validation.type === "empty"
                            ? "border-neutral-700 focus:border-[#A655F7]"
                            : validation.valid
                            ? "border-emerald-500/50 focus:border-emerald-500"
                            : "border-amber-500/50 focus:border-amber-500"
                        }`}
                      />
                  </div>

                  <TierSelector selected={tier} onSelect={setTier} />

                  <div className="mb-5">
                    <label
                      className={`flex items-start gap-3 cursor-pointer border px-3 py-2.5 rounded-sm transition-all ${
                        darkWebMonitoring || tier !== "free"
                          ? "border-[#A655F7]/50 bg-[#A655F7]/5"
                          : "border-neutral-700 bg-neutral-950 hover:border-neutral-600 hover:bg-neutral-900"
                      }`}
                      onClick={() => {
                        if (tier === "free") setDarkWebMonitoring(!darkWebMonitoring);
                      }}
                    >
                      <div
                        className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border transition-colors ${
                          darkWebMonitoring || tier !== "free"
                            ? "border-[#A655F7] bg-[#A655F7]"
                            : "border-neutral-600 bg-neutral-900"
                        }`}
                      >
                        {(darkWebMonitoring || tier !== "free") && (
                          <svg className="h-3 w-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </div>
                      <div>
                        <div
                          className={`text-xs uppercase tracking-wider transition-colors ${
                            darkWebMonitoring || tier !== "free" ? "text-[#E3CAFE]" : "text-neutral-400"
                          }`}
                        >
                          Dark Web Monitoring
                        </div>
                        <div
                          className={`text-[11px] mt-0.5 transition-colors ${
                            darkWebMonitoring || tier !== "free" ? "text-neutral-500" : "text-neutral-600"
                          }`}
                        >
                          {tier === "free"
                            ? "Scan the Dark Web for exposed data related to your target"
                            : `Included on ${getTierConfig("standard").name} and ${getTierConfig("premium").name}`}
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
                          Use an email on the target domain to skip ownership verification, e.g.{" "}
                          <span className="text-neutral-300">you@example.com</span> for example.com.
                        </p>
                        <p className="text-neutral-500 text-[11px] mt-2">
                          Scanning a client&apos;s domain? Use your own email and prove ownership with a
                          DNS record or a file on their site.
                        </p>
                      </Tooltip>
                    </div>
                    <input
                      ref={emailInputRef}
                      type="email"
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value);
                        invalidateOwnership();
                      }}
                      placeholder="your@email.com"
                      spellCheck={false}
                      autoComplete="email"
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
