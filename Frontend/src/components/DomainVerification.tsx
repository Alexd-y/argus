"use client";

import { useState } from "react";

interface DomainVerificationProps {
  target: string;
  email: string;
  recordHost: string;
  recordValue: string;
  verificationId: string;
  onVerified: (verificationId: string) => void;
  onCancel: () => void;
}

export function DomainVerification({
  target,
  email,
  recordHost,
  recordValue,
  verificationId,
  onVerified,
  onCancel,
}: DomainVerificationProps) {
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleVerify = async () => {
    setChecking(true);
    setError(null);
    try {
      const res = await fetch("/api/domain-verification/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verificationId }),
      });
      const data = await res.json();
      if (!res.ok || !data.verified) {
        setError(data.error || "Verification failed");
        return;
      }
      onVerified(verificationId);
    } catch {
      setError("Could not verify DNS record. Try again shortly.");
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="mb-5 border border-amber-500/30 bg-amber-500/5 rounded p-4">
      <h3 className="text-amber-200 font-medium text-sm mb-2">Verify domain ownership</h3>
      <p className="text-xs text-neutral-400 mb-4 leading-relaxed">
        Your email <span className="text-neutral-300">{email}</span> doesn&apos;t match{" "}
        <span className="text-neutral-300">{target}</span>. Add the TXT record below to prove you
        control this domain before scanning.
      </p>

      <div className="space-y-3 mb-4">
        <div className="border border-neutral-700 bg-neutral-950 rounded p-3">
          <div className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Record type</div>
          <div className="text-xs text-white font-mono">TXT</div>
        </div>
        <div className="border border-neutral-700 bg-neutral-950 rounded p-3">
          <div className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Host / Name</div>
          <div className="text-xs text-white font-mono break-all">{recordHost}</div>
        </div>
        <div className="border border-neutral-700 bg-neutral-950 rounded p-3">
          <div className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Value</div>
          <div className="text-xs text-[#E3CAFE] font-mono break-all">{recordValue}</div>
        </div>
      </div>

      {error && (
        <div className="mb-3 border border-red-500/30 bg-red-500/5 rounded p-3 text-xs text-red-300">
          {error}
        </div>
      )}

      <div className="flex flex-col sm:flex-row gap-2">
        <button
          type="button"
          onClick={handleVerify}
          disabled={checking}
          className="flex-1 cursor-pointer bg-[#A655F7] px-4 py-2.5 text-white font-medium hover:bg-[#b875f8] disabled:opacity-60 rounded-sm text-sm"
        >
          {checking ? "Checking DNS..." : "Verify & Continue"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="cursor-pointer px-4 py-2.5 text-neutral-400 border border-neutral-700 hover:text-white rounded-sm text-sm"
        >
          Back
        </button>
      </div>
    </div>
  );
}
