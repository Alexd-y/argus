"use client";

import { useState } from "react";
import { VERIFICATION_RELATIVE_HOST, verificationFileUrl } from "@/lib/domain-verification";

interface DomainVerificationProps {
  target: string;
  email: string;
  recordHost: string;
  recordValue: string;
  verificationId: string;
  onVerified: (verificationId: string) => void;
  onCancel: () => void;
}

type VerifyMethod = "dns" | "file";

export function DomainVerification({
  target,
  email,
  recordValue,
  verificationId,
  onVerified,
  onCancel,
}: DomainVerificationProps) {
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [method, setMethod] = useState<VerifyMethod>("dns");
  const fileUrl = verificationFileUrl(target);

  const handleVerify = async () => {
    setChecking(true);
    setError(null);
    try {
      const res = await fetch("/api/domain-verification/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          verificationId,
          target,
          email,
          token: recordValue,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.verified || typeof data.verificationId !== "string") {
        setError(data.error || "Verification failed");
        return;
      }
      onVerified(data.verificationId);
    } catch {
      setError("Could not verify ownership. Try again shortly.");
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="border border-amber-500/30 bg-amber-500/5 rounded p-4">
      <h3 className="text-amber-200 font-medium text-sm mb-2">Verify domain ownership</h3>
      <p className="text-xs text-neutral-400 mb-4 leading-relaxed">
        Your email <span className="text-neutral-300">{email}</span> doesn&apos;t match{" "}
        <span className="text-neutral-300">{target}</span>. Prove ownership with a DNS TXT record or a
        file on the site, then verify. The value is unique to this email and domain.
      </p>
      <p className="text-[11px] text-neutral-500 mb-4 leading-relaxed">
        Scanning a client&apos;s domain? This is the path for you — either method works from your own
        email, as long as the client gives you DNS or file access.
      </p>

      <div className="flex gap-2 mb-4">
        <button
          type="button"
          onClick={() => setMethod("dns")}
          className={`flex-1 cursor-pointer px-3 py-2 text-xs rounded-sm border ${
            method === "dns"
              ? "border-[#A655F7] bg-[#A655F7]/10 text-white"
              : "border-neutral-700 text-neutral-400 hover:text-white"
          }`}
        >
          DNS TXT
        </button>
        <button
          type="button"
          onClick={() => setMethod("file")}
          className={`flex-1 cursor-pointer px-3 py-2 text-xs rounded-sm border ${
            method === "file"
              ? "border-[#A655F7] bg-[#A655F7]/10 text-white"
              : "border-neutral-700 text-neutral-400 hover:text-white"
          }`}
        >
          File
        </button>
      </div>

      <div className="space-y-3 mb-4">
        {method === "dns" ? (
          <>
            <div className="border border-neutral-700 bg-neutral-950 rounded p-3">
              <div className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Record type</div>
              <div className="text-xs text-white font-mono">TXT</div>
            </div>
            <div className="border border-neutral-700 bg-neutral-950 rounded p-3">
              <div className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Host / Name</div>
              <div className="text-xs text-white font-mono break-all">{VERIFICATION_RELATIVE_HOST}</div>
              <div className="text-[10px] text-neutral-600 mt-1">
                Most DNS panels append {target} automatically — don&apos;t paste the full domain.
              </div>
            </div>
          </>
        ) : (
          <div className="border border-neutral-700 bg-neutral-950 rounded p-3">
            <div className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">File URL</div>
            <div className="text-xs text-white font-mono break-all">{fileUrl}</div>
            <div className="text-[10px] text-neutral-600 mt-1">
              Create this file over HTTPS. The body must be the value below, nothing else.
            </div>
          </div>
        )}
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
          {checking ? "Checking..." : "Verify & Continue"}
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
