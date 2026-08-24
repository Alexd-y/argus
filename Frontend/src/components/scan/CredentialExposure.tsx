"use client";

import type { CredentialLeak } from "@/lib/scan-results";
import { getTierConfig } from "@/lib/scan-tiers";

interface CredentialExposureProps {
  leaks: CredentialLeak[];
  anchor: string;
}

const SECRET_PILL: Record<CredentialLeak["secretKind"], string> = {
  plaintext: "border-red-500/40 bg-red-500/10 text-red-300",
  hash: "border-amber-500/40 bg-amber-500/10 text-amber-300",
};

function LeakRow({ leak }: { leak: CredentialLeak }) {
  const locked = leak.access === "locked";

  return (
    <div className="grid grid-cols-1 gap-x-4 gap-y-2 px-4 py-3.5 sm:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)_minmax(0,1.1fr)]">
      <div className="min-w-0">
        <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-1 sm:hidden">Account</div>
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <p className="text-xs text-white break-all">{leak.identity}</p>
          <span className="text-[10px] uppercase tracking-wider text-neutral-500">
            {leak.identityKind}
          </span>
        </div>
        {leak.exposed.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {leak.exposed.map((item) => (
              <span
                key={item}
                className="text-[10px] border border-neutral-700 bg-neutral-950 text-neutral-400 px-1.5 py-0.5 rounded-full"
              >
                {item}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="min-w-0">
        <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-1 sm:hidden">Source</div>
        {locked ? (
          <p className="text-xs text-neutral-600">Hidden on {getTierConfig("free").name}</p>
        ) : (
          <>
            <p className="text-xs text-neutral-300">{leak.source}</p>
            <p className="text-[11px] text-neutral-500 mt-0.5">{leak.breachedAt}</p>
          </>
        )}
      </div>

      <div className="min-w-0">
        <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-1 sm:hidden">Password</div>
        {leak.access === "full" ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`text-[10px] uppercase tracking-wider border px-1.5 py-0.5 rounded-sm ${SECRET_PILL[leak.secretKind]}`}
              >
                {leak.secretKind === "plaintext" ? "Plaintext" : "Hashed"}
              </span>
              <code className="font-mono text-[11px] text-neutral-200 break-all">{leak.secret}</code>
            </div>
            <p className="text-[11px] text-neutral-500 mt-1">
              {leak.algorithm ?? "Stored without hashing in the dump"}
            </p>
          </>
        ) : (
          <p className="text-xs text-neutral-600">
            {leak.access === "summary"
              ? `Password detail on ${getTierConfig("premium").name}`
              : `Included on ${getTierConfig("standard").name} and ${getTierConfig("premium").name}`}
          </p>
        )}
      </div>
    </div>
  );
}

export function CredentialExposure({ leaks, anchor }: CredentialExposureProps) {
  if (leaks.length === 0) return null;

  return (
    <section id={anchor} className="scroll-mt-6">
      <h2 className="text-white text-base mb-1">Dark web exposure</h2>
      <p className="text-xs text-neutral-500 mb-4 leading-relaxed">
        Email addresses and usernames tied to this domain that appear in public breach dumps and
        credential-stuffing lists. Anyone can buy these, so any password reused elsewhere is already
        compromised.
      </p>

      <div className="border border-neutral-800 bg-neutral-900 rounded-sm overflow-hidden">
        <div className="hidden sm:grid grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)_minmax(0,1.1fr)] gap-x-4 border-b border-neutral-800 bg-neutral-950 px-4 py-2">
          <div className="text-[10px] uppercase tracking-wider text-neutral-500">Account</div>
          <div className="text-[10px] uppercase tracking-wider text-neutral-500">Source</div>
          <div className="text-[10px] uppercase tracking-wider text-neutral-500">Password</div>
        </div>
        <div className="divide-y divide-neutral-800">
          {leaks.map((leak) => (
            <LeakRow key={leak.id} leak={leak} />
          ))}
        </div>
      </div>

      <p className="text-[11px] text-neutral-500 mt-3 leading-relaxed">
        Rotate every password above, revoke the exposed API token, and turn on multi-factor
        authentication for these mailboxes. Secrets are shown redacted; we never store or transmit a
        full credential.
      </p>
    </section>
  );
}
