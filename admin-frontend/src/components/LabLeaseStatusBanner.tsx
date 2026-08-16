"use client";

import { isValidLabLease } from "@/lib/labApproval";
import type { LabLeaseResponse, LabScopeManifestResponse } from "@/lib/scanApi";

interface LabLeaseStatusBannerProps {
  lease: LabLeaseResponse | null;
  manifest?: LabScopeManifestResponse | null;
  className?: string;
}

function leaseStatusClass(status: string, usable: boolean): string {
  if (!usable && status === "active") {
    return "border-amber-800/50 bg-amber-950/20 text-amber-200";
  }
  switch (status) {
    case "active":
      return "border-emerald-800/50 bg-emerald-950/30 text-emerald-200";
    case "expired":
    case "revoked":
    case "kill_switched":
      return "border-red-900/50 bg-red-950/30 text-red-200";
    default:
      return "border-neutral-700 bg-neutral-900/40 text-neutral-300";
  }
}

function formatTs(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toISOString();
}

function joinList(items: string[] | undefined, empty = "—"): string {
  if (!items || items.length === 0) return empty;
  return items.join(", ");
}

export function LabLeaseStatusBanner({
  lease,
  manifest = null,
  className = "",
}: LabLeaseStatusBannerProps) {
  if (!lease && !manifest) {
    return (
      <div
        className={`rounded border border-neutral-700 bg-neutral-900/40 px-3 py-2 text-sm text-neutral-400 ${className}`}
        data-testid="lab-lease-status"
      >
        Lab scope / lease: pending — issued when the scan starts in{" "}
        <span className="text-amber-300">lab_unrestricted</span> mode.
      </div>
    );
  }

  const usable = isValidLabLease(lease);
  const status = lease?.status ?? (manifest ? "pending_lease" : "unknown");

  return (
    <div
      className={`rounded border px-3 py-2 text-sm ${leaseStatusClass(status, usable)} ${className}`}
      data-testid="lab-lease-status"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold uppercase tracking-wide">Lab lease</span>
        <span className="rounded border border-current/30 px-1.5 py-0.5 text-xs uppercase">
          {status.replace(/_/g, " ")}
        </span>
        {lease && !usable && (
          <span className="text-xs uppercase opacity-80">not usable</span>
        )}
      </div>

      {lease && (
        <dl className="mt-2 grid gap-0.5 font-mono text-xs opacity-90 sm:grid-cols-2">
          <div>
            <dt className="inline text-neutral-500">lease_id: </dt>
            <dd className="inline break-all">{lease.lease_id}</dd>
          </div>
          <div>
            <dt className="inline text-neutral-500">expires_at: </dt>
            <dd className="inline">{formatTs(lease.expires_at)}</dd>
          </div>
          <div>
            <dt className="inline text-neutral-500">kill_switch_cleared: </dt>
            <dd className="inline">{String(lease.kill_switch_cleared)}</dd>
          </div>
          <div>
            <dt className="inline text-neutral-500">requires_approval: </dt>
            <dd className="inline">
              {String(lease.policy?.requires_approval ?? false)}
            </dd>
          </div>
          {lease.boundary_proof && (
            <div className="sm:col-span-2">
              <dt className="inline text-neutral-500">boundary_proof: </dt>
              <dd className="inline break-all">{lease.boundary_proof}</dd>
            </div>
          )}
        </dl>
      )}

      {manifest && (
        <div className="mt-3 border-t border-current/20 pt-2">
          <div className="mb-1 text-xs font-semibold uppercase tracking-wide opacity-90">
            LabScopeManifest
          </div>
          <dl className="grid gap-0.5 font-mono text-xs opacity-90 sm:grid-cols-2">
            <div>
              <dt className="inline text-neutral-500">manifest_id: </dt>
              <dd className="inline break-all">{manifest.manifest_id}</dd>
            </div>
            <div>
              <dt className="inline text-neutral-500">expires_at: </dt>
              <dd className="inline">{formatTs(manifest.expires_at)}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="inline text-neutral-500">cidrs: </dt>
              <dd className="inline">{joinList(manifest.cidrs)}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="inline text-neutral-500">dns_suffixes: </dt>
              <dd className="inline">{joinList(manifest.dns_suffixes)}</dd>
            </div>
            <div>
              <dt className="inline text-neutral-500">capture_full: </dt>
              <dd className="inline">{String(manifest.capture_full)}</dd>
            </div>
            <div>
              <dt className="inline text-neutral-500">internet_attached: </dt>
              <dd className="inline">{String(manifest.internet_attached)}</dd>
            </div>
          </dl>
        </div>
      )}
    </div>
  );
}
