"use client";

interface LabUnrestrictedBadgeProps {
  className?: string;
}

/** Persistent LAB indicator (master §17). Never gated by production risk labels. */
export function LabUnrestrictedBadge({ className = "" }: LabUnrestrictedBadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border-2 border-amber-500 bg-amber-950 px-3 py-1 text-sm font-bold uppercase tracking-wider text-amber-200 shadow-[0_0_12px_rgba(245,158,11,0.25)] ${className}`}
      title="Execution mode: lab unrestricted — approval gates bypassed with valid lease"
      data-testid="lab-unrestricted-badge"
      role="status"
    >
      <span className="h-2 w-2 animate-pulse rounded-full bg-amber-400" aria-hidden />
      LAB UNRESTRICTED
    </span>
  );
}
