import type { CheckPriority, Finding } from "@/lib/scan-results";

const PRIORITY_PILL: Record<CheckPriority, string> = {
  critical: "border-red-500/40 text-red-400 bg-red-500/10",
  important: "border-orange-500/40 text-orange-400 bg-orange-500/10",
  medium: "border-amber-500/40 text-amber-400 bg-amber-500/10",
  optional: "border-neutral-700 text-neutral-400 bg-neutral-900",
};

const PRIORITY_MARK: Record<CheckPriority, string> = {
  critical: "bg-red-500",
  important: "bg-orange-400",
  medium: "bg-amber-400",
  optional: "bg-neutral-600",
};

interface TopFindingsListProps {
  findings: Finding[];
  anchor: string;
}

export function TopFindingsList({ findings, anchor }: TopFindingsListProps) {
  if (findings.length === 0) {
    return <p className="text-xs text-neutral-500">No open findings on this target.</p>;
  }

  return (
    <div className="space-y-3">
      <ul className="space-y-px bg-neutral-800">
        {findings.map((finding) => (
          <li key={finding.id} className="flex items-center gap-3 bg-neutral-900 py-2">
            <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center border border-neutral-800 rounded-sm">
              <span className={`h-1.5 w-1.5 rounded-full ${PRIORITY_MARK[finding.priority]}`} />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs text-white">{finding.name}</span>
              <span className="block truncate text-[10px] text-neutral-500">{finding.group}</span>
            </span>
            <span
              className={`flex-shrink-0 border px-1.5 py-0.5 text-[9px] uppercase tracking-wider rounded-sm ${PRIORITY_PILL[finding.priority]}`}
            >
              {finding.priority}
            </span>
          </li>
        ))}
      </ul>
      <a
        href={`#${anchor}`}
        className="inline-flex items-center gap-1.5 text-[11px] text-[#A655F7] hover:text-[#b875f8]"
      >
        View all findings
        <span aria-hidden="true">→</span>
      </a>
    </div>
  );
}
