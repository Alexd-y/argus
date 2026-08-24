import type { CSSProperties } from "react";
import type { CategorySlice, SeverityKey } from "@/lib/scan-summary";

const SEGMENT: Array<{ key: SeverityKey; className: string }> = [
  { key: "critical", className: "bg-red-500" },
  { key: "important", className: "bg-orange-400" },
  { key: "optional", className: "bg-amber-400" },
];

interface CategoryBarsProps {
  rows: CategorySlice[];
}

export function CategoryBars({ rows }: CategoryBarsProps) {
  const max = rows.reduce((peak, row) => Math.max(peak, row.open), 0);

  if (max === 0) {
    return (
      <p className="text-xs text-neutral-500">
        No open findings across the {rows.length} scanned categories.
      </p>
    );
  }

  return (
    <ul className="space-y-3.5">
      {rows.map((row, index) => (
        <li key={row.groupId}>
          <div className="flex items-baseline justify-between gap-3">
            <span className="min-w-0 truncate text-[11px] text-neutral-300">{row.group}</span>
            <span className="flex-shrink-0 text-[11px] text-white tabular-nums">
              {row.open}
              <span className="text-neutral-600">/{row.checks}</span>
            </span>
          </div>
          <div className="mt-1.5 h-2.5 overflow-hidden bg-neutral-950 border border-neutral-800 rounded-sm">
            <div
              className="flex h-full gap-px bar-grow"
              style={{ animationDelay: `${index * 70}ms` } as CSSProperties}
            >
              {SEGMENT.map((segment) => {
                const count = row.bySeverity[segment.key];
                if (count === 0) return null;
                return (
                  <span
                    key={segment.key}
                    className={segment.className}
                    style={{ width: `${(count / max) * 100}%` }}
                  />
                );
              })}
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}
