import type { CSSProperties } from "react";
import type { SeverityKey, SeveritySlice } from "@/lib/scan-summary";

const ARC_COLOR: Record<SeverityKey, string> = {
  critical: "#ef4444",
  important: "#fb923c",
  optional: "#fbbf24",
};

const LEGEND_DOT: Record<SeverityKey, string> = {
  critical: "bg-red-500",
  important: "bg-orange-400",
  optional: "bg-amber-400",
};

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

interface SeverityDonutProps {
  slices: SeveritySlice[];
  open: number;
}

export function SeverityDonut({ slices, open }: SeverityDonutProps) {
  const drawn = slices.filter((slice) => slice.count > 0);
  const gap = drawn.length > 1 ? 3 : 0;

  let cursor = 0;
  const arcs = drawn.map((slice) => {
    const span = (slice.count / open) * CIRCUMFERENCE;
    const arc = { key: slice.key, offset: cursor, length: Math.max(span - gap, 1) };
    cursor += span;
    return arc;
  });

  return (
    <div className="space-y-5">
      <div className="relative mx-auto h-44 w-44 sm:h-48 sm:w-48">
        <svg viewBox="0 0 132 132" className="h-full w-full -rotate-90">
          <circle cx="66" cy="66" r={RADIUS} fill="none" stroke="#262626" strokeWidth="14" />
          {arcs.map((arc, index) => (
            <circle
              key={arc.key}
              cx="66"
              cy="66"
              r={RADIUS}
              fill="none"
              stroke={ARC_COLOR[arc.key]}
              strokeWidth="14"
              strokeDasharray={`${arc.length} ${CIRCUMFERENCE}`}
              strokeDashoffset={-arc.offset}
              className="arc-draw"
              style={
                {
                  "--arc-len": `${arc.length}px`,
                  "--arc-gap": `${CIRCUMFERENCE}px`,
                  animationDelay: `${index * 120}ms`,
                } as CSSProperties
              }
            />
          ))}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl text-white tabular-nums leading-none">{open}</span>
          <span className="text-[10px] uppercase tracking-wider text-neutral-500 mt-1.5">
            {open === 1 ? "Open finding" : "Open findings"}
          </span>
        </div>
      </div>

      <ul className="space-y-2.5 border-t border-neutral-800 pt-4">
        {slices.map((slice) => (
          <li key={slice.key} className="flex items-center gap-2.5 text-xs">
            <span className={`h-2 w-2 flex-shrink-0 rounded-full ${LEGEND_DOT[slice.key]}`} />
            <span className="text-neutral-300 flex-1 truncate">{slice.label}</span>
            <span className="text-white tabular-nums">{slice.count}</span>
            <span className="w-10 text-right text-neutral-500 tabular-nums">
              {open > 0 ? `${slice.pctOfOpen}%` : "—"}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
