"use client";

import { Fragment, useEffect, useRef } from "react";
import type { ComparisonValue, ScanTier } from "@/lib/scan-tiers";
import { SCAN_TIERS, TIER_COMPARISON } from "@/lib/scan-tiers";

interface TierComparisonModalProps {
  open: boolean;
  selected: ScanTier;
  onSelect: (tier: ScanTier) => void;
  onClose: () => void;
}

function Cell({ value, highlight }: { value: ComparisonValue; highlight: boolean }) {
  if (value === true) {
    return <span className="text-emerald-400">✓</span>;
  }
  if (value === false) {
    return <span className="text-neutral-700">—</span>;
  }
  return (
    <span className={highlight ? "text-[#E3CAFE]" : "text-neutral-400"}>{value}</span>
  );
}

export function TierComparisonModal({
  open,
  selected,
  onSelect,
  onClose,
}: TierComparisonModalProps) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    closeRef.current?.focus();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    const { overflow } = document.body.style;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = overflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[200] flex items-end sm:items-center justify-center bg-black/80 p-0 sm:p-6"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Compare scan levels"
        onClick={(e) => e.stopPropagation()}
        className="flex max-h-[92vh] w-full max-w-3xl flex-col overflow-hidden rounded-t sm:rounded border border-neutral-800 bg-neutral-900 font-mono shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 border-b border-neutral-800 px-4 sm:px-5 py-4">
          <div>
            <h2 className="text-white text-sm mb-2">Compare scan levels</h2>
            <p className="text-[11px] text-neutral-500 leading-relaxed">
              Every level runs the same automated external scan. What changes is the scope, how much of
              the result is unlocked, and how often the target is rescanned. Your scan starts right
              away — subscribe only once you&apos;ve seen what it found.
            </p>
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label="Close comparison"
            className="cursor-pointer rounded-sm border border-neutral-700 px-2 py-1 text-xs text-neutral-400 hover:border-[#A655F7]/50 hover:text-white"
          >
            ✕
          </button>
        </div>

        <div className="overflow-y-auto overflow-x-auto">
          <table className="w-full min-w-[560px] border-collapse text-left">
            <thead className="sticky top-0 z-10 bg-neutral-900">
              <tr className="border-b border-neutral-800">
                <th className="w-[34%] px-4 sm:px-5 py-3 text-[10px] uppercase tracking-wider text-neutral-500 font-normal">
                  Feature
                </th>
                {SCAN_TIERS.map((tier) => (
                  <th
                    key={tier.id}
                    className={`px-3 py-3 align-top ${
                      selected === tier.id ? "bg-[#A655F7]/10" : ""
                    }`}
                  >
                    <div className="text-white text-xs font-medium">{tier.name}</div>
                    <div
                      className={`text-[11px] mt-1 ${
                        tier.priceCents === null ? "text-emerald-400" : "text-neutral-300"
                      }`}
                    >
                      {tier.priceLabel}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {TIER_COMPARISON.map((group) => (
                <Fragment key={group.title}>
                  <tr className="bg-neutral-950/60">
                    <td
                      colSpan={SCAN_TIERS.length + 1}
                      className="px-4 sm:px-5 py-2 text-[10px] uppercase tracking-wider text-neutral-500 border-y border-neutral-800"
                    >
                      {group.title}
                    </td>
                  </tr>
                  {group.rows.map((row) => (
                    <tr key={row.label} className="border-b border-neutral-800/60">
                      <td className="px-4 sm:px-5 py-2.5 align-top">
                        <div className="text-[11px] text-neutral-300">{row.label}</div>
                        {row.hint && (
                          <div className="text-[10px] text-neutral-600 mt-0.5">{row.hint}</div>
                        )}
                      </td>
                      {SCAN_TIERS.map((tier) => (
                        <td
                          key={tier.id}
                          className={`px-3 py-2.5 align-top text-[11px] leading-relaxed ${
                            selected === tier.id ? "bg-[#A655F7]/10" : ""
                          }`}
                        >
                          <Cell value={row.values[tier.id]} highlight={selected === tier.id} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>

        <div className="border-t border-neutral-800 px-4 sm:px-5 py-3">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {SCAN_TIERS.map((tier) => (
              <button
                key={tier.id}
                type="button"
                onClick={() => {
                  onSelect(tier.id);
                  onClose();
                }}
                className={`cursor-pointer rounded-sm px-3 py-2 text-xs transition-colors ${
                  selected === tier.id
                    ? "bg-[#A655F7] text-white hover:bg-[#b875f8]"
                    : "border border-neutral-700 text-neutral-300 hover:border-[#A655F7]/50 hover:text-white"
                }`}
              >
                {selected === tier.id ? `Keep ${tier.name}` : `Choose ${tier.name}`}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
