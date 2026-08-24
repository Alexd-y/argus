"use client";

import { useState } from "react";
import type { ScanTier } from "@/lib/scan-tiers";
import { SCAN_TIERS } from "@/lib/scan-tiers";
import { TierComparisonModal } from "@/components/TierComparisonModal";

interface TierSelectorProps {
  selected: ScanTier;
  onSelect: (tier: ScanTier) => void;
}

export function TierSelector({ selected, onSelect }: TierSelectorProps) {
  const [comparing, setComparing] = useState(false);

  return (
    <div className="mb-5">
      <div className="mb-4 flex items-baseline justify-between gap-3">
        <label className="text-xs text-neutral-400 uppercase tracking-wider">
          Choose scan level
        </label>
        <button
          type="button"
          onClick={() => setComparing(true)}
          className="cursor-pointer text-[11px] text-[#A655F7] underline underline-offset-2 hover:text-[#c996fa]"
        >
          Help me choose
        </button>
      </div>
      <div className="grid grid-cols-1 gap-2">
        {SCAN_TIERS.map((tier) => {
          const isSelected = selected === tier.id;
          return (
            <button
              key={tier.id}
              type="button"
              onClick={() => onSelect(tier.id)}
              className={`relative cursor-pointer text-left border rounded-sm overflow-hidden transition-all ${
                isSelected
                  ? "border-[#A655F7] bg-[#A655F7]/10"
                  : "border-neutral-700 bg-neutral-950 hover:border-neutral-600 hover:bg-neutral-900"
              }`}
            >
              {tier.popular && (
                <div className="bg-[#A655F7] text-white text-[9px] uppercase tracking-wider text-center py-1 font-medium">
                  Most popular
                </div>
              )}
              <div className="px-3 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <div
                        className={`h-3.5 w-3.5 rounded-full border flex-shrink-0 ${
                          isSelected ? "border-[#A655F7] bg-[#A655F7]" : "border-neutral-600"
                        }`}
                      >
                        {isSelected && (
                          <div className="h-full w-full rounded-full border-2 border-neutral-950" />
                        )}
                      </div>
                      <span className="text-white font-medium text-sm">{tier.name}</span>
                    </div>
                    <p className="text-[11px] text-neutral-500 leading-relaxed pl-5">{tier.description}</p>
                    {tier.id !== "free" && (
                      <p className="text-[10px] text-neutral-600 mt-1.5 pl-5">
                        {tier.priceLabel} — billed when you unlock the program
                      </p>
                    )}
                  </div>
                  <span
                    className={`text-sm font-medium flex-shrink-0 pt-0.5 ${
                      tier.priceCents === null ? "text-emerald-400" : "text-white"
                    }`}
                  >
                    {tier.priceLabel}
                  </span>
                </div>
              </div>
            </button>
          );
        })}
      </div>

      <TierComparisonModal
        open={comparing}
        selected={selected}
        onSelect={onSelect}
        onClose={() => setComparing(false)}
      />
    </div>
  );
}
