"use client";

import type { ExecutionMode } from "@/lib/lab/types";

interface ExecutionModeSelectorProps {
  value: ExecutionMode;
  onChange: (mode: ExecutionMode) => void;
  disabled?: boolean;
  lockedReason?: string | null;
}

const MODES: { value: ExecutionMode; label: string; description: string }[] = [
  {
    value: "production",
    label: "Production",
    description: "Standard policy gates and approval flows",
  },
  {
    value: "lab_unrestricted",
    label: "LAB Unrestricted",
    description: "Verified LAB lease bypasses approval for mutating actions",
  },
  {
    value: "quick",
    label: "Quick",
    description: "Bounded quick profile — LAB is still listed and selectable before lock",
  },
];

function modeDescription(mode: ExecutionMode): string {
  switch (mode) {
    case "production":
      return MODES[0].description;
    case "lab_unrestricted":
      return MODES[1].description;
    case "quick":
      return MODES[2].description;
    default: {
      const _exhaustive: never = mode;
      return _exhaustive;
    }
  }
}

/** Always list LAB — never hide it behind production risk labels (§17). */
export function ExecutionModeSelector({
  value,
  onChange,
  disabled = false,
  lockedReason,
}: ExecutionModeSelectorProps) {
  return (
    <fieldset
      className="rounded border border-neutral-800 bg-neutral-900 p-4"
      disabled={disabled}
      data-testid="execution-mode-selector"
    >
      <legend className="px-1 text-sm font-medium text-neutral-300">
        Execution mode
        {disabled ? (
          <span className="ml-2 text-xs font-normal text-neutral-500">(locked)</span>
        ) : null}
      </legend>
      <div className="mt-2 flex flex-col gap-2">
        {MODES.map((mode) => (
          <label
            key={mode.value}
            className={`flex cursor-pointer items-start gap-3 rounded border p-3 ${
              value === mode.value
                ? "border-indigo-600 bg-indigo-950/30"
                : "border-neutral-800 bg-neutral-950 hover:border-neutral-700"
            } ${disabled ? "cursor-not-allowed opacity-60" : ""}`}
          >
            <input
              type="radio"
              name="execution_mode"
              value={mode.value}
              checked={value === mode.value}
              onChange={() => onChange(mode.value)}
              disabled={disabled}
              className="mt-0.5"
              data-testid={`execution-mode-${mode.value}`}
            />
            <span>
              <span className="block text-sm font-medium text-white">{mode.label}</span>
              <span className="block text-xs text-neutral-500">
                {modeDescription(mode.value)}
              </span>
            </span>
          </label>
        ))}
      </div>
      {lockedReason ? <p className="mt-2 text-xs text-amber-400">{lockedReason}</p> : null}
    </fieldset>
  );
}
