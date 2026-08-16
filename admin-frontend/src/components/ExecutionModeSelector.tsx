import type { ExecutionMode } from "@/lib/scanApi";

interface ExecutionModeSelectorProps {
  value: ExecutionMode;
  onChange: (mode: ExecutionMode) => void;
  disabled?: boolean;
  lockedReason?: string | null;
}

function modeCopy(mode: ExecutionMode): { label: string; description: string } {
  switch (mode) {
    case "production":
      return {
        label: "Production",
        description: "Standard policy gates and approval flows",
      };
    case "lab_unrestricted":
      return {
        label: "LAB Unrestricted",
        description: "Verified LAB lease bypasses approval for mutating actions",
      };
    case "quick":
      return {
        label: "Quick",
        description:
          "Time-boxed production-like scan — no LAB lease, no exploitation, hard deadline",
      };
    default: {
      const _exhaustive: never = mode;
      return _exhaustive;
    }
  }
}

/** Always list all modes — LAB must not be hidden by production risk labels (§17). */
const MODES: ExecutionMode[] = ["production", "lab_unrestricted", "quick"];

export function ExecutionModeSelector({
  value,
  onChange,
  disabled = false,
  lockedReason,
}: ExecutionModeSelectorProps) {
  return (
    <fieldset className="rounded border border-neutral-800 bg-neutral-900 p-4" disabled={disabled}>
      <legend className="px-1 text-sm font-medium text-neutral-300">
        Execution mode
        {disabled && (
          <span className="ml-2 text-xs font-normal text-neutral-500">(locked)</span>
        )}
      </legend>
      <div className="mt-2 flex flex-col gap-2">
        {MODES.map((mode) => {
          const copy = modeCopy(mode);
          return (
            <label
              key={mode}
              data-testid={`execution-mode-${mode}`}
              className={`flex cursor-pointer items-start gap-3 rounded border p-3 ${
                value === mode
                  ? "border-indigo-600 bg-indigo-950/30"
                  : "border-neutral-800 bg-neutral-950 hover:border-neutral-700"
              } ${disabled ? "cursor-not-allowed opacity-60" : ""}`}
            >
              <input
                type="radio"
                name="execution_mode"
                value={mode}
                checked={value === mode}
                onChange={() => onChange(mode)}
                disabled={disabled}
                className="mt-0.5"
              />
              <span>
                <span className="block text-sm font-medium text-white">{copy.label}</span>
                <span className="block text-xs text-neutral-500">{copy.description}</span>
              </span>
            </label>
          );
        })}
      </div>
      {lockedReason && (
        <p className="mt-2 text-xs text-amber-400">{lockedReason}</p>
      )}
    </fieldset>
  );
}
