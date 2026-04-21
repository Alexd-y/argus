"use client";

/**
 * `CronExpressionField` — visual cron builder + raw escape hatch + live
 * preview (T35, ARG-056).
 *
 * Why no `react-js-cron`?
 *   The leading visual cron component requires `antd` (>=5) as a peer
 *   dependency — that pulls ~150KB of unused styles and a global CSS
 *   namespace into the admin bundle, plus the rendered widget exposes
 *   axe-core a11y violations (no labels on the `<select>` elements,
 *   colour-only state on hover) we'd then need to patch in CSS.
 *
 *   We instead ship a minimal in-house Quick Picks selector + raw text
 *   input + live preview powered by `cron-parser` (~30KB, MIT, no
 *   transitive deps beyond `luxon`). This keeps the bundle small AND the
 *   widget fully accessible by default.
 *
 * Quick Picks:
 *   The five most common cron patterns (every 5/15 min, hourly, daily
 *   midnight, weekly Sunday midnight, monthly 1st midnight). Switching
 *   to "Custom" mode hides the picker and exposes the raw text input
 *   exclusively. Switching back to "Quick" reseeds with the closest
 *   matching preset (or the FIRST option if no exact match).
 *
 * Live preview:
 *   Whenever the cron expression parses, we show the next 3 fire times
 *   formatted as `YYYY-MM-DD HH:mm` UTC. On parse failure we surface a
 *   single closed-taxonomy RU sentence in `role="alert"` (NO
 *   `aria-live`, per T28 fix — `role="alert"` already implies assertive
 *   announcement and adding `aria-live` causes screen-reader double-fire).
 *
 * Maintenance-window mode:
 *   Same surface but with an "Optional — leave blank to disable"
 *   placeholder and a 60-minute frequency floor warning (the backend's
 *   `_MAINTENANCE_CRON_MAX_FREQ_MINUTES`). The warning is informational
 *   only; the actual frequency check happens server-side.
 *
 * The component is fully controlled (`value` / `onChange`). Parent state
 * is the source of truth, which makes it trivial to round-trip the value
 * through the editor dialog without a sync glitch.
 */

import { useId, useMemo, useState } from "react";
import { parseExpression } from "cron-parser";

import { SCHEDULE_CRON_MAX } from "@/lib/adminSchedules";

export type CronFieldMode = "primary" | "maintenance";

export type CronQuickPick = {
  readonly id: string;
  readonly label: string;
  readonly cron: string;
};

const PRIMARY_QUICK_PICKS: ReadonlyArray<CronQuickPick> = [
  { id: "every_5min", label: "Каждые 5 минут", cron: "*/5 * * * *" },
  { id: "every_15min", label: "Каждые 15 минут", cron: "*/15 * * * *" },
  { id: "hourly", label: "Каждый час (00 минут)", cron: "0 * * * *" },
  { id: "daily_midnight", label: "Ежедневно в 00:00 UTC", cron: "0 0 * * *" },
  {
    id: "weekly_sun_midnight",
    label: "Еженедельно в воскресенье 00:00 UTC",
    cron: "0 0 * * 0",
  },
  {
    id: "monthly_1st",
    label: "1 числа каждого месяца 00:00 UTC",
    cron: "0 0 1 * *",
  },
];

const MAINTENANCE_QUICK_PICKS: ReadonlyArray<CronQuickPick> = [
  { id: "hourly", label: "Каждый час (00 минут)", cron: "0 * * * *" },
  { id: "daily_2am", label: "Ежедневно в 02:00 UTC", cron: "0 2 * * *" },
  {
    id: "weekly_sun_3am",
    label: "Еженедельно в воскресенье 03:00 UTC",
    cron: "0 3 * * 0",
  },
];

const PREVIEW_COUNT = 3;

export type CronExpressionFieldProps = {
  readonly value: string;
  readonly onChange: (next: string) => void;
  readonly mode?: CronFieldMode;
  readonly disabled?: boolean;
  readonly id?: string;
  readonly ariaInvalid?: boolean;
  readonly previewNow?: Date;
};

type ParseOutcome =
  | { kind: "ok"; nextFires: ReadonlyArray<Date> }
  | { kind: "empty" }
  | { kind: "error" };

function parseAndPreview(
  expression: string,
  now: Date,
): ParseOutcome {
  const trimmed = expression.trim();
  if (trimmed === "") return { kind: "empty" };
  try {
    const interval = parseExpression(trimmed, {
      currentDate: now,
      utc: true,
    });
    const next: Date[] = [];
    for (let i = 0; i < PREVIEW_COUNT; i += 1) {
      next.push(interval.next().toDate());
    }
    return { kind: "ok", nextFires: next };
  } catch {
    return { kind: "error" };
  }
}

function formatUtc(d: Date): string {
  // Avoid `toLocaleString` because it depends on the user's locale and
  // would render different strings in the test snapshot vs the browser.
  // The preview should always render a stable UTC label.
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mi = String(d.getUTCMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}`;
}

function findMatchingQuickPick(
  expression: string,
  picks: ReadonlyArray<CronQuickPick>,
): CronQuickPick | null {
  const normalized = expression.trim();
  if (normalized === "") return null;
  return picks.find((p) => p.cron === normalized) ?? null;
}

export function CronExpressionField({
  value,
  onChange,
  mode = "primary",
  disabled = false,
  id,
  ariaInvalid,
  previewNow,
}: CronExpressionFieldProps): React.ReactElement {
  const generatedId = useId();
  const fieldId = id ?? generatedId;
  const helpId = `${fieldId}-help`;
  const previewId = `${fieldId}-preview`;
  const errorId = `${fieldId}-error`;

  const picks = mode === "maintenance"
    ? MAINTENANCE_QUICK_PICKS
    : PRIMARY_QUICK_PICKS;

  // Initial input mode: if the value matches a quick pick, start in
  // "quick" mode; otherwise start in "raw" mode so a custom expression
  // is editable straight away.
  const initialMode = useMemo<"quick" | "raw">(() => {
    return findMatchingQuickPick(value, picks) ? "quick" : "raw";
  }, [value, picks]);

  const [requestedMode, setRequestedMode] = useState<"quick" | "raw">(
    initialMode,
  );

  // Derive the rendered mode from `requestedMode` + the current value.
  // If the user requested Quick mode but the value no longer matches any
  // preset (e.g. a programmatic reset from the parent), we transparently
  // fall back to Raw so the input stays editable. This avoids a
  // setState-in-effect cascade that React 19's lints would flag.
  const matchedQuickPick = useMemo(
    () => findMatchingQuickPick(value, picks),
    [value, picks],
  );
  const inputMode: "quick" | "raw" =
    requestedMode === "quick" && matchedQuickPick === null
      ? "raw"
      : requestedMode;

  // Stabilise "now" within a single mount so the preview stays
  // deterministic across re-renders. `useState` lazy initializer runs
  // exactly once per mount and is safe to read during render (unlike a
  // ref, which `react-hooks/refs` flags as a side-effect access).
  const [fallbackNow] = useState<Date>(() => new Date());
  const effectiveNow = previewNow ?? fallbackNow;

  const outcome = useMemo(
    () => parseAndPreview(value, effectiveNow),
    [value, effectiveNow],
  );

  // When the user picks a Quick Pick, push the preset back up via
  // onChange so the parent stays the source of truth.
  const handleQuickPick = (cron: string) => {
    onChange(cron);
  };

  // When the user types in the raw input, propagate verbatim. We do NOT
  // auto-trim — the parent's Zod schema trims at submit so the user can
  // see exactly what they typed during editing.
  const handleRaw = (raw: string) => {
    onChange(raw);
  };

  // Toggling Quick → Raw retains the current value verbatim. Raw →
  // Quick reseeds with the matching preset OR the FIRST preset to give
  // the user a sensible default.
  const handleModeToggle = (next: "quick" | "raw") => {
    setRequestedMode(next);
    if (next === "quick" && matchedQuickPick === null && picks.length > 0) {
      onChange(picks[0].cron);
    }
  };

  return (
    <div className="flex flex-col gap-2" data-testid={`cron-field-${mode}`}>
      <div
        className="inline-flex rounded border border-[var(--border)]"
        role="tablist"
        aria-label="Тип ввода cron"
      >
        <button
          type="button"
          role="tab"
          aria-selected={inputMode === "quick"}
          onClick={() => handleModeToggle("quick")}
          disabled={disabled}
          className={`px-2 py-1 text-xs ${
            inputMode === "quick"
              ? "bg-[var(--bg-tertiary)] text-[var(--accent)]"
              : "text-[var(--text-secondary)]"
          }`}
          data-testid={`cron-tab-quick-${mode}`}
        >
          Quick
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={inputMode === "raw"}
          onClick={() => handleModeToggle("raw")}
          disabled={disabled}
          className={`px-2 py-1 text-xs ${
            inputMode === "raw"
              ? "bg-[var(--bg-tertiary)] text-[var(--accent)]"
              : "text-[var(--text-secondary)]"
          }`}
          data-testid={`cron-tab-raw-${mode}`}
        >
          Raw
        </button>
      </div>

      {inputMode === "quick" ? (
        <select
          id={fieldId}
          value={
            findMatchingQuickPick(value, picks)?.cron ?? picks[0]?.cron ?? ""
          }
          onChange={(e) => handleQuickPick(e.target.value)}
          disabled={disabled}
          aria-describedby={`${helpId} ${previewId}`}
          aria-invalid={ariaInvalid}
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
          data-testid={`cron-quick-select-${mode}`}
        >
          {picks.map((p) => (
            <option key={p.id} value={p.cron}>
              {p.label} ({p.cron})
            </option>
          ))}
        </select>
      ) : (
        <input
          id={fieldId}
          type="text"
          value={value}
          onChange={(e) => handleRaw(e.target.value)}
          disabled={disabled}
          maxLength={SCHEDULE_CRON_MAX}
          spellCheck={false}
          aria-describedby={`${helpId} ${previewId}`}
          aria-invalid={ariaInvalid}
          placeholder={
            mode === "maintenance"
              ? "Опционально, например: 0 2 * * *"
              : "0 * * * *"
          }
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 font-mono text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
          data-testid={`cron-raw-input-${mode}`}
        />
      )}

      <p
        id={helpId}
        className="text-[11px] text-[var(--text-muted)]"
        data-testid={`cron-help-${mode}`}
      >
        {mode === "maintenance"
          ? "Maintenance window: cron описывает НАЧАЛО окна. Длительность окна — 60 минут (фиксированная). Минимальный интервал — раз в час."
          : "Стандартный 5-полевой cron в UTC. Минимальный интервал — раз в 5 минут (DOS-guard)."}
      </p>

      {outcome.kind === "ok" ? (
        <div
          id={previewId}
          role="status"
          className="rounded border border-emerald-500/30 bg-emerald-950/20 px-2 py-1.5 text-[11px] text-emerald-200"
          data-testid={`cron-preview-${mode}`}
        >
          <span className="font-semibold">Ближайшие срабатывания (UTC):</span>
          <ol className="mt-1 list-decimal pl-5 font-mono">
            {outcome.nextFires.map((d, idx) => (
              <li
                key={d.toISOString()}
                data-testid={`cron-preview-${mode}-${idx}`}
              >
                {formatUtc(d)}
              </li>
            ))}
          </ol>
        </div>
      ) : null}

      {outcome.kind === "empty" ? (
        <p
          id={previewId}
          className="text-[11px] text-[var(--text-muted)]"
          data-testid={`cron-preview-empty-${mode}`}
        >
          {mode === "maintenance"
            ? "Maintenance window отключён."
            : "Введите cron-выражение для предпросмотра."}
        </p>
      ) : null}

      {outcome.kind === "error" ? (
        <p
          id={errorId}
          role="alert"
          className="rounded border border-red-500/40 bg-red-950/30 px-2 py-1.5 text-[11px] text-red-200"
          data-testid={`cron-preview-error-${mode}`}
        >
          Невалидное cron-выражение. Проверьте 5 полей: минута, час, день
          месяца, месяц, день недели.
        </p>
      ) : null}
    </div>
  );
}
