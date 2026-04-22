"use client";

/**
 * `PerTenantThrottleDialog` — modal form for the per-tenant emergency
 * throttle (T29, ARG-052).
 *
 * UX intent:
 *   The throttle blocks **future** ToolAdapter dispatches for a single
 *   tenant for a bounded TTL. Compared to the per-scan kill-switch, the
 *   blast radius is wider (every active scan stops emitting new requests)
 *   so the dialog requires a deliberate three-step gesture:
 *     1. (super-admin only) pick the target tenant from a dropdown;
 *     2. pick a duration from the closed `15 / 60 / 240 / 1440` set;
 *     3. write a >=10-character reason (recorded in audit log).
 *
 * RBAC:
 *   The tenant selector is HIDDEN for `admin` operators — the dialog is
 *   pinned to the session-bound tenant the parent client passed in. The
 *   server action also pins to `session.tenantId` independently so a
 *   craftily mounted React tree cannot widen scope.
 *
 * A11y (zero axe-core findings target):
 *   - `role="dialog"` + `aria-modal="true"` + labelled by the visible h2.
 *   - First focusable input auto-focuses on open; on close, focus is
 *     restored to the element that triggered the dialog.
 *   - Esc closes (when not submitting); Tab/Shift-Tab cycle within the
 *     dialog (light-weight focus trap mirroring `PerScanKillSwitchDialog`).
 *   - The disabled submit button carries `aria-disabled` + `aria-describedby`
 *     so AT users hear *why* it is unavailable.
 *
 * Security:
 *   - Backend call is a server action; `X-Admin-Key` never reaches the
 *     browser.
 *   - On error, the dialog renders a closed-taxonomy RU sentence; raw
 *     `detail` strings, stack traces and PII are filtered out by
 *     `throttleActionErrorMessage` and `callAdminBackendJson`.
 */

import {
  useCallback,
  useId,
  useMemo,
  useRef,
  useState,
  useTransition,
  type FormEvent,
} from "react";

import { throttleTenantAction } from "@/app/admin/operations/actions";
import {
  THROTTLE_DURATION_LABELS,
  THROTTLE_DURATIONS,
  THROTTLE_REASON_MAX,
  THROTTLE_REASON_MIN,
  ThrottleActionError,
  ThrottleTenantInputSchema,
  isUuid,
  throttleActionErrorMessage,
  type ThrottleDurationMinutes,
  type ThrottleResponse,
} from "@/lib/adminOperations";
import { useFocusTrap } from "./useFocusTrap";

const DEFAULT_DURATION: ThrottleDurationMinutes = 15;

export type ThrottleTenantOption = {
  readonly id: string;
  readonly name: string;
};

export type PerTenantThrottleDialogProps = {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  /** When `pinnedTenantId` is set, the tenant selector is hidden. */
  readonly pinnedTenantId: string | null;
  readonly availableTenants: ReadonlyArray<ThrottleTenantOption>;
  readonly onSuccess?: (result: ThrottleResponse) => void;
  /**
   * Override the server action — primarily used by unit tests so we don't
   * need to mock the `"use server"` module boundary at the dialog level.
   */
  readonly throttleAction?: typeof throttleTenantAction;
};

function shortName(id: string, options: ReadonlyArray<ThrottleTenantOption>): string {
  const match = options.find((o) => o.id === id);
  if (match) return match.name;
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…`;
}

export function PerTenantThrottleDialog({
  open,
  onOpenChange,
  pinnedTenantId,
  availableTenants,
  onSuccess,
  throttleAction = throttleTenantAction,
}: PerTenantThrottleDialogProps): React.ReactElement | null {
  const titleId = useId();
  const descriptionId = useId();
  const tenantId = useId();
  const durationId = useId();
  const reasonId = useId();
  const reasonHelpId = useId();
  const submitHelpId = useId();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<HTMLElement | null>(null);

  const initialTenantId = useMemo<string>(() => {
    if (pinnedTenantId) return pinnedTenantId;
    return availableTenants[0]?.id ?? "";
  }, [pinnedTenantId, availableTenants]);

  const [selectedTenantId, setSelectedTenantId] = useState<string>(initialTenantId);
  const [duration, setDuration] =
    useState<ThrottleDurationMinutes>(DEFAULT_DURATION);
  const [reason, setReason] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  // React 19 derived-from-props reset pattern (matches PerScanKillSwitchDialog).
  const identityKey = `${open ? "1" : "0"}:${initialTenantId}`;
  const [lastIdentity, setLastIdentity] = useState<string>(identityKey);
  if (identityKey !== lastIdentity) {
    setLastIdentity(identityKey);
    setSelectedTenantId(initialTenantId);
    setDuration(DEFAULT_DURATION);
    setReason("");
    setErrorMessage(null);
  }

  const trimmedReason = useMemo(() => reason.trim(), [reason]);
  const reasonValid =
    trimmedReason.length >= THROTTLE_REASON_MIN &&
    trimmedReason.length <= THROTTLE_REASON_MAX;
  const tenantValid = selectedTenantId !== "" && isUuid(selectedTenantId);
  const canSubmit = tenantValid && reasonValid && !isPending;

  // Esc must be ignored mid-submit; bounce through a stable callback so
  // useFocusTrap does not re-bind its keydown listener on every render.
  const handleEscape = useCallback(() => {
    if (isPending) return;
    onOpenChange(false);
  }, [isPending, onOpenChange]);

  useFocusTrap({
    enabled: open,
    containerRef: dialogRef,
    initialFocusRef: firstFieldRef,
    onEscape: handleEscape,
  });

  const handleBackdropMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.target === e.currentTarget && !isPending) {
      onOpenChange(false);
    }
  };

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canSubmit) return;
    setErrorMessage(null);

    const parsed = ThrottleTenantInputSchema.safeParse({
      tenantId: selectedTenantId,
      durationMinutes: duration,
      reason: trimmedReason,
    });
    if (!parsed.success) {
      setErrorMessage(throttleActionErrorMessage(
        new ThrottleActionError("validation_failed", 400),
      ));
      return;
    }

    startTransition(async () => {
      try {
        const result = await throttleAction(parsed.data);
        onOpenChange(false);
        if (onSuccess) onSuccess(result);
      } catch (err) {
        setErrorMessage(throttleActionErrorMessage(err));
      }
    });
  };

  if (!open) return null;

  const targetLabel = shortName(selectedTenantId, availableTenants);
  const tenantSelectorVisible = pinnedTenantId === null;

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4"
      data-testid="throttle-dialog-backdrop"
      onMouseDown={handleBackdropMouseDown}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        // keep: border-amber-500/60 is a decorative dialog-frame stroke,
        // not a text-bearing fill. `--warning-strong` is intentionally
        // fill-only (see ai_docs/architecture/design-tokens.md §3.5);
        // the warning-action token pair lives on the confirm button.
        className="flex w-full max-w-lg flex-col gap-4 rounded-lg border border-amber-500/60 bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="throttle-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2
            id={titleId}
            className="text-base font-semibold text-[var(--text-primary)]"
          >
            Throttle tenant {targetLabel}
          </h2>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог"
            data-testid="throttle-dialog-close"
          >
            ×
          </button>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <p
            id={descriptionId}
            className="text-sm text-[var(--text-secondary)]"
          >
            Throttle блокирует диспатч новых scan-инструментов для tenant
            на выбранный срок. По истечении TTL Redis автоматически снимает
            флаг — manual override не требуется. Действие фиксируется в
            audit-логе.
          </p>

          {tenantSelectorVisible ? (
            <div className="flex flex-col gap-1">
              <label
                htmlFor={tenantId}
                className="text-xs font-medium text-[var(--text-muted)]"
              >
                Tenant
              </label>
              <select
                id={tenantId}
                ref={firstFieldRef as React.RefObject<HTMLSelectElement>}
                value={selectedTenantId}
                onChange={(e) => setSelectedTenantId(e.target.value)}
                disabled={isPending || availableTenants.length === 0}
                aria-required="true"
                className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
                data-testid="throttle-dialog-tenant"
              >
                {availableTenants.length === 0 ? (
                  <option value="">—</option>
                ) : (
                  availableTenants.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))
                )}
              </select>
            </div>
          ) : (
            <input
              type="hidden"
              data-testid="throttle-dialog-tenant-pinned"
              value={selectedTenantId}
              readOnly
            />
          )}

          <div className="flex flex-col gap-1">
            <label
              htmlFor={durationId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Длительность
            </label>
            <select
              id={durationId}
              ref={
                tenantSelectorVisible
                  ? undefined
                  : (firstFieldRef as React.RefObject<HTMLSelectElement>)
              }
              value={duration}
              onChange={(e) =>
                setDuration(
                  Number.parseInt(e.target.value, 10) as ThrottleDurationMinutes,
                )
              }
              disabled={isPending}
              aria-required="true"
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              data-testid="throttle-dialog-duration"
            >
              {THROTTLE_DURATIONS.map((d) => (
                <option key={d} value={d}>
                  {THROTTLE_DURATION_LABELS[d]}
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={reasonId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Причина (≥{THROTTLE_REASON_MIN} символов)
            </label>
            <textarea
              id={reasonId}
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={THROTTLE_REASON_MAX}
              aria-describedby={reasonHelpId}
              aria-invalid={trimmedReason.length > 0 && !reasonValid}
              aria-required="true"
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              data-testid="throttle-dialog-reason"
              disabled={isPending}
            />
            <span
              id={reasonHelpId}
              className="text-[11px] text-[var(--text-muted)]"
              data-testid="throttle-dialog-reason-help"
            >
              Например: «Активные подозрительные запросы из CIDR
              198.51.100.0/24». Причина уйдёт в audit-лог.
            </span>
          </div>

          {errorMessage ? (
            <div
              role="alert"
              className="rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-xs text-red-200"
              data-testid="throttle-dialog-error"
            >
              {errorMessage}
            </div>
          ) : null}

          <span id={submitHelpId} className="sr-only">
            Кнопка станет активной после выбора tenant, длительности и
            ввода причины ≥{THROTTLE_REASON_MIN} символов.
          </span>

          <footer className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
              className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="throttle-dialog-cancel"
            >
              Отмена
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              aria-describedby={submitHelpId}
              // C7-T08: warning-action fill migrated to design-token pair
              // (`bg-amber-700 text-white` → `bg-[var(--warning-strong)]
              // text-[var(--on-warning)]`). border-amber-500 +
              // focus-visible:ring-amber-400 are decorative accents,
              // not text-bearing surfaces — see design-tokens.md §3.5.
              className="rounded border border-amber-500 bg-[var(--warning-strong)] px-3 py-1.5 text-xs font-medium text-[var(--on-warning)] hover:opacity-90 focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="throttle-dialog-confirm"
            >
              {isPending ? "Применяем…" : "Throttle tenant"}
            </button>
          </footer>
        </form>
      </div>
    </div>
  );
}
