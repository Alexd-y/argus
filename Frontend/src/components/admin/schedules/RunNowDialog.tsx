"use client";

/**
 * `RunNowDialog` — modal that fires a scan schedule out-of-cycle (T35,
 * ARG-056).
 *
 * UX intent:
 *   "Run Now" jumps a queued scheduled scan to the front of the line
 *   ahead of its next cron tick. To prevent fat-finger fires:
 *
 *     1. Operator must type the EXACT schedule NAME (case-sensitive,
 *        paste-blocked) — same gesture as the per-scan kill-switch.
 *     2. Optional `bypass_maintenance_window` checkbox — defaults to
 *        false; the backend hard-rejects 409 `in_maintenance_window`
 *        unless this is set.
 *     3. Mandatory `reason` textarea (10..500 chars) recorded in the
 *        audit trail alongside `enqueued_task_id`.
 *
 * Defence in depth:
 *   - The UI gate is one of THREE checks; the server action re-validates
 *     the reason and the backend re-runs the kill-switch + maintenance
 *     window guards inside the worker.
 *
 * A11y mirrors the throttle / kill-switch dialogs — focus trap, Esc,
 * `role="dialog"` + `aria-modal`, `role="alert"` (NO `aria-live`).
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

import { useFocusTrap } from "@/components/admin/operations/useFocusTrap";
import { runNowAction } from "@/app/admin/schedules/actions";
import {
  RUN_NOW_REASON_MAX,
  RUN_NOW_REASON_MIN,
  RunNowInputSchema,
  ScheduleActionError,
  scheduleActionErrorMessage,
  type RunNowResponse,
  type Schedule,
} from "@/lib/adminSchedules";

export type RunNowDialogProps = {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly schedule: Schedule;
  readonly onSuccess?: (result: RunNowResponse) => void;
  /** Test override — defaults to the canonical run-now action. */
  readonly runAction?: typeof runNowAction;
};

/**
 * Block paste / drop on the typed-name input. The user must physically
 * type the schedule name to prove intent — pasting from clipboard is the
 * very pattern an attacker (or a misclicked drag-and-drop) would use to
 * bypass the gate.
 */
function blockClipboardEvents(): {
  readonly onPaste: (e: React.ClipboardEvent<HTMLInputElement>) => void;
  readonly onDrop: (e: React.DragEvent<HTMLInputElement>) => void;
  readonly onDragOver: (e: React.DragEvent<HTMLInputElement>) => void;
} {
  return {
    onPaste: (e) => e.preventDefault(),
    onDrop: (e) => e.preventDefault(),
    onDragOver: (e) => e.preventDefault(),
  };
}

export function RunNowDialog({
  open,
  onOpenChange,
  schedule,
  onSuccess,
  runAction = runNowAction,
}: RunNowDialogProps): React.ReactElement | null {
  const titleId = useId();
  const descriptionId = useId();
  const typedNameId = useId();
  const reasonId = useId();
  const reasonHelpId = useId();
  const bypassId = useId();
  const submitHelpId = useId();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<HTMLInputElement | null>(null);

  const [typedName, setTypedName] = useState("");
  const [reason, setReason] = useState("");
  const [bypass, setBypass] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  // React 19 derived-from-props reset pattern — reset every time the
  // dialog opens against a new schedule.
  const identityKey = `${open ? "1" : "0"}:${schedule.id}`;
  const [lastIdentity, setLastIdentity] = useState(identityKey);
  if (identityKey !== lastIdentity) {
    setLastIdentity(identityKey);
    setTypedName("");
    setReason("");
    setBypass(false);
    setErrorMessage(null);
    setErrorCode(null);
  }

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

  const trimmedReason = useMemo(() => reason.trim(), [reason]);
  const reasonValid =
    trimmedReason.length >= RUN_NOW_REASON_MIN &&
    trimmedReason.length <= RUN_NOW_REASON_MAX;
  const nameMatches = typedName === schedule.name;
  const canSubmit = nameMatches && reasonValid && !isPending;

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canSubmit) return;
    setErrorMessage(null);
    setErrorCode(null);

    const parsed = RunNowInputSchema.safeParse({
      bypassMaintenanceWindow: bypass,
      reason: trimmedReason,
    });
    if (!parsed.success) {
      const next = new ScheduleActionError("validation_failed", 400);
      setErrorMessage(scheduleActionErrorMessage(next));
      setErrorCode(next.code);
      return;
    }

    startTransition(async () => {
      try {
        const result = await runAction(schedule.id, parsed.data);
        onOpenChange(false);
        if (onSuccess) onSuccess(result);
      } catch (err) {
        setErrorMessage(scheduleActionErrorMessage(err));
        setErrorCode(err instanceof ScheduleActionError ? err.code : null);
      }
    });
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4"
      data-testid="run-now-backdrop"
      onMouseDown={handleBackdropMouseDown}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="flex w-full max-w-lg flex-col gap-4 rounded-lg border border-amber-500/60 bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="run-now-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2 id={titleId} className="text-base font-semibold">
            Run schedule now
          </h2>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог"
            data-testid="run-now-close"
          >
            ×
          </button>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <p
            id={descriptionId}
            className="text-sm text-[var(--text-secondary)]"
          >
            Манульный запуск расписания{" "}
            <span className="font-mono font-semibold text-[var(--text-primary)]">
              {schedule.name}
            </span>{" "}
            против{" "}
            <span className="font-mono text-[var(--text-primary)]">
              {schedule.target_url}
            </span>
            . Глобальный stop / per-tenant throttle и maintenance window
            проверяются и в API, и в worker’е (defence in depth).
          </p>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={typedNameId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Введите имя расписания для подтверждения
            </label>
            <input
              id={typedNameId}
              ref={firstFieldRef}
              type="text"
              value={typedName}
              onChange={(e) => setTypedName(e.target.value)}
              disabled={isPending}
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              aria-required="true"
              aria-invalid={typedName.length > 0 && !nameMatches}
              {...blockClipboardEvents()}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 font-mono text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="run-now-typed-name"
            />
            <span className="text-[11px] text-[var(--text-muted)]">
              Регистр символов важен; вставка заблокирована.
            </span>
          </div>

          <div className="flex items-start gap-2">
            <input
              id={bypassId}
              type="checkbox"
              checked={bypass}
              onChange={(e) => setBypass(e.target.checked)}
              disabled={isPending}
              className="mt-1 h-4 w-4 rounded border border-[var(--border)] focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none"
              data-testid="run-now-bypass"
            />
            <label
              htmlFor={bypassId}
              className="text-xs text-[var(--text-secondary)]"
            >
              Игнорировать maintenance window. Используйте только для
              экстренных проверок; глобальный kill-switch и per-tenant
              throttle ОБХОДУ НЕ ПОДЛЕЖАТ — снимите блокировки отдельно.
            </label>
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={reasonId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Причина (≥{RUN_NOW_REASON_MIN} символов)
            </label>
            <textarea
              id={reasonId}
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              disabled={isPending}
              maxLength={RUN_NOW_REASON_MAX}
              aria-describedby={reasonHelpId}
              aria-required="true"
              aria-invalid={reason.length > 0 && !reasonValid}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="run-now-reason"
            />
            <span
              id={reasonHelpId}
              className="text-[11px] text-[var(--text-muted)]"
            >
              Запишется в audit-лог рядом с enqueued_task_id.
            </span>
          </div>

          {errorMessage ? (
            <div
              role="alert"
              className="rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-xs text-red-200"
              data-testid="run-now-error"
              data-error-code={errorCode ?? ""}
            >
              {errorMessage}
              {errorCode === "in_maintenance_window" ? (
                <span className="ml-1">
                  Включите «Игнорировать maintenance window» и повторите.
                </span>
              ) : null}
            </div>
          ) : null}

          <span id={submitHelpId} className="sr-only">
            Кнопка станет активной после ввода точного имени расписания
            и причины ≥{RUN_NOW_REASON_MIN} символов.
          </span>

          <footer className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
              className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="run-now-cancel"
            >
              Отмена
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              aria-describedby={submitHelpId}
              className="rounded border border-amber-500 bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="run-now-confirm"
            >
              {isPending ? "Запускаем…" : "Run now"}
            </button>
          </footer>
        </form>
      </div>
    </div>
  );
}
