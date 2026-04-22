"use client";

/**
 * `DeleteScheduleDialog` — destructive confirmation modal (T35, ARG-056).
 *
 * Deleting a schedule is a hard delete: the database row is removed AND
 * the corresponding RedBeat key is unlinked, so the next cron tick will
 * NOT fire. Even though the action is reversible (admin can recreate
 * with the same name + cron), in-flight scans linked to the schedule
 * keep running — operators must understand that "delete schedule" ≠
 * "stop running scans".
 *
 * Defence-in-depth gates:
 *   1. Operator must type the EXACT schedule name (case-sensitive,
 *      paste-blocked).
 *   2. Confirm button only enables once name matches.
 *   3. Server action re-validates session role + tenant scope.
 *
 * A11y: focus trap, Esc to close, `role="dialog"` + `aria-modal`,
 * `role="alert"` (NO `aria-live`) — same pattern as RunNow / per-scan.
 */

import {
  useCallback,
  useId,
  useRef,
  useState,
  useTransition,
  type FormEvent,
} from "react";

import { useFocusTrap } from "@/components/admin/operations/useFocusTrap";
import { deleteScheduleAction } from "@/app/admin/schedules/actions";
import {
  extractScheduleActionCode,
  scheduleActionErrorMessage,
  type Schedule,
} from "@/lib/adminSchedules";

export type DeleteScheduleDialogProps = {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly schedule: Schedule;
  readonly onSuccess?: () => void;
  readonly deleteAction?: typeof deleteScheduleAction;
};

export function DeleteScheduleDialog({
  open,
  onOpenChange,
  schedule,
  onSuccess,
  deleteAction = deleteScheduleAction,
}: DeleteScheduleDialogProps): React.ReactElement | null {
  const titleId = useId();
  const descriptionId = useId();
  const typedNameId = useId();
  const submitHelpId = useId();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<HTMLInputElement | null>(null);

  const [typedName, setTypedName] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const identityKey = `${open ? "1" : "0"}:${schedule.id}`;
  const [lastIdentity, setLastIdentity] = useState(identityKey);
  if (identityKey !== lastIdentity) {
    setLastIdentity(identityKey);
    setTypedName("");
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

  const nameMatches = typedName === schedule.name;
  const canSubmit = nameMatches && !isPending;

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canSubmit) return;
    setErrorMessage(null);
    setErrorCode(null);

    startTransition(async () => {
      try {
        await deleteAction(schedule.id);
        onOpenChange(false);
        if (onSuccess) onSuccess();
      } catch (err) {
        setErrorMessage(scheduleActionErrorMessage(err));
        setErrorCode(extractScheduleActionCode(err));
      }
    });
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4"
      data-testid="delete-schedule-backdrop"
      onMouseDown={handleBackdropMouseDown}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="flex w-full max-w-md flex-col gap-4 rounded-lg border border-red-500/60 bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="delete-schedule-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2 id={titleId} className="text-base font-semibold text-red-200">
            Удалить расписание?
          </h2>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог"
            data-testid="delete-schedule-close"
          >
            ×
          </button>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <p
            id={descriptionId}
            className="text-sm text-[var(--text-secondary)]"
          >
            Расписание{" "}
            <span className="font-mono font-semibold text-[var(--text-primary)]">
              {schedule.name}
            </span>{" "}
            будет удалено навсегда вместе с RedBeat-ключом. В будущем
            tick’и не сработают. Уже запущенные сканы продолжат
            выполняться — остановите их отдельно через kill-switch.
          </p>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={typedNameId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Введите имя для подтверждения
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
              onPaste={(e) => e.preventDefault()}
              onDrop={(e) => e.preventDefault()}
              onDragOver={(e) => e.preventDefault()}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 font-mono text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="delete-schedule-typed-name"
            />
            <span className="text-[11px] text-[var(--text-muted)]">
              Регистр символов важен; вставка заблокирована.
            </span>
          </div>

          {errorMessage ? (
            <div
              role="alert"
              className="rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-xs text-red-200"
              data-testid="delete-schedule-error"
              data-error-code={errorCode ?? ""}
            >
              {errorMessage}
            </div>
          ) : null}

          <span id={submitHelpId} className="sr-only">
            Кнопка станет активной после ввода точного имени расписания.
          </span>

          <footer className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
              className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="delete-schedule-cancel"
            >
              Отмена
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              aria-describedby={submitHelpId}
              className="rounded border border-red-500 bg-red-700 px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="delete-schedule-confirm"
            >
              {isPending ? "Удаляем…" : "Удалить"}
            </button>
          </footer>
        </form>
      </div>
    </div>
  );
}
