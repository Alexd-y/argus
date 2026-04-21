"use client";

/**
 * `ResumeAllDialog` — modal confirmation for lifting the global emergency
 * stop (T30, ARG-053).
 *
 * Mirrors `GlobalKillSwitchDialog`: the typed-phrase input is paste-blocked
 * and case-sensitive, the reason is recorded in the audit log. The blast
 * radius is smaller than `stop_all` (resuming does not roll back the
 * scans that `stop_all` cancelled — those stay terminal), but the dialog
 * still demands deliberate confirmation so a fat-finger does not
 * accidentally re-enable dispatch while incident response is mid-flight.
 *
 * Kept as a separate component (not inlined into `GlobalKillSwitchDialog`)
 * for testability and so each surface keeps its own `useFocusTrap`
 * lifecycle — Esc handling, focus restoration, and the
 * "reset state on open" pattern are easier to reason about per-dialog.
 */

import {
  useCallback,
  useId,
  useMemo,
  useRef,
  useState,
  useTransition,
  type ClipboardEvent,
  type DragEvent,
  type FormEvent,
} from "react";

import { resumeAllAction } from "@/app/admin/operations/actions";
import {
  RESUME_ALL_PHRASE,
  ResumeAllInputSchema,
  ThrottleActionError,
  THROTTLE_REASON_MAX,
  THROTTLE_REASON_MIN,
  throttleActionErrorMessage,
  type ResumeAllResponse,
} from "@/lib/adminOperations";
import { useFocusTrap } from "./useFocusTrap";

export type ResumeAllDialogProps = {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly onSuccess: (result: ResumeAllResponse) => void;
  /** Test override — defaults to `resumeAllAction`. */
  readonly resumeAction?: typeof resumeAllAction;
};

export function ResumeAllDialog({
  open,
  onOpenChange,
  onSuccess,
  resumeAction = resumeAllAction,
}: ResumeAllDialogProps): React.ReactElement | null {
  const titleId = useId();
  const descriptionId = useId();
  const phraseId = useId();
  const reasonId = useId();
  const phraseHelpId = useId();
  const reasonHelpId = useId();
  const submitHelpId = useId();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const phraseInputRef = useRef<HTMLInputElement | null>(null);

  const [phrase, setPhrase] = useState<string>("");
  const [reason, setReason] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const identityKey = open ? "open" : "closed";
  const [lastIdentity, setLastIdentity] = useState<string>(identityKey);
  if (identityKey !== lastIdentity) {
    setLastIdentity(identityKey);
    setPhrase("");
    setReason("");
    setErrorMessage(null);
  }

  const trimmedReason = useMemo(() => reason.trim(), [reason]);
  const phraseValid = phrase === RESUME_ALL_PHRASE;
  const reasonValid =
    trimmedReason.length >= THROTTLE_REASON_MIN &&
    trimmedReason.length <= THROTTLE_REASON_MAX;
  const canSubmit = phraseValid && reasonValid && !isPending;

  const handleEscape = useCallback(() => {
    if (isPending) return;
    onOpenChange(false);
  }, [isPending, onOpenChange]);

  useFocusTrap({
    enabled: open,
    containerRef: dialogRef,
    initialFocusRef: phraseInputRef,
    onEscape: handleEscape,
  });

  const handleBackdropMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.target === e.currentTarget && !isPending) {
      onOpenChange(false);
    }
  };

  const blockEvent = useCallback(
    (e: ClipboardEvent<HTMLInputElement> | DragEvent<HTMLInputElement>) => {
      e.preventDefault();
    },
    [],
  );

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canSubmit) return;
    setErrorMessage(null);

    const parsed = ResumeAllInputSchema.safeParse({ reason: trimmedReason });
    if (!parsed.success) {
      setErrorMessage(
        throttleActionErrorMessage(
          new ThrottleActionError("validation_failed", 400),
        ),
      );
      return;
    }

    startTransition(async () => {
      try {
        const result = await resumeAction(parsed.data);
        onOpenChange(false);
        onSuccess(result);
      } catch (err) {
        setErrorMessage(throttleActionErrorMessage(err));
      }
    });
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4"
      data-testid="resume-all-dialog-backdrop"
      onMouseDown={handleBackdropMouseDown}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="flex w-full max-w-lg flex-col gap-4 rounded-lg border border-amber-500/70 bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="resume-all-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2
            id={titleId}
            className="text-base font-semibold text-amber-200"
          >
            Снять глобальный emergency stop
          </h2>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог"
            data-testid="resume-all-dialog-close"
          >
            ×
          </button>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <p
            id={descriptionId}
            className="text-sm text-[var(--text-secondary)]"
          >
            Снимет глобальный флаг блокировки и позволит вновь диспатчить
            scan-инструменты. Уже отменённые scan НЕ возобновляются — они
            остаются в статусе <code>cancelled</code>. Действие фиксируется
            в audit-логе.
          </p>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={phraseId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Подтверждение (введите вручную: <code>{RESUME_ALL_PHRASE}</code>)
            </label>
            <input
              id={phraseId}
              ref={phraseInputRef}
              type="text"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              value={phrase}
              onChange={(e) => setPhrase(e.target.value)}
              onPaste={blockEvent}
              onDrop={blockEvent}
              onDragOver={blockEvent}
              aria-describedby={phraseHelpId}
              aria-invalid={phrase.length > 0 && !phraseValid}
              aria-required="true"
              disabled={isPending}
              className="rounded border border-amber-500/60 bg-[var(--bg-primary)] px-2 py-1.5 font-mono text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="resume-all-dialog-phrase"
            />
            <span
              id={phraseHelpId}
              className="text-[11px] text-[var(--text-muted)]"
            >
              Регистр и пробелы важны. Вставка из буфера и drag-drop
              заблокированы.
            </span>
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
              disabled={isPending}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="resume-all-dialog-reason"
            />
            <span
              id={reasonHelpId}
              className="text-[11px] text-[var(--text-muted)]"
            >
              Например: «Инцидент закрыт, supply-chain attack
              заблокирован на WAF, возобновляем диспатч».
            </span>
          </div>

          {errorMessage ? (
            <div
              role="alert"
              className="rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-xs text-red-200"
              data-testid="resume-all-dialog-error"
            >
              {errorMessage}
            </div>
          ) : null}

          <span id={submitHelpId} className="sr-only">
            Кнопка станет активной после ввода фразы подтверждения и
            причины ≥{THROTTLE_REASON_MIN} символов.
          </span>

          <footer className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
              className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="resume-all-dialog-cancel"
            >
              Отмена
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              aria-describedby={submitHelpId}
              className="rounded border border-amber-500 bg-amber-600 px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="resume-all-dialog-confirm"
            >
              {isPending ? "Снимаем…" : "Resume all scans"}
            </button>
          </footer>
        </form>
      </div>
    </div>
  );
}
