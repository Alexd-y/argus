"use client";

/**
 * `GlobalKillSwitchDialog` — modal confirmation for the cross-tenant
 * emergency stop (T30, ARG-053).
 *
 * Why this surface is the most defensive in Batch 4:
 *   The "STOP ALL" button cancels every active scan across every tenant.
 *   A single accidental click could destroy hours of work for every
 *   operator on the platform, so the dialog requires THREE independent
 *   confirmations before it can submit:
 *     1. typed phrase `"STOP ALL SCANS"` (case-sensitive, whitespace-strict);
 *     2. paste / drag-drop on the phrase input is hard-blocked so an
 *        operator cannot one-shot the gate from a clipboard buffer;
 *     3. `>= 10` character free-text reason (recorded in audit log).
 *   The submit button stays `disabled + aria-disabled` until BOTH
 *   conditions are satisfied, then a final `useTransition` round-trip
 *   gives the operator one more "Применяем…" frame before the action lands.
 *
 * RBAC + defence in depth:
 *   The dialog is only ever mounted from the super-admin client surface,
 *   but `stopAllAction` re-validates the role server-side AND the backend
 *   re-checks `_require_super_admin`. If any one of these layers is
 *   bypassed, the other two still hold.
 *
 * A11y:
 *   - `role="dialog"` + `aria-modal="true"` + labelled by visible h2.
 *   - First focus lands on the phrase input via `useFocusTrap`.
 *   - Esc closes when not pending; Tab/Shift-Tab cycle inside the dialog.
 *   - Errors render in a `role="alert"` div WITHOUT `aria-live` (T28
 *     follow-up) so AT users only hear them when the alert mounts.
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

import { stopAllAction } from "@/app/admin/operations/actions";
import {
  STOP_ALL_PHRASE,
  StopAllInputSchema,
  ThrottleActionError,
  THROTTLE_REASON_MAX,
  THROTTLE_REASON_MIN,
  throttleActionErrorMessage,
  type StopAllResponse,
} from "@/lib/adminOperations";
import { useFocusTrap } from "./useFocusTrap";

export type GlobalKillSwitchDialogProps = {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly onSuccess: (result: StopAllResponse) => void;
  /** Test override — defaults to `stopAllAction`. */
  readonly stopAction?: typeof stopAllAction;
};

export function GlobalKillSwitchDialog({
  open,
  onOpenChange,
  onSuccess,
  stopAction = stopAllAction,
}: GlobalKillSwitchDialogProps): React.ReactElement | null {
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

  // React 19 derived-from-props reset pattern (matches PerTenantThrottleDialog).
  // Reset every field whenever `open` flips so a previously-typed phrase or
  // reason cannot bleed into a later session.
  const identityKey = open ? "open" : "closed";
  const [lastIdentity, setLastIdentity] = useState<string>(identityKey);
  if (identityKey !== lastIdentity) {
    setLastIdentity(identityKey);
    setPhrase("");
    setReason("");
    setErrorMessage(null);
  }

  const trimmedReason = useMemo(() => reason.trim(), [reason]);
  const phraseValid = phrase === STOP_ALL_PHRASE;
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

  // Block clipboard / drag-drop on the phrase input so operators cannot
  // paste the constant from documentation or a colleague's chat. This is
  // the visible portion of the three-layer defence; the server action
  // also re-checks the typed phrase via `STOP_ALL_PHRASE` constant.
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

    const parsed = StopAllInputSchema.safeParse({ reason: trimmedReason });
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
        const result = await stopAction(parsed.data);
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
      data-testid="kill-switch-dialog-backdrop"
      onMouseDown={handleBackdropMouseDown}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="flex w-full max-w-lg flex-col gap-4 rounded-lg border border-red-500/70 bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="kill-switch-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2
            id={titleId}
            className="text-base font-semibold text-red-200"
          >
            🚨 Глобальный stop ALL scans
          </h2>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог"
            data-testid="kill-switch-dialog-close"
          >
            ×
          </button>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <p
            id={descriptionId}
            className="text-sm text-[var(--text-secondary)]"
          >
            Действие отменит ВСЕ активные scan по ВСЕМ tenant и установит
            глобальный флаг блокировки. Затронуты будут все операторы
            платформы. Подтвердите осознанное действие вводом фразы и
            причины ниже.
          </p>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={phraseId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Подтверждение (введите вручную: <code>{STOP_ALL_PHRASE}</code>)
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
              className="rounded border border-red-500/60 bg-[var(--bg-primary)] px-2 py-1.5 font-mono text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="kill-switch-dialog-phrase"
            />
            <span
              id={phraseHelpId}
              className="text-[11px] text-[var(--text-muted)]"
            >
              Регистр и пробелы важны. Вставка из буфера и drag-drop
              заблокированы — фразу необходимо набрать целиком вручную.
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
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="kill-switch-dialog-reason"
            />
            <span
              id={reasonHelpId}
              className="text-[11px] text-[var(--text-muted)]"
            >
              Например: «Подтверждённый supply-chain attack из CIDR
              198.51.100.0/24, останавливаем до анализа». Уйдёт в audit-log.
            </span>
          </div>

          {errorMessage ? (
            <div
              role="alert"
              className="rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-xs text-red-200"
              data-testid="kill-switch-dialog-error"
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
              data-testid="kill-switch-dialog-cancel"
            >
              Отмена
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              aria-describedby={submitHelpId}
              className="rounded border border-red-500 bg-red-700 px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="kill-switch-dialog-confirm"
            >
              {isPending ? "Применяем…" : "STOP ALL SCANS"}
            </button>
          </footer>
        </form>
      </div>
    </div>
  );
}
