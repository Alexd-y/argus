"use client";

/**
 * `AbandonDialog` — modal that marks a webhook DLQ entry terminally
 * abandoned via `abandonWebhookDlqAction` (T41, ARG-053).
 *
 * UX intent:
 *   "Abandon" is destructive — the row never replays again, and the
 *   downstream system never receives the event. To prevent fat-finger
 *   fires we require:
 *
 *     1. Operator must type the EXACT `event_id` (case-sensitive,
 *        paste-blocked) to prove intent — same gesture as the
 *        per-scan kill-switch and run-now dialogs.
 *     2. Mandatory `reason` textarea (10..500 chars). Free-text
 *        justification is recorded ONLY in the audit details (never in
 *        the persisted `abandoned_reason` enum, which always holds the
 *        closed value `"operator"`). This is intentional — operators
 *        sometimes paste customer-sensitive context here, and the audit
 *        row is the proper home for it.
 *
 * A11y mirrors the schedules `RunNowDialog` — focus trap, Esc,
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
import { abandonWebhookDlqAction } from "@/app/admin/webhooks/dlq/actions";
import { DlqErrorAlert } from "@/app/admin/webhooks/dlq/DlqErrorAlert";
import {
  WEBHOOK_DLQ_REASON_MAX,
  WEBHOOK_DLQ_REASON_MIN,
  WebhookDlqAbandonInputSchema,
  WebhookDlqActionError,
  extractWebhookDlqActionCode,
  shortTargetHash,
  type WebhookDlqAbandonResponse,
  type WebhookDlqEntryItem,
  type WebhookDlqFailureCode,
} from "@/lib/adminWebhookDlq";

export type AbandonDialogProps = {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly entry: WebhookDlqEntryItem;
  readonly onComplete?: (result: WebhookDlqAbandonResponse) => void;
  /** Test override — defaults to the canonical abandon action. */
  readonly abandonAction?: typeof abandonWebhookDlqAction;
};

/**
 * Block paste / drop on the typed-event-id input. The user must
 * physically type the event id to prove intent — pasting from
 * clipboard is the very pattern an attacker (or a misclicked
 * drag-and-drop) would use to bypass the gate.
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

export function AbandonDialog({
  open,
  onOpenChange,
  entry,
  onComplete,
  abandonAction = abandonWebhookDlqAction,
}: AbandonDialogProps): React.ReactElement | null {
  const titleId = useId();
  const descriptionId = useId();
  const typedIdId = useId();
  const reasonId = useId();
  const reasonHelpId = useId();
  const submitHelpId = useId();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<HTMLInputElement | null>(null);

  const [typedId, setTypedId] = useState("");
  const [reason, setReason] = useState("");
  const [errorCode, setErrorCode] = useState<WebhookDlqFailureCode | null>(
    null,
  );
  const [hasError, setHasError] = useState(false);
  const [isPending, startTransition] = useTransition();

  const identityKey = `${open ? "1" : "0"}:${entry.id}`;
  const [lastIdentity, setLastIdentity] = useState(identityKey);
  if (identityKey !== lastIdentity) {
    setLastIdentity(identityKey);
    setTypedId("");
    setReason("");
    setErrorCode(null);
    setHasError(false);
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
    trimmedReason.length >= WEBHOOK_DLQ_REASON_MIN &&
    trimmedReason.length <= WEBHOOK_DLQ_REASON_MAX;
  const idMatches = typedId === entry.event_id;
  const canSubmit = idMatches && reasonValid && !isPending;

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canSubmit) return;
    setErrorCode(null);
    setHasError(false);

    const parsed = WebhookDlqAbandonInputSchema.safeParse({
      reason: trimmedReason,
    });
    if (!parsed.success) {
      const next = new WebhookDlqActionError("validation_failed", 400);
      setErrorCode(next.code);
      setHasError(true);
      return;
    }

    startTransition(async () => {
      try {
        const result = await abandonAction(entry.id, parsed.data);
        onOpenChange(false);
        if (onComplete) onComplete(result);
      } catch (err) {
        setErrorCode(extractWebhookDlqActionCode(err));
        setHasError(true);
      }
    });
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4"
      data-testid="dlq-abandon-backdrop"
      onMouseDown={handleBackdropMouseDown}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="flex w-full max-w-lg flex-col gap-4 rounded-lg border border-red-500/60 bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="dlq-abandon-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2 id={titleId} className="text-base font-semibold">
            Отметить webhook как окончательно отброшенный?
          </h2>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог abandon"
            data-testid="dlq-abandon-close"
          >
            ×
          </button>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div
            id={descriptionId}
            className="rounded border border-red-500/60 bg-red-500/5 px-3 py-2 text-xs text-red-100"
          >
            <p>
              Действие необратимо. Запись больше не будет повторяться, а
              получатель никогда не получит это событие.
            </p>
            <dl className="mt-2 grid grid-cols-[110px_1fr] gap-y-1 text-[var(--text-secondary)]">
              <dt className="text-[var(--text-muted)]">Adapter</dt>
              <dd className="font-mono text-[var(--text-primary)]">
                {entry.adapter_name}
              </dd>
              <dt className="text-[var(--text-muted)]">Event</dt>
              <dd
                className="truncate font-mono text-[var(--text-primary)]"
                title={entry.event_id}
              >
                {entry.event_id}
              </dd>
              <dt className="text-[var(--text-muted)]">Type</dt>
              <dd className="font-mono text-[var(--text-primary)]">
                {entry.event_type}
              </dd>
              <dt className="text-[var(--text-muted)]">Target hash</dt>
              <dd
                className="font-mono text-[var(--text-primary)]"
                title={`${entry.target_url_hash} (первые 12 символов SHA-256; URL не сохраняется)`}
              >
                {shortTargetHash(entry.target_url_hash)}
              </dd>
              <dt className="text-[var(--text-muted)]">Попыток</dt>
              <dd className="font-mono text-[var(--text-primary)]">
                {entry.attempt_count}
              </dd>
            </dl>
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={typedIdId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Введите event_id для подтверждения
            </label>
            <input
              id={typedIdId}
              ref={firstFieldRef}
              type="text"
              value={typedId}
              onChange={(e) => setTypedId(e.target.value)}
              disabled={isPending}
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              aria-required="true"
              aria-invalid={typedId.length > 0 && !idMatches}
              {...blockClipboardEvents()}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 font-mono text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="dlq-abandon-typed-id"
            />
            <span className="text-[11px] text-[var(--text-muted)]">
              Регистр символов важен; вставка заблокирована.
            </span>
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={reasonId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Причина (
              {WEBHOOK_DLQ_REASON_MIN}&ndash;{WEBHOOK_DLQ_REASON_MAX}{" "}
              символов)
            </label>
            <textarea
              id={reasonId}
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              disabled={isPending}
              maxLength={WEBHOOK_DLQ_REASON_MAX}
              aria-describedby={reasonHelpId}
              aria-required="true"
              aria-invalid={reason.length > 0 && !reasonValid}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="dlq-abandon-reason"
            />
            <span
              id={reasonHelpId}
              className="text-[11px] text-[var(--text-muted)]"
            >
              Запишется в audit-лог. На самой записи `abandoned_reason`
              хранит закрытую константу `operator`.
            </span>
          </div>

          {hasError ? (
            <DlqErrorAlert
              code={errorCode}
              testId="dlq-abandon-error-alert"
              hint={
                errorCode === "already_replayed" ||
                errorCode === "already_abandoned"
                  ? "Обновите список и проверьте актуальный статус."
                  : null
              }
            />
          ) : null}

          <span id={submitHelpId} className="sr-only">
            Кнопка станет активной после ввода точного event_id и
            причины не короче {WEBHOOK_DLQ_REASON_MIN} символов.
          </span>

          <footer className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
              className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="dlq-abandon-cancel"
            >
              Отмена
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              aria-describedby={submitHelpId}
              className="rounded border border-red-500 bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="dlq-abandon-confirm"
            >
              {isPending ? "Отмечаем…" : "Отметить abandoned"}
            </button>
          </footer>
        </form>
      </div>
    </div>
  );
}
