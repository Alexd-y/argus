"use client";

/**
 * `ReplayDialog` — modal that re-dispatches a single webhook DLQ entry
 * via `replayWebhookDlqAction` (T41, ARG-053).
 *
 * UX intent:
 *   "Повторить" overrides the dispatcher-side circuit-breaker / dedup
 *   bucket — operators are explicitly bypassing the auto-protections
 *   that would otherwise short-circuit the call. To prevent fat-finger
 *   fires we require:
 *
 *     1. Mandatory `reason` textarea (10..500 chars) recorded in the
 *        audit trail; the closed-enum `abandoned_reason="operator"`
 *        carries no free text on the persisted row.
 *     2. Confirm-button only enabled when the reason validates locally
 *        (Zod runs again server-side).
 *
 * Contract notes:
 *   The backend always returns 202; `success=false` + `message_code=
 *   "replay_failed"` is a NORMAL outcome (the entry stays in the DLQ
 *   with an incremented attempt counter). The dialog inspects the
 *   response body to render either a success or "replay_failed" toast
 *   via `onComplete`.
 *
 * A11y mirrors the schedules surface — focus trap, Esc, `role="dialog"`
 * + `aria-modal`, `role="alert"` on the error banner. Buttons carry
 * `aria-label` so the AT user hears the entry context, not just the
 * verb.
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
import { replayWebhookDlqAction } from "@/app/admin/webhooks/dlq/actions";
import { DlqErrorAlert } from "@/app/admin/webhooks/dlq/DlqErrorAlert";
import {
  WEBHOOK_DLQ_REASON_MAX,
  WEBHOOK_DLQ_REASON_MIN,
  WebhookDlqActionError,
  WebhookDlqReplayInputSchema,
  extractWebhookDlqActionCode,
  shortTargetHash,
  type WebhookDlqEntryItem,
  type WebhookDlqFailureCode,
  type WebhookDlqReplayResponse,
} from "@/lib/adminWebhookDlq";

export type ReplayDialogProps = {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly entry: WebhookDlqEntryItem;
  readonly onComplete?: (result: WebhookDlqReplayResponse) => void;
  /** Test override — defaults to the canonical replay action. */
  readonly replayAction?: typeof replayWebhookDlqAction;
};

export function ReplayDialog({
  open,
  onOpenChange,
  entry,
  onComplete,
  replayAction = replayWebhookDlqAction,
}: ReplayDialogProps): React.ReactElement | null {
  const titleId = useId();
  const descriptionId = useId();
  const reasonId = useId();
  const reasonHelpId = useId();
  const submitHelpId = useId();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<HTMLTextAreaElement | null>(null);

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
  const canSubmit = reasonValid && !isPending;

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canSubmit) return;
    setErrorCode(null);
    setHasError(false);

    const parsed = WebhookDlqReplayInputSchema.safeParse({
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
        const result = await replayAction(entry.id, parsed.data);
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
      data-testid="dlq-replay-backdrop"
      onMouseDown={handleBackdropMouseDown}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="flex w-full max-w-lg flex-col gap-4 rounded-lg border border-emerald-500/60 bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="dlq-replay-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2 id={titleId} className="text-base font-semibold">
            Повторить webhook?
          </h2>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог повтора"
            data-testid="dlq-replay-close"
          >
            ×
          </button>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div
            id={descriptionId}
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-xs text-[var(--text-secondary)]"
          >
            <dl className="grid grid-cols-[110px_1fr] gap-y-1">
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
              <dt className="text-[var(--text-muted)]">Last error</dt>
              <dd className="font-mono text-red-200">
                {entry.last_error_code}
                {entry.last_status_code !== null
                  ? ` · HTTP ${entry.last_status_code}`
                  : ""}
              </dd>
            </dl>
            <p className="mt-2 text-[11px] text-[var(--text-muted)]">
              Повтор обходит in-process circuit-breaker и дедуп
              dispatcher&rsquo;а. Используйте для разовой ручной
              отправки.
            </p>
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={reasonId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Причина повтора (
              {WEBHOOK_DLQ_REASON_MIN}&ndash;{WEBHOOK_DLQ_REASON_MAX}{" "}
              символов)
            </label>
            <textarea
              id={reasonId}
              ref={firstFieldRef}
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              disabled={isPending}
              maxLength={WEBHOOK_DLQ_REASON_MAX}
              aria-describedby={reasonHelpId}
              aria-required="true"
              aria-invalid={reason.length > 0 && !reasonValid}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:outline-none disabled:opacity-50"
              data-testid="dlq-replay-reason"
            />
            <span
              id={reasonHelpId}
              className="text-[11px] text-[var(--text-muted)]"
            >
              Запишется в audit-лог вместе с adapter / event_id /
              attempt_count.
            </span>
          </div>

          {hasError ? (
            <DlqErrorAlert
              code={errorCode}
              testId="dlq-replay-error-alert"
              hint={
                errorCode === "already_replayed" ||
                errorCode === "already_abandoned"
                  ? "Обновите список и проверьте актуальный статус."
                  : null
              }
            />
          ) : null}

          <span id={submitHelpId} className="sr-only">
            Кнопка станет активной после ввода причины не короче{" "}
            {WEBHOOK_DLQ_REASON_MIN} символов.
          </span>

          <footer className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
              className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="dlq-replay-cancel"
            >
              Отмена
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              aria-describedby={submitHelpId}
              className="rounded border border-emerald-500 bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="dlq-replay-confirm"
            >
              {isPending ? "Повторяем…" : "Повторить"}
            </button>
          </footer>
        </form>
      </div>
    </div>
  );
}
