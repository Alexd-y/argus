"use client";

/**
 * `ChainVerifyResult` — banner that surfaces the verdict of the audit-log
 * chain replay (T25 endpoint, fired from T22 UI).
 *
 * Behaviour:
 *   - `ok: true`  → green banner (`role="status"`, polite announcement) with
 *     "verified N records" + the effective replay window.
 *   - `ok: false` → red banner (`role="alert"`, assertive announcement)
 *     calling out the drift event id, the timestamp it was detected at, how
 *     many records replayed cleanly first, and the effective window.
 *   - "Прокрутить к записи" surfaces only when `drift_event_id` is present
 *     and the parent says the row is currently loaded — keeps the action
 *     honest (the table can't scroll to a row it doesn't have).
 *   - "Скрыть" dismisses the banner.
 *
 * No PII / secrets are added: only the IDs and timestamps the backend
 * already returned.
 */

import { useMemo } from "react";

import type { AuditChainVerifyResponse } from "@/lib/adminAuditLogs";

export type ChainVerifyResultProps = {
  readonly result: AuditChainVerifyResponse | null;
  readonly errorMessage?: string | null;
  readonly verifying?: boolean;
  readonly onJumpToDrift?: (eventId: string) => void;
  readonly canJumpToDrift?: boolean;
  readonly onDismiss?: () => void;
};

function formatDt(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

export function ChainVerifyResult({
  result,
  errorMessage = null,
  verifying = false,
  onJumpToDrift,
  canJumpToDrift = false,
  onDismiss,
}: ChainVerifyResultProps): React.ReactElement | null {
  const window = useMemo(() => {
    if (!result) return "";
    return `${formatDt(result.effective_since)} — ${formatDt(result.effective_until)}`;
  }, [result]);

  if (verifying) {
    return (
      <div
        role="status"
        aria-live="polite"
        data-testid="audit-chain-verifying"
        className="flex items-center justify-between gap-3 rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]"
      >
        <span>Проверяем целостность цепочки…</span>
      </div>
    );
  }

  if (errorMessage) {
    return (
      <div
        role="alert"
        data-testid="audit-chain-error"
        className="flex items-center justify-between gap-3 rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-sm text-red-200"
      >
        <span>{errorMessage}</span>
        {onDismiss ? (
          <button
            type="button"
            onClick={onDismiss}
            className="rounded border border-red-500/60 px-2 py-1 text-xs text-red-100 hover:bg-red-500/20 focus-visible:ring-2 focus-visible:ring-red-300 focus-visible:outline-none"
            data-testid="audit-chain-dismiss"
          >
            Скрыть
          </button>
        ) : null}
      </div>
    );
  }

  if (!result) {
    return null;
  }

  if (result.ok) {
    return (
      <div
        role="status"
        aria-live="polite"
        data-testid="audit-chain-ok"
        className="flex flex-wrap items-center justify-between gap-3 rounded border border-emerald-600/60 bg-emerald-600/10 px-3 py-2 text-sm text-emerald-200"
      >
        <div className="flex flex-col gap-0.5">
          <span className="font-medium">
            Цепочка целостна. Проверено {result.verified_count} записей.
          </span>
          <span className="text-xs text-emerald-200/80">Окно: {window}</span>
        </div>
        {onDismiss ? (
          <button
            type="button"
            onClick={onDismiss}
            className="rounded border border-emerald-600/60 px-2 py-1 text-xs text-emerald-100 hover:bg-emerald-600/20 focus-visible:ring-2 focus-visible:ring-emerald-300 focus-visible:outline-none"
            data-testid="audit-chain-dismiss"
          >
            Скрыть
          </button>
        ) : null}
      </div>
    );
  }

  // Drift detected.
  return (
    <div
      role="alert"
      data-testid="audit-chain-drift"
      className="flex flex-col gap-2 rounded border border-red-500/70 bg-red-500/10 px-3 py-2 text-sm text-red-100"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <span className="font-medium">Обнаружено расхождение цепочки.</span>
          <span className="text-xs text-red-200/90">
            Проверено успешно: {result.verified_count}; индекс последней
            валидной записи: {result.last_verified_index}.
          </span>
          <span className="text-xs text-red-200/90">
            Drift event ID:{" "}
            <code className="rounded bg-red-500/20 px-1 py-0.5 font-mono text-[11px]">
              {result.drift_event_id ?? "—"}
            </code>
          </span>
          <span className="text-xs text-red-200/90">
            Время фиксации drift: {formatDt(result.drift_detected_at)}
          </span>
          <span className="text-xs text-red-200/90">Окно: {window}</span>
        </div>
        <div className="flex gap-2">
          {onJumpToDrift && result.drift_event_id && canJumpToDrift ? (
            <button
              type="button"
              onClick={() => onJumpToDrift(result.drift_event_id!)}
              className="rounded border border-red-300/70 bg-red-500/20 px-2 py-1 text-xs font-medium text-red-50 hover:bg-red-500/30 focus-visible:ring-2 focus-visible:ring-red-300 focus-visible:outline-none"
              data-testid="audit-chain-jump"
            >
              Прокрутить к записи
            </button>
          ) : null}
          {onDismiss ? (
            <button
              type="button"
              onClick={onDismiss}
              className="rounded border border-red-500/60 px-2 py-1 text-xs text-red-100 hover:bg-red-500/20 focus-visible:ring-2 focus-visible:ring-red-300 focus-visible:outline-none"
              data-testid="audit-chain-dismiss"
            >
              Скрыть
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
