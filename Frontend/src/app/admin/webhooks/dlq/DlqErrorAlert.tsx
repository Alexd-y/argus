"use client";

/**
 * `DlqErrorAlert` — closed-taxonomy error banner used inside the
 * webhook DLQ replay/abandon dialogs (T41, ARG-053).
 *
 * The component intentionally accepts ONLY a closed-taxonomy code (or
 * `null` for the `server_error` fallback) — never a raw `detail`,
 * `message`, or `Error` instance. This guarantees no backend stack
 * traces, internal field names, or PII leak into the rendered DOM.
 *
 * `data-error-code` exposes the taxonomy code to the Playwright/Vitest
 * suites so they can assert the mapping deterministically without
 * scraping localized RU sentences.
 */

import {
  getWebhookDlqUserMessage,
  type WebhookDlqFailureCode,
} from "@/lib/adminWebhookDlq";

export type DlqErrorAlertProps = {
  readonly code: WebhookDlqFailureCode | null;
  /** Optional extra hint appended after the canonical RU sentence. */
  readonly hint?: string | null;
  readonly testId?: string;
};

export function DlqErrorAlert({
  code,
  hint,
  testId = "dlq-error-alert",
}: DlqErrorAlertProps): React.ReactElement {
  const message = getWebhookDlqUserMessage(code);
  return (
    <div
      role="alert"
      className="rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-xs text-red-200"
      data-testid={testId}
      data-error-code={code ?? "server_error"}
    >
      {message}
      {hint ? <span className="ml-1">{hint}</span> : null}
    </div>
  );
}
