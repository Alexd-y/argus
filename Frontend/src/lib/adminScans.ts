/**
 * Closed-taxonomy types, schemas and error helpers for the admin scans
 * surface. Mirrors the pattern established for findings (`adminFindings.ts`)
 * and audit logs (`adminAuditLogs.ts`):
 *
 *  - HTTP status → fixed code (`statusToScanActionCode`)
 *  - Code → RU sentence (`scanActionErrorMessage`)
 *  - Dedicated `Error` subclass (`ScanActionError`) so the UI can distinguish
 *    these failures from generic JS exceptions and never surface backend
 *    `detail`, stack frames or PII.
 *
 * The kill-switch dialog (T28) is the first consumer; the same taxonomy is
 * intended to be reused by every future per-scan write action (retry, force
 * complete, etc.) so the UI can render a single bilingual error registry.
 */

import { z } from "zod";

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const SCAN_ACTION_FAILURE_TAXONOMY = [
  "unauthorized",
  "forbidden",
  "not_found",
  "validation_failed",
  "conflict",
  "rate_limited",
  "server_error",
  "network_error",
] as const;

export const ScanActionFailureCodeSchema = z.enum(
  SCAN_ACTION_FAILURE_TAXONOMY,
);
export type ScanActionFailureCode = z.infer<typeof ScanActionFailureCodeSchema>;

/**
 * Terminal scan statuses — the kill-switch is hidden / disabled for rows in
 * any of these states because there is nothing left to cancel. Kept here
 * (lib, NOT component) so server actions and unit tests can share the same
 * source of truth as the UI.
 */
export const TERMINAL_SCAN_STATUSES = [
  "completed",
  "cancelled",
  "failed",
] as const;

export type TerminalScanStatus = (typeof TERMINAL_SCAN_STATUSES)[number];

export function isTerminalScanStatus(status: string): boolean {
  const normalized = status.trim().toLowerCase();
  return (TERMINAL_SCAN_STATUSES as readonly string[]).includes(normalized);
}

/**
 * Operator-supplied reason. The reason is captured in the UI and forwarded
 * to the operator-subject audit chain (via the structured server-action log
 * + the existing admin bulk-cancel `audit_id`); the bounds match the
 * backend's emergency-action reason cap so the field is interchangeable
 * with stop-all / throttle when the per-scan endpoint grows a body.
 */
export const SCAN_REASON_MIN = 10;
export const SCAN_REASON_MAX = 500;

export const KillScanInputSchema = z.object({
  scanId: z.string().regex(UUID_RE, "scanId must be a UUID"),
  tenantId: z.string().regex(UUID_RE, "tenantId must be a UUID"),
  reason: z
    .string()
    .min(SCAN_REASON_MIN)
    .max(SCAN_REASON_MAX),
});

export type KillScanInput = z.infer<typeof KillScanInputSchema>;

/**
 * Per-scan kill-switch outcome. The `status` field is a closed enum so the
 * UI can branch on it without ever inspecting backend strings.
 *
 *  - `cancelled`        — the scan was active and is now cancelled.
 *  - `skipped_terminal` — already in a terminal state; no-op (idempotent).
 *  - `not_found`        — scan id does not exist (or belongs to another
 *                         tenant; the backend deliberately collapses both
 *                         to avoid leaking existence).
 */
export const KillScanResultSchema = z.object({
  status: z.enum(["cancelled", "skipped_terminal", "not_found"]),
  scanId: z.string(),
  auditId: z.string().nullable(),
});

export type KillScanResult = z.infer<typeof KillScanResultSchema>;

export class ScanActionError extends Error {
  readonly code: ScanActionFailureCode;
  readonly status: number | null;

  constructor(code: ScanActionFailureCode, status: number | null = null) {
    super(code);
    this.name = "ScanActionError";
    this.code = code;
    this.status = status;
  }
}

const ERROR_MESSAGES_RU: Readonly<
  Record<ScanActionFailureCode, string>
> = {
  unauthorized: "Сессия истекла. Войдите заново.",
  forbidden: "Недостаточно прав для отмены этого скана.",
  not_found: "Скан не найден или принадлежит другому tenant.",
  validation_failed:
    "Неверные параметры запроса. Проверьте scan ID и причину.",
  conflict: "Скан уже находится в финальном статусе и не может быть отменён.",
  rate_limited: "Слишком много запросов. Повторите попытку через минуту.",
  server_error: "Не удалось отменить скан. Повторите попытку.",
  network_error: "Сеть недоступна. Проверьте соединение и повторите попытку.",
};

export function scanActionErrorMessage(err: unknown): string {
  if (err instanceof ScanActionError) {
    return ERROR_MESSAGES_RU[err.code];
  }
  return ERROR_MESSAGES_RU.server_error;
}

/**
 * HTTP status → closed code. Centralised so server actions and any future
 * write paths share a single mapping.
 *
 *  - 401 → unauthorized (no/invalid cookie or admin key)
 *  - 403 → forbidden    (RBAC denied at backend)
 *  - 404 → not_found
 *  - 409 → conflict     (terminal state on the backend side)
 *  - 422 / 400 → validation_failed
 *  - 429 → rate_limited
 *  - 503 → network_error (transport / missing ADMIN_API_KEY surfaces as 503
 *         in `callAdminBackendJson`)
 *  - everything else → server_error
 */
export function statusToScanActionCode(
  status: number,
): ScanActionFailureCode {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 400 || status === 422) return "validation_failed";
  if (status === 429) return "rate_limited";
  if (status === 503) return "network_error";
  return "server_error";
}

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}
