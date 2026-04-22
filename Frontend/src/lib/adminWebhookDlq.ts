/**
 * Closed-taxonomy types, Zod schemas and error helpers for the admin
 * **webhook DLQ** surface (`/admin/webhooks/dlq`, T41, ARG-053).
 *
 * Mirrors the canonical pattern established for scan schedules
 * (`adminSchedules.ts`), operations (`adminOperations.ts`) and audit logs
 * (`adminAuditLogs.ts`):
 *
 *   - HTTP status → fixed code (`statusToWebhookDlqActionCode`).
 *   - Backend `detail` token → fixed code (`detailToWebhookDlqActionCode`).
 *     T39 backend uses snake_case identifier tokens (NOT free-text
 *     sentences), so this layer can switch on a closed enum safely.
 *   - Code → user-facing RU sentence (`webhookDlqActionErrorMessage`).
 *   - Dedicated `Error` subclass (`WebhookDlqActionError`) so the React
 *     layer can distinguish action failures from generic JS exceptions
 *     and never surface backend `detail`, stack frames or PII.
 *
 * Wire compatibility (T39 contract, `backend/src/api/routers/admin_webhook_dlq.py`):
 *   - 422 → `validation_failed`
 *   - 409 → `already_replayed` / `already_abandoned`
 *   - 404 → `dlq_entry_not_found` (also for cross-tenant admin probes —
 *           existence-leak protection)
 *   - 403 → `forbidden` / `tenant_required` / `tenant_mismatch`
 *
 * The browser NEVER imports these schemas directly — they live behind
 * `"use server"` actions in `Frontend/src/app/admin/webhooks/dlq/actions.ts`.
 */

import { z } from "zod";

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// ---------------------------------------------------------------------------
// Constants — duplicated from `backend/src/api/schemas.py`. Source of truth
// lives on the backend (`WEBHOOK_DLQ_REASON_*` constants); deviations here
// surface as `validation_failed` short-circuits BEFORE the round-trip.
// ---------------------------------------------------------------------------

export const WEBHOOK_DLQ_REASON_MIN = 10;
export const WEBHOOK_DLQ_REASON_MAX = 500;

export const WEBHOOK_DLQ_LIMIT_DEFAULT = 25;
export const WEBHOOK_DLQ_LIMIT_MAX = 200;

export const WEBHOOK_DLQ_TRIAGE_STATUSES = [
  "pending",
  "replayed",
  "abandoned",
] as const;
export type WebhookDlqTriageStatus = (typeof WEBHOOK_DLQ_TRIAGE_STATUSES)[number];

export const WEBHOOK_DLQ_TRIAGE_STATUS_LABELS_RU: Readonly<
  Record<WebhookDlqTriageStatus, string>
> = {
  pending: "В очереди",
  replayed: "Повторено",
  abandoned: "Отброшено",
};

// ---------------------------------------------------------------------------
// Closed taxonomy — UI ONLY ever inspects these codes (plan §7).
// Adding a new code requires a matching entry in `ERROR_MESSAGES_RU` so the
// renderer always finds a human sentence to show.
// ---------------------------------------------------------------------------

export const WEBHOOK_DLQ_FAILURE_TAXONOMY = [
  "unauthorized",
  "forbidden",
  "tenant_required",
  "tenant_mismatch",
  "dlq_entry_not_found",
  "already_replayed",
  "already_abandoned",
  "replay_failed",
  "rate_limited",
  "validation_failed",
  "store_unavailable",
  "server_error",
  "network_error",
] as const;

export const WebhookDlqFailureCodeSchema = z.enum(WEBHOOK_DLQ_FAILURE_TAXONOMY);
export type WebhookDlqFailureCode = z.infer<typeof WebhookDlqFailureCodeSchema>;

export class WebhookDlqActionError extends Error {
  readonly code: WebhookDlqFailureCode;
  readonly status: number | null;

  constructor(code: WebhookDlqFailureCode, status: number | null = null) {
    super(code);
    this.name = "WebhookDlqActionError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Best-effort extraction of a closed-taxonomy code from an unknown error
 * thrown by a server action. Server actions in Next.js cross a
 * serialization boundary that strips the prototype chain — so a thrown
 * `WebhookDlqActionError` arrives on the client as a plain `Error` whose
 * code only survives in `.message` (the `super(code)` constructor call).
 *
 * Resolution order, each step short-circuiting on success:
 *   1. `instanceof WebhookDlqActionError` — direct/in-process callers
 *      (unit tests, server-side composition).
 *   2. `err.code` — defensive, in case future plumbing forwards it.
 *   3. `err.message` — Next.js dev-mode preserves it; in production the
 *      message is stripped but the digest is logged server-side.
 *
 * Returns `null` when no taxonomy member is recognised. Callers should
 * treat `null` as `server_error` for both the displayed message AND any
 * `data-error-code` DOM hook.
 */
export function extractWebhookDlqActionCode(
  err: unknown,
): WebhookDlqFailureCode | null {
  if (err instanceof WebhookDlqActionError) return err.code;
  if (typeof err !== "object" || err === null) return null;
  const candidate = err as { code?: unknown; message?: unknown };
  const taxonomy = WEBHOOK_DLQ_FAILURE_TAXONOMY as readonly string[];
  if (typeof candidate.code === "string" && taxonomy.includes(candidate.code)) {
    return candidate.code as WebhookDlqFailureCode;
  }
  if (typeof candidate.message === "string") {
    const trimmed = candidate.message.trim();
    if (taxonomy.includes(trimmed)) {
      return trimmed as WebhookDlqFailureCode;
    }
  }
  return null;
}

const ERROR_MESSAGES_RU: Readonly<Record<WebhookDlqFailureCode, string>> = {
  unauthorized: "Сессия истекла. Войдите заново.",
  forbidden: "Недостаточно прав для управления DLQ этого tenant.",
  tenant_required:
    "Не указан tenant. Admin обязан выбрать tenant; super-admin — оставить пустым для cross-tenant.",
  tenant_mismatch: "X-Admin-Tenant не совпадает с tenant записи DLQ.",
  dlq_entry_not_found: "Запись DLQ не найдена.",
  already_replayed: "Запись уже была успешно повторена.",
  already_abandoned: "Запись уже была отброшена.",
  replay_failed:
    "Повтор не удался; попытка засчитана. Запись остаётся в DLQ.",
  rate_limited: "Слишком много запросов. Повторите попытку через минуту.",
  validation_failed:
    "Неверные параметры запроса. Проверьте обоснование (10–500 символов).",
  store_unavailable:
    "Backend временно недоступен. Повторите попытку через минуту.",
  server_error: "Не удалось выполнить операцию. Повторите попытку.",
  network_error:
    "Сеть недоступна. Проверьте соединение и повторите попытку.",
};

export function webhookDlqActionErrorMessage(err: unknown): string {
  return ERROR_MESSAGES_RU[extractWebhookDlqActionCode(err) ?? "server_error"];
}

export function getWebhookDlqUserMessage(
  code: WebhookDlqFailureCode | null,
): string {
  return ERROR_MESSAGES_RU[code ?? "server_error"];
}

// ---------------------------------------------------------------------------
// HTTP status / detail-token mapping (plan §7).
// ---------------------------------------------------------------------------

/**
 * HTTP status → closed code. Note that 409 in the DLQ surface is
 * AMBIGUOUS — it can mean `already_replayed` OR `already_abandoned`.
 * We default to `already_replayed` here and override via
 * `detailToWebhookDlqActionCode` when the backend exposes the
 * concrete token.
 */
export function statusToWebhookDlqActionCode(
  status: number,
): WebhookDlqFailureCode {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "dlq_entry_not_found";
  if (status === 409) return "already_replayed";
  if (status === 422) return "validation_failed";
  if (status === 400) return "validation_failed";
  if (status === 429) return "rate_limited";
  // `callAdminBackendJson` collapses transport errors AND missing
  // ADMIN_API_KEY into 503; the user message is identical for both.
  if (status === 503) return "store_unavailable";
  return "server_error";
}

/**
 * Backend `detail` snake_case tokens → closed codes (T39 contract).
 *
 * The backend's `admin_webhook_dlq.py` exports a small fixed set of
 * strings via the `_DETAIL_*` Final constants; we recognise each.
 * Returning `null` means "fall back to the status-based mapping".
 */
export function detailToWebhookDlqActionCode(
  detail: unknown,
): WebhookDlqFailureCode | null {
  if (typeof detail !== "string") return null;
  const normalized = detail.trim().toLowerCase();
  if (normalized === "") return null;

  switch (normalized) {
    case "forbidden":
      return "forbidden";
    case "tenant_required":
    case "tenant_id_required":
    case "tenant_header_required":
      return "tenant_required";
    case "tenant_mismatch":
      return "tenant_mismatch";
    case "dlq_entry_not_found":
      return "dlq_entry_not_found";
    case "already_replayed":
      return "already_replayed";
    case "already_abandoned":
      return "already_abandoned";
    case "replay_failed":
      return "replay_failed";
    case "store_unavailable":
      return "store_unavailable";
    case "server_error":
      return "server_error";
    default:
      return null;
  }
}

/**
 * Top-level mapper used by tests + server actions. Accepts a raw
 * backend response (`{ status, detail }`) and returns a
 * `WebhookDlqActionError` with a closed code.
 */
export function mapWebhookDlqBackendError(input: {
  status: number;
  detail?: unknown;
}): WebhookDlqActionError {
  const fromDetail = detailToWebhookDlqActionCode(input.detail);
  const code = fromDetail ?? statusToWebhookDlqActionCode(input.status);
  return new WebhookDlqActionError(code, input.status);
}

// ---------------------------------------------------------------------------
// Wire schemas (mirror Pydantic models in `backend/src/api/schemas.py`).
// ---------------------------------------------------------------------------

export const WebhookDlqEntryItemSchema = z.object({
  id: z.string().regex(UUID_RE),
  tenant_id: z.string().regex(UUID_RE),
  adapter_name: z.string().min(1),
  event_type: z.string().min(1),
  event_id: z.string().min(1),
  target_url_hash: z.string().min(1),
  attempt_count: z.number().int().min(0),
  last_error_code: z.string(),
  last_status_code: z.number().int().nullable(),
  next_retry_at: z.string().nullable(),
  created_at: z.string(),
  replayed_at: z.string().nullable(),
  abandoned_at: z.string().nullable(),
  abandoned_reason: z.string().nullable(),
  triage_status: z.enum(WEBHOOK_DLQ_TRIAGE_STATUSES),
});

export type WebhookDlqEntryItem = z.infer<typeof WebhookDlqEntryItemSchema>;

export const WebhookDlqListResponseSchema = z.object({
  items: z.array(WebhookDlqEntryItemSchema),
  total: z.number().int().min(0),
  limit: z.number().int().min(1).max(WEBHOOK_DLQ_LIMIT_MAX),
  offset: z.number().int().min(0),
});

export type WebhookDlqListResponse = z.infer<typeof WebhookDlqListResponseSchema>;

export const WebhookDlqReplayResponseSchema = z.object({
  entry_id: z.string().regex(UUID_RE),
  success: z.boolean(),
  attempt_count: z.number().int().min(0),
  new_status: z.enum(["replayed", "pending"]),
  audit_id: z.string().regex(UUID_RE),
  message_code: z.enum(["replay_succeeded", "replay_failed"]),
});

export type WebhookDlqReplayResponse = z.infer<
  typeof WebhookDlqReplayResponseSchema
>;

export const WebhookDlqAbandonResponseSchema = z.object({
  entry_id: z.string().regex(UUID_RE),
  new_status: z.literal("abandoned"),
  audit_id: z.string().regex(UUID_RE),
});

export type WebhookDlqAbandonResponse = z.infer<
  typeof WebhookDlqAbandonResponseSchema
>;

// ---------------------------------------------------------------------------
// Action input schemas
// ---------------------------------------------------------------------------

const ReasonSchema = z
  .string()
  .transform((s) => s.trim())
  .pipe(
    z
      .string()
      .min(WEBHOOK_DLQ_REASON_MIN)
      .max(WEBHOOK_DLQ_REASON_MAX),
  );

export const WebhookDlqReplayInputSchema = z.object({
  reason: ReasonSchema,
});

export type WebhookDlqReplayInput = z.infer<typeof WebhookDlqReplayInputSchema>;

export const WebhookDlqAbandonInputSchema = z.object({
  reason: ReasonSchema,
});

export type WebhookDlqAbandonInput = z.infer<typeof WebhookDlqAbandonInputSchema>;

export type WebhookDlqListFilters = {
  readonly tenantId: string | null;
  readonly status: WebhookDlqTriageStatus | null;
  readonly adapterName: string | null;
  readonly createdAfter: string | null;
  readonly createdBefore: string | null;
  readonly limit: number;
  readonly offset: number;
};

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

/**
 * Truncate a UUID for display: first 8 chars + ellipsis.
 * Mirrors `adminSchedules.shortUuid`.
 */
export function shortUuid(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…`;
}

/**
 * Truncate a SHA-256 fingerprint to its first 12 hex characters. Used
 * for `target_url_hash` rendering — the raw URL is NEVER persisted, so
 * the hash is the only stable identifier the operator can correlate
 * across rows.
 */
export function shortTargetHash(hash: string): string {
  if (hash.length <= 12) return hash;
  return hash.slice(0, 12);
}
