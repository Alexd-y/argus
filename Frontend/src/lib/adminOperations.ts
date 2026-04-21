/**
 * Closed-taxonomy types, schemas and error helpers for the per-tenant
 * emergency throttle surface (`/admin/operations`, T29, ARG-052).
 *
 * Mirrors the canonical pattern established for scans (`adminScans.ts`),
 * findings (`adminFindings.ts`) and audit logs (`adminAuditLogs.ts`):
 *
 *   - HTTP status → fixed code (`statusToThrottleActionCode`).
 *   - Backend `detail` string → fixed code (`detailToThrottleActionCode`)
 *     so the UI can branch on a closed enum without parsing free-text.
 *   - Code → user-facing RU sentence (`throttleActionErrorMessage`).
 *   - Dedicated `Error` subclass (`ThrottleActionError`) so the React layer
 *     can distinguish action failures from generic JS exceptions and never
 *     surface backend `detail`, stack frames or PII.
 *
 * Wire compatibility:
 *   - Reason min/max length (10 / 500 chars after trim) intentionally LESS
 *     PERMISSIVE than the backend's `EMERGENCY_REASON_MAX_LEN=1000` cap so
 *     the textarea hint matches the cap users see in the UI.
 *   - Allowed durations match `EmergencyThrottleDurationMinutes` literal in
 *     `backend/src/api/schemas.py` (15 / 60 / 240 / 1440 minutes). Sending
 *     anything else short-circuits as `validation_failed` BEFORE the
 *     backend round-trip.
 *
 * No browser-side `fetch` ever uses these schemas — they live behind
 * `"use server"` actions in `Frontend/src/app/admin/operations/actions.ts`.
 */

import { z } from "zod";

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// ---------------------------------------------------------------------------
// Constants — kept as module-level exports so tests + UI share the same
// source of truth. The backend caps these in `EmergencyThrottleRequest`,
// duplicated here to keep the closed-taxonomy errors local to the UI.
// ---------------------------------------------------------------------------

export const THROTTLE_REASON_MIN = 10;
export const THROTTLE_REASON_MAX = 500;

export const THROTTLE_DURATIONS = [15, 60, 240, 1440] as const;
export type ThrottleDurationMinutes = (typeof THROTTLE_DURATIONS)[number];

// Typed-phrase confirmations for the global kill-switch (T30, ARG-053).
// Mirror of `EMERGENCY_STOP_PHRASE` / `EMERGENCY_RESUME_PHRASE` in
// `backend/src/api/schemas.py`. Case-sensitive; UI must paste-block the
// input that compares against them so an operator cannot fat-finger their
// way past the confirmation gate.
export const STOP_ALL_PHRASE = "STOP ALL SCANS";
export const RESUME_ALL_PHRASE = "RESUME ALL SCANS";

export const THROTTLE_DURATION_LABELS: Readonly<
  Record<ThrottleDurationMinutes, string>
> = {
  15: "15 минут",
  60: "1 час",
  240: "4 часа",
  1440: "24 часа",
};

// ---------------------------------------------------------------------------
// Closed taxonomy — the UI ONLY ever inspects these codes. Adding a new code
// requires a matching entry in `ERROR_MESSAGES_RU` so the renderer always
// finds a human sentence to show.
// ---------------------------------------------------------------------------

export const THROTTLE_FAILURE_TAXONOMY = [
  "unauthorized",
  "forbidden",
  "tenant_not_found",
  "validation_failed",
  "duration_not_allowed",
  "already_active",
  "emergency_inactive",
  "store_unavailable",
  "rate_limited",
  "not_implemented",
  "server_error",
  "network_error",
] as const;

export const ThrottleFailureCodeSchema = z.enum(THROTTLE_FAILURE_TAXONOMY);
export type ThrottleFailureCode = z.infer<typeof ThrottleFailureCodeSchema>;

export class ThrottleActionError extends Error {
  readonly code: ThrottleFailureCode;
  readonly status: number | null;

  constructor(code: ThrottleFailureCode, status: number | null = null) {
    super(code);
    this.name = "ThrottleActionError";
    this.code = code;
    this.status = status;
  }
}

const ERROR_MESSAGES_RU: Readonly<
  Record<ThrottleFailureCode, string>
> = {
  unauthorized: "Сессия истекла. Войдите заново.",
  forbidden: "Недостаточно прав для throttle этого tenant.",
  tenant_not_found: "Tenant не найден.",
  validation_failed:
    "Неверные параметры запроса. Проверьте tenant, длительность и причину.",
  duration_not_allowed:
    "Допустимы только длительности 15 минут / 1 час / 4 часа / 24 часа.",
  already_active:
    "Глобальный stop-all активен; throttle отдельного tenant не применяется.",
  emergency_inactive:
    "Глобальный stop не активен — кнопка resume не имеет эффекта.",
  store_unavailable:
    "Хранилище kill-switch недоступно. Повторите попытку через минуту.",
  rate_limited:
    "Слишком много запросов. Повторите попытку через минуту.",
  not_implemented:
    "Ручной resume tenant требует отдельного backend-маршрута (carry-over).",
  server_error: "Не удалось применить throttle. Повторите попытку.",
  network_error:
    "Сеть недоступна. Проверьте соединение и повторите попытку.",
};

export function throttleActionErrorMessage(err: unknown): string {
  if (err instanceof ThrottleActionError) {
    return ERROR_MESSAGES_RU[err.code];
  }
  return ERROR_MESSAGES_RU.server_error;
}

// ---------------------------------------------------------------------------
// HTTP status → closed code. Centralised so server actions and any future
// write paths share a single mapping.
// ---------------------------------------------------------------------------

export function statusToThrottleActionCode(
  status: number,
): ThrottleFailureCode {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  // The throttle endpoint only returns 404 for "tenant not found" today —
  // mirroring the backend's `_DETAIL_TENANT_NOT_FOUND` constant.
  if (status === 404) return "tenant_not_found";
  // 409 from `/throttle` only ever surfaces `emergency_already_active`.
  if (status === 409) return "already_active";
  if (status === 400 || status === 422) return "validation_failed";
  if (status === 429) return "rate_limited";
  // `callAdminBackendJson` collapses transport errors AND missing
  // ADMIN_API_KEY into 503; the user message is identical for both.
  if (status === 503) return "store_unavailable";
  return "server_error";
}

/**
 * Backend `detail` strings → closed codes. The backend's
 * `admin_emergency.py` exports a small fixed set of strings via the
 * `_DETAIL_*` Final constants; we recognise each and downgrade unknown
 * strings to the matching `statusToThrottleActionCode` mapping.
 *
 * Returning `null` means "fall back to the status-based mapping" — the
 * caller (`actions.ts`) decides which path to take.
 */
export function detailToThrottleActionCode(
  detail: unknown,
): ThrottleFailureCode | null {
  if (typeof detail !== "string") return null;
  const normalized = detail.trim().toLowerCase();
  if (normalized === "") return null;
  if (normalized === "forbidden") return "forbidden";
  if (normalized === "tenant not found" || normalized === "tenant_not_found") {
    return "tenant_not_found";
  }
  if (normalized === "tenant mismatch") return "forbidden";
  if (normalized === "emergency_already_active") return "already_active";
  if (normalized === "emergency_not_active") return "emergency_inactive";
  if (normalized === "emergency_store_unavailable") return "store_unavailable";
  if (normalized.startsWith("x-admin-tenant header is required")) {
    return "forbidden";
  }
  if (normalized.startsWith("tenant_id is required")) return "validation_failed";
  return null;
}

/**
 * Top-level mapper used by tests + components. Accepts either a raw
 * backend response (`{ status, detail }`) OR a thrown `ThrottleActionError`
 * and returns a `ThrottleActionError` with a closed code.
 */
export function mapThrottleBackendError(input: {
  status: number;
  detail?: unknown;
}): ThrottleActionError {
  const fromDetail = detailToThrottleActionCode(input.detail);
  const code = fromDetail ?? statusToThrottleActionCode(input.status);
  return new ThrottleActionError(code, input.status);
}

// ---------------------------------------------------------------------------
// Input / output schemas. The Zod parses are the only place where a typed
// view of the backend wire format lives — the action layer parses incoming
// responses and the dialog parses outgoing form values.
// ---------------------------------------------------------------------------

export const ThrottleTenantInputSchema = z.object({
  tenantId: z.string().regex(UUID_RE, "tenantId must be a UUID"),
  durationMinutes: z
    .number()
    .int()
    .refine(
      (v): v is ThrottleDurationMinutes =>
        (THROTTLE_DURATIONS as readonly number[]).includes(v),
      { message: "duration_not_allowed" },
    ),
  reason: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(THROTTLE_REASON_MIN).max(THROTTLE_REASON_MAX)),
});

export type ThrottleTenantInput = z.infer<typeof ThrottleTenantInputSchema>;

export const ThrottleResponseSchema = z.object({
  status: z.literal("throttled"),
  tenant_id: z.string(),
  duration_minutes: z.number().int(),
  expires_at: z.string(),
  audit_id: z.string(),
});

export type ThrottleResponse = z.infer<typeof ThrottleResponseSchema>;

export const EmergencyGlobalStateSchema = z.object({
  active: z.boolean(),
  reason: z.string().nullable().optional(),
  activated_at: z.string().nullable().optional(),
});

export type EmergencyGlobalState = z.infer<typeof EmergencyGlobalStateSchema>;

export const EmergencyTenantThrottleSchema = z.object({
  tenant_id: z.string(),
  reason: z.string(),
  activated_at: z.string(),
  expires_at: z.string(),
  duration_seconds: z.number().int().nonnegative(),
});

export type EmergencyTenantThrottle = z.infer<
  typeof EmergencyTenantThrottleSchema
>;

export const ThrottleStatusResponseSchema = z.object({
  global_state: EmergencyGlobalStateSchema,
  tenant_throttles: z.array(EmergencyTenantThrottleSchema),
  queried_at: z.string(),
});

export type ThrottleStatusResponse = z.infer<
  typeof ThrottleStatusResponseSchema
>;

export const EMERGENCY_AUDIT_EVENT_TYPES = [
  "emergency.stop_all",
  "emergency.resume_all",
  "emergency.throttle",
] as const;

export const EmergencyAuditEventTypeSchema = z.enum(
  EMERGENCY_AUDIT_EVENT_TYPES,
);

export type EmergencyAuditEventType = z.infer<
  typeof EmergencyAuditEventTypeSchema
>;

export const EmergencyAuditItemSchema = z.object({
  audit_id: z.string(),
  event_type: EmergencyAuditEventTypeSchema,
  tenant_id_hash: z.string(),
  operator_subject_hash: z.string().nullable().optional(),
  reason: z.string().nullable().optional(),
  details: z.record(z.string(), z.unknown()).nullable().optional(),
  created_at: z.string(),
});

export type EmergencyAuditItem = z.infer<typeof EmergencyAuditItemSchema>;

export const EmergencyAuditListResponseSchema = z.object({
  items: z.array(EmergencyAuditItemSchema),
  limit: z.number().int().min(1).max(200),
  has_more: z.boolean(),
});

export type EmergencyAuditListResponse = z.infer<
  typeof EmergencyAuditListResponseSchema
>;

// ---------------------------------------------------------------------------
// Global kill-switch (T30, ARG-053)
// Schemas accept ONLY a `reason` from the caller — the typed-phrase
// confirmation is part of the wire body but enforced separately by the UI
// dialog (case-sensitive, paste-blocked) and re-checked server-side. We
// keep the action input minimal so a stale React tree cannot accidentally
// satisfy the phrase gate by passing the constant from a stale module.
// ---------------------------------------------------------------------------

const _emergencyReasonSchema = z
  .string()
  .transform((s) => s.trim())
  .pipe(z.string().min(THROTTLE_REASON_MIN).max(THROTTLE_REASON_MAX));

export const StopAllInputSchema = z.object({
  reason: _emergencyReasonSchema,
});

export type StopAllInput = z.infer<typeof StopAllInputSchema>;

export const StopAllResponseSchema = z.object({
  status: z.literal("stopped"),
  cancelled_count: z.number().int().nonnegative(),
  skipped_terminal_count: z.number().int().nonnegative(),
  tenants_affected: z.number().int().nonnegative(),
  activated_at: z.string(),
  audit_id: z.string(),
});

export type StopAllResponse = z.infer<typeof StopAllResponseSchema>;

export const ResumeAllInputSchema = z.object({
  reason: _emergencyReasonSchema,
});

export type ResumeAllInput = z.infer<typeof ResumeAllInputSchema>;

export const ResumeAllResponseSchema = z.object({
  status: z.literal("resumed"),
  resumed_at: z.string(),
  audit_id: z.string(),
});

export type ResumeAllResponse = z.infer<typeof ResumeAllResponseSchema>;

// ---------------------------------------------------------------------------
// Selector helpers used by the client UI.
// ---------------------------------------------------------------------------

export function findActiveThrottle(
  status: ThrottleStatusResponse | null,
  tenantId: string | null,
): EmergencyTenantThrottle | null {
  if (!status || !tenantId) return null;
  for (const t of status.tenant_throttles) {
    if (t.tenant_id === tenantId) return t;
  }
  return null;
}

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}
