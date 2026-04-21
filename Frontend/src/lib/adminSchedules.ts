/**
 * Closed-taxonomy types, schemas, and error helpers for the admin
 * scan-schedules surface (`/admin/schedules`, T35, ARG-056).
 *
 * Mirrors the canonical pattern established for operations
 * (`adminOperations.ts`), scans (`adminScans.ts`) and audit logs
 * (`adminAuditLogs.ts`):
 *
 *   - HTTP status → fixed code (`statusToScheduleActionCode`).
 *   - Backend `detail` token → fixed code (`detailToScheduleActionCode`).
 *     T33 backend uses snake_case identifier tokens (NOT free-text
 *     sentences), so this layer can switch on a closed enum safely.
 *   - Code → user-facing RU sentence (`scheduleActionErrorMessage`).
 *   - Dedicated `Error` subclass (`ScheduleActionError`) so the React
 *     layer can distinguish action failures from generic JS exceptions
 *     and never surface backend `detail`, stack frames or PII.
 *
 * Wire compatibility (T33 contract, commit `12f3ce4`):
 *   - 422 → `invalid_cron_expression` / `invalid_maintenance_window_cron`
 *   - 409 → `schedule_name_conflict` (create/update)
 *           OR `in_maintenance_window` / `emergency_active` (run-now)
 *   - 404 → `schedule_not_found` (also for cross-tenant admin probes;
 *           existence-leak protection, T33 S1.3)
 *   - 403 → `forbidden` / `tenant_id_required` / `tenant_header_required`
 *           / `tenant_mismatch`
 *
 * No browser-side `fetch` ever uses these schemas — they live behind
 * `"use server"` actions in `Frontend/src/app/admin/schedules/actions.ts`.
 */

import { z } from "zod";

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// ---------------------------------------------------------------------------
// Constants — duplicated from `backend/src/api/schemas.py` so the UI hint
// matches the cap users see in the textarea. Source of truth lives on the
// backend (`SCAN_SCHEDULE_*` Final constants); deviations here surface as
// `validation_failed` short-circuits BEFORE the round-trip.
// ---------------------------------------------------------------------------

export const SCHEDULE_NAME_MIN = 1;
export const SCHEDULE_NAME_MAX = 255;
export const SCHEDULE_CRON_MAX = 64;
export const SCHEDULE_TARGET_MAX = 2048;

export const RUN_NOW_REASON_MIN = 10;
export const RUN_NOW_REASON_MAX = 500;

export const SCAN_MODES = ["standard", "deep"] as const;
export type ScanMode = (typeof SCAN_MODES)[number];

export const SCAN_MODE_LABELS_RU: Readonly<Record<ScanMode, string>> = {
  standard: "Стандартный",
  deep: "Глубокий",
};

// Mirrors `TARGET_PATTERN` in `backend/src/api/schemas.py`:
//   ^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?(/.*)?$
// We replicate it client-side to short-circuit obvious nonsense without a
// round-trip; the backend re-validates so a stale module here cannot
// introduce a hole.
const TARGET_URL_RE =
  /^(https?:\/\/)?[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?(\/.*)?$/;

// ---------------------------------------------------------------------------
// Closed taxonomy — UI ONLY ever inspects these codes.
// Adding a new code requires a matching entry in `ERROR_MESSAGES_RU` so the
// renderer always finds a human sentence to show.
// ---------------------------------------------------------------------------

export const SCHEDULE_FAILURE_TAXONOMY = [
  "unauthorized",
  "forbidden",
  "tenant_required",
  "tenant_mismatch",
  "schedule_not_found",
  "schedule_name_conflict",
  "invalid_cron_expression",
  "invalid_maintenance_window_cron",
  "in_maintenance_window",
  "emergency_active",
  "validation_failed",
  "rate_limited",
  "store_unavailable",
  "server_error",
  "network_error",
] as const;

export const ScheduleFailureCodeSchema = z.enum(SCHEDULE_FAILURE_TAXONOMY);
export type ScheduleFailureCode = z.infer<typeof ScheduleFailureCodeSchema>;

export class ScheduleActionError extends Error {
  readonly code: ScheduleFailureCode;
  readonly status: number | null;

  constructor(code: ScheduleFailureCode, status: number | null = null) {
    super(code);
    this.name = "ScheduleActionError";
    this.code = code;
    this.status = status;
  }
}

const ERROR_MESSAGES_RU: Readonly<Record<ScheduleFailureCode, string>> = {
  unauthorized: "Сессия истекла. Войдите заново.",
  forbidden: "Недостаточно прав для управления расписаниями этого tenant.",
  tenant_required:
    "Не указан tenant. Admin обязан выбрать tenant; super-admin — оставить пустым для cross-tenant.",
  tenant_mismatch:
    "X-Admin-Tenant не совпадает с tenant расписания.",
  schedule_not_found: "Расписание не найдено.",
  schedule_name_conflict:
    "Имя уже занято в этом tenant. Выберите другое.",
  invalid_cron_expression:
    "Невалидное cron-выражение или интервал чаще, чем 5 минут.",
  invalid_maintenance_window_cron:
    "Невалидное cron-выражение для maintenance window (минимальный интервал 60 минут).",
  in_maintenance_window:
    "Сейчас активно maintenance window. Установите bypass и повторите.",
  emergency_active:
    "Активен глобальный emergency stop / per-tenant throttle. Снимите блокировку и повторите.",
  validation_failed:
    "Неверные параметры запроса. Проверьте имя, cron, target_url и режим.",
  rate_limited: "Слишком много запросов. Повторите попытку через минуту.",
  store_unavailable:
    "Backend временно недоступен. Повторите попытку через минуту.",
  server_error: "Не удалось выполнить операцию. Повторите попытку.",
  network_error:
    "Сеть недоступна. Проверьте соединение и повторите попытку.",
};

export function scheduleActionErrorMessage(err: unknown): string {
  if (err instanceof ScheduleActionError) {
    return ERROR_MESSAGES_RU[err.code];
  }
  return ERROR_MESSAGES_RU.server_error;
}

// ---------------------------------------------------------------------------
// HTTP status / detail-token mapping
// ---------------------------------------------------------------------------

/**
 * HTTP status → closed code. Note that 409 in the schedules surface is
 * AMBIGUOUS — it can mean `schedule_name_conflict` (create/update) OR
 * `in_maintenance_window` / `emergency_active` (run-now). We default to
 * `schedule_name_conflict` here and override via `detailToScheduleActionCode`
 * for the run-now path.
 */
export function statusToScheduleActionCode(
  status: number,
): ScheduleFailureCode {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "schedule_not_found";
  if (status === 409) return "schedule_name_conflict";
  if (status === 422) return "invalid_cron_expression";
  if (status === 400) return "validation_failed";
  if (status === 429) return "rate_limited";
  // `callAdminBackendJson` collapses transport errors AND missing
  // ADMIN_API_KEY into 503; the user message is identical for both.
  if (status === 503) return "store_unavailable";
  return "server_error";
}

/**
 * Backend `detail` snake_case tokens → closed codes (T33 contract).
 *
 * The backend's `admin_schedules.py` exports a small fixed set of strings
 * via the `_DETAIL_*` Final constants; we recognise each. Returning `null`
 * means "fall back to the status-based mapping" — the caller (`actions.ts`)
 * decides which path to take.
 */
export function detailToScheduleActionCode(
  detail: unknown,
): ScheduleFailureCode | null {
  if (typeof detail !== "string") return null;
  const normalized = detail.trim().toLowerCase();
  if (normalized === "") return null;

  switch (normalized) {
    case "forbidden":
      return "forbidden";
    case "tenant_id_required":
    case "tenant_header_required":
      return "tenant_required";
    case "tenant_mismatch":
      return "tenant_mismatch";
    case "schedule_not_found":
      return "schedule_not_found";
    case "schedule_name_conflict":
      return "schedule_name_conflict";
    case "invalid_cron_expression":
      return "invalid_cron_expression";
    case "invalid_maintenance_window_cron":
      return "invalid_maintenance_window_cron";
    case "in_maintenance_window":
      return "in_maintenance_window";
    case "emergency_active":
      return "emergency_active";
    case "tenant_not_found":
      // Surface a less alarming sentence than `schedule_not_found` for
      // the create path (which 404s the tenant lookup).
      return "validation_failed";
    default:
      return null;
  }
}

/**
 * Top-level mapper used by tests + components. Accepts either a raw
 * backend response (`{ status, detail }`) OR a thrown `ScheduleActionError`
 * and returns a `ScheduleActionError` with a closed code.
 */
export function mapScheduleBackendError(input: {
  status: number;
  detail?: unknown;
}): ScheduleActionError {
  const fromDetail = detailToScheduleActionCode(input.detail);
  const code = fromDetail ?? statusToScheduleActionCode(input.status);
  return new ScheduleActionError(code, input.status);
}

// ---------------------------------------------------------------------------
// Wire schemas
// ---------------------------------------------------------------------------

export const ScheduleSchema = z.object({
  id: z.string().regex(UUID_RE),
  tenant_id: z.string().regex(UUID_RE),
  name: z.string().min(SCHEDULE_NAME_MIN).max(SCHEDULE_NAME_MAX),
  cron_expression: z.string().min(1).max(SCHEDULE_CRON_MAX),
  target_url: z.string().min(1).max(SCHEDULE_TARGET_MAX),
  scan_mode: z.string(),
  enabled: z.boolean(),
  maintenance_window_cron: z.string().nullable(),
  last_run_at: z.string().nullable(),
  next_run_at: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type Schedule = z.infer<typeof ScheduleSchema>;

export const SchedulesListResponseSchema = z.object({
  items: z.array(ScheduleSchema),
  total: z.number().int().min(0),
  limit: z.number().int().min(1).max(200),
  offset: z.number().int().min(0),
});

export type SchedulesListResponse = z.infer<typeof SchedulesListResponseSchema>;

export const ScheduleCreateInputSchema = z.object({
  tenantId: z.string().regex(UUID_RE, "tenantId must be a UUID"),
  name: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(SCHEDULE_NAME_MIN).max(SCHEDULE_NAME_MAX)),
  cronExpression: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(1).max(SCHEDULE_CRON_MAX)),
  targetUrl: z
    .string()
    .transform((s) => s.trim())
    .pipe(
      z
        .string()
        .min(1)
        .max(SCHEDULE_TARGET_MAX)
        .regex(TARGET_URL_RE, "targetUrl must look like an URL"),
    ),
  scanMode: z.enum(SCAN_MODES),
  enabled: z.boolean(),
  maintenanceWindowCron: z
    .string()
    .nullable()
    .transform((s) => (typeof s === "string" ? s.trim() : s))
    .transform((s) => (s === "" ? null : s))
    .pipe(z.string().max(SCHEDULE_CRON_MAX).nullable()),
});

export type ScheduleCreateInput = z.infer<typeof ScheduleCreateInputSchema>;

export const ScheduleUpdateInputSchema = z.object({
  name: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(SCHEDULE_NAME_MIN).max(SCHEDULE_NAME_MAX))
    .optional(),
  cronExpression: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(1).max(SCHEDULE_CRON_MAX))
    .optional(),
  targetUrl: z
    .string()
    .transform((s) => s.trim())
    .pipe(
      z
        .string()
        .min(1)
        .max(SCHEDULE_TARGET_MAX)
        .regex(TARGET_URL_RE, "targetUrl must look like an URL"),
    )
    .optional(),
  scanMode: z.enum(SCAN_MODES).optional(),
  enabled: z.boolean().optional(),
  maintenanceWindowCron: z
    .string()
    .max(SCHEDULE_CRON_MAX)
    .optional(),
});

export type ScheduleUpdateInput = z.infer<typeof ScheduleUpdateInputSchema>;

export const RunNowInputSchema = z.object({
  bypassMaintenanceWindow: z.boolean(),
  reason: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(RUN_NOW_REASON_MIN).max(RUN_NOW_REASON_MAX)),
});

export type RunNowInput = z.infer<typeof RunNowInputSchema>;

export const RunNowResponseSchema = z.object({
  schedule_id: z.string().regex(UUID_RE),
  enqueued_task_id: z.string(),
  bypassed_maintenance_window: z.boolean(),
  enqueued_at: z.string(),
  audit_id: z.string(),
});

export type RunNowResponse = z.infer<typeof RunNowResponseSchema>;

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

/**
 * Truncate a UUID for display: first 8 chars + ellipsis.
 * Mirrors the pattern used in `AdminScansClient.shortId`.
 */
export function shortUuid(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…`;
}
