/**
 * Admin audit-logs — typed contract + closed-taxonomy errors for the audit
 * viewer page (T22) and the chain-integrity verification panel (T25 backend).
 *
 * Transport-free module: imported by both `"use server"` actions
 * (`Frontend/src/app/admin/audit-logs/actions.ts`) and React components. The
 * browser must NEVER see `X-Admin-Key` (S0-1 / T20) — every read goes through
 * the server-action proxy that injects the key from `ADMIN_API_KEY`.
 *
 * Backend contract (Phase-1, ARG-051b):
 *   GET  /api/v1/admin/audit-logs            → returns a flat
 *                                              list[AuditLogOut] (no envelope,
 *                                              offset/limit pagination)
 *   POST /api/v1/admin/audit-logs/verify-chain
 *                                            → AuditChainVerifyResponse (T25)
 *
 * The list endpoint exposes `action`, `user_id` and offset-based pagination
 * — different from the "T18-era" envelope shape described in the orchestration
 * plan. We bridge this in two ways:
 *   1. The `AuditLogItemSchema` accepts BOTH the wire names (`action`,
 *      `user_id`) and the public/UI names (`event_type`, `actor_subject`) and
 *      normalises them so the rest of the UI sees a single shape. This keeps
 *      the contract forward-compatible if the backend ever adds the public
 *      names alongside the legacy ones.
 *   2. The `AuditLogsListResponseSchema` accepts EITHER a wrapped envelope
 *      (`{items, total, next_cursor}`) OR a bare array, transforming both
 *      into a single envelope shape. The action layer synthesises a
 *      numeric-string `next_cursor` from `offset + items.length` whenever a
 *      page is full so React Query's infinite-scroll keeps working.
 *
 * Severity is OPTIONAL: the persisted `audit_logs` row carries no severity
 * column today. Some chain-aware emitters write `details.severity` (closed
 * enum). The schema lifts that value when present and falls back to `null`,
 * which the table renders as a neutral "info" badge.
 *
 * Error taxonomy is closed (matches `adminFindings.ts` pattern) — every
 * transport / validation failure maps to a `AdminAuditLogsErrorCode` so the
 * UI can render a fixed RU sentence without ever leaking stack traces, query
 * fragments or PII.
 */

import { z } from "zod";

const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"] as const;

export type AuditSeverity = (typeof SEVERITY_VALUES)[number];

export const AUDIT_SEVERITIES: ReadonlyArray<AuditSeverity> = SEVERITY_VALUES;

const SEVERITY_SET = new Set<string>(SEVERITY_VALUES);

export function isAuditSeverity(value: unknown): value is AuditSeverity {
  return typeof value === "string" && SEVERITY_SET.has(value);
}

const SeveritySchema = z
  .union([z.string(), z.null()])
  .optional()
  .transform((v): AuditSeverity | null => {
    if (v == null) return null;
    const lower = v.toLowerCase();
    return SEVERITY_SET.has(lower) ? (lower as AuditSeverity) : null;
  });

const NullableStringSchema = z
  .union([z.string(), z.null()])
  .optional()
  .transform((v): string | null => (v == null ? null : v));

/**
 * JSONB cell. We accept anything serialisable and let the UI render it as
 * pretty-printed JSON via `JSON.stringify` — never `dangerouslySetInnerHTML`.
 */
const DetailsSchema: z.ZodType<unknown> = z.unknown();

/**
 * Severity is sometimes embedded inside `details.severity` rather than a
 * top-level column. Lift it during parse so the UI can render a single
 * `severity` field regardless of where it came from.
 */
function liftSeverityFromDetails(details: unknown): AuditSeverity | null {
  if (
    details === null ||
    typeof details !== "object" ||
    Array.isArray(details)
  ) {
    return null;
  }
  const sev = (details as Record<string, unknown>).severity;
  if (typeof sev !== "string") return null;
  const lower = sev.toLowerCase();
  return SEVERITY_SET.has(lower) ? (lower as AuditSeverity) : null;
}

/**
 * Single audit-log row, normalised to the UI shape. Both the legacy wire
 * names (`action`, `user_id`) and the public names (`event_type`,
 * `actor_subject`) are accepted; the UI sees `event_type` / `actor_subject`.
 */
export const AuditLogItemSchema = z
  .object({
    id: z.string().min(1),
    created_at: z.string().min(1),
    event_type: NullableStringSchema,
    action: NullableStringSchema,
    actor_subject: NullableStringSchema,
    user_id: NullableStringSchema,
    tenant_id: NullableStringSchema,
    resource_type: NullableStringSchema,
    resource_id: NullableStringSchema,
    details: DetailsSchema.nullable().optional(),
    severity: SeveritySchema,
  })
  .transform((raw) => {
    const eventType = raw.event_type ?? raw.action ?? "";
    const actor = raw.actor_subject ?? raw.user_id ?? null;
    const details = raw.details ?? null;
    const severity = raw.severity ?? liftSeverityFromDetails(details);
    return {
      id: raw.id,
      created_at: raw.created_at,
      event_type: eventType,
      actor_subject: actor,
      tenant_id: raw.tenant_id ?? null,
      resource_type: raw.resource_type,
      resource_id: raw.resource_id,
      details,
      severity,
    };
  });

export type AuditLogItem = z.infer<typeof AuditLogItemSchema>;

/**
 * List envelope. Accepts BOTH the wrapped shape (`{items, total,
 * next_cursor}`) and a bare array — the current `GET /admin/audit-logs`
 * returns the latter. After parse, callers always see the wrapped shape so
 * `useInfiniteQuery` can read `next_cursor` uniformly.
 */
const WrappedEnvelopeSchema = z.object({
  items: z.array(AuditLogItemSchema),
  total: z.number().int().nonnegative().optional(),
  next_cursor: z
    .union([z.string(), z.null()])
    .optional()
    .transform((v) => (v == null || v === "" ? null : v)),
});

const BareArraySchema = z.array(AuditLogItemSchema);

export const AuditLogsListResponseSchema = z
  .union([WrappedEnvelopeSchema, BareArraySchema])
  .transform((raw): {
    items: AuditLogItem[];
    total: number;
    next_cursor: string | null;
  } => {
    if (Array.isArray(raw)) {
      return { items: raw, total: raw.length, next_cursor: null };
    }
    return {
      items: raw.items,
      total: raw.total ?? raw.items.length,
      next_cursor: raw.next_cursor ?? null,
    };
  });

export type AuditLogsListResponse = z.infer<typeof AuditLogsListResponseSchema>;

/**
 * Chain-verify response (T25). Mirrors `backend/src/api/schemas.py
 * ::AuditChainVerifyResponse`.
 */
export const AuditChainVerifyResponseSchema = z.object({
  ok: z.boolean(),
  verified_count: z.number().int().min(0),
  last_verified_index: z.number().int().min(-1),
  drift_event_id: z
    .union([z.string(), z.null()])
    .optional()
    .transform((v) => (v == null ? null : v)),
  drift_detected_at: z
    .union([z.string(), z.null()])
    .optional()
    .transform((v) => (v == null ? null : v)),
  effective_since: z.string().min(1),
  effective_until: z.string().min(1),
});

export type AuditChainVerifyResponse = z.infer<
  typeof AuditChainVerifyResponseSchema
>;

/**
 * Wire-level parameter bag accepted by the list server action. Keeps the
 * action a thin pass-through with explicit, server-trusted defaults.
 *
 * NOTE: the backend currently has NO dedicated `actor_subject` query
 * parameter — it exposes `q` (ILIKE on `action / resource_type / details`).
 * The action maps `actorSubject` to `q` so an operator searching for "alice"
 * will match audit rows whose details JSON or action string mentions her.
 * If the backend later adds a typed `actor_subject` filter, the action will
 * be the only place that needs to change.
 */
export type ListAdminAuditLogsParams = {
  readonly tenantId?: string | null;
  readonly eventType?: string | null;
  readonly actorSubject?: string | null;
  readonly since?: string | null;
  readonly until?: string | null;
  readonly cursor?: string | null;
  readonly limit?: number;
};

/**
 * Verify-chain action params. Same filters minus pagination — the verdict
 * applies to the whole window in one go.
 */
export type VerifyAuditChainParams = {
  readonly tenantId?: string | null;
  readonly eventType?: string | null;
  readonly since?: string | null;
  readonly until?: string | null;
};

/**
 * Closed taxonomy of error codes. Translated to fixed RU sentences in the UI
 * — never expose the underlying transport string.
 */
export type AdminAuditLogsErrorCode =
  | "unauthorized"
  | "forbidden"
  | "rate_limited"
  | "invalid_input"
  | "server_error"
  | "network_error";

export class AdminAuditLogsError extends Error {
  readonly code: AdminAuditLogsErrorCode;
  readonly status: number | null;

  constructor(code: AdminAuditLogsErrorCode, status: number | null = null) {
    super(code);
    this.name = "AdminAuditLogsError";
    this.code = code;
    this.status = status;
  }
}

const ERROR_MESSAGES_RU: Readonly<Record<AdminAuditLogsErrorCode, string>> = {
  unauthorized: "Сессия истекла. Войдите заново.",
  forbidden: "Недостаточно прав для просмотра audit log.",
  rate_limited: "Слишком много запросов. Повторите попытку через минуту.",
  invalid_input: "Некорректные параметры фильтра audit log.",
  server_error: "Не удалось загрузить audit log. Повторите попытку.",
  network_error: "Сеть недоступна. Проверьте соединение и повторите попытку.",
};

export function adminAuditLogsErrorMessage(err: unknown): string {
  if (err instanceof AdminAuditLogsError) {
    return ERROR_MESSAGES_RU[err.code];
  }
  return ERROR_MESSAGES_RU.server_error;
}

/**
 * HTTP status → closed-taxonomy code. Exported so the action and any future
 * read paths share a single mapping.
 */
export function statusToAdminAuditLogsCode(
  status: number,
): AdminAuditLogsErrorCode {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 429) return "rate_limited";
  if (status === 400 || status === 422) return "invalid_input";
  return "server_error";
}

/**
 * Detects whether a row carries the chain-aware hash markers
 * (`details._event_hash` / `details._prev_event_hash`) emitted by the
 * audit-aware writer (`backend/src/policy/audit.py`). Used by the table to
 * render a small "chain-aware" badge so operators can see at a glance which
 * rows participate in the integrity chain.
 */
export function hasChainMarkers(details: unknown): boolean {
  if (
    details === null ||
    typeof details !== "object" ||
    Array.isArray(details)
  ) {
    return false;
  }
  const obj = details as Record<string, unknown>;
  return (
    typeof obj._event_hash === "string" ||
    typeof obj._prev_event_hash === "string"
  );
}

/**
 * Pretty-print a JSON value for the drawer. Falls back to a plain string
 * representation for non-JSON-safe inputs (no exception ever bubbles up to
 * the React tree).
 */
export function prettyPrintDetails(details: unknown): string {
  if (details === null || details === undefined) return "—";
  try {
    return JSON.stringify(details, null, 2);
  } catch {
    return String(details);
  }
}
