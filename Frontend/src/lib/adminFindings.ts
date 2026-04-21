/**
 * Admin findings — typed contract + closed-taxonomy errors for the
 * cross-tenant triage console (T20).
 *
 * This module is **transport-free** — both server actions
 * (`Frontend/src/app/admin/findings/actions.ts`) and React components import
 * from here. The previous browser-side fetch helper was removed once we
 * routed all admin reads through the `"use server"` proxy: the browser must
 * never see `X-Admin-Key` and must not be able to inject `X-Admin-Role` /
 * `X-Admin-Tenant` directly into FastAPI (S0-1 / T20).
 *
 * Backend contract is the Phase-1 projection shipped by T24:
 *   GET /api/v1/admin/findings
 *   → { findings, total, limit, offset, has_more }
 *
 * Phase-2 fields documented by the orchestration plan (`epss_score`,
 * `kev_listed`, `ssvc_action`, `cve_ids`, `target`, `discovered_at`,
 * `updated_at`) are NOT yet emitted by the backend; the schema below treats
 * them as optional / nullable so the UI degrades to "Unknown" / "—" today and
 * starts surfacing the values automatically the moment intel-table joins land.
 *
 * Error taxonomy is closed — every transport / validation failure maps to a
 * `AdminFindingsErrorCode`, never a stack trace, so the UI can render a fixed
 * RU sentence without leaking server internals (matches T23 pattern in
 * `findingsExport.ts`).
 */

import { z } from "zod";

const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"] as const;
const STATUS_VALUES = [
  "open",
  "fixed",
  "wontfix",
  "risk_accepted",
  "false_positive",
  "under_investigation",
] as const;
const SSVC_ACTION_VALUES = ["track", "track-star", "attend", "act"] as const;

export type FindingSeverity = (typeof SEVERITY_VALUES)[number];
export type FindingStatus = (typeof STATUS_VALUES)[number];
export type SsvcAction = (typeof SSVC_ACTION_VALUES)[number];

export const FINDING_SEVERITIES: ReadonlyArray<FindingSeverity> = SEVERITY_VALUES;
export const FINDING_STATUSES: ReadonlyArray<FindingStatus> = STATUS_VALUES;
export const SSVC_ACTIONS: ReadonlyArray<SsvcAction> = SSVC_ACTION_VALUES;

const SEVERITY_SET = new Set<string>(SEVERITY_VALUES);
const STATUS_SET = new Set<string>(STATUS_VALUES);
const SSVC_SET = new Set<string>(SSVC_ACTION_VALUES);

export function isFindingSeverity(value: unknown): value is FindingSeverity {
  return typeof value === "string" && SEVERITY_SET.has(value);
}

export function isFindingStatus(value: unknown): value is FindingStatus {
  return typeof value === "string" && STATUS_SET.has(value);
}

export function isSsvcAction(value: unknown): value is SsvcAction {
  return typeof value === "string" && SSVC_SET.has(value);
}

/**
 * Status-mode tri-state used by the filter bar / URL. Maps to the backend's
 * `false_positive` query parameter:
 *   - "all" → omit (default backend behaviour, includes both)
 *   - "open" → false_positive=false
 *   - "false_positive" → false_positive=true
 *
 * The other Phase-2 statuses (fixed, wontfix, …) are intentionally not
 * exposed yet — the backend has no column for them (see T24's schema
 * deviation note) and silently ignoring user-visible chips would mislead
 * operators. They will reappear once a triage workflow lands (ISS-T20-005).
 */
export type FindingStatusMode = "all" | "open" | "false_positive";

const STATUS_MODE_VALUES: ReadonlyArray<FindingStatusMode> = [
  "all",
  "open",
  "false_positive",
];

const STATUS_MODE_SET = new Set<string>(STATUS_MODE_VALUES);

export function isFindingStatusMode(value: unknown): value is FindingStatusMode {
  return typeof value === "string" && STATUS_MODE_SET.has(value);
}

/**
 * Severity ordinal (Critical=5 .. Info=1). Used for the client-side stable
 * sort fallback when the backend cannot pre-sort by SSVC priority yet.
 */
export const SEVERITY_RANK: Readonly<Record<FindingSeverity, number>> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * SSVC action ordinal (Act=4 .. Track=1). Higher = more urgent operator action.
 */
export const SSVC_RANK: Readonly<Record<SsvcAction, number>> = {
  act: 4,
  attend: 3,
  "track-star": 2,
  track: 1,
};

const NullableNumberSchema = z
  .union([z.number(), z.null()])
  .optional()
  .transform((v) => (v == null ? null : v));

const NullableStringSchema = z
  .union([z.string(), z.null()])
  .optional()
  .transform((v) => (v == null ? null : v));

const NullableStringArraySchema = z
  .union([z.array(z.string()), z.null()])
  .optional()
  .transform((v) => (v == null ? null : v));

const SeveritySchema = z
  .string()
  .transform((s) => s.toLowerCase())
  .pipe(z.enum(SEVERITY_VALUES));

const StatusSchema = z
  .union([z.string(), z.null()])
  .optional()
  .transform((v) => (v == null ? null : v.toLowerCase()))
  .pipe(z.enum(STATUS_VALUES).nullable());

const SsvcActionSchema = z
  .union([z.string(), z.null()])
  .optional()
  .transform((v) => (v == null ? null : v.toLowerCase()))
  .pipe(z.enum(SSVC_ACTION_VALUES).nullable());

const NullableBoolSchema = z
  .union([z.boolean(), z.null()])
  .optional()
  .transform((v) => (v == null ? null : v));

/**
 * Zod schema for a single finding row. Phase-2 fields are optional; we accept
 * both legacy backend keys (`cvss`, `created_at`) and forward-looking keys
 * (`cvss_score`, `discovered_at`, `updated_at`) without breaking either path.
 */
export const AdminFindingItemSchema = z
  .object({
    id: z.string().min(1),
    tenant_id: z.string().min(1),
    scan_id: z.string().min(1),
    severity: SeveritySchema,
    title: z.string(),
    status: StatusSchema.optional(),
    target: NullableStringSchema,
    cve_ids: NullableStringArraySchema,
    cvss: NullableNumberSchema,
    cvss_score: NullableNumberSchema,
    epss_score: NullableNumberSchema,
    kev_listed: NullableBoolSchema,
    ssvc_action: SsvcActionSchema.optional(),
    discovered_at: NullableStringSchema,
    updated_at: NullableStringSchema,
    created_at: NullableStringSchema,
  })
  .transform((raw) => {
    const cvssScore = raw.cvss_score ?? raw.cvss ?? null;
    const updatedAt = raw.updated_at ?? raw.created_at ?? null;
    const discoveredAt = raw.discovered_at ?? raw.created_at ?? null;
    return {
      id: raw.id,
      tenant_id: raw.tenant_id,
      scan_id: raw.scan_id,
      severity: raw.severity,
      status: raw.status ?? null,
      target: raw.target,
      title: raw.title,
      cve_ids: raw.cve_ids,
      cvss_score: cvssScore,
      epss_score: raw.epss_score,
      kev_listed: raw.kev_listed,
      ssvc_action: raw.ssvc_action ?? null,
      discovered_at: discoveredAt,
      updated_at: updatedAt,
    };
  });

export type AdminFindingItem = z.infer<typeof AdminFindingItemSchema>;

/**
 * Zod schema for the list envelope. Accepts both the current `findings` key
 * (T24 ships) and the planned `items` key (Phase-2 cursor pagination); the
 * cursor field is mapped to a stable `next_cursor` regardless of source so
 * `useInfiniteQuery` can always read the same shape.
 *
 * The envelope MUST carry at least one of `items` / `findings` — without that
 * the body cannot be distinguished from arbitrary JSON (e.g. an HTML error
 * page returned with `Content-Type: application/json`), and silently treating
 * such a payload as "empty list" hides server contract drift from the
 * operator. The action layer translates a refinement failure into a closed
 * `server_error` so the browser never sees Zod issue paths.
 */
export const AdminFindingsListResponseSchema = z
  .object({
    items: z.array(AdminFindingItemSchema).optional(),
    findings: z.array(AdminFindingItemSchema).optional(),
    total: z.number().int().nonnegative().optional(),
    next_cursor: z
      .union([z.string(), z.null()])
      .optional()
      .transform((v) => (v == null || v === "" ? null : v)),
    limit: z.number().int().nonnegative().optional(),
    offset: z.number().int().nonnegative().optional(),
    has_more: z.boolean().optional(),
  })
  .refine((raw) => raw.items !== undefined || raw.findings !== undefined, {
    message: "missing items/findings array",
    path: ["items"],
  })
  .transform((raw) => {
    const items = raw.items ?? raw.findings ?? [];
    const limit = raw.limit ?? items.length;
    const offset = raw.offset ?? 0;
    const total = raw.total ?? items.length;
    const hasMore = raw.has_more ?? offset + items.length < total;
    let nextCursor: string | null = raw.next_cursor ?? null;
    if (nextCursor === null && hasMore) {
      nextCursor = String(offset + items.length);
    }
    return {
      items,
      total,
      limit,
      offset,
      has_more: hasMore,
      next_cursor: nextCursor,
    };
  });

export type AdminFindingsListResponse = z.infer<typeof AdminFindingsListResponseSchema>;

/**
 * Closed taxonomy of error codes. Translates to a fixed RU sentence in the UI
 * — never expose the underlying transport string (which may include URLs,
 * stack frames, or PII) to operators.
 */
export type AdminFindingsErrorCode =
  | "unauthorized"
  | "forbidden"
  | "rate_limited"
  | "invalid_input"
  | "server_error"
  | "network_error";

export class AdminFindingsError extends Error {
  readonly code: AdminFindingsErrorCode;
  readonly status: number | null;

  constructor(code: AdminFindingsErrorCode, status: number | null = null) {
    super(code);
    this.name = "AdminFindingsError";
    this.code = code;
    this.status = status;
  }
}

const ERROR_MESSAGES_RU: Readonly<Record<AdminFindingsErrorCode, string>> = {
  unauthorized: "Сессия истекла. Войдите заново.",
  forbidden: "Недостаточно прав для просмотра findings.",
  rate_limited: "Слишком много запросов. Повторите попытку через минуту.",
  invalid_input: "Некорректные параметры фильтра.",
  server_error: "Не удалось загрузить findings. Повторите попытку.",
  network_error: "Сеть недоступна. Проверьте соединение и повторите попытку.",
};

export function adminFindingsErrorMessage(err: unknown): string {
  if (err instanceof AdminFindingsError) {
    return ERROR_MESSAGES_RU[err.code];
  }
  return ERROR_MESSAGES_RU.server_error;
}

/**
 * HTTP-status → closed-taxonomy code. Exported so the server action and any
 * future read paths share a single mapping.
 */
export function statusToAdminFindingsCode(status: number): AdminFindingsErrorCode {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 429) return "rate_limited";
  if (status === 400 || status === 422) return "invalid_input";
  return "server_error";
}

/**
 * Wire-level parameter bag accepted by the server action. The shape mirrors
 * the public REST endpoint (`GET /admin/findings`) so the action stays a thin
 * pass-through with explicit, server-trusted defaults.
 *
 * Notes:
 *   - `target` maps to backend `q` (free-text title/host/url substring).
 *   - `statusMode` maps to backend `false_positive` ternary.
 *   - `kevListed` / `ssvcAction` are reserved Phase-2 toggles; the backend
 *     accepts them but currently no-ops them until intel JOIN lands.
 */
export type ListAdminFindingsParams = {
  readonly tenantId?: string | null;
  readonly severity?: ReadonlyArray<FindingSeverity>;
  readonly statusMode?: FindingStatusMode;
  readonly target?: string | null;
  readonly since?: string | null;
  readonly until?: string | null;
  readonly cursor?: string | null;
  readonly limit?: number;
  readonly kevListed?: boolean | null;
  readonly ssvcAction?: SsvcAction | null;
};

/**
 * Stable client-side comparator: SSVC desc → severity desc → CVSS desc →
 * EPSS desc → updated_at desc. Nulls always sink to the bottom.
 *
 * NaN-safety: a malformed `updated_at` (e.g. "tomorrow") would parse to
 * `NaN` and propagate `NaN` through the subtraction, breaking
 * `Array.prototype.sort`'s strict-weak-ordering contract and producing a
 * non-deterministic order. We collapse any unparsable timestamp to `0` so
 * the comparator is total even on bad data.
 */
export function compareFindings(a: AdminFindingItem, b: AdminFindingItem): number {
  const ssvcA = a.ssvc_action ? SSVC_RANK[a.ssvc_action] : -1;
  const ssvcB = b.ssvc_action ? SSVC_RANK[b.ssvc_action] : -1;
  if (ssvcA !== ssvcB) return ssvcB - ssvcA;

  const sevA = SEVERITY_RANK[a.severity];
  const sevB = SEVERITY_RANK[b.severity];
  if (sevA !== sevB) return sevB - sevA;

  const cvssA = a.cvss_score ?? -1;
  const cvssB = b.cvss_score ?? -1;
  if (cvssA !== cvssB) return cvssB - cvssA;

  const epssA = a.epss_score ?? -1;
  const epssB = b.epss_score ?? -1;
  if (epssA !== epssB) return epssB - epssA;

  const tsA = safeTimestamp(a.updated_at);
  const tsB = safeTimestamp(b.updated_at);
  return tsB - tsA;
}

function safeTimestamp(iso: string | null): number {
  if (!iso) return 0;
  const ts = Date.parse(iso);
  return Number.isFinite(ts) ? ts : 0;
}

export function sortFindings(items: ReadonlyArray<AdminFindingItem>): AdminFindingItem[] {
  return [...items].sort(compareFindings);
}
