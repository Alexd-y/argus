/**
 * Admin findings — typed client for the cross-tenant triage console (T20).
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
 * Closed-taxonomy errors only — every transport / validation failure maps to a
 * `AdminFindingsErrorCode`, never a stack trace, so the UI can render a fixed
 * RU sentence without leaking server internals (matches T23 pattern in
 * `findingsExport.ts`).
 *
 * Browser-side fetch goes through the Next.js rewrite (`/api/v1/* → BACKEND`),
 * so callers don't deal with CORS or absolute URLs. The admin key NEVER leaves
 * the server — admin auth headers (`X-Admin-Role`, `X-Admin-Tenant`) are
 * surfaced separately so the SSR proxy can attach them.
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

function statusToCode(status: number): AdminFindingsErrorCode {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 429) return "rate_limited";
  if (status === 400 || status === 422) return "invalid_input";
  return "server_error";
}

export type ListAdminFindingsParams = {
  readonly tenantId?: string | null;
  readonly severity?: ReadonlyArray<FindingSeverity>;
  readonly status?: ReadonlyArray<FindingStatus>;
  readonly target?: string | null;
  readonly since?: string | null;
  readonly until?: string | null;
  readonly cursor?: string | null;
  readonly limit?: number;
  /** Reserved Phase-2 KEV filter; sent only when explicitly enabled. */
  readonly kevListed?: boolean | null;
  /** Reserved Phase-2 SSVC filter; sent only when explicitly set. */
  readonly ssvcAction?: SsvcAction | null;
};

export type ListAdminFindingsOptions = {
  readonly signal?: AbortSignal;
  readonly fetchImpl?: typeof fetch;
  readonly operatorRole?: string | null;
  readonly operatorTenantId?: string | null;
  readonly operatorSubject?: string | null;
};

const FINDINGS_PATH = "/api/v1/admin/findings";

/**
 * Build the query string from a typed parameter bag. Reserved Phase-2 params
 * are omitted unless the caller explicitly opts in (avoids a no-op header that
 * would still trip backend audit warnings).
 */
export function buildAdminFindingsUrl(params: ListAdminFindingsParams): string {
  const sp = new URLSearchParams();
  if (params.tenantId && params.tenantId.trim()) {
    sp.set("tenant_id", params.tenantId.trim());
  }
  for (const sev of params.severity ?? []) {
    sp.append("severity", sev);
  }
  for (const st of params.status ?? []) {
    sp.append("status", st);
  }
  if (params.target && params.target.trim()) {
    sp.set("target", params.target.trim());
  }
  if (params.since) sp.set("since", params.since);
  if (params.until) sp.set("until", params.until);
  if (params.cursor) sp.set("cursor", params.cursor);
  if (params.limit != null) sp.set("limit", String(params.limit));
  if (params.kevListed === true) sp.set("kev_listed", "true");
  if (params.kevListed === false) sp.set("kev_listed", "false");
  if (params.ssvcAction) sp.set("ssvc_action", params.ssvcAction);
  const qs = sp.toString();
  return qs ? `${FINDINGS_PATH}?${qs}` : FINDINGS_PATH;
}

function buildHeaders(opts: ListAdminFindingsOptions): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (opts.operatorRole && opts.operatorRole.trim()) {
    headers["X-Operator-Role"] = opts.operatorRole.trim();
    headers["X-Admin-Role"] = opts.operatorRole.trim();
  }
  if (opts.operatorTenantId && opts.operatorTenantId.trim()) {
    headers["X-Tenant-ID"] = opts.operatorTenantId.trim();
    headers["X-Admin-Tenant"] = opts.operatorTenantId.trim();
  }
  if (opts.operatorSubject && opts.operatorSubject.trim()) {
    headers["X-Operator-Subject"] = opts.operatorSubject.trim();
  }
  return headers;
}

/**
 * Fetch a single page of admin findings. The function:
 *   - validates the response with Zod and throws `AdminFindingsError` on
 *     schema mismatch (closed-taxonomy `server_error`);
 *   - propagates `AbortError` untouched so React Query can cancel races;
 *   - never throws the underlying transport error string — only the closed
 *     taxonomy reaches the UI.
 *
 * Pagination: if the backend returns offset/limit, we synthesise a `next_cursor`
 * as the next offset so the UI can use a single cursor-driven flow.
 */
export async function listAdminFindings(
  params: ListAdminFindingsParams = {},
  options: ListAdminFindingsOptions = {},
): Promise<AdminFindingsListResponse> {
  const url = buildAdminFindingsUrl(params);
  const fetchFn = options.fetchImpl ?? globalThis.fetch;

  let response: Response;
  try {
    response = await fetchFn(url, {
      method: "GET",
      headers: buildHeaders(options),
      signal: options.signal,
      cache: "no-store",
      credentials: "same-origin",
    });
  } catch (err) {
    // Re-throw aborts so React Query can distinguish cancellation.
    if (
      err instanceof DOMException &&
      (err.name === "AbortError" || err.code === DOMException.ABORT_ERR)
    ) {
      throw err;
    }
    throw new AdminFindingsError("network_error");
  }

  if (!response.ok) {
    throw new AdminFindingsError(statusToCode(response.status), response.status);
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new AdminFindingsError("server_error", response.status);
  }

  const parsed = AdminFindingsListResponseSchema.safeParse(body);
  if (!parsed.success) {
    throw new AdminFindingsError("server_error", response.status);
  }

  return parsed.data;
}

/**
 * Stable client-side comparator: SSVC desc → severity desc → CVSS desc →
 * EPSS desc → updated_at desc. Nulls always sink to the bottom.
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

  const tsA = a.updated_at ? Date.parse(a.updated_at) : 0;
  const tsB = b.updated_at ? Date.parse(b.updated_at) : 0;
  return tsB - tsA;
}

export function sortFindings(items: ReadonlyArray<AdminFindingItem>): AdminFindingItem[] {
  return [...items].sort(compareFindings);
}
