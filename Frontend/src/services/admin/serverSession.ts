import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import {
  ADMIN_AUTH_PATHS,
  ADMIN_SESSION_COOKIE,
  buildAuthBackendUrl,
  getAdminAuthMode,
  type AdminAuthMode,
} from "@/lib/adminAuth";
import { getForwardedFor, readSessionCookie } from "@/lib/adminAuthServer";
import { getServerAdminApiKey } from "@/lib/adminProxy";

import type { AdminRole } from "./adminRoles";
import { parseAdminRole } from "./adminRoles";

/**
 * Server-only resolver of the admin operator's identity for use inside
 * Next.js Server Actions and Server Components.
 *
 * Three resolution modes are supported, selected by
 * `NEXT_PUBLIC_ADMIN_AUTH_MODE` (see `lib/adminAuth.ts::getAdminAuthMode`):
 *
 *   1. `cookie`  — legacy shim: reads `argus.admin.role` /
 *      `argus.admin.tenant` / `argus.admin.subject` cookies plus
 *      `NEXT_PUBLIC_ADMIN_DEV_*` env. Backwards-compatible behaviour
 *      preserved for local dev and Playwright smoke tests.
 *   2. `session` — (B6-T08) calls backend `GET /api/v1/auth/admin/whoami`
 *      with the `argus.admin.session` HttpOnly cookie, returning the real
 *      `{role, tenantId, subject}` minted by the database. On 401 the
 *      caller is redirected to `/admin/login`. The browser cannot bypass
 *      this resolver because the session cookie is HttpOnly and the
 *      backend is the only authority on its validity.
 *   3. `auto`    — (default) attempt `session` first; on 401 OR network
 *      error fall through to `cookie`. Lets a fresh dev environment work
 *      without provisioning bcrypt admin users while still honouring real
 *      sessions when present.
 *
 * IMPORTANT — security boundary:
 *   `ADMIN_API_KEY` MUST never reach the browser. Every backend call
 *   here adds it from a server-only env (`getServerAdminApiKey`). Cookies
 *   used by the legacy `cookie` shim are still client-writable, which is
 *   why production MUST set `NEXT_PUBLIC_ADMIN_AUTH_MODE=session` (and the
 *   backend `ADMIN_AUTH_MODE=session`) — the cookie shim is dev-only.
 */

export const ADMIN_ROLE_COOKIE = "argus.admin.role";
export const ADMIN_TENANT_COOKIE = "argus.admin.tenant";
export const ADMIN_SUBJECT_COOKIE = "argus.admin.subject";

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const SUBJECT_MAX_LENGTH = 256;
const SUBJECT_FALLBACK = "admin_console";

/**
 * Belt-and-suspenders for `instrumentation.ts` (B6-T09 / ISS-T20-003).
 *
 * The `register()` hook in `Frontend/instrumentation.ts` is the primary
 * boot-time guard, but if it ever gets disabled (older Next, operator
 * `experimental.instrumentationHook=false`, or a custom server bypassing
 * the standard runtime), this lazy check still catches the misconfig the
 * first time a Server Component or Server Action resolves an admin
 * session. Module-level flag keeps the cost to one comparison after the
 * first hit.
 */
let _prodModeAsserted = false;
const REQUIRED_PROD_AUTH_MODE = "session" as const;

function assertProductionAdminAuthModeOnce(): void {
  if (_prodModeAsserted) return;
  // IMPORTANT: only memoize on a *passing* assertion. If we set the flag
  // before throwing, a caller that catches the error in its own try/catch
  // would silently bypass every subsequent check in the same process —
  // defeating the lazy-guard fallback for environments where the boot-time
  // `instrumentation.ts` hook is disabled.
  if (process.env.NODE_ENV !== "production") {
    _prodModeAsserted = true;
    return;
  }
  const raw = process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE ?? "";
  if (raw.trim().toLowerCase() === REQUIRED_PROD_AUTH_MODE) {
    _prodModeAsserted = true;
    return;
  }
  const reported = raw.trim().length > 0 ? raw : "<unset>";
  throw new Error(
    `ADMIN_AUTH_MODE must be 'session' in production (got: ${reported}). ` +
      `Cookie shim is dev-only — see B6-T09 / ISS-T20-003.`,
  );
}

/** Test-only escape hatch — reset the singleton flag between cases. */
export function _resetProdModeAssertionForTests(): void {
  _prodModeAsserted = false;
}

export type ServerAdminSession = {
  /** Admin role resolved from cookie or env. `null` when the visitor is not signed in. */
  readonly role: AdminRole | null;
  /** Tenant the operator is bound to (`null` for super-admin cross-tenant view). */
  readonly tenantId: string | null;
  /** Operator subject for backend audit trail (`X-Operator-Subject`). */
  readonly subject: string;
  /**
   * Where the resolution came from — useful for tests, logging, and
   * debugging. Optional so existing test fixtures that mock the session
   * without specifying `source` keep working; production code paths in
   * this module always populate it.
   */
  readonly source?: "session" | "cookie";
};

/**
 * Server-only call to `GET /api/v1/auth/admin/whoami` carrying the
 * current request's session cookie and best-effort source IP. Returns
 * `null` for any non-2xx response so callers can deterministically pick
 * a fallback (or 401-redirect). NEVER throws on network errors — those
 * collapse into `null` so the page render is not derailed by a transient
 * backend hiccup.
 */
async function fetchWhoami(): Promise<{
  subject: string;
  role: AdminRole | null;
  tenantId: string | null;
} | null> {
  const sessionId = await readSessionCookie();
  if (!sessionId) return null;

  const url = buildAuthBackendUrl(ADMIN_AUTH_PATHS.whoami);
  const apiKey = getServerAdminApiKey();
  const xff = await getForwardedFor();

  const headers: Record<string, string> = {
    Accept: "application/json",
    Cookie: `${ADMIN_SESSION_COOKIE}=${sessionId}`,
  };
  if (apiKey) headers["X-Admin-Key"] = apiKey;
  if (xff) headers["X-Forwarded-For"] = xff;

  let res: Response;
  try {
    res = await fetch(url, {
      method: "GET",
      headers,
      cache: "no-store",
      // Important: don't follow redirects — a misconfigured proxy could
      // 30x us into a login page and we'd treat that as success.
      redirect: "manual",
    });
  } catch {
    return null;
  }

  if (!res.ok) return null;

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    return null;
  }
  if (!body || typeof body !== "object") return null;
  const obj = body as Record<string, unknown>;
  const subjectRaw = typeof obj.subject === "string" ? obj.subject : "";
  const subject = sanitizeSubject(subjectRaw);
  const role = parseAdminRole(typeof obj.role === "string" ? obj.role : null);
  const tenantId = sanitizeTenantId(
    typeof obj.tenant_id === "string" ? obj.tenant_id : null,
  );

  // The backend guarantees subject + role on a 2xx; treat a missing one
  // as a malformed payload and fall back so the page doesn't render with
  // an empty audit subject.
  if (!subject || role === null) return null;

  return { subject, role, tenantId };
}

function sanitizeTenantId(raw: string | null | undefined): string | null {
  if (raw == null) return null;
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  return UUID_RE.test(trimmed) ? trimmed : null;
}

function sanitizeSubject(raw: string | null | undefined): string | null {
  if (raw == null) return null;
  const trimmed = raw.trim().slice(0, SUBJECT_MAX_LENGTH);
  if (trimmed === "") return null;
  // Reject anything containing control characters; allow standard printable
  // ASCII plus Unicode letters/digits used in usernames or display names.
  if (/[\u0000-\u001F\u007F]/.test(trimmed)) return null;
  return trimmed;
}

function deriveSubjectFromRole(role: AdminRole | null): string {
  if (role === null) return SUBJECT_FALLBACK;
  return `${SUBJECT_FALLBACK}:${role}`;
}

async function resolveFromCookies(): Promise<ServerAdminSession> {
  const store = await cookies();

  const roleCookie = store.get(ADMIN_ROLE_COOKIE)?.value ?? null;
  const role =
    parseAdminRole(roleCookie) ??
    parseAdminRole(process.env.NEXT_PUBLIC_ADMIN_DEV_ROLE);

  const tenantCookie = store.get(ADMIN_TENANT_COOKIE)?.value ?? null;
  const tenantId =
    sanitizeTenantId(tenantCookie) ??
    sanitizeTenantId(process.env.NEXT_PUBLIC_ADMIN_DEV_TENANT);

  const subjectCookie = store.get(ADMIN_SUBJECT_COOKIE)?.value ?? null;
  const subject =
    sanitizeSubject(subjectCookie) ??
    sanitizeSubject(process.env.NEXT_PUBLIC_ADMIN_DEV_SUBJECT) ??
    deriveSubjectFromRole(role);

  return { role, tenantId, subject, source: "cookie" };
}

/**
 * Resolve the admin session for the current request. Always returns a
 * typed `ServerAdminSession`; the caller is responsible for refusing the
 * operation (e.g. forbidden) when `role` is `null` or `tenantId` is
 * missing for an `admin` operator.
 *
 * In `session` mode, redirects to `/admin/login` when the backend says
 * the session is invalid — there is no user-visible "anonymous"
 * surface inside `/admin/*` other than the login page itself. Pages that
 * MUST allow anonymous access (e.g. the login page) should not call this
 * function.
 */
export async function getServerAdminSession(): Promise<ServerAdminSession> {
  assertProductionAdminAuthModeOnce();
  const mode = getAdminAuthMode();
  return resolveByMode(mode);
}

/**
 * Lower-level dispatcher exposed for tests and rare callers (e.g. a page
 * that wants to query the session without the redirect side-effect — for
 * those cases see {@link tryGetServerAdminSession}).
 */
async function resolveByMode(mode: AdminAuthMode): Promise<ServerAdminSession> {
  if (mode === "cookie") {
    return resolveFromCookies();
  }

  if (mode === "session") {
    const whoami = await fetchWhoami();
    if (whoami) {
      return {
        role: whoami.role,
        tenantId: whoami.tenantId,
        subject: whoami.subject,
        source: "session",
      };
    }
    // Pure session mode: no cookie shim fallback. The user MUST sign in.
    redirect("/admin/login");
  }

  // mode === "auto": try session first, fall through to cookie shim on miss.
  const whoami = await fetchWhoami();
  if (whoami) {
    return {
      role: whoami.role,
      tenantId: whoami.tenantId,
      subject: whoami.subject,
      source: "session",
    };
  }
  return resolveFromCookies();
}

/**
 * Non-redirecting variant: returns `null` when no session can be resolved
 * in `session` mode instead of redirecting. Useful for the login page
 * itself, which is allowed to render anonymously.
 */
export async function tryGetServerAdminSession(): Promise<ServerAdminSession | null> {
  assertProductionAdminAuthModeOnce();
  const mode = getAdminAuthMode();
  if (mode === "cookie") {
    return resolveFromCookies();
  }
  const whoami = await fetchWhoami();
  if (whoami) {
    return {
      role: whoami.role,
      tenantId: whoami.tenantId,
      subject: whoami.subject,
      source: "session",
    };
  }
  if (mode === "session") {
    return null;
  }
  // auto
  return resolveFromCookies();
}
