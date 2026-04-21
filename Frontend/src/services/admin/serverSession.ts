import { cookies } from "next/headers";

import type { AdminRole } from "./adminRoles";
import { parseAdminRole } from "./adminRoles";

/**
 * Server-only resolver of the admin operator's identity for use inside
 * Next.js Server Actions. The values are looked up in this order:
 *
 *   1. Cookies set by the admin shell on the client (`AdminAuthProvider`).
 *      These mirror the in-memory `useAdminAuth()` state and survive a hard
 *      reload without exposing a window for the browser to inject privileged
 *      headers directly into the backend (S0-1 / T20).
 *   2. `NEXT_PUBLIC_ADMIN_DEV_*` environment variables. Useful for local
 *      development and Playwright smoke tests where there is no real session
 *      cookie yet.
 *
 * IMPORTANT — security boundary:
 *   This resolver is the ONLY source of truth the admin server actions consult
 *   when shaping `X-Admin-Role` / `X-Admin-Tenant` / `X-Operator-Subject`
 *   headers. The backend's `X-Admin-Key` is added separately by
 *   `callAdminBackendJson` from a server-side env var. Together this means the
 *   browser cannot bypass `require_admin` even if it forges request headers.
 *
 *   Cookies are still ultimately client-writable, so this is a transitional
 *   step — see `ai_docs/develop/issues/ISS-T20-003.md` for the planned move
 *   to a JWT/session-bound identity validated server-side.
 */

export const ADMIN_ROLE_COOKIE = "argus.admin.role";
export const ADMIN_TENANT_COOKIE = "argus.admin.tenant";
export const ADMIN_SUBJECT_COOKIE = "argus.admin.subject";

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const SUBJECT_MAX_LENGTH = 256;
const SUBJECT_FALLBACK = "admin_console";

export type ServerAdminSession = {
  /** Admin role resolved from cookie or env. `null` when the visitor is not signed in. */
  readonly role: AdminRole | null;
  /** Tenant the operator is bound to (`null` for super-admin cross-tenant view). */
  readonly tenantId: string | null;
  /** Operator subject for backend audit trail (`X-Operator-Subject`). */
  readonly subject: string;
};

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

/**
 * Resolve the admin session for the current request. Always returns a typed
 * `ServerAdminSession`; the caller is responsible for refusing the operation
 * (e.g. forbidden) when `role` is `null` or `tenantId` is missing for an
 * `admin` operator.
 */
export async function getServerAdminSession(): Promise<ServerAdminSession> {
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

  return { role, tenantId, subject };
}
