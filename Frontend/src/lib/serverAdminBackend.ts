import { ADMIN_SESSION_COOKIE } from "@/lib/adminAuth";
import { getForwardedFor, readSessionCookie } from "@/lib/adminAuthServer";
import { normalizeAdminDetailError } from "@/lib/adminErrorMapping";
import { getBackendBaseUrl, getServerAdminApiKey } from "@/lib/adminProxy";

const GENERIC_ERROR = "The operation could not be completed.";
const SERVICE_UNAVAILABLE = "Admin service is temporarily unavailable.";

export type AdminJsonResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status: number; detail?: unknown };

/**
 * Read the current request's admin session cookie / forwarded-for header
 * without ever throwing. `next/headers` accessors require an active request
 * scope; outside one (e.g. a unit test that does not mock `next/headers`)
 * they reject, in which case we degrade to `null` and fall back to the
 * `X-Admin-Key` shim.
 */
async function safeReadSessionCookie(): Promise<string | null> {
  try {
    return await readSessionCookie();
  } catch {
    return null;
  }
}

async function safeGetForwardedFor(): Promise<string | null> {
  try {
    return await getForwardedFor();
  } catch {
    return null;
  }
}

/**
 * Server-only JSON call to FastAPI `/api/v1/admin/*`.
 *
 * Auth precedence mirrors the backend's dual-mode `require_admin`:
 *   - Forward the operator's HttpOnly `argus.admin.session` cookie so the
 *     backend resolves the real session in `session` mode (the production-
 *     mandated mode — the `X-Admin-Key` shim is rejected there).
 *   - Also send `X-Admin-Key` from a server-only env when present, keeping
 *     `cookie` / `both` modes working.
 * The call is only refused up-front (503) when NEITHER credential is
 * available, so a session-only deployment with `ADMIN_API_KEY` unset still
 * authenticates via the cookie instead of failing before the request.
 *
 * Maps `detail` through {@link normalizeAdminDetailError}; never leaks stack traces.
 */
export async function callAdminBackendJson<T>(
  adminPath: string,
  init?: RequestInit,
): Promise<AdminJsonResult<T>> {
  const key = getServerAdminApiKey();
  const sessionId = await safeReadSessionCookie();
  if (!key && !sessionId) {
    return { ok: false, error: SERVICE_UNAVAILABLE, status: 503 };
  }

  const path = adminPath.startsWith("/") ? adminPath : `/${adminPath}`;
  const url = `${getBackendBaseUrl()}/api/v1/admin${path}`;

  const authHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (key) authHeaders["X-Admin-Key"] = key;
  if (sessionId) {
    authHeaders["Cookie"] = `${ADMIN_SESSION_COOKIE}=${sessionId}`;
  }
  const xff = await safeGetForwardedFor();
  if (xff) authHeaders["X-Forwarded-For"] = xff;

  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers: {
        ...authHeaders,
        ...(init?.headers as Record<string, string> | undefined),
      },
      cache: "no-store",
    });
  } catch {
    return { ok: false, error: SERVICE_UNAVAILABLE, status: 503 };
  }

  if (res.status === 204) {
    return { ok: true, data: undefined as T };
  }

  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const body: unknown = await res.json();
    if (!res.ok) {
      let message = GENERIC_ERROR;
      let rawDetail: unknown = undefined;
      if (body && typeof body === "object" && "detail" in body) {
        rawDetail = (body as { detail: unknown }).detail;
        const safe = normalizeAdminDetailError(rawDetail);
        if (safe) message = safe;
      }
      return {
        ok: false,
        error: message,
        status: res.status,
        detail: rawDetail,
      };
    }
    return { ok: true, data: body as T };
  }

  if (!res.ok) {
    return { ok: false, error: GENERIC_ERROR, status: res.status };
  }

  return { ok: false, error: GENERIC_ERROR, status: res.status };
}
