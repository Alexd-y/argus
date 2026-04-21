import { normalizeAdminDetailError } from "@/lib/adminErrorMapping";
import { getBackendBaseUrl, getServerAdminApiKey } from "@/lib/adminProxy";

const GENERIC_ERROR = "The operation could not be completed.";
const SERVICE_UNAVAILABLE = "Admin service is temporarily unavailable.";

export type AdminJsonResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status: number };

/**
 * Server-only JSON call to FastAPI `/api/v1/admin/*` with `X-Admin-Key` from env.
 * Maps `detail` through {@link normalizeAdminDetailError}; never leaks stack traces.
 */
export async function callAdminBackendJson<T>(
  adminPath: string,
  init?: RequestInit,
): Promise<AdminJsonResult<T>> {
  const key = getServerAdminApiKey();
  if (!key) {
    return { ok: false, error: SERVICE_UNAVAILABLE, status: 503 };
  }

  const path = adminPath.startsWith("/") ? adminPath : `/${adminPath}`;
  const url = `${getBackendBaseUrl()}/api/v1/admin${path}`;

  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Key": key,
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
      if (body && typeof body === "object" && "detail" in body) {
        const safe = normalizeAdminDetailError(
          (body as { detail: unknown }).detail,
        );
        if (safe) message = safe;
      }
      return { ok: false, error: message, status: res.status };
    }
    return { ok: true, data: body as T };
  }

  if (!res.ok) {
    return { ok: false, error: GENERIC_ERROR, status: res.status };
  }

  return { ok: false, error: GENERIC_ERROR, status: res.status };
}
