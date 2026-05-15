/**
 * ARGUS API client - base config and fetch helpers.
 * Uses NEXT_PUBLIC_API_URL (default /api/v1).
 */

const API_BASE =
  (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_API_URL) || "/api/v1";

/**
 * Base URL for API (may be relative or absolute).
 */
function getBase(): string {
  return API_BASE.endsWith("/") ? API_BASE.slice(0, -1) : API_BASE;
}

/**
 * Returns absolute API URL for client-side (EventSource requires absolute URL).
 */
export function getApiBaseUrl(): string {
  const base = getBase();
  if (typeof window === "undefined") {
    return base;
  }
  if (base.startsWith("http")) {
    return base;
  }
  return `${window.location.origin}${base.startsWith("/") ? "" : "/"}${base}`;
}

/**
 * Base URL for **browser** SSE (`GET /scans/:id/events`).
 *
 * Next.js dev rewrites the same `/api/v1` path for `fetch()`, but Turbopack can drop or
 * reset long-lived EventSource streams — the UI then loses `complete` events and polling
 * may lag. Point SSE at the API the browser reaches directly (usually public nginx), e.g.:
 * `NEXT_PUBLIC_SSE_API_BASE=http://YOUR_HOST:18888/api/v1`
 *
 * CORS / nginx: backend must allow this page's `Origin` (see `CORS_ORIGINS` / nginx CORS map).
 */
export function getSseApiBaseUrl(): string {
  const raw =
    (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_SSE_API_BASE) || "";
  const trimmed = raw.trim().replace(/\/$/, "");
  if (trimmed) {
    return trimmed;
  }
  return getApiBaseUrl();
}

/**
 * Build full URL for an API path (relative or absolute depending on base).
 */
export function apiUrl(path: string): string {
  const base = getBase();
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${base}${normalizedPath}`;
}

export interface ApiError {
  error: string;
  code?: string;
  details?: unknown;
}

/**
 * Safe error message for UI - never leaks stack traces or internal details.
 */
export function getSafeErrorMessage(err: unknown, fallback = "An error occurred"): string {
  const sanitize = (msg: string): string | null =>
    msg && !msg.includes("stack") && !msg.includes("at ") ? msg : null;

  if (err instanceof Error) {
    const msg = (err as Error & { error?: string }).error ?? err.message;
    const safe = sanitize(msg);
    if (safe) return safe;
  }
  if (typeof err === "string") {
    const safe = sanitize(err);
    if (safe) return safe;
  }
  if (typeof err === "object" && err !== null && "error" in err) {
    const apiErr = err as ApiError;
    if (typeof apiErr.error === "string") {
      const safe = sanitize(apiErr.error);
      if (safe) return safe;
    }
  }
  return fallback;
}

/**
 * Generic fetch wrapper with error handling.
 */
export async function apiFetch<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const url = apiUrl(path);
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!res.ok) {
    let body: ApiError | null = null;
    try {
      body = (await res.json()) as ApiError;
    } catch {
      // non-JSON response
    }
    const msg = body?.error ?? `Request failed (${res.status})`;
    throw new Error(msg);
  }

  const contentType = res.headers.get("content-type");
  if (contentType?.includes("application/json")) {
    return res.json() as Promise<T>;
  }
  return res.text() as unknown as Promise<T>;
}
