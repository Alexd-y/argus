/**
 * Pure-utility module shared by every layer of the admin-auth surface
 * (middleware, server actions, server components, login form). Holds
 * only inert values: typed constants, closed taxonomies, and helpers
 * that touch nothing but their arguments.
 *
 * Why "pure":
 *   `Frontend/middleware.ts` runs in the Edge runtime which forbids
 *   `next/headers`. Anything that reads from a request goes into
 *   {@link ./adminAuthServer.ts} instead so this module can be imported
 *   from middleware, server-only code, and (incidentally) client bundles
 *   without runtime failures.
 *
 * Security boundary:
 *   The `NEXT_PUBLIC_*` envs read here are intentionally browser-visible —
 *   they only select UI behaviour (which auth mode to attempt). Real
 *   secrets like `ADMIN_API_KEY` live in {@link ./adminAuthServer.ts}'s
 *   call sites and never enter this module.
 */

/** All supported front-end auth modes. */
export const ADMIN_AUTH_MODES = ["cookie", "session", "auto"] as const;

/** Closed taxonomy of admin-auth modes consumed by the front-end. */
export type AdminAuthMode = (typeof ADMIN_AUTH_MODES)[number];

/** Default mode when the env var is unset / unrecognised. */
export const DEFAULT_ADMIN_AUTH_MODE: AdminAuthMode = "auto";

/** Backend-issued HttpOnly session cookie. Mirrors `admin_auth.ADMIN_SESSION_COOKIE`. */
export const ADMIN_SESSION_COOKIE = "argus.admin.session";

/** Frozen set of auth endpoints on the backend (mounted under `/api/v1`). */
export const ADMIN_AUTH_PATHS = Object.freeze({
  login: "/api/v1/auth/admin/login",
  logout: "/api/v1/auth/admin/logout",
  whoami: "/api/v1/auth/admin/whoami",
} as const);

/**
 * Resolve the current auth mode from the `NEXT_PUBLIC_ADMIN_AUTH_MODE` env.
 * The value is read at call time so unit tests can mutate `process.env`
 * between cases without re-importing the module. Anything outside the
 * taxonomy is downgraded to the default so a typo cannot weaken the gate.
 */
export function getAdminAuthMode(): AdminAuthMode {
  const raw = process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE?.trim().toLowerCase();
  if (raw && (ADMIN_AUTH_MODES as readonly string[]).includes(raw)) {
    return raw as AdminAuthMode;
  }
  return DEFAULT_ADMIN_AUTH_MODE;
}

/**
 * Closed taxonomy of UI-visible auth-action failure codes. Every
 * non-success branch in the login/logout flow MUST map to one of these so
 * the React component never sees an opaque message it cannot localise.
 */
export type AuthActionCode =
  | "invalid_credentials"
  | "rate_limited"
  | "service_unavailable"
  | "config_missing";

/** Russian primary copy. English fallback shipped alongside in the form. */
export const AUTH_ERROR_MESSAGES_RU: Readonly<Record<AuthActionCode, string>> =
  Object.freeze({
    invalid_credentials: "Неверные учётные данные",
    rate_limited: "Слишком много попыток. Попробуйте позже.",
    service_unavailable: "Сервис временно недоступен.",
    config_missing: "Сервис временно недоступен.",
  });

export const AUTH_ERROR_MESSAGES_EN: Readonly<Record<AuthActionCode, string>> =
  Object.freeze({
    invalid_credentials: "Invalid credentials",
    rate_limited: "Too many attempts. Please try again later.",
    service_unavailable: "Service is temporarily unavailable.",
    config_missing: "Service is temporarily unavailable.",
  });

/**
 * Discriminated union returned by every auth server action so the client
 * handles success / failure with one shape. `retryAfterSeconds` is set
 * only on `rate_limited` so the form can render a countdown.
 */
export type AuthActionResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code: AuthActionCode;
      readonly retryAfterSeconds?: number;
    };

/**
 * Build the absolute backend URL for an `/api/v1/auth/admin/...` path.
 * Reuses the same env var convention as `lib/adminProxy.ts` so the
 * auth flow targets the same dev / prod / mock backend that the
 * existing admin server actions do.
 */
export function buildAuthBackendUrl(path: string): string {
  const base =
    process.env.BACKEND_URL?.trim() ||
    process.env.NEXT_PUBLIC_BACKEND_URL?.trim() ||
    "http://localhost:8000";
  const trimmed = base.replace(/\/$/, "");
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${trimmed}${suffix}`;
}

/**
 * Bound on user-supplied login fields — mirrors the backend Pydantic
 * model in `admin_auth.py`. Used by the login server action for cheap
 * pre-flight rejection so we don't burn rate-limit tokens on obviously
 * bad payloads.
 */
export const LOGIN_FIELD_LIMITS = Object.freeze({
  subjectMin: 1,
  subjectMax: 255,
  passwordMin: 1,
  passwordMax: 1024,
});

/**
 * Reject obvious garbage in the login payload before the backend does.
 * Any non-string / out-of-range field returns `invalid_credentials` so
 * the resulting failure is indistinguishable from a wrong password (no
 * enumeration on field shape either).
 */
export type ValidatedLoginCredentials =
  | { readonly ok: true; readonly subject: string; readonly password: string }
  | { readonly ok: false };

export function validateLoginCredentials(
  subject: unknown,
  password: unknown,
): ValidatedLoginCredentials {
  if (typeof subject !== "string" || typeof password !== "string") {
    return { ok: false };
  }
  const s = subject.trim();
  // Password is treated as opaque — leading/trailing whitespace is meaningful.
  const p = password;
  if (
    s.length < LOGIN_FIELD_LIMITS.subjectMin ||
    s.length > LOGIN_FIELD_LIMITS.subjectMax
  ) {
    return { ok: false };
  }
  if (
    p.length < LOGIN_FIELD_LIMITS.passwordMin ||
    p.length > LOGIN_FIELD_LIMITS.passwordMax
  ) {
    return { ok: false };
  }
  return { ok: true, subject: s, password: p };
}

/**
 * Convert a backend HTTP status to one of the closed UI codes. Anything
 * unexpected is downgraded to `service_unavailable` so the user only ever
 * sees one of four messages — no leaking of internals.
 */
export function statusToAuthActionCode(status: number): AuthActionCode {
  if (status === 401 || status === 403) return "invalid_credentials";
  if (status === 422) return "invalid_credentials";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "service_unavailable";
  return "service_unavailable";
}

/**
 * Parse `Retry-After` as a non-negative integer number of seconds. The
 * HTTP spec also allows an HTTP-date form; we treat that as best-effort
 * and fall back to a sensible default countdown so the form never freezes.
 * Capped at 600 s to avoid a misbehaving server pinning the form forever.
 */
export function parseRetryAfterSeconds(
  header: string | null,
  fallbackSeconds = 30,
): number {
  if (!header) return fallbackSeconds;
  const trimmed = header.trim();
  const n = Number.parseInt(trimmed, 10);
  if (Number.isFinite(n) && n >= 0) return Math.min(n, 600);
  const dateMs = Date.parse(trimmed);
  if (Number.isFinite(dateMs)) {
    const delta = Math.ceil((dateMs - Date.now()) / 1000);
    if (delta > 0) return Math.min(delta, 600);
  }
  return fallbackSeconds;
}

/* ────────────────────────────────────────────────────────────────────
 * Set-Cookie parsing
 *
 * The login / logout handlers on the backend mint cookies with strict
 * attributes (HttpOnly, Secure, SameSite=Strict). `next/headers` does
 * not expose a generic "set raw cookie string" API, so we parse just
 * enough to call `cookies().set()` (in adminAuthServer.ts) with the
 * canonical attributes preserved.
 *
 * Pure functions, kept here so they're unit-testable without spinning
 * up a Next runtime. The server-side reflection sits in adminAuthServer.
 * ────────────────────────────────────────────────────────────────── */

export type ParsedSetCookie = {
  readonly name: string;
  readonly value: string;
  readonly path: string | null;
  readonly httpOnly: boolean;
  readonly secure: boolean;
  readonly sameSite: "lax" | "strict" | "none" | undefined;
  readonly maxAge: number | undefined;
  readonly expires: Date | undefined;
};

/**
 * Split a comma-concatenated `Set-Cookie` header into individual cookies
 * without breaking on commas inside `Expires=...` dates (which use
 * the RFC 1123 form `, dd-mon-yyyy hh:mm:ss GMT`).
 */
export function splitSetCookies(raw: string): string[] {
  const parts: string[] = [];
  let buf = "";
  let inExpires = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === "," && !inExpires) {
      const trimmed = buf.trim();
      if (trimmed) parts.push(trimmed);
      buf = "";
      continue;
    }
    if (
      ch.toLowerCase() === "e" &&
      raw.slice(i, i + 8).toLowerCase() === "expires="
    ) {
      inExpires = true;
    }
    if (inExpires && ch === ";") {
      inExpires = false;
    }
    buf += ch;
  }
  const tail = buf.trim();
  if (tail) parts.push(tail);
  return parts;
}

export function parseSetCookie(raw: string): ParsedSetCookie | null {
  const segments = raw
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
  if (segments.length === 0) return null;
  const [first, ...attrs] = segments;
  const eq = first.indexOf("=");
  if (eq <= 0) return null;
  const name = first.slice(0, eq).trim();
  const value = first.slice(eq + 1).trim();

  let path: string | null = null;
  let httpOnly = false;
  let secure = false;
  let sameSite: "lax" | "strict" | "none" | undefined;
  let maxAge: number | undefined;
  let expires: Date | undefined;

  for (const attr of attrs) {
    const lower = attr.toLowerCase();
    if (lower === "httponly") {
      httpOnly = true;
    } else if (lower === "secure") {
      secure = true;
    } else if (lower.startsWith("path=")) {
      path = attr.slice(5).trim();
    } else if (lower.startsWith("samesite=")) {
      const v = attr.slice(9).trim().toLowerCase();
      if (v === "lax" || v === "strict" || v === "none") sameSite = v;
    } else if (lower.startsWith("max-age=")) {
      const n = Number.parseInt(attr.slice(8).trim(), 10);
      if (Number.isFinite(n)) maxAge = n;
    } else if (lower.startsWith("expires=")) {
      const d = new Date(attr.slice(8).trim());
      if (!Number.isNaN(d.getTime())) expires = d;
    }
  }

  return { name, value, path, httpOnly, secure, sameSite, maxAge, expires };
}

/** Whether the cookie was already declared expired by the backend. */
export function isExpiredSetCookie(parsed: ParsedSetCookie): boolean {
  if (parsed.maxAge === 0) return true;
  if (parsed.expires && parsed.expires.getTime() <= Date.now()) return true;
  return false;
}
