/**
 * MCP authentication and tenant resolution layer.
 *
 * The auto-generated `argus-mcp` SDK accepts:
 *   - `OpenAPI.TOKEN`   — bearer token (string | async resolver)
 *   - `OpenAPI.HEADERS` — extra headers (object | async resolver)
 *
 * We expose a small, framework-agnostic provider abstraction so that:
 *   1. In production the application bootstraps a real session provider
 *      (e.g. NextAuth, custom JWT, OAuth2/OIDC) via `setMcpSessionProvider()`.
 *   2. In local development we fall back to `localStorage` keys (with a
 *      visible warning) so engineers can paste a token without wiring SSO.
 *
 * No raw `fetch()` calls live here — every privileged request goes through
 * the SDK and uses the resolvers configured in `services/mcp/index.ts`.
 */

const ACCESS_TOKEN_KEY = "argus.mcp.accessToken";
const TENANT_ID_KEY = "argus.mcp.tenantId";
const DEV_WARNING_FLAG = "__argusMcpDevWarningEmitted";

let devWarningEmitted = false;

/**
 * Pluggable session provider. Production code should implement this against
 * the real auth backend (NextAuth, Cognito, Keycloak …) and register it via
 * `setMcpSessionProvider()`.
 *
 * The contract is intentionally async — token fetches may need to await
 * a session API or refresh flow.
 */
export interface McpSessionProvider {
  getAccessToken(): Promise<string | null>;
  getTenantId(): Promise<string | null>;
  /** Optional refresh hook used by `withMcpAuthRetry()` after a 401. */
  refresh?(): Promise<void>;
}

/**
 * Default provider that reads from `localStorage` only when running in the
 * browser. Emits a single `console.warn` per session to discourage relying
 * on it outside dev. It is safe (returns `null`) on the server.
 */
export class LocalStorageSessionProvider implements McpSessionProvider {
  async getAccessToken(): Promise<string | null> {
    if (typeof window === "undefined") {
      return null;
    }
    emitDevWarningOnce();
    try {
      return window.localStorage.getItem(ACCESS_TOKEN_KEY);
    } catch {
      return null;
    }
  }

  async getTenantId(): Promise<string | null> {
    if (typeof window === "undefined") {
      return null;
    }
    try {
      return window.localStorage.getItem(TENANT_ID_KEY);
    } catch {
      return null;
    }
  }
}

let activeProvider: McpSessionProvider = new LocalStorageSessionProvider();

/**
 * Register a session provider. Call once at application boot, before the
 * first MCP request. Subsequent calls replace the active provider.
 */
export function setMcpSessionProvider(provider: McpSessionProvider): void {
  activeProvider = provider;
}

export function getMcpSessionProvider(): McpSessionProvider {
  return activeProvider;
}

/**
 * Resolve the bearer token. Returns an empty string when missing — the SDK's
 * `isStringWithValue` guard then skips the `Authorization` header entirely
 * instead of sending `Bearer null` / `Bearer undefined`.
 */
export async function resolveMcpBearerToken(): Promise<string> {
  const token = await activeProvider.getAccessToken();
  return token && token.length > 0 ? token : "";
}

/**
 * Resolve the `X-Tenant-Id` header. Returns an empty object when no tenant
 * is bound — the SDK call will then go out without the header and the
 * backend will reject with 4xx, surfacing a clean error to the UI.
 */
export async function resolveMcpHeaders(): Promise<Record<string, string>> {
  const tenantId = await activeProvider.getTenantId();
  if (!tenantId) {
    return {};
  }
  return { "X-Tenant-Id": tenantId };
}

/**
 * Test-only helpers for setting localStorage tokens during dev or e2e runs.
 * Internal API: prefer `setMcpSessionProvider()` for production wiring.
 */
export const __devOnly = {
  setLocalStorageAccessToken(token: string | null): void {
    if (typeof window === "undefined") {
      return;
    }
    if (token === null) {
      window.localStorage.removeItem(ACCESS_TOKEN_KEY);
    } else {
      window.localStorage.setItem(ACCESS_TOKEN_KEY, token);
    }
  },
  setLocalStorageTenantId(tenantId: string | null): void {
    if (typeof window === "undefined") {
      return;
    }
    if (tenantId === null) {
      window.localStorage.removeItem(TENANT_ID_KEY);
    } else {
      window.localStorage.setItem(TENANT_ID_KEY, tenantId);
    }
  },
  resetProvider(): void {
    activeProvider = new LocalStorageSessionProvider();
    devWarningEmitted = false;
    if (typeof window !== "undefined") {
      const w = window as unknown as Record<string, unknown>;
      delete w[DEV_WARNING_FLAG];
    }
  },
};

/**
 * Wrap an SDK call so that a single 401 triggers a session refresh and
 * one retry. Mirrors SWR's revalidation contract: idempotent reads stay
 * idempotent, write-style mutations only fire twice if the first one
 * was rejected before reaching the controller.
 */
export async function withMcpAuthRetry<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (err) {
    if (!isUnauthorizedError(err)) {
      throw err;
    }
    if (typeof activeProvider.refresh !== "function") {
      throw err;
    }
    await activeProvider.refresh();
    return call();
  }
}

function isUnauthorizedError(err: unknown): boolean {
  if (err === null || typeof err !== "object") {
    return false;
  }
  const status = (err as { status?: unknown }).status;
  return status === 401;
}

function emitDevWarningOnce(): void {
  if (devWarningEmitted) {
    return;
  }
  if (typeof window === "undefined") {
    return;
  }
  const w = window as unknown as Record<string, unknown>;
  if (w[DEV_WARNING_FLAG]) {
    devWarningEmitted = true;
    return;
  }
  w[DEV_WARNING_FLAG] = true;
  devWarningEmitted = true;
  if (typeof console !== "undefined" && typeof console.warn === "function") {
    console.warn(
      "[ARGUS MCP] Falling back to localStorage for the bearer token. " +
        "Register a real session provider with setMcpSessionProvider() before shipping to production.",
    );
  }
}
