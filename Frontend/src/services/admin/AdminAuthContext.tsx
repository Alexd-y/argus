"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { AdminRole } from "./adminRoles";
import { parseAdminRole } from "./adminRoles";

export const ADMIN_ROLE_STORAGE_KEY = "argus.admin.role";
/**
 * Cookie name MUST stay in sync with `services/admin/serverSession.ts`'s
 * `ADMIN_ROLE_COOKIE`. We mirror the role into a cookie here so that
 * `"use server"` actions can read the same identity the client thinks it
 * has — the actions themselves still call FastAPI via the server-only
 * `X-Admin-Key`, so this cookie is non-trusted UX state, never an auth token.
 */
const ADMIN_ROLE_COOKIE = "argus.admin.role";
const ADMIN_ROLE_COOKIE_MAX_AGE_S = 60 * 60 * 24;

export type AdminAuthStatus = "loading" | "ready";

export type AdminAuthContextValue = {
  role: AdminRole | null;
  status: AdminAuthStatus;
  setRole: (role: AdminRole | null) => void;
};

const AdminAuthContext = createContext<AdminAuthContextValue | null>(null);

function readRoleFromStorage(): AdminRole | null {
  if (typeof window === "undefined") return null;
  return parseAdminRole(sessionStorage.getItem(ADMIN_ROLE_STORAGE_KEY));
}

function readRoleFromCookie(): AdminRole | null {
  if (typeof document === "undefined") return null;
  const raw = document.cookie ?? "";
  if (raw === "") return null;
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    if (name !== ADMIN_ROLE_COOKIE) continue;
    try {
      return parseAdminRole(decodeURIComponent(part.slice(eq + 1).trim()));
    } catch {
      return null;
    }
  }
  return null;
}

function readRoleFromDevEnv(): AdminRole | null {
  if (typeof process === "undefined") return null;
  return parseAdminRole(process.env.NEXT_PUBLIC_ADMIN_DEV_ROLE);
}

function resolveRole(): AdminRole | null {
  // Cookie comes BEFORE sessionStorage so the session-mode login flow
  // (B6-T09) — which writes the role cookie from the server action —
  // hydrates without a client round-trip even if sessionStorage is
  // empty (private window, fresh tab).
  return (
    readRoleFromStorage() ?? readRoleFromCookie() ?? readRoleFromDevEnv()
  );
}

function writeRoleCookie(role: AdminRole | null): void {
  if (typeof document === "undefined") return;
  const isHttps =
    typeof window !== "undefined" && window.location?.protocol === "https:";
  const secure = isHttps ? "; Secure" : "";
  if (role === null) {
    document.cookie = `${ADMIN_ROLE_COOKIE}=; path=/; max-age=0; SameSite=Strict${secure}`;
    return;
  }
  document.cookie =
    `${ADMIN_ROLE_COOKIE}=${encodeURIComponent(role)}; path=/; ` +
    `max-age=${ADMIN_ROLE_COOKIE_MAX_AGE_S}; SameSite=Strict${secure}`;
}

type AdminAuthState = {
  readonly role: AdminRole | null;
  readonly status: AdminAuthStatus;
};

const INITIAL_AUTH_STATE: AdminAuthState = { role: null, status: "loading" };

export function AdminAuthProvider({ children }: { children: ReactNode }) {
  // Combined state so on-mount hydration is a SINGLE setState — paints the
  // post-hydration view in one frame and avoids the cascading-renders rule
  // (`react-hooks/set-state-in-effect`) firing on two separate updates.
  const [auth, setAuth] = useState<AdminAuthState>(INITIAL_AUTH_STATE);

  useEffect(() => {
    // SSR-safe hydration: sessionStorage / document.cookie are browser-only,
    // so we can only resolve the role after mount. Mirroring the resolved
    // role into the cookie keeps `"use server"` actions in sync on the very
    // first request after a hard reload — the cookie is non-trusted UX state
    // (the actions still attach `X-Admin-Key` from the server-only env).
    const resolved = resolveRole();
    writeRoleCookie(resolved);
    // eslint-disable-next-line react-hooks/set-state-in-effect -- one-shot hydration from external storage
    setAuth({ role: resolved, status: "ready" });
  }, []);

  const setRole = useCallback((next: AdminRole | null) => {
    setAuth((prev) => ({ ...prev, role: next }));
    if (typeof window !== "undefined") {
      if (next === null) {
        sessionStorage.removeItem(ADMIN_ROLE_STORAGE_KEY);
      } else {
        sessionStorage.setItem(ADMIN_ROLE_STORAGE_KEY, next);
      }
    }
    writeRoleCookie(next);
  }, []);

  const value = useMemo<AdminAuthContextValue>(
    () => ({ role: auth.role, status: auth.status, setRole }),
    [auth.role, auth.status, setRole],
  );

  return (
    <AdminAuthContext.Provider value={value}>{children}</AdminAuthContext.Provider>
  );
}

export function useAdminAuthContext(): AdminAuthContextValue {
  const ctx = useContext(AdminAuthContext);
  if (!ctx) {
    throw new Error("useAdminAuthContext must be used within AdminAuthProvider");
  }
  return ctx;
}
