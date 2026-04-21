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

function readRoleFromDevEnv(): AdminRole | null {
  if (typeof process === "undefined") return null;
  return parseAdminRole(process.env.NEXT_PUBLIC_ADMIN_DEV_ROLE);
}

function resolveRole(): AdminRole | null {
  return readRoleFromStorage() ?? readRoleFromDevEnv();
}

export function AdminAuthProvider({ children }: { children: ReactNode }) {
  const [role, setRoleState] = useState<AdminRole | null>(null);
  const [status, setStatus] = useState<AdminAuthStatus>("loading");

  useEffect(() => {
    setRoleState(resolveRole());
    setStatus("ready");
  }, []);

  const setRole = useCallback((next: AdminRole | null) => {
    setRoleState(next);
    if (typeof window !== "undefined") {
      if (next === null) {
        sessionStorage.removeItem(ADMIN_ROLE_STORAGE_KEY);
      } else {
        sessionStorage.setItem(ADMIN_ROLE_STORAGE_KEY, next);
      }
    }
  }, []);

  const value = useMemo<AdminAuthContextValue>(
    () => ({ role, status, setRole }),
    [role, status, setRole],
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
