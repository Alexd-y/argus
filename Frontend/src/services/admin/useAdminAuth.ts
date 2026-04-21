"use client";

import { useMemo } from "react";
import type { AdminRole } from "./adminRoles";
import { canAccessRole } from "./adminRoles";
import { useAdminAuthContext } from "./AdminAuthContext";

export type UseAdminAuthOptions = {
  /** Minimum role required; defaults to operator (baseline admin surface). */
  minimumRole?: AdminRole;
};

export type UseAdminAuthResult = {
  role: AdminRole | null;
  status: "loading" | "ready";
  allowed: boolean;
};

/**
 * Client-side RBAC gate for the admin shell. Real protection for tenant admin CRUD is
 * server actions calling FastAPI with `require_admin` (and `ADMIN_API_KEY` only on the server).
 * Unauthenticated users have role null; callers should redirect or show 403.
 */
export function useAdminAuth(options: UseAdminAuthOptions = {}): UseAdminAuthResult {
  const { minimumRole = "operator" } = options;
  const { role, status } = useAdminAuthContext();

  const allowed = useMemo(
    () => canAccessRole(role, minimumRole),
    [role, minimumRole],
  );

  return { role, status, allowed };
}
