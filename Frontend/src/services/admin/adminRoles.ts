export type AdminRole = "operator" | "admin" | "super-admin";

const RANK: Record<AdminRole, number> = {
  operator: 1,
  admin: 2,
  "super-admin": 3,
};

export function roleRank(role: AdminRole): number {
  return RANK[role];
}

export function parseAdminRole(value: string | null | undefined): AdminRole | null {
  if (value == null || value === "") return null;
  const t = value.trim().toLowerCase();
  if (t === "operator") return "operator";
  if (t === "admin") return "admin";
  if (t === "super-admin" || t === "super_admin" || t === "superadmin") {
    return "super-admin";
  }
  return null;
}

export function canAccessRole(
  userRole: AdminRole | null,
  minimum: AdminRole,
): boolean {
  if (userRole === null) return false;
  return RANK[userRole] >= RANK[minimum];
}
