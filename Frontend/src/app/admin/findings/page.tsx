import { AdminFindingsClient } from "./AdminFindingsClient";

/**
 * Cross-tenant findings triage console (T20).
 *
 * Backend route: GET /api/v1/admin/findings (T24). Admin/super-admin only;
 * non-super-admin operators are auto-pinned to their own tenant.
 */
export default function AdminFindingsPage() {
  return <AdminFindingsClient />;
}
