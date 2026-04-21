import { AdminAuditLogsClient } from "./AdminAuditLogsClient";

/**
 * Admin audit-log viewer + chain-integrity verification page (T22).
 *
 * Backend routes:
 *   GET  /api/v1/admin/audit-logs            — list (T18-era; bridged in
 *                                              `Frontend/src/lib/adminAuditLogs.ts`)
 *   POST /api/v1/admin/audit-logs/verify-chain — chain replay (T25)
 *
 * RBAC: `admin` (own tenant only) or `super-admin` (cross-tenant). The
 * verify-chain endpoint refuses `operator` outright, so the entire page is
 * gated at `admin`.
 */
export default function AdminAuditLogsPage() {
  return <AdminAuditLogsClient />;
}
