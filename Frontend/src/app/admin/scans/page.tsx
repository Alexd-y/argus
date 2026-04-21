import { AdminScansClient } from "./AdminScansClient";

/** Lists scans via server actions + `callAdminBackendJson` (admin key never exposed). */
export default function AdminScansPage() {
  return <AdminScansClient />;
}
