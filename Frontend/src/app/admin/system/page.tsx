import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { SystemClient } from "./SystemClient";

export default function AdminSystemPage() {
  return (
    <AdminRouteGuard minimumRole="super-admin">
      <SystemClient />
    </AdminRouteGuard>
  );
}