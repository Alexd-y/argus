import { TenantsAdminClient } from "./TenantsAdminClient";

/** CRUD calls FastAPI via server actions + `require_admin`; `ADMIN_API_KEY` never hits the browser. */
export default function AdminTenantsPage() {
  return <TenantsAdminClient />;
}
