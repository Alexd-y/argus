import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";

export default function AdminSystemPage() {
  return (
    <AdminRouteGuard minimumRole="super-admin">
      <div className="space-y-3">
        <h1 className="text-lg font-semibold text-[var(--text-primary)]">System</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Super-admin only surface — reserved for destructive or platform-wide controls.
        </p>
        <div className="rounded border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] p-8 text-center text-sm text-[var(--text-muted)]">
          Empty state.
        </div>
      </div>
    </AdminRouteGuard>
  );
}
