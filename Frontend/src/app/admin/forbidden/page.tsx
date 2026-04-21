export default function AdminForbiddenPage() {
  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold text-[var(--text-primary)]">Access denied</h1>
      <p className="text-sm text-[var(--text-secondary)]">
        You do not have permission to use the admin console. Sign in with an authorised role or
        contact your administrator.
      </p>
      <p className="text-xs text-[var(--text-muted)]">
        Development: set{" "}
        <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[var(--text-secondary)]">
          NEXT_PUBLIC_ADMIN_DEV_ROLE
        </code>{" "}
        or set{" "}
        <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[var(--text-secondary)]">
          sessionStorage
        </code>{" "}
        key <code className="rounded bg-[var(--bg-tertiary)] px-1">argus.admin.role</code> to{" "}
        <code className="rounded bg-[var(--bg-tertiary)] px-1">operator</code>,{" "}
        <code className="rounded bg-[var(--bg-tertiary)] px-1">admin</code>, or{" "}
        <code className="rounded bg-[var(--bg-tertiary)] px-1">super-admin</code>.
      </p>
    </div>
  );
}
