export default function AdminDashboardPage() {
  return (
    <div className="space-y-3">
      <h1 className="text-lg font-semibold text-[var(--text-primary)]">Dashboard</h1>
      <p className="text-sm text-[var(--text-secondary)]">
        Admin shell (Batch 2). Use the sidebar to open tenant, scan, and LLM surfaces as they are
        wired to the API.
      </p>
      <div className="rounded border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] p-8 text-center text-sm text-[var(--text-muted)]">
        No widgets yet — placeholders land with T12–T16.
      </div>
    </div>
  );
}
