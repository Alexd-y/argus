"use client";

export default function AdminError({
  error: _error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="flex min-h-[40vh] flex-col items-center justify-center gap-4 rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-8">
      <p className="text-center text-sm text-[var(--text-secondary)]">
        This admin section failed to load. Try again or return to the dashboard.
      </p>
      <button
        type="button"
        onClick={reset}
        className="rounded border border-[var(--border)] bg-[var(--bg-tertiary)] px-4 py-2 text-sm text-[var(--text-primary)] transition hover:border-[var(--accent)]"
      >
        Retry
      </button>
    </div>
  );
}
