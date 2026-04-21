import Link from "next/link";

export interface NotEnabledNoticeProps {
  /** Optional override for the docs anchor used in the call-to-action. */
  docsHref?: string;
}

/**
 * Rendered when `NEXT_PUBLIC_MCP_ENABLED` is unset or `false`. The MCP
 * integration is shipped behind a feature flag so the existing REST UI
 * stays unaffected for tenants that have not yet rolled it out.
 */
export function NotEnabledNotice({
  docsHref = "/docs/mcp-server.md",
}: NotEnabledNoticeProps = {}) {
  return (
    <main
      data-testid="mcp-not-enabled"
      className="mx-auto flex min-h-[60vh] max-w-2xl flex-col items-center justify-center gap-4 px-6 text-center"
    >
      <h1 className="text-2xl font-semibold tracking-tight text-[var(--text-primary)]">
        MCP integration is not enabled
      </h1>
      <p className="text-sm text-[var(--text-secondary)]">
        Set <code className="rounded bg-[var(--bg-tertiary)] px-1.5 py-0.5 font-mono text-xs">NEXT_PUBLIC_MCP_ENABLED=true</code>{" "}
        in your <code className="rounded bg-[var(--bg-tertiary)] px-1.5 py-0.5 font-mono text-xs">.env.local</code>{" "}
        to opt in to the Model Context Protocol surface (catalog browser,
        tool runner, notifications stream).
      </p>
      <p className="text-xs text-[var(--text-muted)]">
        The classic REST-based UI continues to work whether MCP is enabled or not.
      </p>
      <Link
        href={docsHref}
        className="rounded-md border border-[var(--border)] bg-[var(--bg-secondary)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--accent)]"
      >
        Read the MCP setup guide →
      </Link>
    </main>
  );
}
