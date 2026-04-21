import type { ReactNode } from "react";
import type { Metadata } from "next";
import Link from "next/link";
import { McpQueryProvider } from "@/services/mcp/QueryProvider";
import { NotificationsDrawer } from "@/components/mcp/NotificationsDrawer";
import { isMcpEnabled } from "./feature-flag";

export const metadata: Metadata = {
  title: "ARGUS · MCP",
  description: "Model Context Protocol — interactive tool runner",
};

/**
 * MCP-scoped layout. Wraps every `/mcp/**` route with React Query and
 * mounts the slide-out notifications drawer in the top sidebar.
 *
 * The notifications drawer is rendered behind the same feature flag as
 * the page content — when MCP is disabled we render a bare layout so
 * the `NotEnabledNotice` page can flash without dragging in the SSE hook.
 */
export default function McpLayout({ children }: { children: ReactNode }) {
  const enabled = isMcpEnabled();
  if (!enabled) {
    return (
      <div data-testid="mcp-layout-disabled" className="min-h-screen">
        {children}
      </div>
    );
  }
  return (
    <McpQueryProvider>
      <div
        data-testid="mcp-layout-enabled"
        className="flex min-h-screen flex-col bg-[var(--bg-primary)] text-[var(--text-primary)]"
      >
        <header className="flex items-center justify-between border-b border-[var(--border)] bg-[var(--bg-secondary)] px-4 py-3">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="text-sm font-semibold text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
            >
              ← ARGUS
            </Link>
            <span className="text-sm text-[var(--text-muted)]">/</span>
            <span className="text-sm font-semibold text-[var(--text-primary)]">
              MCP
            </span>
          </div>
          <NotificationsDrawer />
        </header>
        <main className="flex-1">{children}</main>
      </div>
    </McpQueryProvider>
  );
}
