"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { AdminAuthProvider } from "@/services/admin/AdminAuthContext";
import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";

const NAV = [
  { href: "/admin", label: "Dashboard" },
  { href: "/admin/tenants", label: "Tenants" },
  { href: "/admin/scans", label: "Scans" },
  { href: "/admin/findings", label: "Findings" },
  { href: "/admin/llm", label: "LLM" },
  { href: "/admin/system", label: "System" },
] as const;

function ForbiddenChrome({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      <header className="border-b border-[var(--border)] bg-[var(--bg-secondary)] px-4 py-3">
        <div className="mx-auto flex max-w-3xl items-center justify-between">
          <Link
            href="/"
            className="text-sm font-semibold text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
          >
            ← ARGUS
          </Link>
          <span className="text-sm text-[var(--text-muted)]">Admin</span>
        </div>
      </header>
      <div className="mx-auto max-w-3xl px-4 py-10">{children}</div>
    </div>
  );
}

function AdminChrome({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isForbidden = pathname === "/admin/forbidden";

  if (isForbidden) {
    return <ForbiddenChrome>{children}</ForbiddenChrome>;
  }

  return (
    <AdminRouteGuard minimumRole="operator">
      <div className="flex min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
        <aside
          className="hidden w-52 shrink-0 border-r border-[var(--border)] bg-[var(--bg-secondary)] md:flex md:flex-col"
          aria-label="Admin navigation"
        >
          <div className="border-b border-[var(--border)] px-4 py-4">
            <Link href="/" className="text-xs text-[var(--text-muted)] hover:text-[var(--accent)]">
              ← Home
            </Link>
            <div className="mt-2 text-sm font-semibold text-[var(--text-primary)]">Admin</div>
          </div>
          <nav className="flex flex-1 flex-col gap-1 p-3">
            {NAV.map((item) => {
              const active =
                item.href === "/admin"
                  ? pathname === "/admin"
                  : pathname === item.href || pathname.startsWith(`${item.href}/`);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`rounded px-3 py-2 text-sm transition ${
                    active
                      ? "bg-[var(--bg-tertiary)] text-[var(--accent)]"
                      : "text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </aside>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex items-center justify-between border-b border-[var(--border)] bg-[var(--bg-secondary)] px-4 py-3">
            <div className="flex min-w-0 items-center gap-2 text-sm">
              <span className="truncate font-semibold text-[var(--text-primary)]">
                ARGUS Administration
              </span>
              <span className="text-[var(--text-muted)]">/</span>
              <span className="truncate text-[var(--text-secondary)]">
                {pathname.replace(/^\/admin/, "") || "dashboard"}
              </span>
            </div>
          </header>
          <nav
            className="flex gap-1 overflow-x-auto border-b border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 md:hidden"
            aria-label="Admin sections"
          >
            {NAV.map((item) => {
              const active =
                item.href === "/admin"
                  ? pathname === "/admin"
                  : pathname === item.href || pathname.startsWith(`${item.href}/`);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`shrink-0 rounded px-2.5 py-1.5 text-xs transition ${
                    active
                      ? "bg-[var(--bg-tertiary)] text-[var(--accent)]"
                      : "text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <main className="flex-1 overflow-auto p-4 md:p-6">{children}</main>
        </div>
      </div>
    </AdminRouteGuard>
  );
}

export function AdminLayoutClient({ children }: { children: React.ReactNode }) {
  return (
    <AdminAuthProvider>
      <AdminChrome>{children}</AdminChrome>
    </AdminAuthProvider>
  );
}
