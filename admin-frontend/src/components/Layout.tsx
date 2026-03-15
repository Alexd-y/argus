"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/", label: "Health" },
  { href: "/tenants", label: "Tenants" },
  { href: "/users", label: "Users" },
  { href: "/subscriptions", label: "Subscriptions" },
  { href: "/providers", label: "Providers" },
  { href: "/policies", label: "Policies" },
  { href: "/audit", label: "Audit Logs" },
  { href: "/usage", label: "Usage" },
  { href: "/auth", label: "Auth" },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-neutral-800 bg-neutral-900 px-4 py-3">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <Link href="/" className="font-semibold text-white">
            ARGUS Admin
          </Link>
          <nav className="flex gap-2 overflow-x-auto">
            {navItems.map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                className={`whitespace-nowrap px-3 py-1.5 text-sm rounded ${
                  pathname === href
                    ? "bg-indigo-600 text-white"
                    : "text-neutral-400 hover:text-white hover:bg-neutral-800"
                }`}
              >
                {label}
              </Link>
            ))}
          </nav>
        </div>
      </header>
      <main className="flex-1 p-4">{children}</main>
    </div>
  );
}
