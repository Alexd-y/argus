"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import type { AdminRole } from "@/services/admin/adminRoles";
import { useAdminAuth } from "@/services/admin/useAdminAuth";

function AdminGateSkeleton() {
  return (
    <div
      className="flex min-h-[50vh] items-center justify-center border border-[var(--border)] bg-[var(--bg-secondary)] p-8"
      data-testid="admin-gate-loading"
    >
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--accent)]" />
    </div>
  );
}

export type AdminRouteGuardProps = {
  minimumRole?: AdminRole;
  children: React.ReactNode;
};

/**
 * Wraps a page or section that requires at least {@link minimumRole}.
 * Unauthorised users are redirected to `/admin/forbidden` (no stack traces).
 */
export function AdminRouteGuard({
  minimumRole = "operator",
  children,
}: AdminRouteGuardProps) {
  const router = useRouter();
  const { allowed, status } = useAdminAuth({ minimumRole });

  useEffect(() => {
    if (status !== "ready" || allowed) return;
    router.replace("/admin/forbidden");
  }, [status, allowed, router]);

  if (status === "loading") {
    return <AdminGateSkeleton />;
  }

  if (!allowed) {
    return <AdminGateSkeleton />;
  }

  return <>{children}</>;
}
