"use client";

import { useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { AdminAuditLogsError } from "@/lib/adminAuditLogs";

/**
 * Route-scoped React Query provider for `/admin/audit-logs`. Mirrors the
 * `AdminFindingsQueryProvider` (T20) so the rest of the admin shell stays
 * decoupled from React Query and SSR gets a fresh client per request.
 *
 * Defaults are tuned for forensic browsing:
 *   - 30 s `staleTime` keeps the page snappy when the operator toggles
 *     filters back and forth.
 *   - 5 min `gcTime` covers a typical drill-down → back-to-list flow.
 *   - `retry` skips closed-taxonomy auth/forbidden/422 codes (no point
 *     hammering the backend after a deterministic refusal); transient
 *     `network_error` / `server_error` get one retry.
 */
export function AdminAuditLogsQueryProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [client] = useState(() => createAdminAuditLogsQueryClient());
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

export function createAdminAuditLogsQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => {
          if (error instanceof AdminAuditLogsError) {
            if (
              error.code === "unauthorized" ||
              error.code === "forbidden" ||
              error.code === "invalid_input"
            ) {
              return false;
            }
          }
          return failureCount < 1;
        },
      },
      mutations: { retry: 0 },
    },
  });
}
