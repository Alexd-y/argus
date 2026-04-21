"use client";

import { useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { AdminFindingsError } from "@/lib/adminFindings";

/**
 * Route-scoped React Query provider for `/admin/findings`. Mirrors the
 * `McpQueryProvider` pattern (see `services/mcp/QueryProvider.tsx`) so the rest
 * of the admin shell keeps zero coupling to React Query and SSR gets a fresh
 * client per request.
 *
 * Defaults are tuned for triage browsing:
 *   - 30 s `staleTime` keeps an open page snappy when the operator toggles
 *     filters back and forth.
 *   - 5 min `gcTime` covers a typical drill-down → back-to-list flow.
 *   - `retry` skips closed-taxonomy auth/forbidden/422 codes (no point in
 *     hammering the backend after a deterministic refusal); transient
 *     `network_error` / `server_error` get one retry.
 */
export function AdminFindingsQueryProvider({ children }: { children: ReactNode }) {
  const [client] = useState(() => createAdminFindingsQueryClient());
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

export function createAdminFindingsQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => {
          if (error instanceof AdminFindingsError) {
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
