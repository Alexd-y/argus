"use client";

import { useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { configureMcpClient } from "./index";

/**
 * App-router compatible React Query provider scoped to the MCP routes.
 *
 * Lives on `/mcp/*` so the rest of the application keeps zero dependency
 * on `@tanstack/react-query`. We deliberately instantiate the client
 * inside `useState` so each request gets a fresh instance during SSR
 * while the browser keeps a single instance across re-renders.
 */
export function McpQueryProvider({ children }: { children: ReactNode }) {
  configureMcpClient();
  const [client] = useState(() => createMcpQueryClient());
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

/**
 * Build a `QueryClient` with defaults tuned for MCP traffic:
 *   - 30 s stale time matches the contract documented in `useMcpResource`.
 *   - 5 min `gcTime` keeps results around long enough to feel instant
 *     when navigating back, without hoarding stale memory.
 *   - retry is disabled for mutations and capped at 1 for queries so a
 *     real backend error surfaces immediately instead of stalling the UI
 *     behind an exponential-backoff loop.
 */
export function createMcpQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        retry: 1,
      },
      mutations: {
        retry: 0,
      },
    },
  });
}
