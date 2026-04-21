"use client";

import {
  useQuery,
  type UseQueryOptions,
  type UseQueryResult,
} from "@tanstack/react-query";
import { configureMcpClient } from "../index";
import { withMcpAuthRetry } from "../auth";

const RESOURCE_KEY_PREFIX = "mcp:resource";
const DEFAULT_STALE_TIME_MS = 30_000;

export type UseMcpResourceOptions<T> = Omit<
  UseQueryOptions<T, Error, T, ReadonlyArray<unknown>>,
  "queryKey" | "queryFn"
>;

export interface UseMcpResourceParams<T> {
  /** Unique URI for the MCP resource — used as the React Query cache key. */
  uri: string;
  /** Async fetcher invoking the SDK; usually a static method reference. */
  fetcher: () => PromiseLike<T>;
  /** Extra data appended to the cache key (path/query params). */
  variables?: ReadonlyArray<unknown>;
  /** Extra React Query options (excluding `queryKey` / `queryFn`). */
  queryOptions?: UseMcpResourceOptions<T>;
}

export type UseMcpResourceResult<T> = UseQueryResult<T, Error>;

/**
 * Type-safe React Query wrapper for an MCP read-only resource.
 *
 * Cache key shape: `["mcp:resource", uri, ...variables]` — pass the same
 * `uri` from anywhere in the tree to share the cache slot. Default
 * `staleTime` is 30 s, matching the read-mostly nature of MCP resources.
 *
 * Wraps the fetcher in `withMcpAuthRetry()` so a 401 triggers a single
 * retry after refreshing the active session.
 */
export function useMcpResource<T>(
  params: UseMcpResourceParams<T>,
): UseMcpResourceResult<T> {
  configureMcpClient();
  const { uri, fetcher, variables = [], queryOptions } = params;
  const queryKey: ReadonlyArray<unknown> = [
    RESOURCE_KEY_PREFIX,
    uri,
    ...variables,
  ];
  return useQuery<T, Error, T, ReadonlyArray<unknown>>({
    staleTime: DEFAULT_STALE_TIME_MS,
    ...queryOptions,
    queryKey,
    queryFn: async () => withMcpAuthRetry(() => Promise.resolve(fetcher())),
  });
}
