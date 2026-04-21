"use client";

import {
  useMutation,
  type UseMutationOptions,
  type UseMutationResult,
} from "@tanstack/react-query";
import { configureMcpClient } from "../index";
import { withMcpAuthRetry } from "../auth";

/**
 * Shape of every tool / RPC method on the auto-generated SDK:
 *   `({ requestBody }: { requestBody: TArgs }) => CancelablePromise<TResult>`
 *
 * We accept anything that resolves to `Promise<TResult>` so consumers
 * can also pass plain async functions (useful for tests or for composing
 * SDK calls behind a façade).
 */
export type McpToolCall<TArgs, TResult> = (params: {
  requestBody: TArgs;
}) => PromiseLike<TResult>;

export type UseMcpToolOptions<TArgs, TResult> = Omit<
  UseMutationOptions<TResult, Error, TArgs>,
  "mutationFn"
>;

export type UseMcpToolResult<TArgs, TResult> = UseMutationResult<
  TResult,
  Error,
  TArgs
>;

/**
 * Type-safe React Query mutation wrapper around any MCP tool / RPC.
 *
 * Usage:
 *   const trigger = useMcpTool(McpToolService.callToolRunTrigger);
 *   trigger.mutate({ tool_id: "nuclei", target: "https://example.com" });
 *
 * A built-in 401 retry runs the request a second time after refreshing
 * the active session provider — see `withMcpAuthRetry()`.
 */
export function useMcpTool<TArgs, TResult>(
  call: McpToolCall<TArgs, TResult>,
  options?: UseMcpToolOptions<TArgs, TResult>,
): UseMcpToolResult<TArgs, TResult> {
  configureMcpClient();
  return useMutation<TResult, Error, TArgs>({
    ...options,
    mutationFn: async (args: TArgs) =>
      withMcpAuthRetry(() => Promise.resolve(call({ requestBody: args }))),
  });
}
