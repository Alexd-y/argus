"use client";

import {
  useMutation,
  type UseMutationOptions,
  type UseMutationResult,
} from "@tanstack/react-query";
import { configureMcpClient } from "../index";
import { withMcpAuthRetry } from "../auth";

/**
 * Shape of every prompt method on the auto-generated SDK:
 *   `({ requestBody }: { requestBody: TArgs }) => CancelablePromise<TResult>`
 */
export type McpPromptCall<TArgs, TResult> = (params: {
  requestBody: TArgs;
}) => PromiseLike<TResult>;

export type UseMcpPromptOptions<TArgs, TResult> = Omit<
  UseMutationOptions<TResult, Error, TArgs>,
  "mutationFn"
>;

export type UseMcpPromptResult<TArgs, TResult> = UseMutationResult<
  TResult,
  Error,
  TArgs
>;

/**
 * Type-safe React Query mutation wrapper for any MCP prompt render call
 * (e.g. `McpPromptService.renderRemediationAdvisor`).
 *
 * Returns the standard React Query mutation surface so consumers can
 * call `.mutate(args)` or `await prompt.mutateAsync(args)` and get the
 * rendered `Record<string, any>` payload back.
 */
export function useMcpPrompt<TArgs, TResult>(
  call: McpPromptCall<TArgs, TResult>,
  options?: UseMcpPromptOptions<TArgs, TResult>,
): UseMcpPromptResult<TArgs, TResult> {
  configureMcpClient();
  return useMutation<TResult, Error, TArgs>({
    ...options,
    mutationFn: async (args: TArgs) =>
      withMcpAuthRetry(() => Promise.resolve(call({ requestBody: args }))),
  });
}
