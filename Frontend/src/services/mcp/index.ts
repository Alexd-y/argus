/**
 * Public entry point for the MCP service layer.
 *
 * Re-exports the auto-generated `argus-mcp` SDK (services + models) and a
 * thin `getMcpClient()` helper. The SDK uses module-level singleton
 * configuration via `OpenAPI`, so calling `getMcpClient()` is technically
 * optional — but doing so once at the top of any module that touches MCP
 * keeps the dependency explicit and makes mocking trivial in tests.
 *
 * No raw `fetch()` calls live in this layer.
 */

import { OpenAPI } from "@/sdk/argus-mcp";
import {
  McpPromptService,
  McpResourceService,
  McpToolService,
} from "@/sdk/argus-mcp";
import { resolveMcpBearerToken, resolveMcpHeaders } from "./auth";

/** Default base URL when no environment override is provided. */
const DEFAULT_MCP_BASE_URL = "http://127.0.0.1:8000/mcp";

let configured = false;

/**
 * Configure the OpenAPI singleton. Idempotent — safe to call from every
 * hook constructor; subsequent calls are no-ops to avoid re-registering
 * the resolvers.
 */
export function configureMcpClient(options?: { baseUrl?: string }): void {
  if (configured) {
    return;
  }
  const baseUrl =
    options?.baseUrl ??
    process.env.NEXT_PUBLIC_MCP_BASE_URL ??
    DEFAULT_MCP_BASE_URL;

  OpenAPI.BASE = stripTrailingSlash(baseUrl);
  OpenAPI.WITH_CREDENTIALS = false;
  OpenAPI.CREDENTIALS = "include";
  OpenAPI.TOKEN = resolveMcpBearerToken;
  OpenAPI.HEADERS = resolveMcpHeaders;
  configured = true;
}

/** Reset configuration. Test-only — exposed via `__devOnly` namespace. */
export const __devOnly = {
  resetConfiguration(): void {
    configured = false;
    OpenAPI.BASE = "https://argus.example.com/mcp";
    OpenAPI.TOKEN = undefined;
    OpenAPI.HEADERS = undefined;
  },
};

/**
 * Bundle of typed service clients. The `argus-mcp` SDK exposes static
 * classes; we surface them through an object so callers can destructure
 * (`const { tools } = getMcpClient()`) without colliding identifiers.
 */
export interface McpClient {
  tools: typeof McpToolService;
  resources: typeof McpResourceService;
  prompts: typeof McpPromptService;
}

/**
 * Lazy-initialise the OpenAPI config and return the typed service bundle.
 * Always prefer this over importing the SDK services directly so the
 * singleton is set up before any RPC fires.
 */
export function getMcpClient(): McpClient {
  configureMcpClient();
  return {
    tools: McpToolService,
    resources: McpResourceService,
    prompts: McpPromptService,
  };
}

export {
  ApiError,
  CancelablePromise,
  CancelError,
  McpPromptService,
  McpResourceService,
  McpToolService,
  OpenAPI,
} from "@/sdk/argus-mcp";

export type * from "@/sdk/argus-mcp";

function stripTrailingSlash(value: string): string {
  if (value.length === 0) {
    return value;
  }
  return value.endsWith("/") ? value.slice(0, -1) : value;
}
