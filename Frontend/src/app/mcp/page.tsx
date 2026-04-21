import { NotEnabledNotice } from "@/components/mcp/NotEnabledNotice";
import { ToolRunnerClient } from "./ToolRunnerClient";
import { isMcpEnabled } from "./feature-flag";

/**
 * `/mcp` entry point. Server component — does the feature-flag check
 * before any client-side React Query / SDK work runs, so disabled tenants
 * never load the MCP bundle into their browsers.
 */
export default function McpPage() {
  if (!isMcpEnabled()) {
    return <NotEnabledNotice />;
  }
  return (
    <div className="mx-auto w-full max-w-7xl px-4 py-6">
      <ToolRunnerClient />
    </div>
  );
}
