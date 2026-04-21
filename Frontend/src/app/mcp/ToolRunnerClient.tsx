"use client";

import { useMemo, useState } from "react";
import type { RJSFSchema } from "@rjsf/utils";
import {
  McpResourceService,
  McpToolService,
  type ToolCatalogEntry,
  type ToolCatalogListResult,
  type ToolRiskLevel,
  type ToolRunTriggerInput,
  type ToolRunTriggerResult,
} from "@/services/mcp";
import { useMcpResource } from "@/services/mcp/hooks/useMcpResource";
import { useMcpTool } from "@/services/mcp/hooks/useMcpTool";
import { ToolForm } from "@/components/mcp/ToolForm";
import { ToolOutputView } from "@/components/mcp/ToolOutputView";

/**
 * The tool runner is intentionally schema-driven: every MCP tool exposed
 * via `tool.run.trigger` accepts the same envelope (`tool_id`, `target`,
 * optional `params`, optional `scan_id`, optional `justification`).
 *
 * We compose this schema once and reuse it for every selected tool. The
 * tool-specific `params` map is rendered as a free-form key/value JSON
 * object — operators can paste a structured payload here while still
 * benefiting from type-safe validation on the surrounding envelope.
 */
function buildTriggerSchema(tool: ToolCatalogEntry): RJSFSchema {
  return {
    type: "object",
    required: ["target"],
    properties: {
      tool_id: {
        type: "string",
        title: "Tool id",
        readOnly: true,
        default: tool.tool_id,
      },
      target: {
        type: "string",
        title: "Target",
        description:
          "Target to run against (URL, IP, hostname, or scoped identifier).",
        minLength: 1,
      },
      scan_id: {
        type: "string",
        title: "Scan id (optional)",
        description: "Bind this run to an existing scan.",
      },
      justification: {
        type: "string",
        title: "Justification",
        description:
          "Required for HIGH / DESTRUCTIVE tools. Recorded in the audit log.",
      },
      params: {
        type: "object",
        title: "Tool parameters (key/value JSON)",
        description:
          "Tool-specific overrides. Leave empty to use the catalog defaults.",
        additionalProperties: { type: "string" },
        default: {},
      },
    },
  };
}

const RISK_TONES: Record<ToolRiskLevel, string> = {
  passive: "border-[var(--success)] text-[var(--success)]",
  low: "border-[var(--success)] text-[var(--success)]",
  medium: "border-[var(--warning)] text-[var(--warning)]",
  high: "border-[var(--warning)] text-[var(--warning)]",
  destructive: "border-[var(--error)] text-[var(--error)]",
};

export function ToolRunnerClient() {
  const [selectedToolId, setSelectedToolId] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const catalogQuery = useMcpResource<ToolCatalogListResult>({
    uri: "/resources/catalog/tools",
    fetcher: () =>
      McpToolService.callToolCatalogList({
        requestBody: { payload: {} },
      }) as unknown as Promise<ToolCatalogListResult>,
    queryOptions: {
      staleTime: 60_000,
    },
  });

  const fallbackResource = useMcpResource<Record<string, unknown>>({
    uri: "/resources/catalog/tools.fallback",
    fetcher: () => McpResourceService.readArgusCatalogTools(),
    queryOptions: {
      enabled: catalogQuery.isError,
      staleTime: 60_000,
    },
  });

  const tools = useMemo<ReadonlyArray<ToolCatalogEntry>>(() => {
    if (catalogQuery.data?.items) {
      return catalogQuery.data.items;
    }
    if (catalogQuery.isError && fallbackResource.data) {
      const items = (fallbackResource.data as { items?: ToolCatalogEntry[] }).items;
      if (Array.isArray(items)) {
        return items;
      }
    }
    return [];
  }, [catalogQuery.data, catalogQuery.isError, fallbackResource.data]);

  const filteredTools = useMemo(() => {
    if (filter.trim().length === 0) {
      return tools;
    }
    const needle = filter.trim().toLowerCase();
    return tools.filter((tool) => {
      const haystack = [
        tool.tool_id,
        tool.category,
        tool.phase,
        tool.description ?? "",
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [tools, filter]);

  const selectedTool = useMemo<ToolCatalogEntry | null>(
    () => tools.find((tool) => tool.tool_id === selectedToolId) ?? null,
    [tools, selectedToolId],
  );

  const triggerSchema = useMemo<RJSFSchema | null>(
    () => (selectedTool === null ? null : buildTriggerSchema(selectedTool)),
    [selectedTool],
  );

  const triggerMutation = useMcpTool<
    ToolRunTriggerInput,
    ToolRunTriggerResult
  >((args) =>
    McpToolService.callToolRunTrigger({
      requestBody: { payload: args.requestBody },
    }),
  );

  const handleSubmit = (formData: Record<string, unknown>) => {
    if (selectedTool === null) {
      return;
    }
    const params = sanitiseParams(formData.params);
    const payload: ToolRunTriggerInput = {
      tool_id: selectedTool.tool_id,
      target: typeof formData.target === "string" ? formData.target : "",
      params,
      scan_id:
        typeof formData.scan_id === "string" && formData.scan_id.length > 0
          ? formData.scan_id
          : null,
      justification:
        typeof formData.justification === "string" &&
        formData.justification.length > 0
          ? formData.justification
          : null,
    };
    triggerMutation.mutate(payload);
  };

  const isLoadingCatalog = catalogQuery.isLoading || catalogQuery.isFetching;
  const catalogError = catalogQuery.isError
    ? catalogQuery.error?.message ?? "Failed to load tool catalog."
    : null;

  return (
    <div
      data-testid="mcp-tool-runner"
      className="grid grid-cols-1 gap-6 md:grid-cols-[18rem_1fr]"
    >
      <aside
        data-testid="mcp-tool-list"
        className="flex flex-col gap-3 rounded-md border border-[var(--border)] bg-[var(--bg-secondary)] p-3"
      >
        <header>
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">
            Tool catalog
          </h2>
          <p className="text-xs text-[var(--text-muted)]">
            {tools.length} tools · pulled from the signed registry
          </p>
        </header>
        <input
          type="search"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          placeholder="Filter by id, category, phase…"
          aria-label="Filter tools"
          data-testid="mcp-tool-list-filter"
          className="w-full rounded border border-[var(--border-light)] bg-[var(--bg-tertiary)] px-2 py-1.5 text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent)]"
        />
        {isLoadingCatalog ? (
          <p data-testid="mcp-tool-list-loading" className="text-xs text-[var(--text-muted)]">
            Loading tool catalog…
          </p>
        ) : catalogError ? (
          <p
            data-testid="mcp-tool-list-error"
            role="alert"
            className="text-xs text-[var(--error)]"
          >
            {catalogError}
          </p>
        ) : filteredTools.length === 0 ? (
          <p
            data-testid="mcp-tool-list-empty"
            className="rounded border border-dashed border-[var(--border-light)] px-3 py-6 text-center text-xs italic text-[var(--text-muted)]"
          >
            {tools.length === 0
              ? "No tools available — confirm your tenant has catalog access."
              : "No tools match the current filter."}
          </p>
        ) : (
          <ul className="flex flex-col gap-1 overflow-y-auto" role="listbox">
            {filteredTools.map((tool) => (
              <li key={tool.tool_id} role="option" aria-selected={selectedToolId === tool.tool_id}>
                <button
                  type="button"
                  data-testid="mcp-tool-list-item"
                  data-tool-id={tool.tool_id}
                  aria-pressed={selectedToolId === tool.tool_id}
                  onClick={() => setSelectedToolId(tool.tool_id)}
                  className={`flex w-full flex-col items-start rounded border px-2 py-1.5 text-left text-xs transition ${
                    selectedToolId === tool.tool_id
                      ? "border-[var(--accent)] bg-[var(--bg-tertiary)] text-[var(--text-primary)]"
                      : "border-[var(--border-light)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <span className="font-mono text-[0.75rem]">{tool.tool_id}</span>
                  <span className="text-[0.6875rem] text-[var(--text-muted)]">
                    {tool.category} · {tool.phase}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </aside>

      <section
        data-testid="mcp-tool-detail"
        className="flex flex-col gap-4 rounded-md border border-[var(--border)] bg-[var(--bg-secondary)] p-4"
      >
        {selectedTool === null || triggerSchema === null ? (
          <EmptyDetail isCatalogReady={!isLoadingCatalog && !catalogError} />
        ) : (
          <>
            <header className="flex flex-col gap-2 border-b border-[var(--border)] pb-3">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="font-mono text-base text-[var(--text-primary)]">
                  {selectedTool.tool_id}
                </h2>
                <span
                  data-testid="mcp-tool-risk-badge"
                  className={`rounded border px-1.5 py-0.5 text-[0.6875rem] uppercase tracking-wide ${RISK_TONES[selectedTool.risk_level]}`}
                >
                  {selectedTool.risk_level}
                </span>
                {selectedTool.requires_approval ? (
                  <span className="rounded border border-[var(--warning)] px-1.5 py-0.5 text-[0.6875rem] uppercase tracking-wide text-[var(--warning)]">
                    Approval required
                  </span>
                ) : null}
              </div>
              <p className="text-xs text-[var(--text-secondary)]">
                {selectedTool.description ?? "No description provided."}
              </p>
              <p className="text-[0.6875rem] uppercase tracking-wide text-[var(--text-muted)]">
                Category: {selectedTool.category} · Phase: {selectedTool.phase}
              </p>
            </header>

            <ToolForm
              schema={triggerSchema}
              initialFormData={{
                tool_id: selectedTool.tool_id,
                target: "",
                params: {},
              }}
              onSubmit={handleSubmit}
              disabled={triggerMutation.isPending}
              submitLabel={
                selectedTool.requires_approval
                  ? "Request approval"
                  : "Run tool"
              }
            />

            {triggerMutation.isError ? (
              <p
                role="alert"
                data-testid="mcp-tool-trigger-error"
                className="rounded border border-[var(--error)] bg-[var(--bg-tertiary)] px-3 py-2 text-xs text-[var(--error)]"
              >
                {triggerMutation.error?.message ??
                  "Failed to trigger the tool — check the audit log for details."}
              </p>
            ) : null}

            <ToolOutputView
              data={triggerMutation.data}
              title={
                triggerMutation.data
                  ? `Run result · ${(triggerMutation.data as ToolRunTriggerResult).status}`
                  : "Run result"
              }
            />
          </>
        )}
      </section>
    </div>
  );
}

function EmptyDetail({ isCatalogReady }: { isCatalogReady: boolean }) {
  return (
    <div
      data-testid="mcp-tool-detail-empty"
      className="flex flex-1 items-center justify-center px-4 py-12 text-center"
    >
      <div className="max-w-md">
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">
          {isCatalogReady ? "Pick a tool to begin" : "Loading catalog…"}
        </h2>
        <p className="mt-2 text-sm text-[var(--text-secondary)]">
          {isCatalogReady
            ? "Select a tool from the catalog on the left. The form is generated from the signed schema and validates inputs before contacting the MCP server."
            : "We are pulling the tool catalog from the MCP server. This usually takes less than a second."}
        </p>
      </div>
    </div>
  );
}

function sanitiseParams(input: unknown): Record<string, string> {
  if (input === null || input === undefined || typeof input !== "object") {
    return {};
  }
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (typeof value === "string") {
      out[key] = value;
    } else if (typeof value === "number" || typeof value === "boolean") {
      out[key] = String(value);
    }
  }
  return out;
}
