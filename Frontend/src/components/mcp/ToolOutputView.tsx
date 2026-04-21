"use client";

import { useCallback, useMemo, useState } from "react";
import { JsonView, allExpanded, darkStyles } from "react-json-view-lite";
import "react-json-view-lite/dist/index.css";

export type ToolOutputMode = "tree" | "json";

export interface ToolOutputViewProps {
  /** Structured output from a successful MCP tool / RPC. */
  data: unknown;
  /** Optional title displayed above the viewer. */
  title?: string;
  /** Initial display mode (defaults to "tree"). */
  defaultMode?: ToolOutputMode;
  /** Disable the copy-to-clipboard button (useful in embedded/SSR previews). */
  disableCopy?: boolean;
}

/**
 * Renders structured tool output as either an expandable JSON tree
 * (`react-json-view-lite`) or a syntax-highlighted JSON code block.
 *
 * Outputs are typically `Record<string, any>` from the MCP SDK, but the
 * component accepts arbitrary unknown payloads — primitives are wrapped
 * in `{ value: … }` so the tree always has a stable root.
 */
export function ToolOutputView({
  data,
  title,
  defaultMode = "tree",
  disableCopy = false,
}: ToolOutputViewProps) {
  const [mode, setMode] = useState<ToolOutputMode>(defaultMode);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");

  const treeData = useMemo(() => normalizeForTree(data), [data]);
  const formattedJson = useMemo(() => safeStringify(data), [data]);

  const handleCopy = useCallback(async () => {
    if (
      typeof navigator === "undefined" ||
      typeof navigator.clipboard === "undefined"
    ) {
      setCopyState("error");
      return;
    }
    try {
      await navigator.clipboard.writeText(formattedJson);
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1_500);
    } catch {
      setCopyState("error");
    }
  }, [formattedJson]);

  const isEmpty = data === null || data === undefined;

  return (
    <section
      data-testid="mcp-tool-output"
      className="rounded-md border border-[var(--border)] bg-[var(--bg-secondary)]"
    >
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] px-3 py-2">
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">
          {title ?? "Output"}
        </h3>
        <div className="flex items-center gap-2">
          <ModeToggle mode={mode} onChange={setMode} />
          {!disableCopy ? (
            <button
              type="button"
              onClick={handleCopy}
              data-testid="mcp-tool-output-copy"
              className="rounded border border-[var(--border-light)] px-2 py-1 text-xs text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              {copyState === "copied"
                ? "Copied"
                : copyState === "error"
                  ? "Copy failed"
                  : "Copy JSON"}
            </button>
          ) : null}
        </div>
      </header>
      <div className="px-3 py-2 text-sm text-[var(--text-secondary)]">
        {isEmpty ? (
          <p data-testid="mcp-tool-output-empty" className="italic">
            No output yet — run the tool to see its response.
          </p>
        ) : mode === "tree" ? (
          <div data-testid="mcp-tool-output-tree">
            <JsonView
              data={treeData}
              style={darkStyles}
              shouldExpandNode={allExpanded}
            />
          </div>
        ) : (
          <pre
            data-testid="mcp-tool-output-json"
            className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded bg-[var(--bg-tertiary)] p-3 font-mono text-xs text-[var(--text-primary)]"
          >
            {formattedJson}
          </pre>
        )}
      </div>
    </section>
  );
}

function ModeToggle({
  mode,
  onChange,
}: {
  mode: ToolOutputMode;
  onChange: (next: ToolOutputMode) => void;
}) {
  return (
    <div
      role="tablist"
      aria-label="Output view mode"
      className="inline-flex overflow-hidden rounded border border-[var(--border-light)] text-xs"
    >
      <ModeButton
        label="Tree"
        active={mode === "tree"}
        onClick={() => onChange("tree")}
        testId="mcp-tool-output-mode-tree"
      />
      <ModeButton
        label="JSON"
        active={mode === "json"}
        onClick={() => onChange("json")}
        testId="mcp-tool-output-mode-json"
      />
    </div>
  );
}

function ModeButton({
  label,
  active,
  onClick,
  testId,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  testId: string;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      data-testid={testId}
      onClick={onClick}
      className={`px-2 py-1 transition ${
        active
          ? "bg-[var(--accent)] text-white"
          : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
      }`}
    >
      {label}
    </button>
  );
}

function normalizeForTree(value: unknown): object {
  if (value === null || value === undefined) {
    return { value: null };
  }
  if (typeof value === "object" && !Array.isArray(value)) {
    return value as object;
  }
  if (Array.isArray(value)) {
    return { items: value };
  }
  return { value };
}

function safeStringify(value: unknown): string {
  if (value === undefined) {
    return "undefined";
  }
  try {
    return JSON.stringify(value, replaceCircular(), 2);
  } catch {
    return String(value);
  }
}

function replaceCircular(): (key: string, value: unknown) => unknown {
  const seen = new WeakSet<object>();
  return (_key, value) => {
    if (typeof value === "object" && value !== null) {
      if (seen.has(value as object)) {
        return "[Circular]";
      }
      seen.add(value as object);
    }
    return value;
  };
}
