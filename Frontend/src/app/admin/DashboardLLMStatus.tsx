"use client";

import { useEffect, useState, useTransition } from "react";
import Link from "next/link";
import { getLlmRuntimeSummary, type LlmRuntimeSummary } from "./dashboard-actions";

const providerLabels: Record<string, string> = {
  openai: "OpenAI",
  deepseek: "DeepSeek",
  openrouter: "OpenRouter",
  google: "Google AI",
  kimi: "Kimi",
  perplexity: "Perplexity",
  whiterabbitneo: "WhiteRabbitNeo",
};

export function DashboardLLMStatus() {
  const [summary, setSummary] = useState<LlmRuntimeSummary | null>(null);
  const [error, setError] = useState("");
  const [pending, startTransition] = useTransition();

  useEffect(() => {
    startTransition(async () => {
      try {
        const data = await getLlmRuntimeSummary();
        setSummary(data);
        setError("");
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load LLM status");
      }
    });
  }, []);

  const providers = summary?.global_env_providers ?? {};

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--text-primary)]">
          LLM Providers
        </h2>
        <Link
          href="/admin/llm"
          className="text-xs text-[var(--accent)] hover:underline"
        >
          Configure
        </Link>
      </div>
      {error && (
        <div role="alert" className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </div>
      )}
      {pending && !summary ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-6 animate-pulse rounded bg-[var(--bg-tertiary)]" />
          ))}
        </div>
      ) : Object.keys(providers).length === 0 ? (
        <div className="py-4 text-center text-sm text-[var(--text-muted)]">
          No LLM providers configured
        </div>
      ) : (
        <div className="space-y-2">
          {Object.entries(providers).map(([key, configured]) => (
            <div key={key} className="flex items-center justify-between">
              <span className="text-sm text-[var(--text-secondary)]">
                {providerLabels[key] ?? key}
              </span>
              <span
                className={
                  configured
                    ? "rounded bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-400"
                    : "rounded bg-red-500/10 px-2 py-0.5 text-xs text-red-400"
                }
              >
                {configured ? "Configured" : "Not set"}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}