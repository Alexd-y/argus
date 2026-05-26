"use client";

import { useCallback, useEffect, useId, useMemo, useState, useTransition } from "react";

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { getSafeErrorMessage } from "@/lib/api";
import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import {
  createLlmProviderRow,
  getLlmRuntimeSummary,
  listLlmProvidersForTenant,
  patchLlmProvider,
  type AdminLlmProviderRow,
  type LlmRuntimeSummary,
} from "./actions";

const ADDABLE_PROVIDER_KEYS = [
  "openai",
  "deepseek",
  "openrouter",
  "kimi",
  "perplexity",
  "google",
  "anthropic",
] as const;

type ProviderKey = (typeof ADDABLE_PROVIDER_KEYS)[number];

const PROVIDER_INFO: Record<ProviderKey, { name: string; desc: string; models: string }> = {
  openai: { name: "OpenAI", desc: "GPT-4o, GPT-4o-mini, o1, o3 and more", models: "gpt-4o-mini, gpt-4o, o1-mini, o3-mini" },
  deepseek: { name: "DeepSeek", desc: "DeepSeek-V3, DeepSeek-Reasoner", models: "deepseek-chat, deepseek-reasoner" },
  openrouter: { name: "OpenRouter", desc: "Multi-model gateway (OpenAI, Anthropic, Google, Mistral, Llama)", models: "openai/gpt-4o-mini, anthropic/claude-3.5-sonnet, google/gemini-pro" },
  kimi: { name: "Kimi (Moonshot)", desc: "Moonshot AI models with long context", models: "moonshot-v1-8k, moonshot-v1-32k" },
  perplexity: { name: "Perplexity", desc: "Real-time search-augmented answers", models: "sonar, sonar-pro" },
  google: { name: "Google (Gemini)", desc: "Gemini 1.5 Flash, Gemini 1.5 Pro", models: "gemini-1.5-flash, gemini-1.5-pro" },
  anthropic: { name: "Anthropic (Claude)", desc: "Claude 3.5 Sonnet, Claude 3 Opus, Haiku", models: "claude-3-5-sonnet-20241022, claude-3-opus-20240229" },
};

function errMsg(e: unknown): string {
  return getSafeErrorMessage(e, "Operation failed.");
}

function formatKeyDisplay(row: AdminLlmProviderRow): string {
  if (!row.api_key_set) return "\u2014";
  if (row.api_key_last4) return `***${row.api_key_last4}`;
  return "***";
}

type ProviderStats = {
  enabled: number;
  disabled: number;
  withKey: number;
  total: number;
};

function ProviderStatCards({ stats, isLoading }: { stats: ProviderStats; isLoading: boolean }) {
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <div className="rounded-lg border border-[var(--border)] border-l-4 border-l-[var(--accent)] bg-[var(--bg-secondary)] p-4">
        <div className="text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">Total</div>
        {isLoading ? (
          <div className="mt-2 h-8 w-16 animate-pulse rounded bg-[var(--bg-tertiary)]" />
        ) : (
          <div className="mt-2 text-2xl font-bold text-[var(--text-primary)]">{stats.total}</div>
        )}
        <div className="mt-1 text-xs text-[var(--text-secondary)]">providers</div>
      </div>
      <div className="rounded-lg border border-[var(--border)] border-l-4 border-l-emerald-500 bg-[var(--bg-secondary)] p-4">
        <div className="text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">Active</div>
        {isLoading ? (
          <div className="mt-2 h-8 w-16 animate-pulse rounded bg-[var(--bg-tertiary)]" />
        ) : (
          <div className="mt-2 text-2xl font-bold text-[var(--text-primary)]">{stats.enabled}</div>
        )}
        <div className="mt-1 text-xs text-[var(--text-secondary)]">enabled</div>
      </div>
      <div className="rounded-lg border border-[var(--border)] border-l-4 border-l-zinc-500 bg-[var(--bg-secondary)] p-4">
        <div className="text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">Disabled</div>
        {isLoading ? (
          <div className="mt-2 h-8 w-16 animate-pulse rounded bg-[var(--bg-tertiary)]" />
        ) : (
          <div className="mt-2 text-2xl font-bold text-[var(--text-primary)]">{stats.disabled}</div>
        )}
        <div className="mt-1 text-xs text-[var(--text-secondary)]">disabled</div>
      </div>
      <div className="rounded-lg border border-[var(--border)] border-l-4 border-l-amber-500 bg-[var(--bg-secondary)] p-4">
        <div className="text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">With Key</div>
        {isLoading ? (
          <div className="mt-2 h-8 w-16 animate-pulse rounded bg-[var(--bg-tertiary)]" />
        ) : (
          <div className="mt-2 text-2xl font-bold text-[var(--text-primary)]">{stats.withKey}</div>
        )}
        <div className="mt-1 text-xs text-[var(--text-secondary)]">API key set</div>
      </div>
    </div>
  );
}

function ProviderRow({
  row,
  busy,
  onToggle,
  onEdit,
}: {
  row: AdminLlmProviderRow;
  busy: boolean;
  onToggle: (r: AdminLlmProviderRow) => void;
  onEdit: (r: AdminLlmProviderRow) => void;
}) {
  const info = PROVIDER_INFO[row.provider_key as ProviderKey];
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <div className="flex items-start gap-3">
        <div className="flex flex-col gap-0.5 min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span
              className={`inline-block size-2.5 rounded-full ${row.enabled ? "bg-emerald-400" : "bg-zinc-500"}`}
              aria-hidden="true"
            />
            <span className="font-medium text-[var(--text-primary)]">
              {info?.name ?? row.provider_key}
            </span>
            <span className="text-xs text-[var(--text-muted)]">{row.provider_key}</span>
            <span
              className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${
                row.enabled
                  ? "border border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                  : "border border-zinc-500/30 bg-zinc-500/10 text-zinc-400"
              }`}
            >
              {row.enabled ? "Active" : "Disabled"}
            </span>
          </div>
          {info ? (
            <p className="mt-0.5 text-xs text-[var(--text-muted)]">{info.desc}</p>
          ) : null}
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-[var(--text-muted)]">
            <span>API key: {formatKeyDisplay(row)}</span>
            {row.model_fallback_chain && row.model_fallback_chain.length > 0 ? (
              <span>Models: {row.model_fallback_chain.join(" \u2192 ")}</span>
            ) : (
              <span>Models: default</span>
            )}
          </div>
          <div className="mt-1 text-[10px] text-[var(--text-muted)]">
            ID: {row.id.slice(0, 8)}\u2026
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-tertiary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
            disabled={busy}
            onClick={() => onToggle(row)}
          >
            {row.enabled ? "Disable" : "Enable"}
          </button>
          <button
            type="button"
            className="rounded border border-[var(--accent)]/40 bg-[var(--accent)]/10 px-3 py-1.5 text-xs font-medium text-[var(--accent)] transition-colors hover:bg-[var(--accent)]/20 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
            disabled={busy}
            onClick={() => onEdit(row)}
          >
            Edit
          </button>
        </div>
      </div>
    </div>
  );
}

function AdminLlmBody() {
  const [isPending, startTransition] = useTransition();
  const tenantSelectId = useId();

  const [tenants, setTenants] = useState<AdminTenant[]>([]);
  const [tenantId, setTenantId] = useState<string>("");
  const [runtime, setRuntime] = useState<LlmRuntimeSummary | null>(null);
  const [rows, setRows] = useState<AdminLlmProviderRow[]>([]);
  const [listError, setListError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [newKey, setNewKey] = useState<string>(ADDABLE_PROVIDER_KEYS[0]);
  const [editKey, setEditKey] = useState<string>("");
  const [editFallback, setEditFallback] = useState<string>("");
  const [editingId, setEditingId] = useState<string | null>(null);

  const providerStats = useMemo<ProviderStats>(() => {
    const enabled = rows.filter((r) => r.enabled).length;
    const withKey = rows.filter((r) => r.api_key_set).length;
    return {
      enabled,
      disabled: rows.length - enabled,
      withKey,
      total: rows.length,
    };
  }, [rows]);

  const loadTenants = useCallback(() => {
    startTransition(async () => {
      try {
        const t = await listTenants({ limit: 200, offset: 0 });
        setTenants(t);
        setTenantId((cur) => {
          if (cur && t.some((x) => x.id === cur)) return cur;
          return t[0]?.id ?? "";
        });
      } catch (e) {
        setListError(errMsg(e));
        setTenants([]);
      }
    });
  }, []);

  const loadRuntime = useCallback(() => {
    startTransition(async () => {
      try {
        const result = await getLlmRuntimeSummary();
        setRuntime(result);
      } catch {
        setRuntime(null);
      }
    });
  }, []);

  const refreshProviders = useCallback(() => {
    if (!tenantId.trim()) {
      setRows([]);
      return;
    }
    setListError(null);
    startTransition(async () => {
      try {
        setRows(await listLlmProvidersForTenant(tenantId.trim()));
      } catch (e) {
        setListError(errMsg(e));
        setRows([]);
      }
    });
  }, [tenantId]);

  useEffect(() => {
    loadTenants();
    loadRuntime();
  }, [loadTenants, loadRuntime]);

  useEffect(() => {
    refreshProviders();
  }, [refreshProviders]);

  const openEdit = (r: AdminLlmProviderRow) => {
    setActionError(null);
    setEditingId(r.id);
    setEditKey("");
    setEditFallback((r.model_fallback_chain ?? []).join(", "));
  };

  const closeEdit = () => {
    setEditingId(null);
    setEditKey("");
    setEditFallback("");
  };

  const saveEdit = () => {
    if (!editingId) return;
    setActionError(null);
    const raw = editFallback.trim();
    let chain: string[] | null;
    if (!raw) {
      chain = [];
    } else {
      chain = raw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    }
    setBusyId(editingId);
    startTransition(async () => {
      try {
        await patchLlmProvider({
          providerId: editingId,
          apiKey: editKey.trim() ? editKey : undefined,
          modelFallbackChain: chain,
        });
        closeEdit();
        refreshProviders();
      } catch (e) {
        setActionError(errMsg(e));
      } finally {
        setBusyId(null);
      }
    });
  };

  const toggleEnabled = (r: AdminLlmProviderRow) => {
    setActionError(null);
    setBusyId(r.id);
    startTransition(async () => {
      try {
        await patchLlmProvider({ providerId: r.id, enabled: !r.enabled });
        refreshProviders();
      } catch (e) {
        setActionError(errMsg(e));
      } finally {
        setBusyId(null);
      }
    });
  };

  const addProvider = () => {
    if (!tenantId.trim()) return;
    setActionError(null);
    setBusyId("__add__");
    startTransition(async () => {
      try {
        await createLlmProviderRow({ tenantId: tenantId.trim(), providerKey: newKey });
        refreshProviders();
      } catch (e) {
        setActionError(errMsg(e));
      } finally {
        setBusyId(null);
      }
    });
  };

  const missingKeys = useMemo(
    () =>
      ADDABLE_PROVIDER_KEYS.filter(
        (k) => !rows.some((r) => r.provider_key.toLowerCase() === k),
      ),
    [rows],
  );

  useEffect(() => {
    if (missingKeys.length === 0) return;
    const ok = missingKeys.some((k) => k === newKey);
    if (!ok) setNewKey(missingKeys[0]);
  }, [missingKeys, newKey]);

  const editingRow = editingId ? rows.find((r) => r.id === editingId) : null;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-lg font-semibold text-[var(--text-primary)]">Cloud Providers</h1>
        <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
          Per-tenant LLM provider configuration. Toggle providers on/off, set API keys, and configure model fallback chains for pentest operations.
        </p>
      </header>

      {runtime?.execution_uses_global_env ? (
        <div
          className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-[var(--text-secondary)]"
          role="status"
        >
          <span className="font-medium text-[var(--text-primary)]">Runtime note:</span>{" "}
          The orchestration stack currently resolves LLM calls from{" "}
          <span className="text-[var(--text-primary)]">global environment variables</span>.
          Per-tenant keys stored here are persisted for upcoming tenant-scoped routing.
        </div>
      ) : null}

      {!tenantId && !isPending && tenants.length === 0 ? (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] px-6 py-12 text-center">
          <div className="flex size-12 items-center justify-center rounded-full bg-[var(--bg-tertiary)]">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-[var(--text-muted)]">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
            </svg>
          </div>
          <h3 className="text-sm font-medium text-[var(--text-primary)]">
            {listError ? "Cannot load tenants" : "No tenants found"}
          </h3>
          <p className="max-w-sm text-xs text-[var(--text-muted)]">
            {listError
              ? "The backend is unreachable. Check your ADMIN_API_KEY configuration and backend connectivity."
              : "Create a tenant first, then configure LLM providers for it."}
          </p>
          {listError ? (
            <button
              type="button"
              className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-tertiary)]"
              onClick={loadTenants}
            >
              Retry
            </button>
          ) : null}
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-end gap-3 rounded-lg border border-[var(--border-light)] bg-[var(--bg-secondary)] px-4 py-3">
            <div className="min-w-[12rem] flex-1">
              <label className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]" htmlFor={tenantSelectId}>
                Tenant
              </label>
              <select
                id={tenantSelectId}
                className="mt-1 w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                disabled={isPending && tenants.length === 0}
              >
                {tenants.length === 0 ? <option value="">Loading\u2026</option> : null}
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.id.slice(0, 8)}\u2026)
                  </option>
                ))}
              </select>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <select
                className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
                value={missingKeys.length === 0 ? "" : newKey}
                onChange={(e) => setNewKey(e.target.value)}
                disabled={!tenantId || missingKeys.length === 0}
              >
                {missingKeys.length === 0 ? (
                  <option value="">All providers added</option>
                ) : (
                  missingKeys.map((k) => (
                    <option key={k} value={k}>
                      {PROVIDER_INFO[k]?.name ?? k}
                    </option>
                  ))
                )}
              </select>
              <button
                type="button"
                className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-[var(--on-accent)] transition-colors hover:bg-[var(--accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"
                disabled={!tenantId || missingKeys.length === 0 || busyId !== null}
                onClick={addProvider}
              >
                Add provider
              </button>
            </div>
          </div>

          {listError ? (
            <div className="rounded-lg border border-red-500/30 bg-red-950/30 px-4 py-2 text-sm text-red-200" role="alert">
              {listError}
            </div>
          ) : null}
          {actionError ? (
            <div className="rounded-lg border border-red-500/30 bg-red-950/30 px-4 py-2 text-sm text-red-200" role="alert">
              {actionError}
            </div>
          ) : null}

          <ProviderStatCards stats={providerStats} isLoading={isPending && rows.length === 0} />

          {rows.length === 0 && !isPending && tenantId ? (
            <div className="rounded-lg border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] p-6">
              <h3 className="text-sm font-medium text-[var(--text-primary)]">Add your first provider</h3>
              <p className="mt-1 text-xs text-[var(--text-muted)]">
                Select a provider from the dropdown above to configure LLM access. Each provider can have an API key and a model fallback chain.
              </p>
              <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {ADDABLE_PROVIDER_KEYS.map((k) => {
                  const info = PROVIDER_INFO[k];
                  return (
                    <button
                      key={k}
                      type="button"
                      className="flex flex-col gap-0.5 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3 text-left transition-colors hover:bg-[var(--bg-tertiary)] disabled:opacity-50"
                      disabled={busyId !== null || !tenantId}
                      onClick={() => {
                        setNewKey(k);
                        if (tenantId) {
                          setActionError(null);
                          setBusyId("__add__");
                          startTransition(async () => {
                            try {
                              await createLlmProviderRow({ tenantId: tenantId.trim(), providerKey: k });
                              refreshProviders();
                            } catch (e) {
                              setActionError(errMsg(e));
                            } finally {
                              setBusyId(null);
                            }
                          });
                        }
                      }}
                    >
                      <span className="text-sm font-medium text-[var(--text-primary)]">{info.name}</span>
                      <span className="text-[10px] text-[var(--text-muted)]">{info.desc}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          ) : rows.length === 0 && !isPending ? null : (
            <div className="space-y-3">
              {rows.map((r) => (
                <ProviderRow
                  key={r.id}
                  row={r}
                  busy={busyId !== null}
                  onToggle={toggleEnabled}
                  onEdit={openEdit}
                />
              ))}
            </div>
          )}

          {runtime ? (
            <details className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
              <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                Global env providers (process-level)
              </summary>
              <div className="border-t border-[var(--border)] px-4 py-3">
                <ul className="grid gap-1 sm:grid-cols-2 md:grid-cols-3">
                  {Object.entries(runtime.global_env_providers).map(([k, on]) => (
                    <li key={k} className="flex items-center gap-2 text-xs">
                      <span className={`inline-block size-2 rounded-full ${on ? "bg-emerald-400" : "bg-zinc-500"}`} />
                      <span className="text-[var(--text-primary)]">{PROVIDER_INFO[k as ProviderKey]?.name ?? k}</span>
                      <span className="text-[var(--text-muted)]">{on ? "configured" : "not set"}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </details>
          ) : null}
        </>
      )}

      {editingRow ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-md rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-6 shadow-lg">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              Edit {PROVIDER_INFO[editingRow.provider_key as ProviderKey]?.name ?? editingRow.provider_key} provider
            </h2>
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              Leave API key blank to keep the current secret. Use comma-separated model IDs for the fallback chain (empty clears the chain).
            </p>
            {PROVIDER_INFO[editingRow.provider_key as ProviderKey] ? (
              <p className="mt-2 text-xs text-[var(--text-muted)]">
                Suggested models: {PROVIDER_INFO[editingRow.provider_key as ProviderKey].models}
              </p>
            ) : null}
            <label className="mt-4 block text-xs text-[var(--text-muted)]">
              New API key (optional)
              <input
                type="password"
                autoComplete="off"
                className="mt-1 w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
                value={editKey}
                onChange={(e) => setEditKey(e.target.value)}
              />
            </label>
            <label className="mt-3 block text-xs text-[var(--text-muted)]">
              Model fallback chain (comma-separated)
              <input
                className="mt-1 w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
                value={editFallback}
                onChange={(e) => setEditFallback(e.target.value)}
                placeholder="gpt-4o-mini, gpt-4o"
              />
            </label>
            <div className="mt-4 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                className="rounded border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs text-red-200 transition-colors hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                disabled={busyId !== null}
                onClick={() => {
                  if (!editingId) return;
                  setActionError(null);
                  setBusyId(editingId);
                  startTransition(async () => {
                    try {
                      await patchLlmProvider({ providerId: editingId, apiKey: "" });
                      closeEdit();
                      refreshProviders();
                    } catch (e) {
                      setActionError(errMsg(e));
                    } finally {
                      setBusyId(null);
                    }
                  });
                }}
              >
                Remove API key
              </button>
              <button
                type="button"
                className="rounded border border-[var(--border)] px-3 py-1.5 text-sm text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-tertiary)]"
                onClick={closeEdit}
                disabled={busyId !== null}
              >
                Cancel
              </button>
              <button
                type="button"
                className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-[var(--on-accent)] transition-colors hover:bg-[var(--accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"
                onClick={saveEdit}
                disabled={busyId !== null}
              >
                Save
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function AdminLlmClient() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <AdminLlmBody />
    </AdminRouteGuard>
  );
}