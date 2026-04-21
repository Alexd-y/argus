"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useId, useState, useTransition } from "react";

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { getSafeErrorMessage } from "@/lib/api";

import {
  createScopeTarget,
  deleteScopeTarget,
  previewScope,
  updateScopeTarget,
  type AdminScopeTarget,
  type PreviewScopeResult,
} from "./actions";

const DEFAULT_RULES_JSON = '{\n  "rules": []\n}';

const SCOPE_FAIL_LABEL: Record<string, string> = {
  target_not_in_scope: "Target is not allowed by the current rules.",
  target_explicitly_denied: "Target matches a deny rule.",
  target_port_not_allowed: "Port is not allowed for the matching rule.",
  scope_rule_malformed: "A scope rule is malformed.",
};

function formatScopeFailure(code: string | null): string | null {
  if (!code) return null;
  return SCOPE_FAIL_LABEL[code] ?? "Target is not allowed.";
}

function actionErr(err: unknown): string {
  return getSafeErrorMessage(err, "Something went wrong. Please try again.");
}

function parseRulesJson(raw: string): { rules: Record<string, unknown>[] } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Scope rules must be valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error('Scope rules JSON must be an object with a "rules" array.');
  }
  const rules = (parsed as { rules?: unknown }).rules;
  if (!Array.isArray(rules)) {
    throw new Error('Scope rules JSON must include a "rules" array.');
  }
  return { rules: rules as Record<string, unknown>[] };
}

function ownershipHint(o: AdminScopeTarget["ownership_proof"]): string {
  if (o.policy_requires_proof === true) return "Policy requires proof";
  if (o.policy_requires_proof === false) return "Policy does not require proof";
  return "—";
}

type Props = {
  tenantId: string;
  tenantName: string;
  initialTargets: AdminScopeTarget[];
};

export function TenantScopesClient({
  tenantId,
  tenantName,
  initialTargets,
}: Props) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [targets, setTargets] = useState(initialTargets);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [newUrl, setNewUrl] = useState("https://");
  const [newRulesJson, setNewRulesJson] = useState(DEFAULT_RULES_JSON);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editUrl, setEditUrl] = useState("");
  const [editRulesJson, setEditRulesJson] = useState(DEFAULT_RULES_JSON);

  const [previewProbe, setPreviewProbe] = useState("https://");
  const [previewPort, setPreviewPort] = useState("");
  const [previewRulesJson, setPreviewRulesJson] = useState(DEFAULT_RULES_JSON);
  const [previewDns, setPreviewDns] = useState("");
  const [previewCidr, setPreviewCidr] = useState("");
  const [previewResult, setPreviewResult] = useState<PreviewScopeResult | null>(
    null,
  );

  useEffect(() => {
    setTargets(initialTargets);
  }, [initialTargets]);

  const formNewUrlId = useId();
  const formNewRulesId = useId();
  const prevProbeId = useId();
  const prevPortId = useId();
  const prevRulesId = useId();
  const prevDnsId = useId();
  const prevCidrId = useId();

  const inputClass =
    "mt-1 w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-secondary)]";

  const applyList = useCallback((next: AdminScopeTarget[]) => {
    setTargets(next);
  }, []);

  const refresh = useCallback(() => {
    router.refresh();
  }, [router]);

  const addTarget = () => {
    setError(null);
    setMessage(null);
    let scope_config: { rules: Record<string, unknown>[] };
    try {
      scope_config = parseRulesJson(newRulesJson);
    } catch (e) {
      setError(e instanceof Error ? e.message : actionErr(e));
      return;
    }
    const url = newUrl.trim();
    if (!url) {
      setError("URL is required.");
      return;
    }
    startTransition(async () => {
      try {
        const row = await createScopeTarget(tenantId, {
          url,
          scope_config,
        });
        applyList([row, ...targets]);
        setMessage("Target added.");
        setNewUrl("https://");
        setNewRulesJson(DEFAULT_RULES_JSON);
        refresh();
      } catch (e) {
        setError(actionErr(e));
      }
    });
  };

  const startEdit = (t: AdminScopeTarget) => {
    setEditingId(t.id);
    setEditUrl(t.url);
    setEditRulesJson(
      JSON.stringify(
        t.scope_config ?? { rules: [] },
        null,
        2,
      ),
    );
    setError(null);
    setMessage(null);
  };

  const saveEdit = () => {
    if (!editingId) return;
    setError(null);
    setMessage(null);
    let scope_config: { rules: Record<string, unknown>[] };
    try {
      scope_config = parseRulesJson(editRulesJson);
    } catch (e) {
      setError(e instanceof Error ? e.message : actionErr(e));
      return;
    }
    const url = editUrl.trim();
    if (!url) {
      setError("URL is required.");
      return;
    }
    startTransition(async () => {
      try {
        const row = await updateScopeTarget(tenantId, editingId, {
          url,
          scope_config,
        });
        applyList(targets.map((x) => (x.id === row.id ? row : x)));
        setEditingId(null);
        setMessage("Target updated.");
        refresh();
      } catch (e) {
        setError(actionErr(e));
      }
    });
  };

  const removeTarget = (id: string) => {
    if (!globalThis.confirm("Delete this target?")) return;
    setError(null);
    setMessage(null);
    startTransition(async () => {
      try {
        await deleteScopeTarget(tenantId, id);
        applyList(targets.filter((x) => x.id !== id));
        setMessage("Target deleted.");
        if (editingId === id) setEditingId(null);
        refresh();
      } catch (e) {
        setError(actionErr(e));
      }
    });
  };

  const runPreview = () => {
    setError(null);
    setMessage(null);
    let rules: Record<string, unknown>[];
    try {
      rules = parseRulesJson(previewRulesJson).rules;
    } catch (e) {
      setError(e instanceof Error ? e.message : actionErr(e));
      return;
    }
    const probe = previewProbe.trim();
    if (!probe) {
      setError("Probe is required for preview.");
      return;
    }
    let port: number | null | undefined;
    const pr = previewPort.trim();
    if (pr !== "") {
      const n = Number(pr);
      if (!Number.isInteger(n) || n < 1 || n > 65_535) {
        setError("Port must be between 1 and 65535 or empty.");
        return;
      }
      port = n;
    }
    startTransition(async () => {
      try {
        const res = await previewScope(tenantId, {
          probe,
          rules,
          port: port ?? null,
          dns_hostname: previewDns.trim() || null,
          cidr: previewCidr.trim() || null,
        });
        setPreviewResult(res);
        setMessage("Preview completed.");
      } catch (e) {
        setPreviewResult(null);
        setError(actionErr(e));
      }
    });
  };

  return (
    <AdminRouteGuard minimumRole="admin">
      <div className="space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold text-[var(--text-primary)]">
              Scopes
            </h1>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              <span className="font-medium text-[var(--text-primary)]">
                {tenantName}
              </span>
              <span className="mx-2 text-[var(--text-muted)]">·</span>
              <span className="font-mono text-xs text-[var(--text-muted)]">
                {tenantId}
              </span>
            </p>
          </div>
          <div className="flex flex-wrap gap-3 text-sm">
            <Link
              href={`/admin/tenants/${encodeURIComponent(tenantId)}/settings`}
              className="text-[var(--accent)] hover:underline focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none rounded px-1"
            >
              Tenant limits
            </Link>
            <Link
              href="/admin/tenants"
              className="text-[var(--accent)] hover:underline focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none rounded px-1"
            >
              ← All tenants
            </Link>
          </div>
        </div>

        {message ? (
          <div
            role="status"
            className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]"
          >
            {message}
          </div>
        ) : null}
        {error ? (
          <div
            role="alert"
            className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]"
          >
            {error}
          </div>
        ) : null}

        <section className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4 space-y-3">
          <h2 className="text-base font-medium text-[var(--text-primary)]">
            Add target
          </h2>
          <p className="text-sm text-[var(--text-muted)]">
            Each target has a primary URL and an optional JSON scope rule set
            (<span className="font-mono">rules</span> array; see backend{" "}
            <span className="font-mono">ScopeRule</span>).
          </p>
          <div>
            <label htmlFor={formNewUrlId} className="text-sm text-[var(--text-secondary)]">
              URL
            </label>
            <input
              id={formNewUrlId}
              value={newUrl}
              onChange={(e) => setNewUrl(e.target.value)}
              className={inputClass}
              autoComplete="off"
            />
          </div>
          <div>
            <label htmlFor={formNewRulesId} className="text-sm text-[var(--text-secondary)]">
              Scope JSON
            </label>
            <textarea
              id={formNewRulesId}
              rows={10}
              value={newRulesJson}
              onChange={(e) => setNewRulesJson(e.target.value)}
              className={`${inputClass} font-mono text-xs`}
              spellCheck={false}
            />
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              disabled={isPending}
              onClick={addTarget}
              className="rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--bg-primary)] disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            >
              Add target
            </button>
          </div>
        </section>

        <section className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4 space-y-3">
          <h2 className="text-base font-medium text-[var(--text-primary)]">
            Preview (DNS / CIDR / scope)
          </h2>
          <p className="text-sm text-[var(--text-muted)]">
            Evaluates a probe against rules on the server. Optional DNS hostname
            and CIDR fields run additional previews without affecting scope logic.
          </p>
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label htmlFor={prevProbeId} className="text-sm text-[var(--text-secondary)]">
                Probe
              </label>
              <input
                id={prevProbeId}
                value={previewProbe}
                onChange={(e) => setPreviewProbe(e.target.value)}
                className={`${inputClass} font-mono text-xs`}
              />
            </div>
            <div>
              <label htmlFor={prevPortId} className="text-sm text-[var(--text-secondary)]">
                Port (optional)
              </label>
              <input
                id={prevPortId}
                inputMode="numeric"
                placeholder="e.g. 443"
                value={previewPort}
                onChange={(e) => setPreviewPort(e.target.value)}
                className={inputClass}
              />
            </div>
          </div>
          <div>
            <label htmlFor={prevRulesId} className="text-sm text-[var(--text-secondary)]">
              Rules JSON
            </label>
            <textarea
              id={prevRulesId}
              rows={8}
              value={previewRulesJson}
              onChange={(e) => setPreviewRulesJson(e.target.value)}
              className={`${inputClass} font-mono text-xs`}
              spellCheck={false}
            />
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label htmlFor={prevDnsId} className="text-sm text-[var(--text-secondary)]">
                DNS hostname (optional)
              </label>
              <input
                id={prevDnsId}
                placeholder="e.g. api.example.com"
                value={previewDns}
                onChange={(e) => setPreviewDns(e.target.value)}
                className={`${inputClass} font-mono text-xs`}
              />
            </div>
            <div>
              <label htmlFor={prevCidrId} className="text-sm text-[var(--text-secondary)]">
                CIDR (optional)
              </label>
              <input
                id={prevCidrId}
                placeholder="e.g. 10.0.0.0/24"
                value={previewCidr}
                onChange={(e) => setPreviewCidr(e.target.value)}
                className={`${inputClass} font-mono text-xs`}
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              disabled={isPending}
              onClick={runPreview}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm font-medium text-[var(--text-primary)] disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            >
              Run preview
            </button>
          </div>
          {previewResult ? (
            <pre className="max-h-80 overflow-auto rounded border border-[var(--border)] bg-[var(--bg-primary)] p-3 font-mono text-xs text-[var(--text-secondary)]">
              {JSON.stringify(
                {
                  scope_allowed: previewResult.scope_allowed,
                  scope_message: formatScopeFailure(
                    previewResult.scope_failure_summary,
                  ),
                  dns: previewResult.dns,
                  cidr: previewResult.cidr,
                },
                null,
                2,
              )}
            </pre>
          ) : null}
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-medium text-[var(--text-primary)]">Targets</h2>
          {targets.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)]">No targets yet.</p>
          ) : (
            <ul className="space-y-3">
              {targets.map((t) => (
                <li
                  key={t.id}
                  className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-3"
                >
                  {editingId === t.id ? (
                    <div className="space-y-2">
                      <input
                        value={editUrl}
                        onChange={(e) => setEditUrl(e.target.value)}
                        className={inputClass}
                      />
                      <textarea
                        rows={8}
                        value={editRulesJson}
                        onChange={(e) => setEditRulesJson(e.target.value)}
                        className={`${inputClass} font-mono text-xs`}
                        spellCheck={false}
                      />
                      <div className="flex flex-wrap gap-2 justify-end">
                        <button
                          type="button"
                          disabled={isPending}
                          onClick={() => setEditingId(null)}
                          className="rounded border border-[var(--border)] px-3 py-1.5 text-sm"
                        >
                          Cancel
                        </button>
                        <button
                          type="button"
                          disabled={isPending}
                          onClick={saveEdit}
                          className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-[var(--bg-primary)] disabled:opacity-50"
                        >
                          Save
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                      <div className="min-w-0 space-y-1">
                        <div className="font-mono text-sm text-[var(--text-primary)] break-all">
                          {t.url}
                        </div>
                        <div className="text-xs text-[var(--text-muted)]">
                          Ownership: {ownershipHint(t.ownership_proof)}
                          {t.ownership_proof.lookup_available
                            ? ""
                            : " · proof lookup unavailable"}
                        </div>
                      </div>
                      <div className="flex shrink-0 gap-2">
                        <button
                          type="button"
                          disabled={isPending}
                          onClick={() => startEdit(t)}
                          className="rounded border border-[var(--border)] px-2 py-1 text-xs"
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          disabled={isPending}
                          onClick={() => removeTarget(t.id)}
                          className="rounded border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-secondary)]"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </AdminRouteGuard>
  );
}
