"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useId, useState, useTransition } from "react";

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { getSafeErrorMessage } from "@/lib/api";
import {
  updateTenant,
  type AdminTenant,
} from "@/app/admin/tenants/actions";

const RATE_MIN = 1;
const RATE_MAX = 50_000;
const RET_MIN = 1;
const RET_MAX = 3650;

function tenantActionErrorMessage(err: unknown): string {
  return getSafeErrorMessage(err, "Something went wrong. Please try again.");
}

function normalizeTenant(t: AdminTenant): AdminTenant {
  return {
    ...t,
    rate_limit_rpm: t.rate_limit_rpm ?? null,
    scope_blacklist: t.scope_blacklist ?? null,
    retention_days: t.retention_days ?? null,
  };
}

type Props = { tenantId: string; initial: AdminTenant };

export function TenantSettingsClient({ tenantId, initial }: Props) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [tenant, setTenant] = useState(() => normalizeTenant(initial));
  const [rateInput, setRateInput] = useState(() =>
    initial.rate_limit_rpm != null ? String(initial.rate_limit_rpm) : "",
  );
  const [blacklistText, setBlacklistText] = useState(() =>
    (initial.scope_blacklist ?? []).join("\n"),
  );
  const [retentionInput, setRetentionInput] = useState(() =>
    initial.retention_days != null ? String(initial.retention_days) : "",
  );
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const rateLabelId = useId();
  const blacklistLabelId = useId();
  const retentionLabelId = useId();

  const inputClass =
    "mt-1 w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-secondary)]";

  const applyTenant = useCallback((t: AdminTenant) => {
    const n = normalizeTenant(t);
    setTenant(n);
    setRateInput(n.rate_limit_rpm != null ? String(n.rate_limit_rpm) : "");
    setBlacklistText((n.scope_blacklist ?? []).join("\n"));
    setRetentionInput(n.retention_days != null ? String(n.retention_days) : "");
  }, []);

  const saveRate = () => {
    setError(null);
    setMessage(null);
    const raw = rateInput.trim();
    let rate_limit_rpm: number | null;
    if (raw === "") {
      rate_limit_rpm = null;
    } else {
      const n = Number(raw);
      if (!Number.isInteger(n)) {
        setError("Rate limit must be a whole number.");
        return;
      }
      if (n < RATE_MIN || n > RATE_MAX) {
        setError(`Rate limit must be between ${RATE_MIN} and ${RATE_MAX} (requests per minute).`);
        return;
      }
      rate_limit_rpm = n;
    }
    startTransition(async () => {
      try {
        const next = await updateTenant(tenantId, { rate_limit_rpm });
        applyTenant(next);
        setMessage("Rate limit saved.");
        router.refresh();
      } catch (e) {
        setError(tenantActionErrorMessage(e));
      }
    });
  };

  const saveBlacklist = () => {
    setError(null);
    setMessage(null);
    const lines = blacklistText
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const scope_blacklist = lines.length === 0 ? null : lines;
    startTransition(async () => {
      try {
        const next = await updateTenant(tenantId, { scope_blacklist });
        applyTenant(next);
        setMessage("Scope blacklist saved.");
        router.refresh();
      } catch (e) {
        setError(tenantActionErrorMessage(e));
      }
    });
  };

  const saveRetention = () => {
    setError(null);
    setMessage(null);
    const raw = retentionInput.trim();
    let retention_days: number | null;
    if (raw === "") {
      retention_days = null;
    } else {
      const n = Number(raw);
      if (!Number.isInteger(n)) {
        setError("Retention must be a whole number of days.");
        return;
      }
      if (n < RET_MIN || n > RET_MAX) {
        setError(`Retention must be between ${RET_MIN} and ${RET_MAX} days.`);
        return;
      }
      retention_days = n;
    }
    startTransition(async () => {
      try {
        const next = await updateTenant(tenantId, { retention_days });
        applyTenant(next);
        setMessage("Retention saved.");
        router.refresh();
      } catch (e) {
        setError(tenantActionErrorMessage(e));
      }
    });
  };

  return (
    <AdminRouteGuard minimumRole="admin">
      <div className="space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold text-[var(--text-primary)]">
              Tenant limits
            </h1>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              <span className="font-medium text-[var(--text-primary)]">{tenant.name}</span>
              <span className="mx-2 text-[var(--text-muted)]">·</span>
              <span className="font-mono text-xs text-[var(--text-muted)]">{tenantId}</span>
            </p>
          </div>
          <Link
            href="/admin/tenants"
            className="text-sm text-[var(--accent)] hover:underline focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none rounded px-1"
          >
            ← All tenants
          </Link>
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
          <h2 className="text-base font-medium text-[var(--text-primary)]">Rate limit</h2>
          <p className="text-sm text-[var(--text-muted)]">
            Max requests per minute for this tenant. Leave empty to use the platform default (
            {RATE_MIN}–{RATE_MAX} when set).
          </p>
          <div>
            <label htmlFor={rateLabelId} className="text-sm text-[var(--text-secondary)]">
              Requests per minute
            </label>
            <input
              id={rateLabelId}
              type="number"
              inputMode="numeric"
              min={RATE_MIN}
              max={RATE_MAX}
              placeholder="Default"
              value={rateInput}
              onChange={(e) => setRateInput(e.target.value)}
              className={inputClass}
            />
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              disabled={isPending}
              onClick={saveRate}
              className="rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--bg-primary)] disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            >
              Save rate limit
            </button>
          </div>
        </section>

        <section className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4 space-y-3">
          <h2 className="text-base font-medium text-[var(--text-primary)]">Scope blacklist</h2>
          <p className="text-sm text-[var(--text-muted)]">
            One pattern per line (host or path prefix). Empty file clears the override. The server
            enforces length and entry limits.
          </p>
          <div>
            <label htmlFor={blacklistLabelId} className="text-sm text-[var(--text-secondary)]">
              Blocked patterns
            </label>
            <textarea
              id={blacklistLabelId}
              rows={8}
              value={blacklistText}
              onChange={(e) => setBlacklistText(e.target.value)}
              className={`${inputClass} font-mono text-xs`}
              spellCheck={false}
            />
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              disabled={isPending}
              onClick={saveBlacklist}
              className="rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--bg-primary)] disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            >
              Save blacklist
            </button>
          </div>
        </section>

        <section className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4 space-y-3">
          <h2 className="text-base font-medium text-[var(--text-primary)]">Data retention</h2>
          <p className="text-sm text-[var(--text-muted)]">
            Retention window in days. Leave empty for platform default ({RET_MIN}–{RET_MAX} when
            set).
          </p>
          <div>
            <label htmlFor={retentionLabelId} className="text-sm text-[var(--text-secondary)]">
              Days
            </label>
            <input
              id={retentionLabelId}
              type="number"
              inputMode="numeric"
              min={RET_MIN}
              max={RET_MAX}
              placeholder="Default"
              value={retentionInput}
              onChange={(e) => setRetentionInput(e.target.value)}
              className={inputClass}
            />
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              disabled={isPending}
              onClick={saveRetention}
              className="rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--bg-primary)] disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            >
              Save retention
            </button>
          </div>
        </section>

        <p className="text-xs text-[var(--text-muted)]">
          Also see{" "}
          <Link
            href={`/admin/tenants/${encodeURIComponent(tenantId)}/scopes`}
            className="text-[var(--accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] rounded"
          >
            Scopes
          </Link>
          .
        </p>
      </div>
    </AdminRouteGuard>
  );
}
