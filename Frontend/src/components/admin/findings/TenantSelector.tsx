"use client";

/**
 * `TenantSelector` — cross-tenant scope picker for super-admin operators.
 *
 * Two modes:
 *  - When `tenants` is non-empty (i.e. `GET /admin/tenants` succeeded), the
 *    operator picks from a typed `<select>` and gets a "All tenants" option to
 *    fall back to the cross-tenant view.
 *  - Otherwise we degrade to a free-text UUID input as a Phase-1 fallback so
 *    the page is still usable on stripped backends (matches the orchestration
 *    plan's deviation note).
 */

import { useId, type ChangeEvent } from "react";

export type TenantOption = {
  readonly id: string;
  readonly name: string;
};

export type TenantSelectorProps = {
  readonly value: string;
  readonly tenants: ReadonlyArray<TenantOption>;
  readonly onChange: (tenantId: string) => void;
  readonly disabled?: boolean;
};

const UUID_LIKE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export function TenantSelector({
  value,
  tenants,
  onChange,
  disabled = false,
}: TenantSelectorProps): React.ReactElement {
  const inputId = useId();

  const hasOptions = tenants.length > 0;

  const handleSelectChange = (e: ChangeEvent<HTMLSelectElement>) => {
    onChange(e.target.value);
  };

  const handleInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value.trim());
  };

  const validation =
    !hasOptions && value && !UUID_LIKE.test(value)
      ? "UUID должен быть в формате 8-4-4-4-12"
      : null;

  return (
    <div className="flex flex-col gap-1" data-testid="tenant-selector">
      <label
        htmlFor={inputId}
        className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]"
      >
        Tenant
      </label>
      {hasOptions ? (
        <select
          id={inputId}
          value={value}
          onChange={handleSelectChange}
          disabled={disabled}
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
          data-testid="tenant-selector-select"
        >
          <option value="">Все tenants</option>
          {tenants.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
      ) : (
        <input
          id={inputId}
          type="text"
          value={value}
          onChange={handleInputChange}
          disabled={disabled}
          placeholder="UUID или пусто"
          aria-invalid={validation != null}
          aria-describedby={validation ? `${inputId}-err` : undefined}
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 font-mono text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
          data-testid="tenant-selector-input"
        />
      )}
      {validation ? (
        <span
          id={`${inputId}-err`}
          role="alert"
          className="text-xs text-red-500"
          data-testid="tenant-selector-error"
        >
          {validation}
        </span>
      ) : null}
    </div>
  );
}
