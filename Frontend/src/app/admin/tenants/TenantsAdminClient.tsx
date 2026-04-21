"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  useTransition,
} from "react";

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { getSafeErrorMessage } from "@/lib/api";
import {
  createTenant,
  deleteTenant,
  listTenants,
  updateTenant,
  type AdminTenant,
} from "./actions";

function tenantActionErrorMessage(err: unknown): string {
  return getSafeErrorMessage(err, "Something went wrong. Please try again.");
}

function formatDt(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function TenantsAdminBody() {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [rows, setRows] = useState<AdminTenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const createDialogRef = useRef<HTMLDialogElement>(null);
  const editDialogRef = useRef<HTMLDialogElement>(null);
  const deleteDialogRef = useRef<HTMLDialogElement>(null);

  const createNameId = useId();
  const editNameId = useId();
  const editExportId = useId();

  const [createName, setCreateName] = useState("");
  const [editing, setEditing] = useState<AdminTenant | null>(null);
  const [editName, setEditName] = useState("");
  const [editExport, setEditExport] = useState(false);
  const [deleting, setDeleting] = useState<AdminTenant | null>(null);

  const refresh = useCallback(() => {
    setListError(null);
    setLoading(true);
    startTransition(async () => {
      try {
        const data = await listTenants({ limit: 100, offset: 0 });
        setRows(data);
        router.refresh();
      } catch (e) {
        setListError(tenantActionErrorMessage(e));
        setRows([]);
      } finally {
        setLoading(false);
      }
    });
  }, [router]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const openCreate = () => {
    setActionError(null);
    setCreateName("");
    createDialogRef.current?.showModal();
  };

  const submitCreate = () => {
    const name = createName.trim();
    if (!name) {
      setActionError("Name is required.");
      return;
    }
    setActionError(null);
    startTransition(async () => {
      try {
        await createTenant({ name });
        createDialogRef.current?.close();
        setLoading(true);
        const data = await listTenants({ limit: 100, offset: 0 });
        setRows(data);
        router.refresh();
      } catch (e) {
        setActionError(tenantActionErrorMessage(e));
      } finally {
        setLoading(false);
      }
    });
  };

  const openEdit = (t: AdminTenant) => {
    setActionError(null);
    setEditing(t);
    setEditName(t.name);
    setEditExport(t.exports_sarif_junit_enabled);
    editDialogRef.current?.showModal();
  };

  const submitEdit = () => {
    if (!editing) return;
    const name = editName.trim();
    if (!name) {
      setActionError("Name is required.");
      return;
    }
    setActionError(null);
    startTransition(async () => {
      try {
        await updateTenant(editing.id, {
          name,
          exports_sarif_junit_enabled: editExport,
        });
        editDialogRef.current?.close();
        setEditing(null);
        setLoading(true);
        const data = await listTenants({ limit: 100, offset: 0 });
        setRows(data);
        router.refresh();
      } catch (e) {
        setActionError(tenantActionErrorMessage(e));
      } finally {
        setLoading(false);
      }
    });
  };

  const openDelete = (t: AdminTenant) => {
    setActionError(null);
    setDeleting(t);
    deleteDialogRef.current?.showModal();
  };

  const confirmDelete = () => {
    if (!deleting) return;
    setActionError(null);
    startTransition(async () => {
      try {
        await deleteTenant(deleting.id);
        deleteDialogRef.current?.close();
        setDeleting(null);
        setLoading(true);
        const data = await listTenants({ limit: 100, offset: 0 });
        setRows(data);
        router.refresh();
      } catch (e) {
        setActionError(tenantActionErrorMessage(e));
      } finally {
        setLoading(false);
      }
    });
  };

  const inputClass =
    "mt-1 w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-secondary)]";

  return (
    <div className="space-y-4">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold text-[var(--text-primary)]">
              Tenants
            </h1>
            <p className="text-sm text-[var(--text-secondary)]">
              Create and manage tenants via server actions (admin API key stays on
              the Next.js server).
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => refresh()}
              disabled={isPending}
              className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--bg-tertiary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            >
              Refresh
            </button>
            <button
              type="button"
              onClick={openCreate}
              disabled={isPending}
              className="rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--bg-primary)] transition hover:opacity-90 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            >
              New tenant
            </button>
          </div>
        </div>

        {listError ? (
          <div
            role="alert"
            className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]"
          >
            {listError}
          </div>
        ) : null}

        {actionError ? (
          <div
            role="alert"
            className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]"
          >
            {actionError}
          </div>
        ) : null}

        <div className="overflow-x-auto rounded border border-[var(--border)] bg-[var(--bg-secondary)]">
          {loading ? (
            <div className="p-8 text-center text-sm text-[var(--text-muted)]">
              Loading…
            </div>
          ) : rows.length === 0 ? (
            <div className="p-8 text-center text-sm text-[var(--text-muted)]">
              No tenants yet.
            </div>
          ) : (
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead className="border-b border-[var(--border)] bg-[var(--bg-tertiary)] text-[var(--text-muted)]">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Name
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    ID
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    SARIF/JUnit
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Updated
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((t) => (
                  <tr
                    key={t.id}
                    className="border-b border-[var(--border)] last:border-b-0"
                  >
                    <td className="px-3 py-2 font-medium text-[var(--text-primary)]">
                      {t.name}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-[var(--text-secondary)]">
                      {t.id}
                    </td>
                    <td className="px-3 py-2 text-[var(--text-secondary)]">
                      {t.exports_sarif_junit_enabled ? "On" : "Off"}
                    </td>
                    <td className="px-3 py-2 text-[var(--text-muted)]">
                      {formatDt(t.updated_at)}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-2">
                        <Link
                          href={`/admin/tenants/${encodeURIComponent(t.id)}/settings`}
                          className="text-xs text-[var(--accent)] hover:underline focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none rounded px-1"
                        >
                          Settings
                        </Link>
                        <button
                          type="button"
                          onClick={() => openEdit(t)}
                          disabled={isPending}
                          className="text-xs text-[var(--accent)] hover:underline focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none rounded px-1 disabled:opacity-50"
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          onClick={() => openDelete(t)}
                          disabled={isPending}
                          className="text-xs text-red-500 hover:underline focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:outline-none rounded px-1 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <dialog
          ref={createDialogRef}
          className="w-[min(100%,28rem)] rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4 text-[var(--text-primary)] shadow-lg backdrop:bg-black/40"
          aria-labelledby={`${createNameId}-title`}
        >
          <h2 id={`${createNameId}-title`} className="text-base font-semibold">
            New tenant
          </h2>
          <div className="mt-3">
            <label htmlFor={createNameId} className="text-sm text-[var(--text-secondary)]">
              Name
            </label>
            <input
              id={createNameId}
              type="text"
              autoComplete="off"
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              className={inputClass}
            />
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <button
              type="button"
              className="rounded border border-[var(--border)] px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              onClick={() => createDialogRef.current?.close()}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={isPending}
              className="rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--bg-primary)] disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              onClick={() => submitCreate()}
            >
              Create
            </button>
          </div>
        </dialog>

        <dialog
          ref={editDialogRef}
          className="w-[min(100%,28rem)] rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4 text-[var(--text-primary)] shadow-lg backdrop:bg-black/40"
          aria-labelledby={`${editNameId}-etitle`}
        >
          <h2 id={`${editNameId}-etitle`} className="text-base font-semibold">
            Edit tenant
          </h2>
          {editing ? (
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              ID: <span className="font-mono">{editing.id}</span>
            </p>
          ) : null}
          <div className="mt-3">
            <label htmlFor={editNameId} className="text-sm text-[var(--text-secondary)]">
              Name
            </label>
            <input
              id={editNameId}
              type="text"
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              className={inputClass}
            />
          </div>
          <div className="mt-3 flex items-center gap-2">
            <input
              id={editExportId}
              type="checkbox"
              checked={editExport}
              onChange={(e) => setEditExport(e.target.checked)}
              className="size-4 rounded border-[var(--border)] text-[var(--accent)] focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
            />
            <label htmlFor={editExportId} className="text-sm text-[var(--text-secondary)]">
              Allow SARIF / JUnit exports
            </label>
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <button
              type="button"
              className="rounded border border-[var(--border)] px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              onClick={() => editDialogRef.current?.close()}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={isPending}
              className="rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--bg-primary)] disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              onClick={() => submitEdit()}
            >
              Save
            </button>
          </div>
        </dialog>

        <dialog
          ref={deleteDialogRef}
          className="w-[min(100%,28rem)] rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4 text-[var(--text-primary)] shadow-lg backdrop:bg-black/40"
          aria-labelledby="tenant-del-title"
        >
          <h2 id="tenant-del-title" className="text-base font-semibold text-red-500">
            Delete tenant
          </h2>
          {deleting ? (
            <p className="mt-2 text-sm text-[var(--text-secondary)]">
              This will permanently remove{" "}
              <strong className="text-[var(--text-primary)]">{deleting.name}</strong>{" "}
              and related data (cascade). This cannot be undone.
            </p>
          ) : null}
          <div className="mt-4 flex justify-end gap-2">
            <button
              type="button"
              className="rounded border border-[var(--border)] px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              onClick={() => deleteDialogRef.current?.close()}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={isPending}
              className="rounded bg-red-600 px-3 py-2 text-sm font-medium text-white disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:outline-none"
              onClick={() => confirmDelete()}
            >
              Delete
            </button>
          </div>
        </dialog>
    </div>
  );
}

export function TenantsAdminClient() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <TenantsAdminBody />
    </AdminRouteGuard>
  );
}
