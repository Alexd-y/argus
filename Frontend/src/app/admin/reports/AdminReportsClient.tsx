"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  useTransition,
} from "react";

import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import { getSafeErrorMessage } from "@/lib/api";
import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";

import {
  createShareLink,
  deleteShareLink,
  downloadAdminReport,
  generateAdminReport,
  getAdminReportDetail,
  listAdminReports,
  listShareLinks,
  regenerateAdminReport,
  type AdminReportDetail,
  type AdminReportListItem,
  type AdminReportSort,
  type ReportShareLink,
} from "./actions";

const PAGE_SIZE = 25;
const VALID_TIERS = ["midgard", "asgard", "valhalla"] as const;
const VALID_FORMATS = ["pdf", "html", "json", "csv", "md"] as const;
const COMPLIANCE_OPTIONS = ["OWASP Top 10", "PCI-DSS", "HIPAA", "ISO 27001", "NIST 800-53"] as const;
const REPORT_TEMPLATES = [
  { key: "executive", label: "Executive", tier: "midgard" },
  { key: "technical", label: "Technical", tier: "asgard" },
  { key: "full", label: "Full (Compliance)", tier: "valhalla" },
] as const;

function errMsg(e: unknown): string {
  return getSafeErrorMessage(e, "Something went wrong. Please try again.");
}

function formatDt(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function shortId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…`;
}

function statusBadge(status: string): string {
  switch (status) {
    case "pending":
      return "bg-yellow-900/30 text-yellow-200";
    case "processing":
      return "bg-blue-900/30 text-blue-200";
    case "ready":
      return "bg-green-900/30 text-green-200";
    case "failed":
      return "bg-red-900/30 text-red-200";
    default:
      return "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]";
  }
}

function tierBadge(tier: string): string {
  switch (tier) {
    case "midgard":
      return "bg-sky-900/30 text-sky-200";
    case "asgard":
      return "bg-amber-900/30 text-amber-200";
    case "valhalla":
      return "bg-purple-900/30 text-purple-200";
    default:
      return "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]";
  }
}

function SeverityDots({ counts }: { counts: Record<string, number> | null }) {
  if (!counts) return null;
  const items: { label: string; color: string; value: number }[] = [
    { label: "Crit", color: "bg-red-500", value: counts.critical ?? 0 },
    { label: "High", color: "bg-orange-500", value: counts.high ?? 0 },
    { label: "Med", color: "bg-yellow-500", value: counts.medium ?? 0 },
    { label: "Low", color: "bg-blue-400", value: counts.low ?? 0 },
  ];
  const hasAny = items.some((i) => i.value > 0);
  if (!hasAny) return <span className="text-xs text-[var(--text-muted)]">—</span>;
  return (
    <div className="flex items-center gap-1.5">
      {items.map((i) =>
        i.value > 0 ? (
          <span key={i.label} className="inline-flex items-center gap-0.5">
            <span className={`inline-block h-2 w-2 rounded-full ${i.color}`} />
            <span className="text-xs">{i.value}</span>
          </span>
        ) : null,
      )}
    </div>
  );
}

function AdminReportsBody() {
  const [isPending, startTransition] = useTransition();

  const [tenants, setTenants] = useState<AdminTenant[]>([]);
  const [tenantId, setTenantId] = useState<string>("");
  const [sort, setSort] = useState<AdminReportSort>("created_at_desc");
  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [tierFilter, setTierFilter] = useState<string>("");
  const [search, setSearch] = useState("");
  const [sinceDate, setSinceDate] = useState("");
  const [untilDate, setUntilDate] = useState("");
  const [rows, setRows] = useState<AdminReportListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<Record<string, boolean>>({});

  const [listError, setListError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionInfo, setActionInfo] = useState<string | null>(null);

  const [detailOpen, setDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detail, setDetail] = useState<AdminReportDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [generateOpen, setGenerateOpen] = useState(false);
  const [genScanId, setGenScanId] = useState("");
  const [genTier, setGenTier] = useState<string>("midgard");
  const [genFormats, setGenFormats] = useState<string[]>(["pdf", "html", "json"]);
  const [genAssignee, setGenAssignee] = useState("");
  const [genComplianceTags, setGenComplianceTags] = useState<string[]>([]);
  const [genSummary, setGenSummary] = useState("");
  const [genTemplate, setGenTemplate] = useState<string>("executive");
  const [genSubmitting, setGenSubmitting] = useState(false);

  const [shareLinks, setShareLinks] = useState<ReportShareLink[]>([]);
  const [shareLoading, setShareLoading] = useState(false);
  const [shareDays, setShareDays] = useState(7);
  const [shareCreating, setShareCreating] = useState(false);
  const [shareCopied, setShareCopied] = useState<string | null>(null);

  const selectedIds = useMemo(
    () => Object.keys(selected).filter((k) => selected[k]),
    [selected],
  );

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
        setTenantId("");
      }
    });
  }, []);

  const loadReports = useCallback(() => {
    if (!tenantId) {
      setRows([]);
      setTotal(0);
      return;
    }
    setListError(null);
    startTransition(async () => {
      try {
        const res = await listAdminReports({
          tenantId,
          offset,
          limit: PAGE_SIZE,
          sort,
          status: statusFilter || undefined,
          tier: tierFilter || undefined,
          q: search || undefined,
          since: sinceDate || undefined,
          until: untilDate || undefined,
        });
        setRows(res.reports);
        setTotal(res.total);
        setSelected({});
      } catch (e) {
        setListError(errMsg(e));
        setRows([]);
        setTotal(0);
      }
    });
  }, [tenantId, offset, sort, statusFilter, tierFilter, search, sinceDate, untilDate]);

  useEffect(() => {
    loadTenants();
  }, [loadTenants]);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const toggleSortCreated = () => {
    setSort((s) =>
      s === "created_at_desc" ? "created_at_asc" : "created_at_desc",
    );
    setOffset(0);
  };

  const toggleAllPage = (checked: boolean) => {
    const next: Record<string, boolean> = { ...selected };
    for (const r of rows) {
      next[r.id] = checked;
    }
    setSelected(next);
  };

  const openDetail = (reportId: string) => {
    if (!tenantId) return;
    setDetailOpen(true);
    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    setShareLinks([]);
    startTransition(async () => {
      try {
        const d = await getAdminReportDetail(tenantId, reportId);
        setDetail(d);
      } catch (e) {
        setDetailError(errMsg(e));
      } finally {
        setDetailLoading(false);
      }
    });
  };

  const loadShareLinks = (reportId: string) => {
    if (!tenantId) return;
    setShareLoading(true);
    startTransition(async () => {
      try {
        const links = await listShareLinks(tenantId, reportId);
        setShareLinks(links);
      } catch {
        setShareLinks([]);
      } finally {
        setShareLoading(false);
      }
    });
  };

  const closeDetail = () => {
    setDetailOpen(false);
    setDetail(null);
    setDetailError(null);
    setShareLinks([]);
  };

  const handleTemplateChange = (key: string) => {
    setGenTemplate(key);
    const tmpl = REPORT_TEMPLATES.find((t) => t.key === key);
    if (tmpl) {
      setGenTier(tmpl.tier);
    }
  };

  const handleGenerate = () => {
    if (!tenantId || !genScanId.trim()) return;
    setGenSubmitting(true);
    setActionError(null);
    setActionInfo(null);
    startTransition(async () => {
      try {
        const res = await generateAdminReport({
          tenantId,
          scanId: genScanId.trim(),
          tier: genTier,
          formats: genFormats,
          assignedTo: genAssignee.trim() || undefined,
          complianceTags: genComplianceTags.length > 0 ? genComplianceTags : undefined,
          executiveSummary: genSummary.trim() || undefined,
        });
        setActionInfo(`Report generation queued (ID: ${shortId(res.report_id)})`);
        setGenerateOpen(false);
        resetGenForm();
        await loadReports();
      } catch (e) {
        setActionError(errMsg(e));
      } finally {
        setGenSubmitting(false);
      }
    });
  };

  const handleRegenerate = (reportId: string) => {
    if (!tenantId) return;
    setActionError(null);
    setActionInfo(null);
    startTransition(async () => {
      try {
        const res = await regenerateAdminReport(tenantId, reportId);
        setActionInfo(`Report v${res.version} queued (ID: ${shortId(res.report_id)})`);
        await loadReports();
        if (detailOpen) openDetail(res.report_id);
      } catch (e) {
        setActionError(errMsg(e));
      }
    });
  };

  const handleDownload = async (reportId: string, format: string) => {
    if (!tenantId) return;
    try {
      const res = await downloadAdminReport(tenantId, reportId, format);
      if (res.download_url) {
        window.open(res.download_url, "_blank");
      } else {
        setActionError("Download URL unavailable. The report artifact may not be ready yet.");
      }
    } catch (e) {
      setActionError(errMsg(e));
    }
  };

  const handleBulkDownload = async () => {
    if (!tenantId || selectedIds.length === 0) return;
    for (const id of selectedIds) {
      const row = rows.find((r) => r.id === id);
      const fmt = row?.requested_formats?.[0] ?? "pdf";
      await handleDownload(id, fmt);
    }
  };

  const handleCreateShareLink = () => {
    if (!tenantId || !detail) return;
    setShareCreating(true);
    startTransition(async () => {
      try {
        const link = await createShareLink(tenantId, detail.id, shareDays);
        setActionInfo(`Share link created. Expires in ${shareDays} day(s).`);
        loadShareLinks(detail.id);
      } catch (e) {
        setActionError(errMsg(e));
      } finally {
        setShareCreating(false);
      }
    });
  };

  const handleDeleteShareLink = (linkId: string) => {
    if (!tenantId || !detail) return;
    startTransition(async () => {
      try {
        await deleteShareLink(tenantId, detail.id, linkId);
        setActionInfo("Share link revoked.");
        loadShareLinks(detail.id);
      } catch (e) {
        setActionError(errMsg(e));
      }
    });
  };

  const toggleFormat = (fmt: string) => {
    setGenFormats((prev) =>
      prev.includes(fmt) ? prev.filter((f) => f !== fmt) : [...prev, fmt],
    );
  };

  const toggleComplianceTag = (tag: string) => {
    setGenComplianceTags((prev) =>
      prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag],
    );
  };

  const resetGenForm = () => {
    setGenScanId("");
    setGenTier("midgard");
    setGenFormats(["pdf", "html", "json"]);
    setGenAssignee("");
    setGenComplianceTags([]);
    setGenSummary("");
    setGenTemplate("executive");
  };

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const pageIndex = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">
            Reports history
          </h1>
          <p className="text-sm text-[var(--text-secondary)]">
            Manage, view, and generate pentest reports
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-xs text-[var(--text-muted)]" htmlFor="admin-report-tenant">
            Tenant
          </label>
          <select
            id="admin-report-tenant"
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
            value={tenantId}
            onChange={(e) => {
              setTenantId(e.target.value);
              setOffset(0);
              setSelected({});
            }}
            disabled={isPending && tenants.length === 0}
          >
            {tenants.length === 0 ? (
              <option value="">—</option>
            ) : (
              tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))
            )}
          </select>
        </div>
      </div>

      {listError ? (
        <div className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200" role="alert">
          {listError}
        </div>
      ) : null}
      {actionError ? (
        <div className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200" role="alert">
          {actionError}
        </div>
      ) : null}
      {actionInfo ? (
        <div className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]">
          {actionInfo}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
          disabled={!tenantId || isPending}
          onClick={() => setGenerateOpen(true)}
        >
          Create report
        </button>
        <button
          type="button"
          className="rounded border border-[var(--border)] px-3 py-1.5 text-sm disabled:opacity-50"
          disabled={selectedIds.length === 0 || !tenantId || isPending}
          onClick={handleBulkDownload}
        >
          Bulk download ({selectedIds.length})
        </button>

        <input
          type="text"
          placeholder="Search by ID or target…"
          className="max-w-[200px] rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)]"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setOffset(0);
          }}
        />

        <select
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setOffset(0);
          }}
        >
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="processing">Processing</option>
          <option value="ready">Ready</option>
          <option value="failed">Failed</option>
        </select>

        <select
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
          value={tierFilter}
          onChange={(e) => {
            setTierFilter(e.target.value);
            setOffset(0);
          }}
        >
          <option value="">All tiers</option>
          {VALID_TIERS.map((t) => (
            <option key={t} value={t}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </option>
          ))}
        </select>

        <input
          type="date"
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
          value={sinceDate}
          onChange={(e) => {
            setSinceDate(e.target.value);
            setOffset(0);
          }}
          title="From date"
        />
        <input
          type="date"
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
          value={untilDate}
          onChange={(e) => {
            setUntilDate(e.target.value);
            setOffset(0);
          }}
          title="Until date"
        />

        <span className="text-xs text-[var(--text-muted)]">
          {total} report{total === 1 ? "" : "s"} total
        </span>
      </div>

      <div className="overflow-x-auto rounded border border-[var(--border)]">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b border-[var(--border)] bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
            <tr>
              <th className="px-2 py-2">
                <input
                  type="checkbox"
                  aria-label="Select all on page"
                  checked={rows.length > 0 && rows.every((r) => selected[r.id])}
                  onChange={(e) => toggleAllPage(e.target.checked)}
                  disabled={rows.length === 0 || isPending}
                />
              </th>
              <th className="px-2 py-2">ID</th>
              <th className="px-2 py-2">Pentester</th>
              <th className="px-2 py-2">Target</th>
              <th className="px-2 py-2">Tier</th>
              <th className="px-2 py-2">Tags</th>
              <th className="px-2 py-2">Findings</th>
              <th className="px-2 py-2">Formats</th>
              <th className="px-2 py-2">Ver</th>
              <th className="px-2 py-2">
                <button
                  type="button"
                  className="inline-flex items-center gap-1 font-medium text-[var(--accent)] hover:underline"
                  onClick={toggleSortCreated}
                  disabled={!tenantId}
                >
                  Created
                  {sort === "created_at_desc" ? " ↓" : " ↑"}
                </button>
              </th>
              <th className="px-2 py-2">Status</th>
              <th className="px-2 py-2"> </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)] text-[var(--text-primary)]">
            {!tenantId ? (
              <tr>
                <td colSpan={12} className="px-3 py-8 text-center text-[var(--text-muted)]">
                  Select a tenant to load reports.
                </td>
              </tr>
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={12} className="px-3 py-8 text-center text-[var(--text-muted)]">
                  No reports found.
                </td>
              </tr>
            ) : (
              rows.map((r) => (
                <tr
                  key={r.id}
                  className="hover:bg-[var(--bg-secondary)]/60"
                >
                  <td className="px-2 py-2">
                    <input
                      type="checkbox"
                      aria-label={`Select report ${r.id}`}
                      checked={!!selected[r.id]}
                      onChange={(e) =>
                        setSelected((s) => ({ ...s, [r.id]: e.target.checked }))
                      }
                    />
                  </td>
                  <td className="px-2 py-2 font-mono text-xs" title={r.id}>
                    {shortId(r.id)}
                  </td>
                  <td className="max-w-[100px] truncate px-2 py-2 text-xs" title={r.assigned_to ?? ""}>
                    {r.assigned_to || "—"}
                  </td>
                  <td className="max-w-[160px] truncate px-2 py-2" title={r.target}>
                    {r.target || "—"}
                  </td>
                  <td className="px-2 py-2">
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${tierBadge(r.tier)}`}>
                      {r.tier}
                    </span>
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex flex-wrap gap-1">
                      {(r.compliance_tags ?? []).map((tag) => (
                        <span
                          key={tag}
                          className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[10px] text-[var(--text-secondary)]"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-2 py-2">
                    <SeverityDots counts={r.severity_counts} />
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex flex-wrap gap-1">
                      {(r.requested_formats ?? []).slice(0, 3).map((fmt) => (
                        <button
                          key={fmt}
                          type="button"
                          className="rounded border border-[var(--border)] px-1 py-0.5 text-[10px] text-[var(--accent)] hover:bg-[var(--bg-tertiary)] disabled:opacity-30"
                          disabled={r.generation_status !== "ready"}
                          onClick={() => handleDownload(r.id, fmt)}
                          title={`Download ${fmt.toUpperCase()}`}
                        >
                          {fmt.toUpperCase()}
                        </button>
                      ))}
                      {(r.requested_formats ?? []).length > 3 && (
                        <span className="text-[10px] text-[var(--text-muted)]">
                          +{(r.requested_formats ?? []).length - 3}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-2 py-2 text-xs text-[var(--text-secondary)]">
                    v{r.version}
                  </td>
                  <td className="whitespace-nowrap px-2 py-2 text-[var(--text-secondary)]">
                    {formatDt(r.created_at)}
                  </td>
                  <td className="px-2 py-2">
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${statusBadge(r.generation_status)}`}>
                      {r.generation_status}
                    </span>
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        className="text-[var(--accent)] hover:underline text-xs"
                        onClick={() => openDetail(r.id)}
                      >
                        Details
                      </button>
                      {(r.generation_status === "ready" || r.generation_status === "failed") && (
                        <button
                          type="button"
                          className="text-[var(--accent)] hover:underline text-xs"
                          onClick={() => handleRegenerate(r.id)}
                        >
                          Regenerate
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between gap-2 text-sm">
        <button
          type="button"
          className="rounded border border-[var(--border)] px-3 py-1.5 disabled:opacity-50"
          disabled={offset <= 0 || !tenantId || isPending}
          onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
        >
          Previous
        </button>
        <span className="text-[var(--text-muted)]">
          Page {pageIndex} / {pageCount}
        </span>
        <button
          type="button"
          className="rounded border border-[var(--border)] px-3 py-1.5 disabled:opacity-50"
          disabled={offset + PAGE_SIZE >= total || !tenantId || isPending}
          onClick={() => setOffset((o) => o + PAGE_SIZE)}
        >
          Next
        </button>
      </div>

      {generateOpen ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
          role="presentation"
          onClick={() => {
            setGenerateOpen(false);
            resetGenForm();
          }}
        >
          <div
            className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded border border-[var(--border)] bg-[var(--bg-primary)] p-6 shadow-xl"
            role="dialog"
            aria-modal="true"
            aria-label="Create report"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 className="mb-4 text-base font-semibold text-[var(--text-primary)]">
              Create report
            </h2>

            <div className="space-y-4">
              <div>
                <label className="mb-1 block text-sm text-[var(--text-secondary)]" htmlFor="gen-scan-id">
                  Scan ID *
                </label>
                <input
                  id="gen-scan-id"
                  type="text"
                  className="w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
                  placeholder="Enter scan ID"
                  value={genScanId}
                  onChange={(e) => setGenScanId(e.target.value)}
                />
              </div>

              <div>
                <label className="mb-1 block text-sm text-[var(--text-secondary)]">
                  Report Template / Type
                </label>
                <div className="flex flex-wrap gap-2">
                  {REPORT_TEMPLATES.map((tmpl) => (
                    <button
                      key={tmpl.key}
                      type="button"
                      className={`rounded px-3 py-1.5 text-sm ${
                        genTemplate === tmpl.key
                          ? "bg-[var(--accent)] text-white"
                          : "border border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]"
                      }`}
                      onClick={() => handleTemplateChange(tmpl.key)}
                    >
                      {tmpl.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="mb-1 block text-sm text-[var(--text-secondary)]" htmlFor="gen-tier">
                  Tier
                </label>
                <select
                  id="gen-tier"
                  className="w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
                  value={genTier}
                  onChange={(e) => setGenTier(e.target.value)}
                >
                  {VALID_TIERS.map((t) => (
                    <option key={t} value={t}>
                      {t.charAt(0).toUpperCase() + t.slice(1)}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <span className="mb-1 block text-sm text-[var(--text-secondary)]">
                  Formats
                </span>
                <div className="flex flex-wrap gap-3">
                  {VALID_FORMATS.map((fmt) => (
                    <label key={fmt} className="flex items-center gap-1.5 text-sm">
                      <input
                        type="checkbox"
                        checked={genFormats.includes(fmt)}
                        onChange={() => toggleFormat(fmt)}
                      />
                      <span className="text-[var(--text-primary)]">{fmt.toUpperCase()}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="mb-1 block text-sm text-[var(--text-secondary)]" htmlFor="gen-assignee">
                  Assignee (Pentester)
                </label>
                <input
                  id="gen-assignee"
                  type="text"
                  className="w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
                  placeholder="Name or nickname"
                  value={genAssignee}
                  onChange={(e) => setGenAssignee(e.target.value)}
                />
              </div>

              <div>
                <span className="mb-1 block text-sm text-[var(--text-secondary)]">
                  Compliance Tags
                </span>
                <div className="flex flex-wrap gap-3">
                  {COMPLIANCE_OPTIONS.map((tag) => (
                    <label key={tag} className="flex items-center gap-1.5 text-sm">
                      <input
                        type="checkbox"
                        checked={genComplianceTags.includes(tag)}
                        onChange={() => toggleComplianceTag(tag)}
                      />
                      <span className="text-[var(--text-primary)]">{tag}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="mb-1 block text-sm text-[var(--text-secondary)]" htmlFor="gen-summary">
                  Executive Summary
                </label>
                <textarea
                  id="gen-summary"
                  className="w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
                  rows={4}
                  placeholder="Describe critical risks and key findings for leadership…"
                  value={genSummary}
                  onChange={(e) => setGenSummary(e.target.value)}
                />
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                className="rounded border border-[var(--border)] px-4 py-2 text-sm"
                onClick={() => {
                  setGenerateOpen(false);
                  resetGenForm();
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="rounded bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
                disabled={!genScanId.trim() || genFormats.length === 0 || genSubmitting}
                onClick={handleGenerate}
              >
                {genSubmitting ? "Generating…" : "Generate Report"}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {detailOpen ? (
        <div
          className="fixed inset-0 z-40 flex justify-end bg-black/40"
          role="presentation"
          onClick={closeDetail}
        >
          <div
            className="h-full w-full max-w-lg overflow-y-auto border-l border-[var(--border)] bg-[var(--bg-primary)] p-4 shadow-xl"
            role="dialog"
            aria-modal="true"
            aria-label="Report details"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-2">
              <h2 className="text-base font-semibold text-[var(--text-primary)]">
                Report details
              </h2>
              <button
                type="button"
                className="text-sm text-[var(--accent)] hover:underline"
                onClick={closeDetail}
              >
                Close
              </button>
            </div>
            {detailLoading ? (
              <p className="mt-4 text-sm text-[var(--text-muted)]">Loading…</p>
            ) : null}
            {detailError ? (
              <p className="mt-4 text-sm text-red-300" role="alert">{detailError}</p>
            ) : null}
            {detail ? (
              <div className="mt-4 space-y-4 text-sm">
                <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[var(--text-secondary)]">
                  <dt className="text-[var(--text-muted)]">ID</dt>
                  <dd className="font-mono text-xs text-[var(--text-primary)]">{detail.id}</dd>
                  <dt className="text-[var(--text-muted)]">Target</dt>
                  <dd className="break-all text-[var(--text-primary)]">{detail.target || "—"}</dd>
                  <dt className="text-[var(--text-muted)]">Tier</dt>
                  <dd>
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${tierBadge(detail.tier)}`}>
                      {detail.tier}
                    </span>
                  </dd>
                  <dt className="text-[var(--text-muted)]">Status</dt>
                  <dd>
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${statusBadge(detail.generation_status)}`}>
                      {detail.generation_status}
                    </span>
                  </dd>
                  <dt className="text-[var(--text-muted)]">Scan ID</dt>
                  <dd className="font-mono text-xs">{detail.scan_id ?? "—"}</dd>
                  <dt className="text-[var(--text-muted)]">Pentester</dt>
                  <dd>{detail.assigned_to ?? "—"}</dd>
                  <dt className="text-[var(--text-muted)]">Version</dt>
                  <dd>v{detail.version}{detail.parent_report_id ? ` (from ${shortId(detail.parent_report_id)})` : ""}</dd>
                  <dt className="text-[var(--text-muted)]">Created</dt>
                  <dd>{formatDt(detail.created_at)}</dd>
                  {detail.last_error_message ? (
                    <>
                      <dt className="text-[var(--text-muted)]">Error</dt>
                      <dd className="text-red-300">{detail.last_error_message}</dd>
                    </>
                  ) : null}
                </dl>

                {(detail.compliance_tags ?? []).length > 0 && (
                  <div>
                    <h3 className="mb-2 font-medium text-[var(--text-primary)]">Compliance Tags</h3>
                    <div className="flex flex-wrap gap-1">
                      {detail.compliance_tags!.map((tag) => (
                        <span
                          key={tag}
                          className="rounded bg-[var(--bg-tertiary)] px-2 py-0.5 text-xs text-[var(--accent)]"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {(detail.severity_counts && Object.keys(detail.severity_counts).length > 0) ? (
                  <div>
                    <h3 className="mb-2 font-medium text-[var(--text-primary)]">
                      Findings by severity ({detail.findings_count} total)
                    </h3>
                    <SeverityDots counts={detail.severity_counts} />
                  </div>
                ) : null}

                {detail.technologies && detail.technologies.length > 0 ? (
                  <div>
                    <h3 className="mb-2 font-medium text-[var(--text-primary)]">Technologies</h3>
                    <div className="flex flex-wrap gap-1">
                      {detail.technologies.map((t) => (
                        <span
                          key={t}
                          className="rounded bg-[var(--bg-tertiary)] px-1.5 py-0.5 text-xs text-[var(--text-secondary)]"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}

                {detail.available_formats.length > 0 ? (
                  <div>
                    <h3 className="mb-2 font-medium text-[var(--text-primary)]">Available downloads</h3>
                    <div className="flex flex-wrap gap-2">
                      {detail.available_formats.map((fmt) => (
                        <button
                          key={fmt}
                          type="button"
                          className="rounded border border-[var(--border)] px-2 py-1 text-xs text-[var(--accent)] hover:bg-[var(--bg-tertiary)]"
                          onClick={() => handleDownload(detail.id, fmt)}
                        >
                          {fmt.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : null}

                <div>
                  <h3 className="mb-2 font-medium text-[var(--text-primary)]">Share Links</h3>
                  {shareLinks.length > 0 ? (
                    <div className="space-y-2">
                      {shareLinks.map((link) => (
                        <div
                          key={link.id}
                          className="flex items-center gap-2 rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-2 py-1.5 text-xs"
                        >
                          <span className="font-mono text-[var(--text-primary)]">{link.token.slice(0, 12)}…</span>
                          <span className="text-[var(--text-muted)]">
                            Expires: {formatDt(link.expires_at)}
                          </span>
                          <span className="text-[var(--text-muted)]">
                            Views: {link.view_count}
                          </span>
                          {link.share_url && (
                            <button
                              type="button"
                              className="text-[var(--accent)] hover:underline"
                              onClick={() => {
                                navigator.clipboard.writeText(link.share_url!);
                                setShareCopied(link.id);
                                setTimeout(() => setShareCopied(null), 2000);
                              }}
                            >
                              {shareCopied === link.id ? "Copied!" : "Copy URL"}
                            </button>
                          )}
                          <button
                            type="button"
                            className="text-red-400 hover:text-red-300"
                            onClick={() => handleDeleteShareLink(link.id)}
                          >
                            Revoke
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-[var(--text-muted)]">No share links yet.</p>
                  )}
                  <div className="mt-2 flex items-center gap-2">
                    <select
                      className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1 text-xs text-[var(--text-primary)]"
                      value={shareDays}
                      onChange={(e) => setShareDays(Number(e.target.value))}
                    >
                      <option value={1}>1 day</option>
                      <option value={3}>3 days</option>
                      <option value={7}>7 days</option>
                      <option value={30}>30 days</option>
                    </select>
                    <button
                      type="button"
                      className="rounded bg-[var(--accent)] px-2 py-1 text-xs font-medium text-white disabled:opacity-50"
                      disabled={shareCreating}
                      onClick={handleCreateShareLink}
                    >
                      Create Share Link
                    </button>
                    <button
                      type="button"
                      className="text-xs text-[var(--accent)] hover:underline"
                      onClick={() => {
                        if (detail) loadShareLinks(detail.id);
                      }}
                    >
                      Refresh
                    </button>
                  </div>
                </div>

                <div className="flex gap-2 pt-2">
                  {(detail.generation_status === "ready" || detail.generation_status === "failed") && (
                    <button
                      type="button"
                      className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--accent)] hover:bg-[var(--bg-tertiary)]"
                      onClick={() => handleRegenerate(detail.id)}
                    >
                      Regenerate (v{detail.version + 1})
                    </button>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function AdminReportsClient() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <AdminReportsBody />
    </AdminRouteGuard>
  );
}