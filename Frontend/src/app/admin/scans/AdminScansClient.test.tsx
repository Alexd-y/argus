import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const router = {
  replace: vi.fn(),
  push: vi.fn(),
  back: vi.fn(),
  forward: vi.fn(),
  refresh: vi.fn(),
  prefetch: vi.fn(),
};
vi.mock("next/navigation", () => ({
  useRouter: () => router,
}));

const listAdminScans = vi.fn();
const bulkCancelAdminScans = vi.fn();
const getAdminScanDetail = vi.fn();
const cancelAdminScan = vi.fn();
vi.mock("./actions", () => ({
  listAdminScans: (...args: unknown[]) => listAdminScans(...args),
  bulkCancelAdminScans: (...args: unknown[]) => bulkCancelAdminScans(...args),
  getAdminScanDetail: (...args: unknown[]) => getAdminScanDetail(...args),
  cancelAdminScan: (...args: unknown[]) => cancelAdminScan(...args),
}));

const listTenants = vi.fn();
vi.mock("@/app/admin/tenants/actions", () => ({
  listTenants: (...args: unknown[]) => listTenants(...args),
}));

const downloadFindingsExport = vi.fn();
vi.mock("@/lib/findingsExport", async () => {
  const actual = await vi.importActual<
    typeof import("@/lib/findingsExport")
  >("@/lib/findingsExport");
  return {
    ...actual,
    downloadFindingsExport: (...args: unknown[]) =>
      downloadFindingsExport(...args),
  };
});

import type { AdminScanListItem } from "./actions";
import type { AdminTenant } from "@/app/admin/tenants/actions";
import { AdminAuthProvider } from "@/services/admin/AdminAuthContext";
import type { AdminRole } from "@/services/admin/adminRoles";
import { AdminScansClient } from "./AdminScansClient";

const TENANT_ID = "00000000-0000-0000-0000-000000000001";

function setRole(role: AdminRole) {
  window.sessionStorage.setItem("argus.admin.role", role);
}

function makeTenant(over: Partial<AdminTenant> = {}): AdminTenant {
  return {
    id: over.id ?? TENANT_ID,
    name: over.name ?? "Acme",
    exports_sarif_junit_enabled: over.exports_sarif_junit_enabled ?? true,
    rate_limit_rpm: over.rate_limit_rpm ?? null,
    scope_blacklist: over.scope_blacklist ?? null,
    retention_days: over.retention_days ?? null,
    created_at: over.created_at ?? "2026-04-01T00:00:00Z",
    updated_at: over.updated_at ?? "2026-04-01T00:00:00Z",
  };
}

function makeScan(over: Partial<AdminScanListItem> = {}): AdminScanListItem {
  return {
    id:
      over.id ?? "11111111-1111-1111-1111-111111111111",
    status: over.status ?? "running",
    progress: over.progress ?? 35,
    phase: over.phase ?? "fingerprint",
    target: over.target ?? "https://example.com",
    created_at: over.created_at ?? "2026-04-21T08:00:00Z",
    updated_at: over.updated_at ?? "2026-04-21T08:01:00Z",
    scan_mode: over.scan_mode ?? "deep",
  };
}

function renderClient() {
  return render(
    <AdminAuthProvider>
      <AdminScansClient />
    </AdminAuthProvider>,
  );
}

beforeEach(() => {
  router.replace.mockClear();
  router.push.mockClear();
  router.refresh.mockClear();
  window.sessionStorage.clear();
  if (typeof document !== "undefined") {
    document.cookie =
      "argus.admin.role=; path=/; max-age=0; SameSite=Strict";
  }
  listAdminScans.mockReset();
  bulkCancelAdminScans.mockReset();
  getAdminScanDetail.mockReset();
  cancelAdminScan.mockReset();
  listTenants.mockReset();
  downloadFindingsExport.mockReset();
  listTenants.mockResolvedValue([makeTenant()]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AdminScansClient — per-scan kill-switch button (T28)", () => {
  it("renders an enabled Kill scan button for active rows", async () => {
    setRole("admin");
    const scan = makeScan({ status: "running" });
    listAdminScans.mockResolvedValue({
      scans: [scan],
      total: 1,
      limit: 25,
      offset: 0,
    });

    renderClient();

    const btn = await screen.findByTestId(`scans-row-kill-${scan.id}`);
    expect(btn).toBeInTheDocument();
    expect(btn).toBeEnabled();
    expect(btn).toHaveAttribute("aria-disabled", "false");
  });

  it.each([
    ["completed"],
    ["cancelled"],
    ["failed"],
  ] as const)(
    "disables the Kill scan button for terminal-status row (%s)",
    async (status) => {
      setRole("admin");
      const scan = makeScan({ status });
      listAdminScans.mockResolvedValue({
        scans: [scan],
        total: 1,
        limit: 25,
        offset: 0,
      });

      renderClient();

      const btn = await screen.findByTestId(`scans-row-kill-${scan.id}`);
      expect(btn).toBeDisabled();
      expect(btn).toHaveAttribute("aria-disabled", "true");
    },
  );

  it("opens PerScanKillSwitchDialog with the row's scan id when Kill scan is clicked", async () => {
    setRole("admin");
    const user = userEvent.setup();
    const scan = makeScan({ status: "running" });
    listAdminScans.mockResolvedValue({
      scans: [scan],
      total: 1,
      limit: 25,
      offset: 0,
    });

    renderClient();

    await user.click(await screen.findByTestId(`scans-row-kill-${scan.id}`));

    const dialog = await screen.findByTestId("kill-scan-dialog");
    expect(dialog).toBeInTheDocument();
    expect(screen.getByTestId("kill-scan-dialog-scan-id")).toHaveTextContent(
      scan.id,
    );
    expect(screen.getByTestId("kill-scan-dialog-target")).toHaveTextContent(
      scan.target,
    );
    expect(cancelAdminScan).not.toHaveBeenCalled();
  });

  it("on successful confirm: refreshes the list and surfaces an info banner", async () => {
    setRole("admin");
    const user = userEvent.setup();
    const scan = makeScan({ status: "running" });
    listAdminScans.mockResolvedValue({
      scans: [scan],
      total: 1,
      limit: 25,
      offset: 0,
    });
    cancelAdminScan.mockResolvedValue({
      status: "cancelled",
      scanId: scan.id,
      auditId: "audit-1",
    });

    renderClient();

    await user.click(await screen.findByTestId(`scans-row-kill-${scan.id}`));

    const input = screen.getByTestId(
      "kill-scan-dialog-input",
    ) as HTMLInputElement;
    await user.type(input, scan.id);
    await user.click(screen.getByTestId("kill-scan-dialog-confirm"));

    await waitFor(() => expect(cancelAdminScan).toHaveBeenCalledTimes(1));
    expect(cancelAdminScan).toHaveBeenCalledWith({
      scanId: scan.id,
      tenantId: TENANT_ID,
      reason: expect.any(String),
    });

    // Dialog disappears, banner appears, list reloads.
    await waitFor(() =>
      expect(screen.queryByTestId("kill-scan-dialog")).not.toBeInTheDocument(),
    );
    expect(
      await screen.findByText(/Cancelled scan/i),
    ).toBeInTheDocument();
    // 1 — initial load. 2 — post-cancel reload.
    expect(listAdminScans).toHaveBeenCalledTimes(2);
  });
});
