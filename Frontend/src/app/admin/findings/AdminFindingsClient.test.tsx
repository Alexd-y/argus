import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const routerReplace = vi.fn();
const router = {
  replace: routerReplace,
  push: vi.fn(),
  back: vi.fn(),
  forward: vi.fn(),
  refresh: vi.fn(),
  prefetch: vi.fn(),
};

const searchParamsRef: { current: URLSearchParams } = {
  current: new URLSearchParams(),
};

// CRITICAL: hooks must return STABLE references; otherwise effects depending
// on them re-run forever in tests (no real Next router to update them).
function makeReadonlySearchParams(sp: URLSearchParams) {
  return {
    toString: () => sp.toString(),
    get: (k: string) => sp.get(k),
    getAll: (k: string) => sp.getAll(k),
    has: (k: string) => sp.has(k),
    entries: () => sp.entries(),
    keys: () => sp.keys(),
    values: () => sp.values(),
    forEach: (
      cb: (v: string, k: string, parent: URLSearchParams) => void,
    ) => sp.forEach(cb),
    [Symbol.iterator]: () => sp[Symbol.iterator](),
  };
}

let cachedReadonlyParams = makeReadonlySearchParams(searchParamsRef.current);

vi.mock("next/navigation", () => ({
  useRouter: () => router,
  useSearchParams: () => cachedReadonlyParams,
}));

const listAdminFindings = vi.fn();
vi.mock("@/lib/adminFindings", async () => {
  const actual = await vi.importActual<
    typeof import("@/lib/adminFindings")
  >("@/lib/adminFindings");
  return {
    ...actual,
    listAdminFindings: (...args: unknown[]) => listAdminFindings(...args),
  };
});

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

import {
  AdminFindingsError,
  type AdminFindingItem,
  type AdminFindingsListResponse,
} from "@/lib/adminFindings";
import { AdminAuthProvider } from "@/services/admin/AdminAuthContext";
import type { AdminRole } from "@/services/admin/adminRoles";
import { AdminFindingsClient } from "./AdminFindingsClient";

beforeAll(() => {
  if (typeof Element !== "undefined") {
    Object.defineProperty(Element.prototype, "getBoundingClientRect", {
      configurable: true,
      value() {
        return {
          width: 1000,
          height: 400,
          top: 0,
          left: 0,
          bottom: 400,
          right: 1000,
          x: 0,
          y: 0,
          toJSON: () => ({}),
        };
      },
    });
  }
  if (typeof HTMLElement !== "undefined") {
    Object.defineProperty(HTMLElement.prototype, "clientHeight", {
      configurable: true,
      get: () => 400,
    });
    Object.defineProperty(HTMLElement.prototype, "clientWidth", {
      configurable: true,
      get: () => 1000,
    });
    Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
      configurable: true,
      get: () => 400,
    });
    Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
      configurable: true,
      get: () => 1000,
    });
  }
  if (typeof window !== "undefined") {
    (window as unknown as { ResizeObserver: typeof ResizeObserver }).ResizeObserver =
      class {
        observe(): void {}
        unobserve(): void {}
        disconnect(): void {}
      } as unknown as typeof ResizeObserver;
  }
});

function setRole(role: AdminRole) {
  window.sessionStorage.setItem("argus.admin.role", role);
}

function makeItem(over: Partial<AdminFindingItem> = {}): AdminFindingItem {
  return {
    id: over.id ?? "f-x",
    tenant_id: over.tenant_id ?? "00000000-0000-0000-0000-000000000001",
    scan_id: over.scan_id ?? "scan-1",
    severity: over.severity ?? "high",
    status: over.status ?? null,
    target: over.target ?? "example.com",
    title: over.title ?? "Some finding",
    cve_ids: over.cve_ids ?? null,
    cvss_score: over.cvss_score ?? null,
    epss_score: over.epss_score ?? null,
    kev_listed: over.kev_listed ?? null,
    ssvc_action: over.ssvc_action ?? null,
    discovered_at: over.discovered_at ?? null,
    updated_at: over.updated_at ?? "2026-04-21T08:00:00Z",
  };
}

function pageOf(
  items: ReadonlyArray<AdminFindingItem>,
  opts: Partial<AdminFindingsListResponse> = {},
): AdminFindingsListResponse {
  return {
    items: [...items],
    total: opts.total ?? items.length,
    limit: opts.limit ?? 50,
    offset: opts.offset ?? 0,
    has_more: opts.has_more ?? false,
    next_cursor: opts.next_cursor ?? null,
  };
}

function renderClient() {
  return render(
    <AdminAuthProvider>
      <AdminFindingsClient />
    </AdminAuthProvider>,
  );
}

function setSearchParams(input: string | URLSearchParams) {
  searchParamsRef.current =
    typeof input === "string" ? new URLSearchParams(input) : input;
  cachedReadonlyParams = makeReadonlySearchParams(searchParamsRef.current);
}

beforeEach(() => {
  routerReplace.mockClear();
  setSearchParams("");
  // router.replace would normally update searchParams; in tests we simulate
  // that side-effect ourselves so the URL-sync effect quiesces.
  routerReplace.mockImplementation((url: string) => {
    const qIdx = url.indexOf("?");
    setSearchParams(qIdx >= 0 ? url.slice(qIdx + 1) : "");
  });
  window.sessionStorage.clear();
  listAdminFindings.mockReset();
  listTenants.mockReset();
  downloadFindingsExport.mockReset();
  listTenants.mockResolvedValue([]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AdminFindingsClient", () => {
  it("hydrates findings for super-admin and renders the Tenant column", async () => {
    setRole("super-admin");
    listAdminFindings.mockResolvedValue(
      pageOf([
        makeItem({ id: "f-1", title: "RCE in api", severity: "critical" }),
      ]),
    );
    renderClient();

    expect(await screen.findByText("RCE in api")).toBeInTheDocument();
    // "Tenant" appears in both the TenantSelector and the column header for
    // super-admin → narrow to the column-header role.
    expect(
      screen.getByRole("columnheader", { name: "Tenant" }),
    ).toBeInTheDocument();
    expect(screen.getByTestId("findings-counter")).toHaveTextContent("1 / 1");
    expect(listAdminFindings).toHaveBeenCalled();
  });

  it("hides the Tenant column for plain admin role", async () => {
    setRole("admin");
    listTenants.mockResolvedValue([
      {
        id: "00000000-0000-0000-0000-000000000001",
        name: "Acme",
        exports_sarif_junit_enabled: true,
        rate_limit_rpm: null,
        scope_blacklist: null,
        retention_days: null,
        created_at: "2026-04-01T00:00:00Z",
        updated_at: "2026-04-01T00:00:00Z",
      },
    ]);
    listAdminFindings.mockResolvedValue(
      pageOf([makeItem({ id: "f-only", title: "Single finding" })]),
    );
    renderClient();

    await waitFor(() => {
      expect(listAdminFindings).toHaveBeenCalled();
    });
    expect(screen.queryByText("Tenant")).not.toBeInTheDocument();
    expect(screen.queryByTestId("tenant-selector")).not.toBeInTheDocument();
  });

  it("re-issues fetch with the new severity filter and updates the URL", async () => {
    setRole("super-admin");
    listAdminFindings.mockResolvedValue(pageOf([]));
    const user = userEvent.setup();
    renderClient();

    await waitFor(() => {
      expect(listAdminFindings).toHaveBeenCalled();
    });

    listAdminFindings.mockClear();
    routerReplace.mockClear();
    listAdminFindings.mockResolvedValue(
      pageOf([makeItem({ id: "f-crit", severity: "critical", title: "Critical" })]),
    );

    await user.click(screen.getByTestId("filter-severity-critical"));

    await waitFor(() => {
      expect(listAdminFindings).toHaveBeenCalled();
    });
    const params = listAdminFindings.mock.calls[0][0] as {
      severity: ReadonlyArray<string>;
    };
    expect(params.severity).toEqual(["critical"]);

    await waitFor(() => {
      expect(routerReplace).toHaveBeenCalled();
    });
    const target = routerReplace.mock.calls[0][0] as string;
    expect(target).toContain("severity=critical");
  });

  it("paginates via fetchNextPage when next_cursor is set (cursor forwarded)", async () => {
    setRole("super-admin");
    // Use a tiny page so the auto-load trigger fires once everything is
    // rendered (lastVisibleIndex >= totalRows - 5).
    const firstPage = pageOf(
      Array.from({ length: 3 }, (_, i) =>
        makeItem({ id: `f-${i}`, title: `Finding ${i}` }),
      ),
      { total: 6, limit: 3, has_more: true, next_cursor: "cursor-page-2" },
    );
    const secondPage = pageOf(
      Array.from({ length: 3 }, (_, i) =>
        makeItem({ id: `f-${i + 3}`, title: `Finding ${i + 3}` }),
      ),
      {
        total: 6,
        limit: 3,
        offset: 3,
        has_more: false,
        next_cursor: null,
      },
    );

    listAdminFindings
      .mockResolvedValueOnce(firstPage)
      .mockResolvedValueOnce(secondPage);

    renderClient();

    await waitFor(() => {
      expect(screen.getByTestId("findings-counter")).toHaveTextContent(
        "3 / 6",
      );
    });

    await waitFor(
      () => {
        expect(listAdminFindings).toHaveBeenCalledTimes(2);
      },
      { timeout: 5000 },
    );
    const secondCallArgs = listAdminFindings.mock.calls[1][0] as {
      cursor: string | null;
    };
    expect(secondCallArgs.cursor).toBe("cursor-page-2");
  });

  it("renders a closed-taxonomy error message when the network fails (no PII)", async () => {
    setRole("super-admin");
    listAdminFindings.mockRejectedValue(
      new AdminFindingsError("network_error"),
    );
    renderClient();

    // network_error retries once with the default 1s exponential delay.
    const err = await screen.findByTestId("findings-error", {}, { timeout: 5000 });
    expect(err).toHaveAttribute("role", "alert");
    expect(err.textContent ?? "").toMatch(/Сеть недоступна/);
    expect(err.textContent ?? "").not.toMatch(/at .+\.ts:|stack/i);
  });

  it("does not retry when the API replies 401/403 (closed taxonomy)", async () => {
    setRole("super-admin");
    listAdminFindings.mockRejectedValue(new AdminFindingsError("forbidden", 403));
    renderClient();

    const err = await screen.findByTestId("findings-error");
    expect(err.textContent ?? "").toMatch(/Недостаточно прав/);
    // No retry — exactly one call.
    expect(listAdminFindings).toHaveBeenCalledTimes(1);
  });

  it("shows the export popover with ExportFormatToggle when items are present", async () => {
    setRole("super-admin");
    listAdminFindings.mockResolvedValue(
      pageOf([makeItem({ id: "f", scan_id: "scan-42", title: "row" })]),
    );
    const user = userEvent.setup();
    renderClient();

    await screen.findByText("row");
    const toggle = screen.getByTestId("findings-export-toggle");
    expect(toggle).not.toBeDisabled();

    await user.click(toggle);
    const popover = await screen.findByTestId("findings-export-popover");
    expect(popover).toHaveAttribute("role", "dialog");
    expect(within(popover).getByTestId("export-format-sarif")).toBeInTheDocument();
  });

  it("hydrates filters from URL search params on initial mount", async () => {
    setRole("super-admin");
    setSearchParams(
      "severity=critical&severity=high&status=open&target=example.com",
    );
    listAdminFindings.mockResolvedValue(pageOf([]));
    renderClient();

    await waitFor(() => {
      expect(listAdminFindings).toHaveBeenCalled();
    });
    const params = listAdminFindings.mock.calls[0][0] as {
      severity: ReadonlyArray<string>;
      status: ReadonlyArray<string>;
      target: string | null;
    };
    expect(params.severity).toEqual(["critical", "high"]);
    expect(params.status).toEqual(["open"]);
    expect(params.target).toBe("example.com");

    expect(screen.getByTestId("filter-severity-critical")).toBeChecked();
    expect(screen.getByTestId("filter-severity-high")).toBeChecked();
    expect(screen.getByTestId("filter-status-open")).toBeChecked();
    expect(screen.getByTestId("filter-target")).toHaveValue("example.com");
  });
});
