import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
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

const listAdminFindingsAction = vi.fn();
const bulkSuppressFindingsAction = vi.fn();
const bulkMarkFalsePositiveFindingsAction = vi.fn();
vi.mock("./actions", () => ({
  listAdminFindingsAction: (...args: unknown[]) =>
    listAdminFindingsAction(...args),
  bulkSuppressFindingsAction: (...args: unknown[]) =>
    bulkSuppressFindingsAction(...args),
  bulkMarkFalsePositiveFindingsAction: (...args: unknown[]) =>
    bulkMarkFalsePositiveFindingsAction(...args),
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

import {
  AdminFindingsError,
  type AdminFindingItem,
  type AdminFindingsListResponse,
  type ListAdminFindingsParams,
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
  // Wipe any role cookie left behind by AdminAuthProvider.
  if (typeof document !== "undefined") {
    document.cookie =
      "argus.admin.role=; path=/; max-age=0; SameSite=Strict";
  }
  listAdminFindingsAction.mockReset();
  bulkSuppressFindingsAction.mockReset();
  bulkMarkFalsePositiveFindingsAction.mockReset();
  listTenants.mockReset();
  downloadFindingsExport.mockReset();
  listTenants.mockResolvedValue([]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AdminFindingsClient — super-admin", () => {
  it("hydrates findings via the server action and renders the Tenant column", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(
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
    expect(listAdminFindingsAction).toHaveBeenCalled();
  });

  it("re-issues the action with the new severity filter and updates the URL", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(pageOf([]));
    const user = userEvent.setup();
    renderClient();

    await waitFor(() => expect(listAdminFindingsAction).toHaveBeenCalled());

    listAdminFindingsAction.mockClear();
    routerReplace.mockClear();
    listAdminFindingsAction.mockResolvedValue(
      pageOf([makeItem({ id: "f-crit", severity: "critical", title: "Critical" })]),
    );

    await user.click(screen.getByTestId("filter-severity-critical"));

    await waitFor(() => expect(listAdminFindingsAction).toHaveBeenCalled());
    const params = listAdminFindingsAction.mock
      .calls[0][0] as ListAdminFindingsParams;
    expect(params.severity).toEqual(["critical"]);

    await waitFor(() => expect(routerReplace).toHaveBeenCalled());
    expect(routerReplace.mock.calls[0][0] as string).toContain(
      "severity=critical",
    );
  });

  it("paginates via fetchNextPage when next_cursor is set (cursor forwarded)", async () => {
    setRole("super-admin");
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

    listAdminFindingsAction
      .mockResolvedValueOnce(firstPage)
      .mockResolvedValueOnce(secondPage);

    renderClient();

    await waitFor(() => {
      expect(screen.getByTestId("findings-counter")).toHaveTextContent(
        "3 / 6",
      );
    });

    await waitFor(
      () => expect(listAdminFindingsAction).toHaveBeenCalledTimes(2),
      { timeout: 5000 },
    );
    const secondCallArgs = listAdminFindingsAction.mock.calls[1][0] as {
      cursor: string | null;
    };
    expect(secondCallArgs.cursor).toBe("cursor-page-2");
  });

  it("renders a closed-taxonomy error message when the network fails (no stack/PII)", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockRejectedValue(
      new AdminFindingsError("network_error"),
    );
    renderClient();

    // network_error retries once with the default 1s exponential delay.
    const err = await screen.findByTestId(
      "findings-error",
      {},
      { timeout: 5000 },
    );
    expect(err).toHaveAttribute("role", "alert");
    expect(err.textContent ?? "").toMatch(/Сеть недоступна/);
    expect(err.textContent ?? "").not.toMatch(/at .+\.ts:|stack/i);
  });

  it("does NOT retry when the server action throws 403 (closed taxonomy)", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockRejectedValue(
      new AdminFindingsError("forbidden", 403),
    );
    renderClient();

    const err = await screen.findByTestId("findings-error");
    expect(err.textContent ?? "").toMatch(/Недостаточно прав/);
    expect(listAdminFindingsAction).toHaveBeenCalledTimes(1);
  });
});

describe("AdminFindingsClient — URL hydration & filter params", () => {
  it("hydrates filters from URL search params on initial mount (severity + status_mode + target)", async () => {
    setRole("super-admin");
    setSearchParams(
      "severity=critical&severity=high&status_mode=open&target=example.com",
    );
    listAdminFindingsAction.mockResolvedValue(pageOf([]));
    renderClient();

    await waitFor(() => expect(listAdminFindingsAction).toHaveBeenCalled());
    const params = listAdminFindingsAction.mock
      .calls[0][0] as ListAdminFindingsParams;
    expect(params.severity).toEqual(["critical", "high"]);
    expect(params.statusMode).toBe("open");
    expect(params.target).toBe("example.com");

    expect(screen.getByTestId("filter-severity-critical")).toBeChecked();
    expect(screen.getByTestId("filter-severity-high")).toBeChecked();
    expect(screen.getByTestId("filter-status-open")).toBeChecked();
    expect(screen.getByTestId("filter-target")).toHaveValue("example.com");
  });

  it("propagates statusMode='false_positive' to the server action when chosen (S1-2)", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(pageOf([]));
    const user = userEvent.setup();
    renderClient();

    await waitFor(() => expect(listAdminFindingsAction).toHaveBeenCalled());

    listAdminFindingsAction.mockClear();
    await user.click(screen.getByTestId("filter-status-false_positive"));

    await waitFor(() => expect(listAdminFindingsAction).toHaveBeenCalled());
    const params = listAdminFindingsAction.mock
      .calls.at(-1)?.[0] as ListAdminFindingsParams;
    expect(params.statusMode).toBe("false_positive");
  });

  it("defaults statusMode to 'all' (no false_positive override) on first mount", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(pageOf([]));
    renderClient();

    await waitFor(() => expect(listAdminFindingsAction).toHaveBeenCalled());
    const params = listAdminFindingsAction.mock
      .calls[0][0] as ListAdminFindingsParams;
    expect(params.statusMode).toBe("all");
  });

  it("forwards the trimmed target text in the action params (mapping to backend `q` is server-side, S1-1)", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(pageOf([]));
    setSearchParams("target=  trim-me  ");
    renderClient();

    await waitFor(() => expect(listAdminFindingsAction).toHaveBeenCalled());
    const params = listAdminFindingsAction.mock
      .calls[0][0] as ListAdminFindingsParams;
    expect(params.target).toBe("trim-me");
  });
});

describe("AdminFindingsClient — admin (non-super) tenant binding (S1-6)", () => {
  it("renders the explicit no-tenant empty state and does NOT fire the action", async () => {
    setRole("admin");
    listAdminFindingsAction.mockResolvedValue(pageOf([]));
    renderClient();

    expect(
      await screen.findByTestId("findings-admin-no-tenant"),
    ).toBeInTheDocument();
    // Give React Query a chance to fire if it was going to.
    await new Promise((r) => setTimeout(r, 50));
    expect(listAdminFindingsAction).not.toHaveBeenCalled();
  });

  it("hides the Tenant column AND the tenant selector for admin role", async () => {
    setRole("admin");
    renderClient();

    await waitFor(() =>
      expect(screen.queryByTestId("tenant-selector")).not.toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("columnheader", { name: "Tenant" }),
    ).not.toBeInTheDocument();
  });
});

describe("AdminFindingsClient — debouncing (S1-4)", () => {
  it("does NOT fire the action on every keystroke (debounced 300ms)", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(pageOf([]));
    const user = userEvent.setup();
    renderClient();

    await waitFor(() =>
      expect(listAdminFindingsAction).toHaveBeenCalledTimes(1),
    );

    listAdminFindingsAction.mockClear();
    const input = screen.getByTestId("filter-target");
    await user.click(input);

    // 5 keystrokes back-to-back; without debouncing this would queue 5 fetches.
    await user.keyboard("hello");

    // Wait long enough for the debounced effect to flush (debounce is 300ms).
    // Wrap in act() so React commits the state update from the debounced setter.
    await act(async () => {
      await new Promise((r) => setTimeout(r, 600));
    });

    await waitFor(() =>
      expect(listAdminFindingsAction).toHaveBeenCalledTimes(1),
    );
    const params = listAdminFindingsAction.mock
      .calls.at(-1)?.[0] as ListAdminFindingsParams;
    expect(params.target).toBe("hello");
  }, 10_000);
});

describe("AdminFindingsClient — export surface (S1-5)", () => {
  it("does NOT render a global export popover (per-row export only lives in the drawer)", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(
      pageOf([makeItem({ id: "f", scan_id: "scan-42", title: "row" })]),
    );
    renderClient();

    await screen.findByText("row");
    expect(
      screen.queryByTestId("findings-export-toggle"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("findings-export-popover"),
    ).not.toBeInTheDocument();
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Bulk findings actions integration (T21)
// ────────────────────────────────────────────────────────────────────────────

const TENANT_A = "00000000-0000-0000-0000-000000000001";
const TENANT_B = "00000000-0000-0000-0000-000000000002";
const FIND_A1 = "11111111-1111-1111-1111-111111111111";
const FIND_A2 = "22222222-2222-2222-2222-222222222222";
const FIND_B1 = "33333333-3333-3333-3333-333333333333";

describe("AdminFindingsClient — bulk actions (T21)", () => {
  it("toolbar stays hidden until at least one row is selected", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(
      pageOf([
        makeItem({ id: FIND_A1, tenant_id: TENANT_A, title: "row a" }),
      ]),
    );
    renderClient();

    await screen.findByText("row a");
    expect(
      screen.queryByTestId("bulk-actions-toolbar"),
    ).not.toBeInTheDocument();
  });

  it("selecting a row reveals the toolbar with the right count", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(
      pageOf([
        makeItem({ id: FIND_A1, tenant_id: TENANT_A, title: "row a" }),
        makeItem({ id: FIND_A2, tenant_id: TENANT_A, title: "row b" }),
      ]),
    );
    const user = userEvent.setup();
    renderClient();

    await screen.findByText("row a");
    await user.click(screen.getByTestId(`findings-select-row-${FIND_A1}`));

    expect(
      await screen.findByTestId("bulk-actions-toolbar"),
    ).toBeInTheDocument();
    expect(screen.getByTestId("bulk-selection-count")).toHaveTextContent(
      "Выбрано 1 findings",
    );
  });

  it("running 'Suppress' calls bulkSuppressFindingsAction with grouped tenant targets and shows the success banner", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(
      pageOf([
        makeItem({ id: FIND_A1, tenant_id: TENANT_A, title: "row a1" }),
        makeItem({ id: FIND_B1, tenant_id: TENANT_B, title: "row b1" }),
      ]),
    );
    bulkSuppressFindingsAction.mockResolvedValue({
      affected_count: 2,
      skipped_count: 0,
      failed_ids: [],
      failure_reason_taxonomy: null,
      audit_ids: ["audit-1", "audit-2"],
    });
    const user = userEvent.setup();
    renderClient();

    await screen.findByText("row a1");
    await user.click(screen.getByTestId(`findings-select-row-${FIND_A1}`));
    await user.click(screen.getByTestId(`findings-select-row-${FIND_B1}`));
    await user.click(screen.getByTestId("bulk-action-suppress"));

    await user.selectOptions(
      await screen.findByTestId("bulk-suppress-reason"),
      "duplicate",
    );
    await user.click(screen.getByTestId("bulk-action-dialog-confirm"));

    await waitFor(() =>
      expect(bulkSuppressFindingsAction).toHaveBeenCalledTimes(1),
    );
    const args = bulkSuppressFindingsAction.mock.calls[0][0] as {
      targets: Array<{ id: string; tenant_id: string }>;
      reason: string;
    };
    const ids = args.targets.map((t) => t.id);
    expect(ids).toEqual(expect.arrayContaining([FIND_A1, FIND_B1]));
    const tenants = args.targets.map((t) => t.tenant_id);
    expect(tenants).toEqual(expect.arrayContaining([TENANT_A, TENANT_B]));
    expect(args.reason).toBe("duplicate");

    const banner = await screen.findByTestId("bulk-action-banner");
    expect(banner.getAttribute("data-tone")).toBe("success");
    expect(banner.textContent ?? "").toMatch(/Применено к 2 findings/);
  });

  it("partial-success response renders a yellow warning banner with the breakdown", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(
      pageOf([
        makeItem({ id: FIND_A1, tenant_id: TENANT_A }),
        makeItem({ id: FIND_A2, tenant_id: TENANT_A }),
      ]),
    );
    bulkSuppressFindingsAction.mockResolvedValue({
      affected_count: 1,
      skipped_count: 0,
      failed_ids: [FIND_A2],
      failure_reason_taxonomy: null,
      audit_ids: ["audit-x"],
    });
    const user = userEvent.setup();
    renderClient();

    await screen.findByTestId(`findings-row-${FIND_A1}`);
    await user.click(screen.getByTestId(`findings-select-row-${FIND_A1}`));
    await user.click(screen.getByTestId(`findings-select-row-${FIND_A2}`));
    await user.click(screen.getByTestId("bulk-action-suppress"));

    await user.selectOptions(
      await screen.findByTestId("bulk-suppress-reason"),
      "duplicate",
    );
    await user.click(screen.getByTestId("bulk-action-dialog-confirm"));

    const banner = await screen.findByTestId("bulk-action-banner");
    expect(banner.getAttribute("data-tone")).toBe("warning");
    expect(banner.textContent ?? "").toMatch(/Применено к 1 из 2/);
    expect(banner.textContent ?? "").toMatch(/не применено к 1/);
  });

  it("server-action failure (forbidden) renders a closed-taxonomy error banner inside the dialog", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(
      pageOf([makeItem({ id: FIND_A1, tenant_id: TENANT_A })]),
    );
    const { BulkFindingsActionError } = await import(
      "@/lib/adminFindings"
    );
    bulkSuppressFindingsAction.mockRejectedValue(
      new BulkFindingsActionError("forbidden", 403),
    );
    const user = userEvent.setup();
    renderClient();

    await screen.findByTestId(`findings-row-${FIND_A1}`);
    await user.click(screen.getByTestId(`findings-select-row-${FIND_A1}`));
    await user.click(screen.getByTestId("bulk-action-suppress"));

    await user.selectOptions(
      await screen.findByTestId("bulk-suppress-reason"),
      "duplicate",
    );
    await user.click(screen.getByTestId("bulk-action-dialog-confirm"));

    const err = await screen.findByTestId("bulk-action-dialog-error");
    expect(err).toHaveAttribute("role", "alert");
    expect(err.textContent ?? "").toMatch(/Недостаточно прав/);
    // Closed-taxonomy: must NOT echo HTTP details / stack traces.
    expect(err.textContent ?? "").not.toMatch(/403|stack|forbidden/i);
  });

  it("'mark_false_positive' funnels through bulkMarkFalsePositiveFindingsAction with a confirmation checkbox", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(
      pageOf([makeItem({ id: FIND_A1, tenant_id: TENANT_A })]),
    );
    bulkMarkFalsePositiveFindingsAction.mockResolvedValue({
      affected_count: 1,
      skipped_count: 0,
      failed_ids: [],
      failure_reason_taxonomy: null,
      audit_ids: ["audit-fp"],
    });
    const user = userEvent.setup();
    renderClient();

    await screen.findByTestId(`findings-row-${FIND_A1}`);
    await user.click(screen.getByTestId(`findings-select-row-${FIND_A1}`));
    await user.click(screen.getByTestId("bulk-action-mark_false_positive"));

    const confirmCb = await screen.findByTestId("bulk-fp-confirm");
    await user.click(confirmCb);
    await user.click(screen.getByTestId("bulk-action-dialog-confirm"));

    await waitFor(() =>
      expect(bulkMarkFalsePositiveFindingsAction).toHaveBeenCalledTimes(1),
    );
    const banner = await screen.findByTestId("bulk-action-banner");
    expect(banner.getAttribute("data-tone")).toBe("success");
  });

  it("admin-no-tenant view (S1-6) does NOT render the bulk toolbar or selection checkboxes", async () => {
    setRole("admin");
    renderClient();

    expect(
      await screen.findByTestId("findings-admin-no-tenant"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("bulk-actions-toolbar"),
    ).not.toBeInTheDocument();
    expect(screen.queryByTestId("findings-select-all")).not.toBeInTheDocument();
  });

  it("'Снять выбор' clears the selection and hides the toolbar", async () => {
    setRole("super-admin");
    listAdminFindingsAction.mockResolvedValue(
      pageOf([
        makeItem({ id: FIND_A1, tenant_id: TENANT_A, title: "clear me" }),
      ]),
    );
    const user = userEvent.setup();
    renderClient();

    await screen.findByText("clear me");
    await user.click(screen.getByTestId(`findings-select-row-${FIND_A1}`));
    expect(
      await screen.findByTestId("bulk-actions-toolbar"),
    ).toBeInTheDocument();

    await user.click(screen.getByTestId("bulk-action-clear"));
    await waitFor(() =>
      expect(
        screen.queryByTestId("bulk-actions-toolbar"),
      ).not.toBeInTheDocument(),
    );
  });
});
